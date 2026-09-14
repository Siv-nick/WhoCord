"""
tests/test_sanitizers.py
------------------------
Tests for input sanitizers and validators.

Coverage focus for this revision
--------------------------------
- ``sanitize_email`` preserves ``%`` in the local part (the bug: the
  strip regex was dropping it, mangling ``user%tag@host`` before
  validation).
- ``validate_email`` rejects bare ``@``, ``user@``, and ``@host``.
- New helpers: ``sanitize_url`` / ``validate_url`` / ``sanitize_phone``
  / ``validate_phone``.
- SSRF guard (``discord_osint.utils.url_safety``): loopback, private
  ranges, link-local / cloud metadata, IPv6 loopback, DNS-resolved hosts.
"""

import ipaddress
import socket
from unittest.mock import patch

import pytest

from discord_osint.errors import InputValidationError
from discord_osint.utils.sanitizers import (
    sanitize_username,
    sanitize_email,
    sanitize_user_id,
    sanitize_domain,
    sanitize_url,
    sanitize_phone,
    validate_email,
    validate_url,
    validate_phone,
    validate_mode,
    MAX_EMAIL_LEN,
    MAX_URL_LEN,
)
from discord_osint.utils.url_safety import (
    UnsafeURLError,
    validate_url as ssrf_validate_url,
    is_safe_url,
)


# ===========================================================================
# sanitize_username
# ===========================================================================

class TestSanitizeUsername:
    def test_valid_passes_through(self):
        assert sanitize_username("john_doe") == "john_doe"

    def test_leading_dot_stripped(self):
        assert sanitize_username(".john") == "john"

    def test_special_chars_removed(self):
        assert sanitize_username("john<script>") == "johnscript"

    def test_empty_raises(self):
        with pytest.raises(InputValidationError):
            sanitize_username("")

    def test_length_capped(self):
        assert len(sanitize_username("x" * 200)) == 50

    def test_non_string_raises(self):
        with pytest.raises(InputValidationError):
            sanitize_username(None)  # type: ignore[arg-type]


# ===========================================================================
# sanitize_email — the % fix
# ===========================================================================

class TestSanitizeEmail:
    def test_plain_email(self):
        assert sanitize_email("test@example.com") == "test@example.com"

    def test_uppercase_lowercased(self):
        assert sanitize_email("USER@EXAMPLE.COM") == "user@example.com"

    def test_whitespace_stripped(self):
        assert sanitize_email("  test@example.com  ") == "test@example.com"

    def test_percent_sign_preserved(self):
        """The bug: `%` was in `_EMAIL_INVALID` and got stripped."""
        assert sanitize_email("user%tag@example.com") == "user%tag@example.com"

    def test_plus_sign_preserved(self):
        assert sanitize_email("user+tag@example.com") == "user+tag@example.com"

    def test_illegal_chars_removed(self):
        # Spaces / angle brackets are not legal; strip them.
        result = sanitize_email("bad<space> name@example.com")
        assert "<" not in result and ">" not in result
        assert "@" in result

    def test_length_capped_to_rfc_limit(self):
        local = "a" * (MAX_EMAIL_LEN + 50)
        email = f"{local}@example.com"
        out = sanitize_email(email)
        assert len(out) <= MAX_EMAIL_LEN


# ===========================================================================
# validate_email — bare @ rejection
# ===========================================================================

class TestValidateEmail:
    def test_valid(self):
        ok, reason = validate_email("alice@example.com")
        assert ok and reason == ""

    def test_empty(self):
        ok, reason = validate_email("")
        assert not ok and "empty" in reason

    def test_bare_at(self):
        ok, reason = validate_email("@")
        assert not ok
        # Must not be a bare "no @" — we now catch it explicitly.
        assert ok is False

    def test_missing_local_part(self):
        ok, reason = validate_email("@example.com")
        assert not ok
        assert "exactly one" in reason or "local" in reason

    def test_missing_domain(self):
        ok, reason = validate_email("alice@")
        assert not ok
        assert "domain" in reason or "one @" in reason

    def test_two_ats(self):
        ok, reason = validate_email("alice@@example.com")
        assert not ok

    def test_bad_tld(self):
        ok, reason = validate_email("alice@example.jpg")
        assert not ok
        assert "tld" in reason.lower() or "TLD" in reason

    def test_too_long(self):
        ok, reason = validate_email("a" * 300 + "@example.com")
        assert not ok
        assert "length" in reason

    def test_percent_in_local_part_accepted(self):
        ok, _ = validate_email("user%tag@example.com")
        assert ok


# ===========================================================================
# sanitize_user_id / sanitize_domain
# ===========================================================================

class TestSanitizeUserId:
    def test_digits_only(self):
        assert sanitize_user_id("123abc") == "123"

    def test_empty_raises(self):
        with pytest.raises(InputValidationError):
            sanitize_user_id("abc")


class TestSanitizeDomain:
    def test_protocol_stripped(self):
        assert sanitize_domain("https://example.com") == "example.com"

    def test_path_stripped(self):
        assert sanitize_domain("example.com/some/path?q=1") == "example.com"

    def test_lowercased(self):
        assert sanitize_domain("EXAMPLE.COM") == "example.com"

    def test_empty_raises(self):
        with pytest.raises(InputValidationError):
            sanitize_domain("")


# ===========================================================================
# sanitize_url / validate_url  (new helpers)
# ===========================================================================

class TestSanitizeUrl:
    def test_http_accepted(self):
        assert sanitize_url("http://example.com/a") == "http://example.com/a"

    def test_https_accepted(self):
        assert sanitize_url("https://example.com") == "https://example.com"

    def test_whitespace_stripped(self):
        assert sanitize_url("  https://example.com  ") == "https://example.com"

    def test_javascript_scheme_rejected(self):
        with pytest.raises(InputValidationError):
            sanitize_url("javascript:alert(1)")

    def test_data_scheme_rejected(self):
        with pytest.raises(InputValidationError):
            sanitize_url("data:text/html,<script>alert(1)</script>")

    def test_no_scheme_rejected(self):
        with pytest.raises(InputValidationError):
            sanitize_url("example.com")

    def test_empty_raises(self):
        with pytest.raises(InputValidationError):
            sanitize_url("")

    def test_too_long_raises(self):
        with pytest.raises(InputValidationError):
            sanitize_url("https://example.com/" + "a" * MAX_URL_LEN)


class TestValidateUrl:
    def test_valid_https(self):
        ok, reason = validate_url("https://example.com")
        assert ok and reason == ""

    def test_valid_http(self):
        ok, _ = validate_url("http://example.com")
        assert ok

    def test_javascript(self):
        ok, reason = validate_url("javascript:alert(1)")
        assert not ok
        assert "scheme" in reason.lower()

    def test_file_scheme(self):
        ok, reason = validate_url("file:///etc/passwd")
        assert not ok

    def test_empty(self):
        ok, _ = validate_url("")
        assert not ok

    def test_no_host(self):
        ok, _ = validate_url("http://")
        assert not ok

    def test_too_long(self):
        ok, _ = validate_url("https://" + "a" * MAX_URL_LEN)
        assert not ok


# ===========================================================================
# sanitize_phone / validate_phone  (new helpers)
# ===========================================================================

class TestSanitizePhone:
    def test_parentheses_and_dashes_preserved(self):
        assert sanitize_phone("+1 (555) 000-0000") == "+1 (555) 000-0000"

    def test_letters_removed(self):
        result = sanitize_phone("+1abc555def0000000")
        assert "a" not in result and "d" not in result

    def test_whitespace_collapsed(self):
        assert sanitize_phone("+1     555") == "+1 555"

    def test_length_capped(self):
        assert len(sanitize_phone("1" * 100)) <= 24

    def test_empty_string_ok(self):
        # An optional field — empty is not an error.
        assert sanitize_phone("") == ""


class TestValidatePhone:
    def test_valid_us(self):
        ok, _ = validate_phone("+1 555 000 0000")
        assert ok

    def test_valid_digits_only(self):
        ok, _ = validate_phone("15550000000")
        assert ok

    def test_too_short(self):
        ok, reason = validate_phone("12345")
        assert not ok
        assert "7" in reason

    def test_too_long(self):
        ok, reason = validate_phone("1" * 20)
        assert not ok
        assert "15" in reason

    def test_empty(self):
        ok, _ = validate_phone("")
        assert not ok


# ===========================================================================
# validate_mode
# ===========================================================================

class TestValidateMode:
    def test_manual(self):
        assert validate_mode("manual") == "manual"

    def test_discord(self):
        assert validate_mode("discord") == "discord"

    def test_invalid(self):
        with pytest.raises(InputValidationError):
            validate_mode("invalid")


# ===========================================================================
# SSRF guard — utils.url_safety
# ===========================================================================

def _resolved_addrs(*ips):
    """Build a fake socket.getaddrinfo return tuple for the given IPs."""
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
        for ip in ips
    ]


class TestSsrfGuardIpLiterals:
    """
    IP literals don't require DNS — validate_url should reject them
    without any socket call.
    """

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/admin",
        "http://127.1.2.3/",
        "https://10.0.0.1/",
        "http://10.255.255.255/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.0.1/",
        "http://0.0.0.0/",
    ])
    def test_private_ipv4_blocked(self, url):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url(url)
        assert not is_safe_url(url)

    @pytest.mark.parametrize("url", [
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://[::ffff:127.0.0.1]/",  # v4-mapped
    ])
    def test_private_ipv6_blocked(self, url):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url(url)

    @pytest.mark.parametrize("url", [
        "http://8.8.8.8/",
        "https://1.1.1.1/",
        "http://93.184.216.34/",
    ])
    def test_public_ipv4_allowed(self, url):
        # No DNS required — should not raise.
        ssrf_validate_url(url)
        assert is_safe_url(url)


class TestSsrfGuardHostnames:
    def test_localhost_blocked_by_name(self):
        # Hardcoded blocklist — no DNS call needed.
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("http://localhost/admin")

    def test_metadata_google_internal_blocked(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("http://metadata.google.internal/")

    def test_metadata_blocked(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("http://metadata/")

    def test_hostname_resolving_to_private_blocked(self):
        """A hostname that resolves to 10.0.0.1 must be rejected."""
        with patch("socket.getaddrinfo", return_value=_resolved_addrs("10.0.0.1")):
            with pytest.raises(UnsafeURLError):
                ssrf_validate_url("http://internal.example.com/")

    def test_hostname_resolving_to_metadata_blocked(self):
        with patch("socket.getaddrinfo", return_value=_resolved_addrs("169.254.169.254")):
            with pytest.raises(UnsafeURLError):
                ssrf_validate_url("http://evil.example.com/")

    def test_hostname_resolving_to_public_allowed(self):
        with patch("socket.getaddrinfo", return_value=_resolved_addrs("1.2.3.4")):
            ssrf_validate_url("http://example.com/")

    def test_mixed_resolution_rejected(self):
        """Any private address in the resolved set → whole URL rejected."""
        with patch("socket.getaddrinfo",
                   return_value=_resolved_addrs("1.2.3.4", "10.0.0.1")):
            with pytest.raises(UnsafeURLError):
                ssrf_validate_url("http://mixed.example.com/")


class TestSsrfGuardSchemes:
    def test_ftp_rejected(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("ftp://example.com/file")

    def test_file_rejected(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("file:///etc/passwd")

    def test_javascript_rejected(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("javascript:alert(1)")

    def test_gopher_rejected(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("gopher://example.com")

    def test_empty_rejected(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("")

    def test_no_scheme_rejected(self):
        with pytest.raises(UnsafeURLError):
            ssrf_validate_url("example.com/path")


class TestIsSafeUrl:
    """
    is_safe_url must never raise — callers use it as a bool gate before
    doing their own request.
    """

    def test_returns_false_on_garbage(self):
        assert is_safe_url("") is False
        assert is_safe_url("not a url") is False
        assert is_safe_url("javascript:alert(1)") is False

    def test_returns_true_on_public(self):
        assert is_safe_url("https://8.8.8.8/") is True

    def test_never_raises_on_resolution_error(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            # Should not raise, just report unsafe.
            assert is_safe_url("http://does-not-resolve.example/") is False