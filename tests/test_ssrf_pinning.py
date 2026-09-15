
"""
tests/test_ssrf_pinning.py
--------------------------
Regression tests for Tier 1, item 1.4: the SSRF guard must reject URLs
whose host resolves to a private, loopback, link-local, or metadata
address, and the pinned fetch must not silently fall back to the
unvalidated address between validation and connect.

By design the positive case — a public URL actually succeeding — is not
asserted. That path depends on real DNS and a real network and is not
what makes the guard worth having. Only the negative cases are tested.

Change log
----------
- Initial. Covers IP literals (v4, v6), blocked hostnames, bad schemes,
  hostname resolution to private / metadata / mixed addresses, the
  thread-local DNS pin itself, and the safe_get_pinned entry point.
"""

from __future__ import annotations

import socket
import threading

import pytest

from discord_osint.utils import url_safety
from discord_osint.utils.url_safety import (
    UnsafeURLError,
    is_safe_url,
    safe_get_pinned,
    validate_url,
)


def _fake_getaddrinfo(*ips: str) -> list:
    """Build a socket.getaddrinfo-shaped return value for the given IPs."""
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))
        for ip in ips
    ]


# ---------------------------------------------------------------------------
# validate_url — IP literals
# ---------------------------------------------------------------------------

class TestValidateUrlIpLiterals:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/",
        "http://127.0.0.1:5000/admin",
        "http://10.0.0.1/",
        "http://10.255.255.255/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
    ])
    def test_private_ipv4_literals_blocked(self, url):
        with pytest.raises(UnsafeURLError):
            validate_url(url)

    @pytest.mark.parametrize("url", [
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
    ])
    def test_private_ipv6_literals_blocked(self, url):
        with pytest.raises(UnsafeURLError):
            validate_url(url)


# ---------------------------------------------------------------------------
# validate_url — hostnames, schemes, malformed input
# ---------------------------------------------------------------------------

class TestValidateUrlHostnamesAndSchemes:
    @pytest.mark.parametrize("url", [
        "http://localhost/",
        "http://metadata/",
        "http://metadata.google.internal/",
        "http://instance-data/",
    ])
    def test_blocked_hostnames(self, url):
        with pytest.raises(UnsafeURLError):
            validate_url(url)

    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://example.com/",
        "ftp://example.com/",
    ])
    def test_bad_schemes_blocked(self, url):
        with pytest.raises(UnsafeURLError):
            validate_url(url)

    def test_empty_and_unparseable(self):
        with pytest.raises(UnsafeURLError):
            validate_url("")
        with pytest.raises(UnsafeURLError):
            validate_url("not a url")


# ---------------------------------------------------------------------------
# validate_url — DNS resolution
# ---------------------------------------------------------------------------

class TestValidateUrlResolution:
    def test_hostname_resolving_to_private_blocked(self, monkeypatch):
        monkeypatch.setattr(
            url_safety, "_original_getaddrinfo",
            lambda *a, **k: _fake_getaddrinfo("10.0.0.1"),
        )
        with pytest.raises(UnsafeURLError):
            validate_url("http://internal.example.com/")

    def test_hostname_resolving_to_metadata_blocked(self, monkeypatch):
        monkeypatch.setattr(
            url_safety, "_original_getaddrinfo",
            lambda *a, **k: _fake_getaddrinfo("169.254.169.254"),
        )
        with pytest.raises(UnsafeURLError):
            validate_url("http://evil.example.com/")

    def test_mixed_resolution_rejected(self, monkeypatch):
        """
        A hostname resolving to both a public and a private address is a
        DNS-rebinding red flag — reject the whole URL, do not pick the
        public address and hope.
        """
        monkeypatch.setattr(
            url_safety, "_original_getaddrinfo",
            lambda *a, **k: _fake_getaddrinfo("1.2.3.4", "10.0.0.1"),
        )
        with pytest.raises(UnsafeURLError):
            validate_url("http://mixed.example.com/")

    def test_public_only_resolution_passes(self, monkeypatch):
        monkeypatch.setattr(
            url_safety, "_original_getaddrinfo",
            lambda *a, **k: _fake_getaddrinfo("1.2.3.4"),
        )
        # Must not raise.
        validate_url("http://example.com/")

    def test_dns_failure_raises_unsafe(self, monkeypatch):
        def boom(*a, **k):
            raise socket.gaierror("no such host")
        monkeypatch.setattr(url_safety, "_original_getaddrinfo", boom)
        with pytest.raises(UnsafeURLError):
            validate_url("http://does-not-resolve.example.com/")


# ---------------------------------------------------------------------------
# The pin mechanism itself (no network involved)
# ---------------------------------------------------------------------------

class TestDnsPinOverride:
    def test_pin_host_overrides_getaddrinfo(self):
        with url_safety._pin_host("example.com", "1.2.3.4"):
            infos = socket.getaddrinfo("example.com", 80)
        assert infos[0][4][0] == "1.2.3.4"

    def test_pin_restored_after_context(self):
        with url_safety._pin_host("example.com", "1.2.3.4"):
            overrides = getattr(url_safety._pin_local, "overrides", {}) or {}
            assert overrides.get("example.com") == "1.2.3.4"
        overrides = getattr(url_safety._pin_local, "overrides", {}) or {}
        assert "example.com" not in overrides

    def test_nested_pin_restores_previous(self):
        with url_safety._pin_host("example.com", "1.1.1.1"):
            with url_safety._pin_host("example.com", "2.2.2.2"):
                overrides = getattr(url_safety._pin_local, "overrides", {}) or {}
                assert overrides.get("example.com") == "2.2.2.2"
            overrides = getattr(url_safety._pin_local, "overrides", {}) or {}
            assert overrides.get("example.com") == "1.1.1.1"

    def test_pins_are_thread_local(self):
        """
        A pin installed in one thread must not leak into a sibling
        thread. This is what lets concurrent investigations each pin
        their own connections without cross-talk.
        """
        seen_in_other_thread: list = []
        ready = threading.Event()

        def other_thread():
            ready.wait(timeout=2)
            try:
                infos = socket.getaddrinfo("example.com", 80)
                seen_in_other_thread.extend(infos)
            except socket.gaierror:
                # No real DNS in this environment. The assertion below
                # still holds: an empty list does not contain the pin.
                pass

        with url_safety._pin_host("example.com", "1.2.3.4"):
            t = threading.Thread(target=other_thread)
            t.start()
            ready.set()
            t.join(timeout=5)

        pinned_ips = [i[4][0] for i in seen_in_other_thread]
        assert "1.2.3.4" not in pinned_ips


# ---------------------------------------------------------------------------
# safe_get_pinned — entry point
# ---------------------------------------------------------------------------

class TestSafeGetPinned:
    def test_blocks_loopback_before_any_request(self):
        """
        If this reached the HTTP layer, connecting to 127.0.0.1:1 would
        fail with ConnectionRefused in a millisecond. We want the guard
        to fire first, with UnsafeURLError.
        """
        with pytest.raises(UnsafeURLError):
            safe_get_pinned("http://127.0.0.1:1/", timeout=1)

    def test_blocks_metadata_service(self):
        with pytest.raises(UnsafeURLError):
            safe_get_pinned("http://169.254.169.254/latest/meta-data/", timeout=1)

    def test_blocks_ipv6_loopback(self):
        with pytest.raises(UnsafeURLError):
            safe_get_pinned("http://[::1]/", timeout=1)

    def test_blocks_bad_scheme(self):
        with pytest.raises(UnsafeURLError):
            safe_get_pinned("file:///etc/passwd", timeout=1)


# ---------------------------------------------------------------------------
# is_safe_url — bool gate, must never raise
# ---------------------------------------------------------------------------

class TestIsSafeUrl:
    def test_false_on_bad_scheme(self):
        assert is_safe_url("javascript:alert(1)") is False
        assert is_safe_url("file:///etc/passwd") is False

    def test_false_on_empty(self):
        assert is_safe_url("") is False
        assert is_safe_url("not a url") is False

    def test_false_on_loopback(self):
        assert is_safe_url("http://127.0.0.1/") is False

    def test_never_raises_on_resolution_error(self, monkeypatch):
        def boom(*a, **k):
            raise socket.gaierror("nope")
        monkeypatch.setattr(url_safety, "_original_getaddrinfo", boom)
        assert url_safety.is_safe_url("http://does-not-resolve.example/") is False


# ---------------------------------------------------------------------------
# Redirect trail — url_analysis needs the real chain, not a collapsed hop
# ---------------------------------------------------------------------------

class TestRedirectTrail:
    """
    ``safe_get_pinned`` follows redirects manually so each hop can be
    re-resolved and re-pinned. That means ``response.history`` is
    always empty and ``response.url`` only shows the final URL, so a
    caller comparing ``final_url == url`` could only ever report zero
    or one redirect regardless of how many hops actually happened.
    ``redirect_trail`` fixes that by recording every URL visited.
    """

    def test_trail_records_every_hop(self, monkeypatch):
        import requests

        from discord_osint.utils import url_safety

        hops = [
            "http://example.com/start",
            "http://example.com/step2",
            "http://example.com/step3",
        ]

        monkeypatch.setattr(
            url_safety, "resolve_and_validate", lambda host: "93.184.216.34",
        )

        call_count = {"n": 0}

        def fake_get(self, url, **kwargs):
            idx = call_count["n"]
            call_count["n"] += 1
            resp = requests.Response()
            resp.status_code = 302 if idx < len(hops) - 1 else 200
            resp.url = url
            if idx < len(hops) - 1:
                resp.headers["Location"] = hops[idx + 1]
            return resp

        monkeypatch.setattr(requests.Session, "get", fake_get)

        trail: list[str] = []
        resp = url_safety.safe_get_pinned(hops[0], redirect_trail=trail)

        assert trail == hops
        assert resp.status_code == 200

    def test_no_redirect_trail_has_single_entry(self, monkeypatch):
        import requests
        from discord_osint.utils import url_safety

        monkeypatch.setattr(
            url_safety, "resolve_and_validate", lambda host: "93.184.216.34",
        )

        def fake_get(self, url, **kwargs):
            resp = requests.Response()
            resp.status_code = 200
            resp.url = url
            return resp

        monkeypatch.setattr(requests.Session, "get", fake_get)

        trail: list[str] = []
        url_safety.safe_get_pinned("http://example.com/", redirect_trail=trail)
        assert trail == ["http://example.com/"]

    def test_trail_defaults_to_none_and_is_optional(self, monkeypatch):
        # Existing callers that don't pass redirect_trail must be
        # completely unaffected.
        import requests
        from discord_osint.utils import url_safety

        monkeypatch.setattr(
            url_safety, "resolve_and_validate", lambda host: "93.184.216.34",
        )

        def fake_get(self, url, **kwargs):
            resp = requests.Response()
            resp.status_code = 200
            resp.url = url
            return resp

        monkeypatch.setattr(requests.Session, "get", fake_get)

        resp = url_safety.safe_get_pinned("http://example.com/")
        assert resp.status_code == 200
