"""
discord_osint/utils/sanitizers.py
---------------------------------
Input sanitization and validation helpers.

These functions are the single source of truth for cleaning all
user-supplied values before they touch the file system, subprocess
calls, or network requests.  web_app.py and __main__.py both import
from here instead of rolling their own inline re.sub() calls.

Change log
----------
- ``sanitize_email``'s strip regex was missing ``%``, a character that
  is legal in the local part of an email address. ``user%tag@host``
  was being silently mangled to ``usertag@host`` before it reached the
  validator, which then accepted the (wrong) mangled value.
- ``validate_email`` now rejects a bare ``@`` or a missing local part.
- Added ``sanitize_url`` / ``validate_url`` so the URL module has a
  proper helper instead of a two-line inline check in web_app.py.
- Added ``sanitize_phone`` / ``validate_phone`` for the same reason.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..errors import InputValidationError

# ---------------------------------------------------------------------------
# Compiled patterns (module level for performance)
# ---------------------------------------------------------------------------
_USERNAME_INVALID = re.compile(r"[^a-zA-Z0-9._\-]")
# Legal characters in an email per RFC 5321 §4.1.2: printable ASCII minus
# the ones that need quoting. We're permissive here and let the format
# validator below enforce structure.
_EMAIL_INVALID = re.compile(r"[^a-zA-Z0-9._%@+\-]")
_EMAIL_FORMAT = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_DOMAIN_INVALID = re.compile(r"[^a-z0-9.\-]")
_NON_DIGIT = re.compile(r"\D")
_PHONE_INVALID = re.compile(r"[^0-9+\-() .]")

_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

_BAD_TLDS = frozenset(
    {
        "jpg", "jpeg", "png", "gif", "svg", "bmp", "ico",
        "mp4", "mov", "avi", "css", "js", "json", "xml",
        "pdf", "doc", "xls", "zip", "gz", "bz2", "rar",
        "7z", "webp", "mp3", "wav", "flac",
    }
)

MAX_USERNAME_LEN = 50
MAX_EMAIL_LEN = 254   # RFC 5321
MAX_URL_LEN = 2048
MAX_PHONE_LEN = 24


# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------

def sanitize_username(raw: str) -> str:
    """
    Strip leading dots/whitespace, remove characters that are not
    alphanumeric, dot, underscore, or hyphen, then cap to 50 chars.

    Extends the existing ``clean_username()`` in utils.py with stricter
    char-level filtering and a length cap.

    Raises InputValidationError if the result is empty.
    """
    if not isinstance(raw, str):
        raise InputValidationError("username", "must be a string")
    s = raw.strip()
    # Remove leading dots (matches existing clean_username() behaviour)
    s = re.sub(r"^\.+", "", s)
    # Remove every char that isn't valid in a username
    s = _USERNAME_INVALID.sub("", s)
    s = s[:MAX_USERNAME_LEN]
    if not s:
        raise InputValidationError("username", "empty after sanitisation")
    return s


def sanitize_email(raw: str) -> str:
    """
    Strip whitespace and characters that cannot appear in an email address.
    Does NOT validate format – call validate_email() for that.

    Returns an empty string (not an error) when input is empty so that
    optional email fields can be passed through safely.
    """
    if not isinstance(raw, str):
        raise InputValidationError("email", "must be a string")
    # Preserve ``%`` — a legal character in the local part — so that
    # user%tag@host survives sanitisation intact.
    s = _EMAIL_INVALID.sub("", raw.strip().lower())
    return s[:MAX_EMAIL_LEN]


def sanitize_user_id(raw: str) -> str:
    """
    Strip all non-digit characters.  Discord IDs (snowflakes) are
    purely numeric; anything else is an injection attempt.

    Raises InputValidationError if no digits remain.
    """
    if not isinstance(raw, str):
        raise InputValidationError("user_id", "must be a string")
    digits = _NON_DIGIT.sub("", raw)
    if not digits:
        raise InputValidationError("user_id", "must contain at least one digit")
    return digits


def sanitize_domain(raw: str) -> str:
    """
    Strip protocol prefix and path, lowercase, then remove any
    character that cannot appear in a hostname.

    Raises InputValidationError if the result is empty.
    """
    if not isinstance(raw, str):
        raise InputValidationError("domain", "must be a string")
    s = raw.strip().lower()
    # Remove protocol
    s = re.sub(r"^https?://", "", s)
    # Discard path and query string
    s = s.split("/")[0].split("?")[0]
    s = _DOMAIN_INVALID.sub("", s)
    if not s:
        raise InputValidationError("domain", "empty after sanitisation")
    return s


def sanitize_url(raw: str) -> str:
    """
    Strip surrounding whitespace, cap length, and require an http/https
    scheme. Returns the value unchanged otherwise — full SSRF validation
    happens later via ``utils.url_safety.validate_url``.

    Raises InputValidationError for anything that isn't a well-formed
    http(s) URL.
    """
    if not isinstance(raw, str):
        raise InputValidationError("url", "must be a string")
    s = raw.strip()
    if not s:
        raise InputValidationError("url", "empty")
    if len(s) > MAX_URL_LEN:
        raise InputValidationError(
            "url", f"exceeds maximum length ({MAX_URL_LEN})"
        )
    parsed = urlparse(s)
    if parsed.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        raise InputValidationError(
            "url", f"scheme {parsed.scheme!r} not allowed (use http or https)"
        )
    if not parsed.netloc:
        raise InputValidationError("url", "missing host")
    return s


def sanitize_phone(raw: str) -> str:
    """
    Keep only characters that can legally appear in a phone number —
    digits, leading ``+``, spaces, dashes, parens, dots — and cap length.

    Returns an empty string when nothing remains, so the caller can
    treat an optional field as unset rather than erroring out.
    """
    if not isinstance(raw, str):
        raise InputValidationError("phone", "must be a string")
    s = _PHONE_INVALID.sub("", raw.strip())
    # Collapse runs of whitespace and cap.
    s = re.sub(r"\s+", " ", s).strip()
    return s[:MAX_PHONE_LEN]


# ---------------------------------------------------------------------------
# Validators (return (bool, reason_str) – never raise)
# ---------------------------------------------------------------------------

def validate_email(email: str) -> tuple[bool, str]:
    """
    Return ``(True, '')`` when *email* is syntactically valid,
    otherwise ``(False, <reason>)``.
    """
    if not email:
        return False, "empty string"
    if len(email) > MAX_EMAIL_LEN:
        return False, "exceeds maximum length"
    if email.count("@") != 1:
        return False, "must contain exactly one @"
    local, _, domain = email.partition("@")
    if not local:
        return False, "missing local part"
    if not domain:
        return False, "missing domain"
    if not _EMAIL_FORMAT.match(email):
        return False, "does not match email pattern"
    if "." not in domain:
        return False, "domain has no dot"
    tld = domain.rsplit(".", 1)[-1]
    if tld in _BAD_TLDS:
        return False, f"invalid TLD: .{tld}"
    return True, ""


def validate_url(url: str) -> tuple[bool, str]:
    """
    Return ``(True, '')`` when *url* has an http/https scheme and a host,
    otherwise ``(False, <reason>)``.

    This is a *format* check. It does NOT do SSRF validation — that
    requires resolving the host and lives in ``utils.url_safety``.
    """
    if not url:
        return False, "empty string"
    if len(url) > MAX_URL_LEN:
        return False, "exceeds maximum length"
    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"unparseable: {exc}"
    if parsed.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        return False, f"scheme {parsed.scheme!r} not allowed"
    if not parsed.netloc:
        return False, "missing host"
    return True, ""


def validate_phone(raw: str) -> tuple[bool, str]:
    """
    Loose validation: at least 7 digits after removing formatting
    characters, optional leading ``+``. Not a full libphonenumber check —
    that's what ``phonenumbers`` does inside the phone module.
    """
    if not raw:
        return False, "empty string"
    stripped = re.sub(r"[^\d+]", "", raw)
    digits = stripped.lstrip("+")
    if not digits.isdigit():
        return False, "contains non-digit characters"
    if len(digits) < 7:
        return False, "fewer than 7 digits"
    if len(digits) > 15:
        return False, "more than 15 digits"
    return True, ""


def validate_mode(mode: str) -> str:
    """
    Return *mode* unchanged if it is ``'manual'`` or ``'discord'``.
    Raises InputValidationError otherwise.
    """
    if mode in ("manual", "discord"):
        return mode
    raise InputValidationError(
        "mode", f"must be 'manual' or 'discord', got {mode!r}"
    )


def validate_output_format(fmt: str) -> str:
    """Validate report output format. Returns normalised lowercase string."""
    valid = {"json", "markdown", "html", "md"}
    f = fmt.lower().strip()
    if f not in valid:
        raise InputValidationError(
            "output", f"must be one of {sorted(valid)}, got {fmt!r}"
        )
    return f