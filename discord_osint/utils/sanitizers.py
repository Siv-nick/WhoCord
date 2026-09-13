"""
discord_osint/sanitizers.py
---------------------------
Input sanitization and validation helpers.

These functions are the single source of truth for cleaning all
user-supplied values before they touch the file system, subprocess
calls, or network requests.  web_app.py and __main__.py both import
from here instead of rolling their own inline re.sub() calls.
"""

from __future__ import annotations

import re

from ..errors import InputValidationError

# ---------------------------------------------------------------------------
# Compiled patterns (module level for performance)
# ---------------------------------------------------------------------------
_USERNAME_INVALID = re.compile(r"[^a-zA-Z0-9._\-]")
_EMAIL_INVALID = re.compile(r"[^a-zA-Z0-9._@+\-]")
_EMAIL_FORMAT = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_DOMAIN_INVALID = re.compile(r"[^a-z0-9.\-]")
_NON_DIGIT = re.compile(r"\D")

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


# ---------------------------------------------------------------------------
# Validators (return (bool, reason_str) – never raise)
# ---------------------------------------------------------------------------

def validate_email(email: str) -> tuple[bool, str]:
    """
    Return ``(True, '')`` when *email* is syntactically valid,
    otherwise ``(False, <reason>)``.

    Mirrors the logic in scraping.is_valid_email() but returns a
    structured result rather than a bare bool, and lives here so web_app
    and __main__ can import a single helper.
    """
    if not email:
        return False, "empty string"
    if len(email) > MAX_EMAIL_LEN:
        return False, "exceeds maximum length"
    if not _EMAIL_FORMAT.match(email):
        return False, "does not match email pattern"
    domain = email.split("@")[1].lower()
    if "." not in domain:
        return False, "domain has no dot"
    tld = domain.rsplit(".", 1)[-1]
    if tld in _BAD_TLDS:
        return False, f"invalid TLD: .{tld}"
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
