"""
discord_osint/api_extractor.py
-------------------------------
Helper for fetching, labelling, normalising, and *deriving* JSON API
responses discovered during an investigation.

Change log
----------
``fetch_api()`` now routes every request through
``utils.url_safety.safe_get_pinned``, which resolves DNS once, validates
every address, and pins the actual TCP connect to the validated IP for
the duration of the request. This closes the validate-then-reconnect
TOCTOU where an attacker could flip the DNS record between validation
and the fetch. TLS SNI is preserved end-to-end, so certificate
verification still checks the original hostname.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .utils.url_safety import safe_get_pinned, UnsafeURLError

# ── Trace into the active debug log (safe no-op if none is set up) ──
try:
    from .utils import log_trace
except Exception:  # pragma: no cover
    def log_trace(msg: str) -> None:
        pass


# URLs containing any of these substrings are likely JSON API endpoints.
API_HINTS = (
    "/api/",
    "/oembed",
    "?validate=",
    "checkusername",
    "email_available",
    "/lookup",
    "/graphql/",
    "username_available",
    "showAuthorExists",
    "/public/users",
    "/public/v1/",
    "/rest/v",
    "/v1/",
    "/v2/",
    "/v3/",
    "/v4/",
    "/v6/",
    "/account/v1/accounts/",
    ".json",
    "api.",       # catches api.github.com, api.imgur.com, etc.
)

_USELESS_KEYS = frozenset({"status", "message", "success"})


def looks_like_api(url: str) -> bool:
    """Return True if *url* probably returns JSON."""
    if not url or not url.startswith("http"):
        return False
    u = url.lower()
    return any(hint in u for hint in API_HINTS)


def is_useful_response(data: Any) -> bool:
    if isinstance(data, dict):
        if len(data) == 0:
            return False
        if set(data.keys()).issubset(_USELESS_KEYS):
            return False
        return True
    if isinstance(data, list):
        return len(data) > 0
    return False


def human_label(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        for prefix in ("www.", "api.", "public-api.", "spclient.", "public."):
            if host.startswith(prefix):
                host = host[len(prefix):]
        path  = parsed.path.lower()
        query = (parsed.query or "").lower()
        full  = url.lower()

        suffix = ""
        if "email_available" in path or "email_available" in full:
            suffix = "email check"
        elif "email" in query and "validate" in query:
            suffix = "email validation"
        elif "checkusername" in path or "username_available" in full:
            suffix = "username check"
        elif "lookup" in path:
            suffix = "lookup"
        elif "/signup/" in path:
            suffix = "signup"
        elif "graphql" in path:
            suffix = "graphql"
        elif "showAuthorExists" in full:
            suffix = "author check"
        elif path.endswith(".json"):
            suffix = "profile"
        elif any(seg in path for seg in ("/api/", "/v1/", "/v2/", "/v3/")):
            suffix = "api"

        if suffix:
            return f"{host}: {suffix}"
        return host or url[:40]
    except Exception:
        return url[:40]


# ──────────────────────────────────────────────────────────────────────
# Canonical field extraction
# ──────────────────────────────────────────────────────────────────────

CANONICAL_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Username", ("username", "login", "handle", "nickname",
                  "preferredUsername", "customId", "author_name",
                  "ousername", "mal_username", "profile_artstation_website",
                  "twitch_username", "periscope_username")),
    ("Real Name", ("name", "full_name", "fullname", "realName", "real_name",
                   "public_name", "display_name", "displayName")),
    ("Account Created", ("created_at", "createdOn", "createDate", "createdDate",
                         "cdate", "ctime", "date_joined", "registration_date",
                         "activated_at", "created", "creation_date")),
    ("Location", ("country", "country_name", "country_code", "city",
                  "location", "region")),
    ("Followers", ("followers", "followers_count", "follower_count",
                   "follower_cnt", "flw", "numFollowers", "followersCount")),
    ("Bio", ("bio", "description", "headline", "about", "aboutMe",
             "summary", "bio_excerpt", "bio_raw", "status")),
    ("Verified", ("isVerified", "verified", "isPro", "pro", "is_pro",
                  "pro_member", "hasProPermissions")),
)

SPECIAL_FIELDS: dict[str, str] = {
    "proofs_summary":      "Cross-platform proofs",
    "spotifyAuth":         "Linked Spotify",
    "instagram_username":  "Linked Instagram",
    "twitter_username":    "Linked Twitter",
    "premium_tier":        "Premium Tier",
    "stealer_family":      "Stealer Family",
    "total_user_services": "Breached services",
    "skill_level":         "Skill level",
    "faceit_elo":          "Elo",
    "demographics":        "Demographics",
}

_SKIP_EXACT = frozenset({
    "id", "uuid", "gcid", "realCID", "demoCID", "playerID", "accountID",
    "mal_uid", "type", "kind", "version", "is_admin", "is_staff", "admin",
    "moderator", "restricted", "prohibit_login", "active", "blocked",
    "closed", "limited_account", "disabled", "is_private", "isPrivate",
    "is_beta", "is_beta_user", "is_employee", "is_twitter_verified",
    "verified_email", "email_verified", "is_profile_visible", "public",
    "visibility", "locale", "language", "languageIsoCode", "timezone",
    "modifyDate", "lastModified", "lastLogin", "last_login", "last_seen_at",
    "lastLookup", "last_posted_at", "updated_at", "mtime", "udate",
    "registration_completed", "oauth_password_credentials_allowed",
    "escrowcom_interaction_required", "showLocale", "primary_currency",
    "primary_language", "currentBlobStorageLocation",
    "defaultBinaryStorageLocation", "allowDisplayFullName", "optOut",
    "whiteLabel", "piLevel", "isPi", "isProInvestor", "accountType",
    "fundType", "verificationLevel", "accountStatus", "userFlowSignature",
    "gdprInfo", "masterAccountCid", "avatar_id", "cover_id", "avatar_url",
    "cover_url", "picture", "image", "ico", "bg_color", "backgroundUrl",
    "hash_user_id", "afcn", "provider", "official", "url", "pic_s",
    "pic_m", "pic_b", "cover_src", "priority", "brand_priority",
    "show_kids_friendly", "banned", "setup", "color", "star", "ft", "fp",
    "birthDate", "photosNumber", "photoId", "photos", "sex", "age",
    "email", "website", "facebook", "lulu", "smashwords", "bubok",
    "allowCrawler", "isMuted", "numStoriesPublished", "votesReceived",
    "numMessages", "numLists", "genderCode", "custom_avatar_template",
    "avatar_template", "featured_topic", "featured_user_badge_ids",
    "user_fields", "custom_fields", "time_read", "recent_time_read",
    "primary_group_id", "primary_group_name", "flair_group_id",
    "flair_name", "flair_url", "flair_bg_color", "flair_color", "groups",
    "user_notification_schedule", "can_edit", "can_edit_username",
    "can_edit_email", "can_edit_name", "uploaded_avatar_id",
    "pending_count", "profile_view_count",
    "profile_background_upload_url", "can_upload_profile_header",
    "can_upload_user_card_background", "custom_avatar_upload_id",
    "trust_level", "badge_count", "title",
})


def _stringify(value: Any, limit: int = 120) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        s = value.strip()
        return s[:limit] if s else ""
    return ""


def extract_key_fields(data: Any, url: str = "") -> list[dict[str, str]]:
    if not isinstance(data, dict):
        return []

    flat: dict[str, Any] = {}
    for k, v in data.items():
        if k in _SKIP_EXACT:
            continue
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if k2 in _SKIP_EXACT or isinstance(v2, dict):
                    continue
                flat.setdefault(f"{k}.{k2}", v2)
                flat.setdefault(k2, v2)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, (str, int, float, bool)) and item not in (None, ""):
                    flat.setdefault(k, item)
                    break
        else:
            flat.setdefault(k, v)

    result: list[dict[str, str]] = []
    used_labels: set[str] = set()

    for label, aliases in CANONICAL_FIELDS:
        for alias in aliases:
            if alias not in flat:
                continue
            value = _stringify(flat[alias])
            if not value:
                continue
            if label == "Real Name" and len(value) < 2:
                continue
            result.append({"label": label, "value": value})
            used_labels.add(label)
            break

    if "Real Name" not in used_labels:
        first = _stringify(flat.get("firstName") or flat.get("first_name"))
        last  = _stringify(flat.get("lastName")  or flat.get("last_name"))
        combined = " ".join(x for x in (first, last) if x).strip()
        if combined:
            result.append({"label": "Real Name", "value": combined})
            used_labels.add("Real Name")

    if "Location" not in used_labels:
        city    = _stringify(flat.get("city"))
        country = _stringify(flat.get("country_name") or flat.get("country"))
        combined = ", ".join(x for x in (city, country) if x).strip()
        if combined:
            result.append({"label": "Location", "value": combined})
            used_labels.add("Location")

    for key, label in SPECIAL_FIELDS.items():
        if key in data:
            v = data[key]
            if isinstance(v, dict) and "displayName" in v:
                v = v["displayName"]
            value = _stringify(v)
            if value:
                result.append({"label": label, "value": value})

    return result


# ──────────────────────────────────────────────────────────────────────
# URL → API endpoint derivation
# ──────────────────────────────────────────────────────────────────────

_PATH_REWRITES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r'^https?://hub\.docker\.com/u/([^/?#]+)/?.*$'),
     r'https://hub.docker.com/v2/users/\1/'),
    (re.compile(r'^https?://hub\.docker\.com/u/([^/?#]+)/?.*$'),
     r'https://hub.docker.com/v2/orgs/\1/'),
    (re.compile(r'^https?://(?:www\.)?github\.com/([^/?#]+)/?$'),
     r'https://api.github.com/users/\1'),
    (re.compile(r'^https?://(?:www\.)?github\.com/([^/?#]+)/?$'),
     r'https://api.github.com/users/\1/gists'),
    (re.compile(r'^https?://(?:www\.)?gitlab\.com/([^/?#]+)/?$'),
     r'https://gitlab.com/api/v4/users?username=\1'),
    (re.compile(r'^https?://codeberg\.org/([^/?#]+)/?$'),
     r'https://codeberg.org/api/v1/users/\1'),
    (re.compile(r'^https?://(?:www\.)?gitea\.com/([^/?#]+)/?$'),
     r'https://gitea.com/api/v1/users/\1'),
    (re.compile(r'^https?://(?:www\.)?reddit\.com/(?:user|u)/([^/?#]+)/?.*$'),
     r'https://www.reddit.com/user/\1/about.json'),
    (re.compile(r'^https?://([^/]+)/@([^/?#]+)/?$'),
     r'https://\1/api/v1/accounts/lookup?acct=\2'),
    (re.compile(r'^https?://bsky\.app/profile/([^/?#]+)/?$'),
     r'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=\1'),
    (re.compile(r'^https?://(?:www\.)?imgur\.com/user/([^/?#]+)/?.*$'),
     r'https://api.imgur.com/account/v1/accounts/\1?client_id=546c25a59c58ad7'),
    (re.compile(r'^https?://(?:www\.)?tiktok\.com/@([^/?#]+)/?.*$'),
     r'https://www.tiktok.com/oembed?url=https://www.tiktok.com/@\1'),
    (re.compile(r'^https?://(?:www\.)?aparat\.com/([^/?#]+)/?$'),
     r'https://www.aparat.com/api/fa/v1/user/user/information/username/\1'),
    (re.compile(r'^https?://(?:www\.)?artstation\.com/([^/?#]+)/?$'),
     r'https://www.artstation.com/api/v2/user_profiles/\1.json'),
    (re.compile(r'^https?://(?:www\.)?bandlab\.com/([^/?#]+)/?$'),
     r'https://www.bandlab.com/api/v1.3/users/\1'),
    (re.compile(r'^https?://(?:www\.)?codewars\.com/users/([^/?#]+)/?$'),
     r'https://www.codewars.com/api/v1/users/\1'),
    (re.compile(r'^https?://(?:www\.)?etoro\.com/people/([^/?#]+)/?.*$'),
     r'https://www.etoro.com/api/logininfo/v1.1/users/\1'),
    (re.compile(r'^https?://(?:www\.)?faceit\.com/(?:en/)?players/([^/?#]+)/?.*$'),
     r'https://www.faceit.com/api/users/v1/nicknames/\1'),
    (re.compile(r'^https?://(?:www\.)?freelancer\.com/u/([^/?#]+)/?$'),
     r'https://www.freelancer.com/api/users/0.1/users?usernames%5B%5D=\1&compact=true'),
    (re.compile(r'^https?://keybase\.io/([^/?#]+)/?$'),
     r'https://keybase.io/_/api/1.0/user/lookup.json?usernames=\1'),
    (re.compile(r'^https?://(?:www\.)?minds\.com/([^/?#]+)/?$'),
     r'https://www.minds.com/api/v3/register/validate?username=\1'),
    (re.compile(r'^https?://(?:www\.)?mixcloud\.com/([^/?#]+)/?$'),
     r'https://api.mixcloud.com/\1/'),
    (re.compile(r'^https?://picsart\.com/u/([^/?#]+)/?$'),
     r'https://api.picsart.com/users/show/\1.json'),
    (re.compile(r'^https?://(?:www\.)?sports-tracker\.com/view_profile/([^/?#]+)/?.*$'),
     r'https://api.sports-tracker.com/apiserver/v1/user/name/\1'),
    (re.compile(r'^https?://stats\.fm/([^/?#]+)/?$'),
     r'https://api.stats.fm/api/v1/users/\1'),
    (re.compile(r'^https?://(?:www\.)?chess\.com/member/([^/?#]+)/?.*$'),
     r'https://api.chess.com/pub/player/\1'),
    (re.compile(r'^https?://scratch\.mit\.edu/users/([^/?#]+)/?$'),
     r'https://api.scratch.mit.edu/accounts/checkusername/\1/'),
    (re.compile(r'^https?://substack\.com/@([^/?#]+)/?$'),
     r'https://substack.com/api/v1/user/\1/public_profile'),
    (re.compile(r'^https?://fotka\.com/profil/([^/?#]+)/?$'),
     r'https://api.fotka.com/v2/user/dataStatic?login=\1'),
    (re.compile(r'^https?://calendly\.com/([^/?#]+)/?$'),
     r'https://calendly.com/api/booking/profiles/\1'),
    (re.compile(r'^https?://(?:www\.)?gravatar\.com/([^/?#]+)/?$'),
     r'https://en.gravatar.com/\1.json'),
    (re.compile(r'^https?://profiles\.wordpress\.org/([^/?#]+)/?$'),
     r'https://login.wordpress.org/wp-json/wporg/v1/username-available/\1'),
    (re.compile(r'^https?://([^/]+)/u/([^/?#]+)/?$'),
     r'https://\1/u/\2.json'),
    (re.compile(r'^https?://(?:www\.)?vimeo\.com/([^/?#]+)/?$'),
     r'https://vimeo.com/api/v2/\1/info.json'),
    (re.compile(r'^https?://([^/?#]+)\.bandcamp\.com/?$'),
     r'https://\1.bandcamp.com/api/'),
)

_GENERIC_API_PREFIXES = ("/api/v1", "/api/v2", "/api", "/rest")


def derive_api_candidates(url: str, max_candidates: int = 4) -> list[str]:
    if not url or not url.startswith("http"):
        return []

    out:  list[str] = []
    seen: set[str]  = set()

    def _add(u: str) -> None:
        if u and u not in seen and len(out) < max_candidates:
            seen.add(u)
            out.append(u)

    for pattern, replacement in _PATH_REWRITES:
        if pattern.match(url):
            _add(pattern.sub(replacement, url))

    try:
        parsed = urlparse(url)
    except Exception:
        return out

    scheme = parsed.scheme or "https"
    host   = parsed.netloc
    path   = (parsed.path or "/").rstrip("/")

    if not path.endswith(".json"):
        _add(f"{scheme}://{host}{path}.json")

    if path and not path.startswith(("/api", "/rest", "/graphql")):
        for prefix in _GENERIC_API_PREFIXES:
            _add(f"{scheme}://{host}{prefix}{path}")

    return out


# ──────────────────────────────────────────────────────────────────────
# Fetching
# ──────────────────────────────────────────────────────────────────────

def fetch_api(url: str, timeout: int = 6) -> dict | list | None:
    """
    Fetch *url* and return its parsed JSON, or ``None`` on any failure.

    SSRF guard
    ----------
    Requests go through ``utils.url_safety.safe_get_pinned``, which
    resolves once, validates every address, and pins the actual TCP
    connect to the validated IP for the duration of the request. Every
    redirect hop is re-validated and re-pinned. TLS SNI is preserved,
    so certificate verification still checks the original hostname.
    """
    log_trace(f"fetch_api: --> GET {url}")

    try:
        import requests
    except ImportError:
        log_trace("fetch_api: requests library not importable")
        return None

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept":     "application/json, application/ld+json, */*;q=0.1",
    }

    try:
        r = safe_get_pinned(url, headers=headers, timeout=timeout)
    except UnsafeURLError as exc:
        log_trace(f"fetch_api: SSRF BLOCKED {url} — {exc}")
        return None
    except Exception as exc:
        log_trace(f"fetch_api: EXCEPTION {type(exc).__name__}: {exc}")
        return None

    ct   = r.headers.get("Content-Type", "")
    size = len(r.content)
    log_trace(f"fetch_api: <-- {r.status_code} ct={ct!r} bytes={size}")

    if r.status_code != 200:
        log_trace(f"fetch_api: REJECT status != 200 ({r.status_code})")
        return None

    ct_lower = ct.lower()
    looks_json = (
        "json" in ct_lower
        or url.lower().endswith(".json")
        or (r.text[:1] in ("{", "[") and "html" not in ct_lower)
    )
    if not looks_json:
        head = r.text[:60].replace("\n", " ")
        log_trace(f"fetch_api: REJECT non-JSON ct={ct_lower!r} head={head!r}")
        return None

    try:
        data = r.json()
    except Exception as exc:
        log_trace(f"fetch_api: REJECT json() raised {type(exc).__name__}: {exc}")
        return None

    if isinstance(data, dict):
        log_trace(f"fetch_api: OK dict keys={list(data.keys())[:8]}")
    elif isinstance(data, list):
        log_trace(f"fetch_api: OK list len={len(data)}")
    else:
        log_trace(f"fetch_api: OK {type(data).__name__}")
    return data