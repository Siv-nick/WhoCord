"""
discord_osint/intelligence/extractor.py
-----------------------------------------
Parse the raw ``intel`` dict (and ``avatar_urls`` set) produced by the
pipeline into typed :class:`BaseEntity` objects with confidence scores.

Change log
----------
- ``_try_phash`` now routes every fetch through
  ``utils.url_safety.safe_get_pinned``. The previous implementation used
  a bare ``requests.get`` on the URL, which is attacker-influenced: an
  avatar URL scraped from an external profile page could point at
  ``http://169.254.169.254/…`` and this function would fetch it
  unguarded. Body size is now capped so a slow-drip or oversize
  response cannot exhaust memory.
- ``_try_phash`` distinguishes a missing optional dependency
  (``imagehash`` / ``Pillow``) from an actual failure. The previous
  bare ``except Exception: return None`` silently discarded every
  failure mode.
"""

from __future__ import annotations

import re
from typing import Any

from .entities import (
    AvatarEntity,
    BaseEntity,
    EmailEntity,
    LocationEntity,
    NameEntity,
    PlatformProfileEntity,
    UsernameEntity,
)
from ..utils import log_trace
from ..utils.url_safety import safe_get_pinned, UnsafeURLError


# ---------------------------------------------------------------------------
# Confidence table  (source string → confidence float)
# ---------------------------------------------------------------------------
_SOURCE_CONFIDENCE: dict[str, float] = {
    "manual_input":         0.92,
    "discord_api":          0.88,
    "discord_enrich":       0.82,
    "snowflake":            0.82,
    "gitfive":              0.72,
    "scrape_github":        0.72,
    "smtp_verify":          0.70,
    "ghunt":                0.68,
    "hibp":                 0.65,
    "h8mail":               0.65,
    "holehe":               0.65,
    "emailrep":             0.62,
    "discord_bio":          0.60,
    "scrape_twitter":       0.60,
    "scrape_reddit":        0.58,
    "scrape_":              0.55,
    "gravatar":             0.55,
    "socid-extractor":      0.52,
    "wayback":              0.50,
    "nametrace":            0.48,
    "whois":                0.47,
    "location_inference":   0.44,
    "langdetect":           0.44,
    "naminter":             0.40,
    "generic_scrape":       0.36,
    "avatar_collection":    0.70,
}

_DEFAULT_CONFIDENCE: float = 0.38
_URL_PREFIX_RE = re.compile(r"^https?://")

# Largest avatar this will accept. Real profile avatars are well under
# 2 MB; the cap exists so a malicious host cannot stream until the
# process is OOM-killed.
_MAX_PHASH_BYTES = 8 * 1024 * 1024


def _source_conf(source: str) -> float:
    """
    Look up confidence for *source*.

    Falls back to prefix matching (covers ``"scrape_github"``,
    ``"scrape_*"`` etc.) and then to ``_DEFAULT_CONFIDENCE``.
    """
    if source in _SOURCE_CONFIDENCE:
        return _SOURCE_CONFIDENCE[source]
    best_key = ""
    best_val = _DEFAULT_CONFIDENCE
    for key, val in _SOURCE_CONFIDENCE.items():
        if source.startswith(key) and len(key) > len(best_key):
            best_key = key
            best_val = val
    return best_val


def _unpack(entry: Any) -> tuple[str, str]:
    """
    Return (value_str, source_str) from an intel dict entry.

    Handles both the standard ``{"value": ..., "source": ...}`` format
    and legacy plain-string values.
    """
    if isinstance(entry, dict):
        val = entry.get("value", "")
        src = entry.get("source", "unknown")
        if not isinstance(val, str):
            val = str(val) if val else ""
    else:
        val = str(entry) if entry else ""
        src = "unknown"
    return val.strip(), src


# ---------------------------------------------------------------------------
# Platform detection helpers
# ---------------------------------------------------------------------------

_KNOWN_PLATFORMS = frozenset({
    "github", "twitter", "reddit", "instagram", "linkedin", "facebook",
    "youtube", "tiktok", "twitch", "steam", "spotify", "pinterest",
    "soundcloud", "medium", "dev", "gitlab", "bitbucket", "keybase",
    "telegram", "discord", "gravatar",
})


def _platform_from_key(key: str) -> str | None:
    """
    Derive a platform name from a social_profiles dict key.
    """
    if key.startswith("discord_connected_"):
        candidate = key.replace("discord_connected_", "").split("_")[0]
        return candidate if candidate else None
    if "/" in key:
        candidate = key.split("/")[0]
        return candidate if candidate in _KNOWN_PLATFORMS else None
    first_token = key.split("_")[0]
    return first_token if first_token in _KNOWN_PLATFORMS else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_entities(
    intel: dict[str, Any],
    avatar_urls: set[str] | None = None,
) -> list[BaseEntity]:
    """
    Parse *intel* and *avatar_urls* and return a flat list of typed entities.
    """
    entities: list[BaseEntity] = []
    seen_values: dict[str, BaseEntity] = {}
    avatar_urls = avatar_urls or set()

    def _add(ent: BaseEntity) -> None:
        """Add entity only if we haven't seen this (type, value) pair yet."""
        dedup_key = f"{ent.entity_type}:{ent.value.lower()}"
        if dedup_key in seen_values:
            existing = seen_values[dedup_key]
            if ent.confidence > existing.confidence:
                entities.remove(existing)
                seen_values[dedup_key] = ent
                entities.append(ent)
        else:
            seen_values[dedup_key] = ent
            entities.append(ent)

    # 1. Email addresses
    for _key, entry in intel.get("emails", {}).items():
        val, src = _unpack(entry)
        if val and "@" in val and len(val) < 254:
            _add(EmailEntity(
                value=val.lower(),
                source=src,
                confidence=_source_conf(src),
            ))

    # 2. Social profiles
    for key, entry in intel.get("social_profiles", {}).items():
        val, src = _unpack(entry)
        if not val or "socid_raw" in key or "bio" in key:
            continue

        if _URL_PREFIX_RE.match(val):
            platform = _platform_from_key(key) or "unknown"
            _add(PlatformProfileEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
                platform=platform,
                url=val,
            ))
        else:
            platform = _platform_from_key(key)
            _add(UsernameEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
                platform=platform,
            ))

    # 3. Identity clues
    for key, entry in intel.get("identity_clues", {}).items():
        val, src = _unpack(entry)
        if not val:
            continue

        if key == "inferred_location":
            _add(LocationEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
            ))
        elif key == "language":
            pass
        elif key.startswith("name_"):
            _add(NameEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
            ))

    # 4. Discord username
    for key, entry in intel.get("discord", {}).items():
        if key != "username":
            continue
        val, src = _unpack(entry)
        if val:
            _add(UsernameEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
                platform="discord",
            ))

    # 5. Avatar URLs
    for url in avatar_urls:
        if url and _URL_PREFIX_RE.match(url):
            _add(AvatarEntity(
                value=url,
                source="avatar_collection",
                confidence=0.70,
                url=url,
                phash=_try_phash(url),
            ))

    return entities


def _try_phash(url: str) -> str | None:
    """
    Attempt a perceptual hash of an image at *url*.

    Returns ``None`` when the optional dependency is missing — that case
    is not logged, because it would fire once per avatar and the operator
    has no action to take on the message anyway. Every other failure is
    logged via ``log_trace``.

    SSRF and resource-exhaustion hardening
    --------------------------------------
    The URL originates from scraped profile data and is therefore
    attacker-influenced. It goes through ``safe_get_pinned`` so a
    redirect to ``http://169.254.169.254/…`` (or any other blocked
    range) is rejected with ``UnsafeURLError`` before the connect, and
    the body is read in bounded chunks so a drip or an oversize
    response cannot exhaust memory. ``Content-Length`` is checked when
    present as a fast rejection path.
    """
    try:
        import io
        import imagehash
        from PIL import Image
    except ImportError:
        return None

    try:
        resp = safe_get_pinned(url, timeout=8, stream=True)
        resp.raise_for_status()

        declared = resp.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > _MAX_PHASH_BYTES:
                    log_trace(
                        f"_try_phash: oversize Content-Length "
                        f"{declared} for {url[:80]}"
                    )
                    return None
            except (TypeError, ValueError):
                pass

        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) > _MAX_PHASH_BYTES:
                log_trace(
                    f"_try_phash: body exceeded {_MAX_PHASH_BYTES} bytes "
                    f"for {url[:80]} — aborting"
                )
                return None

        img = Image.open(io.BytesIO(bytes(buf))).convert("RGB")
        return str(imagehash.phash(img))
    except UnsafeURLError as exc:
        log_trace(f"_try_phash: SSRF BLOCKED {url[:80]} — {exc}")
        return None
    except Exception as exc:
        log_trace(f"_try_phash: {type(exc).__name__}: {exc} for {url[:80]}")
        return None