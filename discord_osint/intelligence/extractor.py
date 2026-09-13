"""
discord_osint/intelligence/extractor.py
-----------------------------------------
Parse the raw ``intel`` dict (and ``avatar_urls`` set) produced by the
pipeline into typed :class:`BaseEntity` objects with confidence scores.

Design notes
------------
- All input comes from ``InvestigationContext.intel_core.intel``, whose
  values are stored as ``{"value": <data>, "source": <str>}`` dicts by
  ``InvestigationCore.add_intel()``.
- Confidence is assigned per-source using ``_SOURCE_CONFIDENCE``; the
  value degrades gracefully for unrecognised sources via prefix matching.
- This module is pure data transformation – no network calls, no side
  effects.  Tests can call it with a handcrafted ``intel`` dict.
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

# ---------------------------------------------------------------------------
# Confidence table  (source string → confidence float)
# ---------------------------------------------------------------------------
_SOURCE_CONFIDENCE: dict[str, float] = {
    # Direct user input and confirmed API responses are most reliable
    "manual_input":         0.92,
    "discord_api":          0.88,
    "discord_enrich":       0.82,
    "snowflake":            0.82,
    # Semi-reliable automated sources
    "gitfive":              0.72,
    "scrape_github":        0.72,
    "smtp_verify":          0.70,
    "ghunt":                0.68,
    "hibp":                 0.65,
    "h8mail":               0.65,
    "holehe":               0.65,
    "emailrep":             0.62,
    # Discord bio / social scrapes
    "discord_bio":          0.60,
    "scrape_twitter":       0.60,
    "scrape_reddit":        0.58,
    "scrape_":              0.55,   # prefix match fallback for all scrape_*
    # Third-party lookups and enrichment
    "gravatar":             0.55,
    "socid-extractor":      0.52,
    "wayback":              0.50,
    "nametrace":            0.48,
    "whois":                0.47,
    # Weakest signals
    "location_inference":   0.44,
    "langdetect":           0.44,
    "naminter":             0.40,
    "generic_scrape":       0.36,
    "avatar_collection":    0.70,   # avatars are generally trustworthy
}

_DEFAULT_CONFIDENCE: float = 0.38
_URL_PREFIX_RE = re.compile(r"^https?://")


def _source_conf(source: str) -> float:
    """
    Look up confidence for *source*.

    Falls back to prefix matching (covers ``"scrape_github"``, ``"scrape_*"``
    etc.) and then to ``_DEFAULT_CONFIDENCE``.
    """
    if source in _SOURCE_CONFIDENCE:
        return _SOURCE_CONFIDENCE[source]
    # Prefix scan – longest key that is a prefix of source wins
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
        # value may itself be a dict (e.g. Holehe result); stringify it
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

    Examples::

        "github/user/bio"             → "github"
        "discord_connected_spotify"   → "spotify"
        "gravatar_email@example.com"  → "gravatar"
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

    Parameters
    ----------
    intel:
        ``InvestigationCore.intel`` dict.
    avatar_urls:
        ``InvestigationContext.avatar_urls`` set (optional).

    Returns
    -------
    list[BaseEntity]
        Mixed list of ``EmailEntity``, ``UsernameEntity``,
        ``PlatformProfileEntity``, ``NameEntity``, ``LocationEntity``,
        and ``AvatarEntity`` objects.
    """
    entities: list[BaseEntity] = []
    seen_values: dict[str, BaseEntity] = {}   # deduplicate by (type, value)
    avatar_urls = avatar_urls or set()

    def _add(ent: BaseEntity) -> None:
        """Add entity only if we haven't seen this (type, value) pair yet."""
        dedup_key = f"{ent.entity_type}:{ent.value.lower()}"
        if dedup_key in seen_values:
            # Keep the higher-confidence copy
            existing = seen_values[dedup_key]
            if ent.confidence > existing.confidence:
                entities.remove(existing)
                seen_values[dedup_key] = ent
                entities.append(ent)
        else:
            seen_values[dedup_key] = ent
            entities.append(ent)

    # ------------------------------------------------------------------ #
    # 1. Email addresses                                                    #
    # ------------------------------------------------------------------ #
    for _key, entry in intel.get("emails", {}).items():
        val, src = _unpack(entry)
        if val and "@" in val and len(val) < 254:
            _add(EmailEntity(
                value=val.lower(),
                source=src,
                confidence=_source_conf(src),
            ))

    # ------------------------------------------------------------------ #
    # 2. Social profiles → PlatformProfileEntity or UsernameEntity         #
    # ------------------------------------------------------------------ #
    for key, entry in intel.get("social_profiles", {}).items():
        val, src = _unpack(entry)
        # Skip internal raw dumps (socid_raw etc.) and bios stored here
        if not val or "socid_raw" in key or "bio" in key:
            continue

        if _URL_PREFIX_RE.match(val):
            # It's a profile URL
            platform = _platform_from_key(key) or "unknown"
            _add(PlatformProfileEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
                platform=platform,
                url=val,
            ))
        else:
            # It's a plain username / handle
            platform = _platform_from_key(key)
            _add(UsernameEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
                platform=platform,
            ))

    # ------------------------------------------------------------------ #
    # 3. Identity clues → NameEntity or LocationEntity                     #
    # ------------------------------------------------------------------ #
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
            # Language is metadata, not a linkable entity – skip it here
            pass
        elif key.startswith("name_"):
            _add(NameEntity(
                value=val,
                source=src,
                confidence=_source_conf(src),
            ))

    # ------------------------------------------------------------------ #
    # 4. Discord username (top-level)                                       #
    # ------------------------------------------------------------------ #
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

    # ------------------------------------------------------------------ #
    # 5. Avatar URLs                                                        #
    # ------------------------------------------------------------------ #
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

    Returns ``None`` if ``imagehash``/``Pillow`` is not installed or the
    download fails.  This keeps the package optional and avoids crashing
    the extraction phase for missing optional deps.
    """
    try:
        import io
        import imagehash
        from PIL import Image
        import requests as _req

        resp = _req.get(url, timeout=8, stream=True)
        resp.raise_for_status()
        img = Image.open(io.BytesIO(resp.content)).convert("RGB")
        return str(imagehash.phash(img))
    except Exception:
        return None
