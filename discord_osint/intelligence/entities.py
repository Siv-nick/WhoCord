"""
discord_osint/intelligence/entities.py
---------------------------------------
Typed entity data classes for the knowledge graph.

Each entity represents a single piece of intelligence about the target.
Entities are the nodes in the knowledge graph built by graph.py.

Confidence scores
-----------------
0.9+ → directly supplied by the user or confirmed Discord API
0.7–0.9 → reliable automated source (GitHub API, GitFive, SMTP verify)
0.5–0.7 → scraped / inferred from third-party sources
0.3–0.5 → weak signals (name-trace, location inference, generic scrape)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_id() -> str:
    """Return a compact unique identifier for an entity node."""
    return uuid.uuid4().hex[:10]


# ---------------------------------------------------------------------------
# Base entity
# ---------------------------------------------------------------------------

@dataclass
class BaseEntity:
    """
    Attributes shared by every entity type.

    Parameters
    ----------
    value:
        The canonical string value of the entity (email address, URL, …).
    source:
        Where this value was obtained (e.g. ``"discord_bio"``, ``"gitfive"``).
    confidence:
        Float in [0, 1] – how much weight to give this entity.
    id:
        Auto-generated unique node key; override only in tests.
    """

    value: str
    source: str
    confidence: float = 0.50
    id: str = field(default_factory=_short_id)

    @property
    def entity_type(self) -> str:  # noqa: D401
        """Discriminator string used as the graph node ``entity_type`` attribute."""
        return "base"

    # Make entities hashable so they can live in sets / dict keys.
    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BaseEntity):
            return self.id == other.id
        return NotImplemented

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON storage."""
        return {
            "id": self.id,
            "type": self.entity_type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Concrete entity types
# ---------------------------------------------------------------------------

@dataclass
class EmailEntity(BaseEntity):
    """A discovered email address."""

    @property
    def entity_type(self) -> str:
        return "email"

    @property
    def local_part(self) -> str:
        """The part before the '@' symbol."""
        return self.value.split("@")[0] if "@" in self.value else self.value

    @property
    def domain(self) -> str:
        """The domain after the '@' symbol."""
        return self.value.split("@")[1] if "@" in self.value else ""


@dataclass
class UsernameEntity(BaseEntity):
    """
    A plain username / handle (not a full URL).

    The ``platform`` attribute is filled when the source tells us which
    site the handle belongs to (e.g. ``"github"``, ``"twitter"``).
    """

    platform: Optional[str] = None

    @property
    def entity_type(self) -> str:
        return "username"

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["platform"] = self.platform
        return d


@dataclass
class PlatformProfileEntity(BaseEntity):
    """
    A full profile URL on a known platform.

    ``value`` is the URL; ``platform`` is the site name; ``url`` mirrors
    ``value`` for clarity when iterating a mixed entity list.
    """

    platform: str = ""
    url: str = ""

    @property
    def entity_type(self) -> str:
        return "platform_profile"

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["platform"] = self.platform
        d["url"] = self.url
        return d


@dataclass
class NameEntity(BaseEntity):
    """A real-world name clue (full name or partial name)."""

    @property
    def entity_type(self) -> str:
        return "name"


@dataclass
class LocationEntity(BaseEntity):
    """
    An inferred or stated location.

    ``value`` is a free-text location string as returned by
    ``infer_location()`` (e.g. ``"London, UK"``).
    """

    @property
    def entity_type(self) -> str:
        return "location"


@dataclass
class AvatarEntity(BaseEntity):
    """
    An avatar image.

    ``url``   – CDN / direct URL of the image.
    ``phash`` – optional perceptual hash string used for reuse detection.
    """

    url: str = ""
    phash: Optional[str] = None

    @property
    def entity_type(self) -> str:
        return "avatar"

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["url"] = self.url
        d["phash"] = self.phash
        return d
