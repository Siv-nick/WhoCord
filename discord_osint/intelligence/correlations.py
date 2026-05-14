"""
discord_osint/intelligence/correlations.py
--------------------------------------------
Correlation detectors – traverse the knowledge graph and return
:class:`Correlation` objects describing cross-source patterns.

Five detectors (matching the plan specification):

  1. Avatar reuse         – same image / phash across different profiles
  2. Email-platform cluster – one email linked to multiple platforms
  3. Username variants    – similar usernames (Levenshtein distance ≤ 2)
  4. Name-email link      – name tokens match email local-part
  5. Location consistency – multiple location entities: consistent or conflicting

Each detector is a standalone function so individual detectors can be
unit-tested in isolation.  :func:`run_all_detectors` calls them all and
returns a sorted merged list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False


# ---------------------------------------------------------------------------
# Correlation data class
# ---------------------------------------------------------------------------

@dataclass
class Correlation:
    """A detected pattern linking two or more entities."""

    correlation_type: str
    """Short machine-readable label, e.g. ``"avatar_reuse"``."""

    description: str
    """Human-readable explanation of the finding."""

    confidence: float
    """
    Confidence that this is a real correlation (0–1).
    Combine evidence strength with detector reliability.
    """

    entities_involved: list[str] = field(default_factory=list)
    """List of ``entity.value`` strings involved in the pattern."""

    metadata: dict = field(default_factory=dict)
    """Extra data for the LLM prompt and HTML rendering."""

    def to_dict(self) -> dict:
        return {
            "type":        self.correlation_type,
            "description": self.description,
            "confidence":  self.confidence,
            "entities":    self.entities_involved,
            "metadata":    self.metadata,
        }


# ---------------------------------------------------------------------------
# Pure-Python Levenshtein (no third-party dep)
# ---------------------------------------------------------------------------

def _levenshtein(s1: str, s2: str) -> int:
    """Return the Levenshtein edit distance between *s1* and *s2*."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


# ---------------------------------------------------------------------------
# Detector 1 – Avatar reuse
# ---------------------------------------------------------------------------

def detect_avatar_reuse(
    entities: list[BaseEntity], G: Any = None
) -> list[Correlation]:
    """
    Detect the same avatar image used across different profiles.

    Matching strategy (in order of reliability):
    1. Identical CDN URL  → confidence 0.88
    2. Identical perceptual hash → confidence 0.82
    """
    correlations: list[Correlation] = []
    avatars = [e for e in entities if isinstance(e, AvatarEntity)]

    checked: set[tuple[str, str]] = set()

    for i, a in enumerate(avatars):
        for b in avatars[i + 1:]:
            pair_key = tuple(sorted([a.id, b.id]))
            if pair_key in checked:
                continue
            checked.add(pair_key)

            same, reason, conf = False, "", 0.0

            if a.url and b.url and a.url == b.url:
                same, reason, conf = True, "identical URL", 0.88
            elif a.phash and b.phash and a.phash == b.phash:
                same, reason, conf = True, "identical perceptual hash", 0.82

            if same and a.source != b.source:
                correlations.append(Correlation(
                    correlation_type="avatar_reuse",
                    description=(
                        f"Avatar reused across different sources ({reason}): "
                        f"{a.source!r} and {b.source!r} – likely the same person."
                    ),
                    confidence=conf,
                    entities_involved=[a.value, b.value],
                    metadata={
                        "reason":  reason,
                        "sources": [a.source, b.source],
                        "url":     a.url,
                    },
                ))

    return correlations


# ---------------------------------------------------------------------------
# Detector 2 – Email-platform cluster
# ---------------------------------------------------------------------------

def detect_email_platform_clusters(
    entities: list[BaseEntity], G: Any = None
) -> list[Correlation]:
    """
    Identify emails that are linked to multiple platform profiles in the graph.

    Requires the graph to have been built; degrades gracefully if *G* is None.
    """
    correlations: list[Correlation] = []

    if G is None or not _NX_AVAILABLE:
        return correlations

    emails   = [e for e in entities if isinstance(e, EmailEntity)]
    profiles = [e for e in entities if isinstance(e, PlatformProfileEntity)]
    profile_ids = {p.id for p in profiles}
    profile_by_id = {p.id: p for p in profiles}

    for email in emails:
        if email.id not in G:
            continue

        linked_profile_ids = [
            n for n in G.neighbors(email.id)
            if n in profile_ids
        ]

        if len(linked_profile_ids) >= 2:
            linked_profiles = [profile_by_id[pid] for pid in linked_profile_ids]
            platform_names  = [p.platform or p.value[:40] for p in linked_profiles]

            correlations.append(Correlation(
                correlation_type="email_platform_cluster",
                description=(
                    f"Email {email.value!r} is linked to "
                    f"{len(linked_profile_ids)} platform profiles: "
                    f"{', '.join(platform_names[:6])}"
                    f"{'…' if len(platform_names) > 6 else ''}."
                ),
                confidence=min(0.90, 0.65 + len(linked_profile_ids) * 0.05),
                entities_involved=[email.value] + platform_names,
                metadata={
                    "email":          email.value,
                    "platform_count": len(linked_profile_ids),
                    "platforms":      platform_names,
                },
            ))

    return correlations


# ---------------------------------------------------------------------------
# Detector 3 – Username variants
# ---------------------------------------------------------------------------

def detect_username_variants(
    entities: list[BaseEntity], G: Any = None
) -> list[Correlation]:
    """
    Find ``UsernameEntity`` pairs whose values are similar (edit distance ≤ 2).

    Distance 1 → likely same person with minor variation (extra char, typo).
    Distance 2 → possible variant; lower confidence.
    """
    correlations: list[Correlation] = []
    usernames = [e for e in entities if isinstance(e, UsernameEntity)]

    seen_pairs: set[tuple[str, str]] = set()

    for i, a in enumerate(usernames):
        for b in usernames[i + 1:]:
            # Skip identical values (same username on two platforms – handled
            # by the graph co-occurrence rule, not this detector)
            if a.value.lower() == b.value.lower():
                continue

            pair_key = tuple(sorted([a.value.lower(), b.value.lower()]))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            dist = _levenshtein(a.value.lower(), b.value.lower())
            if 0 < dist <= 2:
                conf = 0.78 if dist == 1 else 0.55
                plat_a = a.platform or "unknown"
                plat_b = b.platform or "unknown"

                correlations.append(Correlation(
                    correlation_type="username_variant",
                    description=(
                        f"Username variant: {a.value!r} ({plat_a}) ↔ "
                        f"{b.value!r} ({plat_b}) – edit distance {dist}."
                    ),
                    confidence=conf,
                    entities_involved=[a.value, b.value],
                    metadata={
                        "edit_distance": dist,
                        "username_a":   a.value,
                        "username_b":   b.value,
                        "platform_a":   plat_a,
                        "platform_b":   plat_b,
                    },
                ))

    return correlations


# ---------------------------------------------------------------------------
# Detector 4 – Name-email link
# ---------------------------------------------------------------------------

def detect_name_email_links(
    entities: list[BaseEntity], G: Any = None
) -> list[Correlation]:
    """
    Find ``NameEntity`` / ``EmailEntity`` pairs where the name tokens appear
    in the email local-part (or vice versa).

    This is a graph-independent detector; the graph is only consulted to
    report the existing edge weight when present.
    """
    correlations: list[Correlation] = []
    names  = [e for e in entities if isinstance(e, NameEntity)]
    emails = [e for e in entities if isinstance(e, EmailEntity)]

    seen_pairs: set[tuple[str, str]] = set()

    for name in names:
        name_tokens = [
            t.lower() for t in name.value.replace("-", " ").split()
            if len(t) >= 3
        ]
        if not name_tokens:
            continue

        for email in emails:
            pair_key = (name.id, email.id)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            local = email.local_part.lower().replace(".", "").replace("_", "").replace("-", "")
            matched_tokens = [t for t in name_tokens if t in local]

            if matched_tokens:
                conf = min(0.88, 0.55 + len(matched_tokens) * 0.12)
                correlations.append(Correlation(
                    correlation_type="name_email_link",
                    description=(
                        f"Name {name.value!r} matches email {email.value!r} "
                        f"(matched tokens: {', '.join(matched_tokens)})."
                    ),
                    confidence=conf,
                    entities_involved=[name.value, email.value],
                    metadata={
                        "name":           name.value,
                        "email":          email.value,
                        "matched_tokens": matched_tokens,
                    },
                ))

    return correlations


# ---------------------------------------------------------------------------
# Detector 5 – Location consistency
# ---------------------------------------------------------------------------

def detect_location_consistency(
    entities: list[BaseEntity], G: Any = None
) -> list[Correlation]:
    """
    Evaluate multiple ``LocationEntity`` nodes for consistency or conflict.

    - One unique location across multiple sources → strong confirmation.
    - Multiple different locations → flag as inconsistency / VPN use.
    """
    correlations: list[Correlation] = []
    locations = [e for e in entities if isinstance(e, LocationEntity)]

    if len(locations) < 2:
        return correlations

    unique_values: list[str] = list(dict.fromkeys(
        loc.value.strip().lower() for loc in locations if loc.value.strip()
    ))

    if len(unique_values) == 1:
        correlations.append(Correlation(
            correlation_type="location_consistency",
            description=(
                f"Location confirmed as {locations[0].value!r} "
                f"across {len(locations)} independent sources."
            ),
            confidence=min(0.90, 0.60 + len(locations) * 0.08),
            entities_involved=[loc.value for loc in locations],
            metadata={
                "location":     locations[0].value,
                "source_count": len(locations),
                "sources":      [loc.source for loc in locations],
            },
        ))
    else:
        correlations.append(Correlation(
            correlation_type="location_inconsistency",
            description=(
                f"Conflicting locations detected across {len(locations)} sources: "
                f"{', '.join(unique_values[:5])}"
                f"{'…' if len(unique_values) > 5 else ''}. "
                f"Possible VPN / privacy tool use."
            ),
            confidence=0.65,
            entities_involved=[loc.value for loc in locations],
            metadata={
                "locations": unique_values,
                "sources":   [loc.source for loc in locations],
            },
        ))

    return correlations


# ---------------------------------------------------------------------------
# Master runner
# ---------------------------------------------------------------------------

_DETECTORS = [
    detect_avatar_reuse,
    detect_email_platform_clusters,
    detect_username_variants,
    detect_name_email_links,
    detect_location_consistency,
]


def run_all_detectors(
    entities: list[BaseEntity], G: Any = None
) -> list[Correlation]:
    """
    Run every detector and return a deduplicated list sorted by
    confidence (descending).

    Detector failures are caught and printed so one broken detector
    cannot abort the entire intelligence stage.
    """
    all_correlations: list[Correlation] = []

    for detector in _DETECTORS:
        try:
            results = detector(entities, G)
            all_correlations.extend(results)
        except Exception as exc:
            print(f"  [!] Correlation detector {detector.__name__!r} failed: {exc}")

    # Sort by confidence, highest first
    all_correlations.sort(key=lambda c: c.confidence, reverse=True)
    return all_correlations
