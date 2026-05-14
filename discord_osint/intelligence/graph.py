"""
discord_osint/intelligence/graph.py
-------------------------------------
Build a ``networkx.Graph`` from a list of typed entities.

Graph semantics
---------------
Nodes   – one per entity, keyed by ``entity.id``.
          Node attrs: ``entity_type``, ``value``, ``confidence``,
          ``source``, ``entity`` (the object reference).

Edges   – created by five co-occurrence rules from the plan:

  1. Email ↔ PlatformProfile  if they appear in the same source.
  2. Username ↔ PlatformProfile  if they share the same platform.
  3. Name ↔ Email  if the email local-part matches the name tokens.
  4. Avatar ↔ PlatformProfile  if extracted from the same page/source.
  5. Any two entities from the same investigation source get a weak
     "co_occurrence" edge (weight 0.3) when not already connected.

Edge attrs: ``reason`` (str), ``weight`` (float 0–1).

The ``networkx`` package is optional; if it is missing the public
functions raise a clear ``ImportError`` so the caller can degrade
gracefully.
"""

from __future__ import annotations

from typing import Any

from .entities import (
    AvatarEntity,
    BaseEntity,
    EmailEntity,
    NameEntity,
    PlatformProfileEntity,
    UsernameEntity,
)

# ---------------------------------------------------------------------------
# networkx guard
# ---------------------------------------------------------------------------
try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False


def _require_nx() -> None:
    if not _NX_AVAILABLE:
        raise ImportError(
            "networkx is required for the intelligence knowledge graph.\n"
            "Install it with:  pip install networkx"
        )


# ---------------------------------------------------------------------------
# Name / email normalisation helpers
# ---------------------------------------------------------------------------

def _norm_name(name: str) -> str:
    """Collapse a full name to a lowercase concatenated token."""
    return name.lower().replace(" ", "").replace(".", "").replace("-", "")


def _norm_local(local: str) -> str:
    """Normalise the local-part of an email for fuzzy name matching."""
    return local.lower().replace(".", "").replace("_", "").replace("-", "")


def _name_matches_email(name_value: str, local_part: str) -> bool:
    """
    Return True when the name tokens substantially overlap with the
    email local-part.

    Heuristic rules (order matters):

    1. Exact: ``norm(name) == norm(local)``
    2. Containment: one of the two is a substring of the other
    3. First-name hit: first word of the name appears in local-part
    """
    nm = _norm_name(name_value)
    lp = _norm_local(local_part)

    if not nm or not lp:
        return False

    if nm == lp:
        return True

    if nm in lp or lp in nm:
        return True

    # First-name only
    first = _norm_name(name_value.split()[0]) if " " in name_value else nm
    if len(first) >= 3 and first in lp:
        return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_graph(entities: list[BaseEntity]) -> Any:
    """
    Build and return a ``networkx.Graph`` from *entities*.

    Parameters
    ----------
    entities:
        Output of :func:`~discord_osint.intelligence.extractor.extract_entities`.

    Returns
    -------
    networkx.Graph

    Raises
    ------
    ImportError
        If ``networkx`` is not installed.
    """
    _require_nx()
    G = nx.Graph()

    # --- Add nodes ---
    for ent in entities:
        G.add_node(
            ent.id,
            entity_type=ent.entity_type,
            value=ent.value,
            confidence=ent.confidence,
            source=ent.source,
            entity=ent,   # keep a reference for correlation detectors
        )

    # --- Partition by type for rule application ---
    emails:   list[EmailEntity]          = [e for e in entities if isinstance(e, EmailEntity)]
    usernames: list[UsernameEntity]      = [e for e in entities if isinstance(e, UsernameEntity)]
    profiles:  list[PlatformProfileEntity] = [e for e in entities if isinstance(e, PlatformProfileEntity)]
    names:    list[NameEntity]           = [e for e in entities if isinstance(e, NameEntity)]
    avatars:  list[AvatarEntity]         = [e for e in entities if isinstance(e, AvatarEntity)]

    def _add_edge(a: BaseEntity, b: BaseEntity, reason: str, weight: float) -> None:
        """Add (or upgrade) an edge between two entities."""
        if G.has_edge(a.id, b.id):
            if G[a.id][b.id].get("weight", 0) < weight:
                G[a.id][b.id]["weight"] = weight
                G[a.id][b.id]["reason"] = reason
        else:
            G.add_edge(a.id, b.id, reason=reason, weight=weight)

    # --- Rule 1: Email ↔ PlatformProfile (same source) ---
    for email in emails:
        for prof in profiles:
            if email.source and email.source == prof.source:
                _add_edge(email, prof, "shared_source", 0.75)

    # --- Rule 2: Username ↔ PlatformProfile (same platform) ---
    for uname in usernames:
        for prof in profiles:
            if (
                uname.platform
                and prof.platform
                and uname.platform.lower() == prof.platform.lower()
            ):
                _add_edge(uname, prof, "shared_platform", 0.82)

    # --- Rule 3: Name ↔ Email (local-part match) ---
    for name in names:
        for email in emails:
            if _name_matches_email(name.value, email.local_part):
                _add_edge(name, email, "name_email_match", 0.65)

    # --- Rule 4: Avatar ↔ PlatformProfile (same source) ---
    for avatar in avatars:
        for prof in profiles:
            if avatar.source and avatar.source == prof.source:
                _add_edge(avatar, prof, "shared_source", 0.68)

    # --- Rule 5: Weak co-occurrence for same source ---
    source_buckets: dict[str, list[BaseEntity]] = {}
    for ent in entities:
        if ent.source:
            source_buckets.setdefault(ent.source, []).append(ent)

    for src, bucket in source_buckets.items():
        if len(bucket) < 2:
            continue
        for i, a in enumerate(bucket):
            for b in bucket[i + 1:]:
                if not G.has_edge(a.id, b.id):
                    _add_edge(a, b, "co_occurrence", 0.30)

    return G


def graph_summary(G: Any) -> dict:
    """
    Return a serialisable summary of *G* for use in LLM prompts and
    HTML reports.

    Returns an empty dict if *G* is ``None`` or networkx is unavailable.
    """
    if G is None or not _NX_AVAILABLE:
        return {}

    # Count nodes per entity type
    node_counts: dict[str, int] = {}
    for _, data in G.nodes(data=True):
        t = data.get("entity_type", "unknown")
        node_counts[t] = node_counts.get(t, 0) + 1

    # Count edges per reason
    edge_reasons: dict[str, int] = {}
    for _, _, data in G.edges(data=True):
        r = data.get("reason", "unknown")
        edge_reasons[r] = edge_reasons.get(r, 0) + 1

    # Top nodes by degree (most connected)
    top_nodes = sorted(
        [
            {
                "id":         nid,
                "type":       data.get("entity_type"),
                "value":      data.get("value"),
                "confidence": data.get("confidence"),
                "degree":     G.degree(nid),
            }
            for nid, data in G.nodes(data=True)
        ],
        key=lambda x: (x["degree"], x["confidence"]),
        reverse=True,
    )[:10]

    # Identify isolated nodes (no connections = low information value)
    isolated = [
        nid for nid in G.nodes() if G.degree(nid) == 0
    ]

    return {
        "total_nodes":          G.number_of_nodes(),
        "total_edges":          G.number_of_edges(),
        "node_counts_by_type":  node_counts,
        "edge_reasons":         edge_reasons,
        "top_connected_nodes":  top_nodes,
        "isolated_node_count":  len(isolated),
        "density":              round(nx.density(G), 4) if G.number_of_nodes() > 1 else 0.0,
    }
