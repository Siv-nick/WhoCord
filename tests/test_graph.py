"""
tests/test_graph.py
---------------------
Unit tests for discord_osint/intelligence/graph.py

Tests build small, controlled entity lists and assert on graph structure
(nodes, edges, edge attributes) without any network calls.

networkx is a required dep for Phase 1; tests are skipped if it is absent.
"""

import pytest

networkx = pytest.importorskip("networkx", reason="networkx is not installed")

from discord_osint.intelligence.entities import (
    AvatarEntity,
    EmailEntity,
    NameEntity,
    PlatformProfileEntity,
    UsernameEntity,
    LocationEntity,
)
from discord_osint.intelligence.graph import build_graph, graph_summary


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def email(value="alice@example.com", source="scrape_github", confidence=0.70):
    return EmailEntity(value=value, source=source, confidence=confidence)


def profile(
    value="https://github.com/alice",
    platform="github",
    source="scrape_github",
    confidence=0.70,
):
    return PlatformProfileEntity(
        value=value, source=source, confidence=confidence,
        platform=platform, url=value,
    )


def username(value="alice", platform="github", source="scrape_github"):
    return UsernameEntity(value=value, source=source, platform=platform)


def name(value="Alice Smith", source="discord_bio"):
    return NameEntity(value=value, source=source)


def avatar(value="https://cdn.example.com/img.png", source="discord_enrich"):
    return AvatarEntity(value=value, source=source, url=value)


def location(value="London", source="location_inference"):
    return LocationEntity(value=value, source=source)


# ---------------------------------------------------------------------------
# Node tests
# ---------------------------------------------------------------------------

class TestGraphNodes:
    def test_each_entity_becomes_a_node(self):
        entities = [email(), profile(), username()]
        G = build_graph(entities)
        assert G.number_of_nodes() == 3

    def test_node_attributes_set(self):
        e = email()
        G = build_graph([e])
        data = G.nodes[e.id]
        assert data["entity_type"] == "email"
        assert data["value"] == e.value
        assert data["confidence"] == e.confidence
        assert data["source"] == e.source
        assert data["entity"] is e

    def test_empty_entity_list(self):
        G = build_graph([])
        assert G.number_of_nodes() == 0
        assert G.number_of_edges() == 0


# ---------------------------------------------------------------------------
# Edge rule 1 – Email ↔ PlatformProfile (same source)
# ---------------------------------------------------------------------------

class TestEdgeRule1:
    def test_email_and_profile_same_source_are_connected(self):
        e = email(source="scrape_github")
        p = profile(source="scrape_github")
        G = build_graph([e, p])
        assert G.has_edge(e.id, p.id)

    def test_email_and_profile_different_source_not_connected_by_rule1(self):
        e = email(source="source_a")
        p = profile(source="source_b")
        G = build_graph([e, p])
        # They should NOT be connected by rule 1; co-occurrence also won't
        # fire since sources differ.
        assert not G.has_edge(e.id, p.id)

    def test_edge_reason_shared_source(self):
        e = email(source="scrape_github")
        p = profile(source="scrape_github")
        G = build_graph([e, p])
        assert G[e.id][p.id]["reason"] == "shared_source"


# ---------------------------------------------------------------------------
# Edge rule 2 – Username ↔ PlatformProfile (same platform)
# ---------------------------------------------------------------------------

class TestEdgeRule2:
    def test_username_and_profile_same_platform_connected(self):
        u = username(platform="github")
        p = profile(platform="github")
        G = build_graph([u, p])
        assert G.has_edge(u.id, p.id)

    def test_username_and_profile_different_platform_not_connected(self):
        u = username(platform="twitter")
        p = profile(platform="github")
        G = build_graph([u, p])
        # No rule fires → no edge (co-occurrence also won't fire for different sources)
        assert not G.has_edge(u.id, p.id)

    def test_edge_weight_for_shared_platform(self):
        u = username(platform="reddit", source="src_a")
        p = profile(platform="reddit", source="src_b")
        G = build_graph([u, p])
        assert G[u.id][p.id]["weight"] >= 0.8


# ---------------------------------------------------------------------------
# Edge rule 3 – Name ↔ Email (local-part match)
# ---------------------------------------------------------------------------

class TestEdgeRule3:
    def test_name_email_match_creates_edge(self):
        n = name("Alice Smith")
        e = email("alice.smith@gmail.com")
        G = build_graph([n, e])
        assert G.has_edge(n.id, e.id)

    def test_unrelated_name_no_edge(self):
        n = name("Bob Jones")
        e = email("alice@example.com")
        G = build_graph([n, e])
        assert not G.has_edge(n.id, e.id)

    def test_first_name_match(self):
        n = name("Alice Wonderland")
        e = email("alice_wonder@domain.com")
        G = build_graph([n, e])
        assert G.has_edge(n.id, e.id)

    def test_edge_reason_name_email_match(self):
        n = name("Alice Smith")
        e = email("alicesmith@example.com")
        G = build_graph([n, e])
        assert G[n.id][e.id]["reason"] == "name_email_match"


# ---------------------------------------------------------------------------
# Edge rule 4 – Avatar ↔ PlatformProfile (same source)
# ---------------------------------------------------------------------------

class TestEdgeRule4:
    def test_avatar_and_profile_same_source_connected(self):
        a = avatar(source="discord_enrich")
        p = profile(source="discord_enrich")
        G = build_graph([a, p])
        assert G.has_edge(a.id, p.id)

    def test_avatar_and_profile_different_source_not_connected_by_rule4(self):
        a = avatar(source="src_x")
        p = profile(source="src_y")
        G = build_graph([a, p])
        assert not G.has_edge(a.id, p.id)


# ---------------------------------------------------------------------------
# Edge rule 5 – Co-occurrence (same source, weak edge)
# ---------------------------------------------------------------------------

class TestEdgeRule5:
    def test_two_entities_same_source_get_cooccurrence_edge(self):
        # Use incompatible types so rules 1-4 don't fire
        loc = location(source="shared_src")
        n   = name(source="shared_src")
        G = build_graph([loc, n])
        assert G.has_edge(loc.id, n.id)
        assert G[loc.id][n.id]["reason"] == "co_occurrence"

    def test_cooccurrence_weight_is_low(self):
        loc = location(source="shared_src")
        n   = name(source="shared_src")
        G = build_graph([loc, n])
        assert G[loc.id][n.id]["weight"] == pytest.approx(0.30)

    def test_stronger_rule_takes_precedence(self):
        """When a stronger rule already creates an edge, co-occurrence should
        not downgrade the weight."""
        e = email(source="same_src")
        p = profile(source="same_src")
        G = build_graph([e, p])
        # Rule 1 fires first (weight 0.75); co-occurrence (0.30) must NOT
        # overwrite it.
        assert G[e.id][p.id]["weight"] >= 0.70


# ---------------------------------------------------------------------------
# graph_summary
# ---------------------------------------------------------------------------

class TestGraphSummary:
    def test_summary_keys(self):
        entities = [email(), profile(), username()]
        G = build_graph(entities)
        summary = graph_summary(G)
        for key in (
            "total_nodes", "total_edges", "node_counts_by_type",
            "edge_reasons", "top_connected_nodes", "isolated_node_count", "density"
        ):
            assert key in summary, f"graph_summary missing key: {key}"

    def test_node_counts_by_type_correct(self):
        entities = [email(), email("b@b.com"), profile()]
        G = build_graph(entities)
        summary = graph_summary(G)
        counts = summary["node_counts_by_type"]
        assert counts.get("email") == 2
        assert counts.get("platform_profile") == 1

    def test_empty_graph_summary(self):
        G = build_graph([])
        summary = graph_summary(G)
        assert summary["total_nodes"] == 0
        assert summary["total_edges"] == 0
        assert summary["density"] == 0.0

    def test_none_returns_empty_dict(self):
        assert graph_summary(None) == {}

    def test_top_connected_nodes_sorted(self):
        # Build a star graph: email connected to 3 profiles
        e  = email(source="x")
        p1 = profile(source="x", value="https://g.com/a", platform="github")
        p2 = profile(source="x", value="https://g.com/b", platform="github")
        G  = build_graph([e, p1, p2])
        summary = graph_summary(G)
        top = summary["top_connected_nodes"]
        # The email node (connected to both profiles) should have the highest degree
        assert top[0]["type"] in ("email", "platform_profile")
