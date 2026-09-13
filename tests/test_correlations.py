"""
tests/test_correlations.py
----------------------------
Unit tests for discord_osint/intelligence/correlations.py

Each detector is tested in isolation using hand-crafted entity lists.
The ``G`` (graph) parameter is built with ``build_graph()`` only for
detectors that require it; others receive ``G=None``.

networkx is a required dep for graph-dependent detectors; those tests are
skipped automatically if networkx is absent.
"""

import pytest

from discord_osint.intelligence.entities import (
    AvatarEntity,
    EmailEntity,
    LocationEntity,
    NameEntity,
    PlatformProfileEntity,
    UsernameEntity,
)
from discord_osint.intelligence.correlations import (
    Correlation,
    _levenshtein,
    detect_avatar_reuse,
    detect_email_platform_clusters,
    detect_location_consistency,
    detect_name_email_links,
    detect_username_variants,
    run_all_detectors,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mk_email(val="alice@example.com", source="holehe", conf=0.65):
    return EmailEntity(value=val, source=source, confidence=conf)


def mk_profile(val="https://github.com/alice", platform="github",
               source="scrape_github", conf=0.70):
    return PlatformProfileEntity(
        value=val, source=source, confidence=conf,
        platform=platform, url=val,
    )


def mk_username(val="alice", platform="github", source="naminter"):
    return UsernameEntity(value=val, source=source, platform=platform)


def mk_name(val="Alice Smith", source="discord_bio"):
    return NameEntity(value=val, source=source)


def mk_location(val="London, UK", source="location_inference"):
    return LocationEntity(value=val, source=source)


def mk_avatar(url="https://cdn.discord.com/avatars/123/abc.png",
              phash=None, source="discord_enrich"):
    return AvatarEntity(value=url, source=source, url=url, phash=phash)


def _build_graph(entities):
    pytest.importorskip("networkx")
    from discord_osint.intelligence.graph import build_graph
    return build_graph(entities)


# ---------------------------------------------------------------------------
# Levenshtein helper
# ---------------------------------------------------------------------------

class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("abc", "abc") == 0

    def test_single_substitution(self):
        assert _levenshtein("abc", "axc") == 1

    def test_single_insertion(self):
        assert _levenshtein("abc", "abcd") == 1

    def test_single_deletion(self):
        assert _levenshtein("abcd", "abc") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "abc") == 3
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "") == 0

    def test_symmetric(self):
        assert _levenshtein("kitten", "sitting") == _levenshtein("sitting", "kitten")


# ---------------------------------------------------------------------------
# Correlation data class
# ---------------------------------------------------------------------------

class TestCorrelationDataClass:
    def test_to_dict_keys(self):
        c = Correlation(
            correlation_type="test",
            description="Test correlation",
            confidence=0.80,
            entities_involved=["a", "b"],
            metadata={"k": "v"},
        )
        d = c.to_dict()
        for key in ("type", "description", "confidence", "entities", "metadata"):
            assert key in d

    def test_defaults(self):
        c = Correlation(
            correlation_type="test",
            description="desc",
            confidence=0.5,
        )
        assert c.entities_involved == []
        assert c.metadata == {}


# ---------------------------------------------------------------------------
# Detector 1 – Avatar reuse
# ---------------------------------------------------------------------------

class TestDetectAvatarReuse:
    def test_same_url_different_sources_is_reuse(self):
        a1 = mk_avatar(url="https://example.com/img.png", source="discord_enrich")
        a2 = mk_avatar(url="https://example.com/img.png", source="gravatar")
        corrs = detect_avatar_reuse([a1, a2])
        assert len(corrs) == 1
        c = corrs[0]
        assert c.correlation_type == "avatar_reuse"
        assert c.confidence >= 0.85

    def test_same_phash_different_sources(self):
        a1 = mk_avatar(phash="deadbeef0000", source="discord_enrich")
        a2 = mk_avatar(
            url="https://other.com/img.png", phash="deadbeef0000", source="gravatar"
        )
        corrs = detect_avatar_reuse([a1, a2])
        assert len(corrs) == 1
        assert corrs[0].confidence >= 0.80

    def test_different_url_no_reuse(self):
        a1 = mk_avatar(url="https://example.com/a.png", source="src_a")
        a2 = mk_avatar(url="https://example.com/b.png", source="src_b")
        corrs = detect_avatar_reuse([a1, a2])
        assert len(corrs) == 0

    def test_same_source_ignored(self):
        """Same avatar from the same source is not 'reuse' across profiles."""
        a1 = mk_avatar(url="https://cdn.com/img.png", source="discord_enrich")
        a2 = mk_avatar(url="https://cdn.com/img.png", source="discord_enrich")
        corrs = detect_avatar_reuse([a1, a2])
        assert len(corrs) == 0

    def test_no_avatars(self):
        assert detect_avatar_reuse([mk_email()]) == []


# ---------------------------------------------------------------------------
# Detector 2 – Email-platform cluster
# ---------------------------------------------------------------------------

class TestDetectEmailPlatformCluster:
    def test_email_linked_to_two_profiles(self):
        email    = mk_email(source="holehe")
        profile1 = mk_profile(
            val="https://github.com/alice", platform="github", source="holehe"
        )
        profile2 = mk_profile(
            val="https://spotify.com/alice", platform="spotify", source="holehe"
        )
        entities = [email, profile1, profile2]
        G = _build_graph(entities)
        corrs = detect_email_platform_clusters(entities, G)
        assert len(corrs) == 1
        c = corrs[0]
        assert c.correlation_type == "email_platform_cluster"
        assert c.metadata["platform_count"] == 2

    def test_email_linked_to_one_profile_no_cluster(self):
        email   = mk_email(source="holehe")
        profile1 = mk_profile(source="holehe")
        entities = [email, profile1]
        G = _build_graph(entities)
        corrs = detect_email_platform_clusters(entities, G)
        assert len(corrs) == 0

    def test_no_graph_returns_empty(self):
        corrs = detect_email_platform_clusters([mk_email(), mk_profile()], G=None)
        assert corrs == []

    def test_confidence_increases_with_more_platforms(self):
        email = mk_email(source="holehe")
        profiles = [
            mk_profile(
                val=f"https://site{i}.com/alice",
                platform=f"site{i}",
                source="holehe",
            )
            for i in range(5)
        ]
        entities = [email] + profiles
        G = _build_graph(entities)
        corrs = detect_email_platform_clusters(entities, G)
        assert len(corrs) == 1
        assert corrs[0].confidence >= 0.85


# ---------------------------------------------------------------------------
# Detector 3 – Username variants
# ---------------------------------------------------------------------------

class TestDetectUsernameVariants:
    def test_single_char_difference_detected(self):
        u1 = mk_username("alice",  platform="github",  source="src_a")
        u2 = mk_username("alice_", platform="twitter", source="src_b")
        corrs = detect_username_variants([u1, u2])
        assert len(corrs) == 1
        assert corrs[0].correlation_type == "username_variant"
        assert corrs[0].metadata["edit_distance"] == 1

    def test_distance_two_detected(self):
        u1 = mk_username("alice",  platform="github",  source="src_a")
        u2 = mk_username("alice00", platform="reddit", source="src_b")
        corrs = detect_username_variants([u1, u2])
        assert len(corrs) == 1
        assert corrs[0].metadata["edit_distance"] == 2

    def test_distance_three_not_detected(self):
        u1 = mk_username("alice",    platform="github",  source="src_a")
        u2 = mk_username("alice_123", platform="reddit", source="src_b")
        corrs = detect_username_variants([u1, u2])
        assert len(corrs) == 0

    def test_identical_usernames_ignored(self):
        """Same username on two platforms is graph co-occurrence, not a variant."""
        u1 = mk_username("alice", platform="github",  source="src_a")
        u2 = mk_username("alice", platform="twitter", source="src_b")
        corrs = detect_username_variants([u1, u2])
        assert len(corrs) == 0

    def test_confidence_higher_for_distance_one(self):
        u1 = mk_username("bob",  platform="github",  source="src_a")
        u2 = mk_username("bob_", platform="twitter", source="src_b")
        u3 = mk_username("Bob2", platform="reddit",  source="src_c")
        corrs_d1 = detect_username_variants([u1, u2])
        corrs_d2 = detect_username_variants([u1, u3])
        assert corrs_d1[0].confidence > corrs_d2[0].confidence

    def test_no_usernames(self):
        assert detect_username_variants([mk_email()]) == []


# ---------------------------------------------------------------------------
# Detector 4 – Name-email links
# ---------------------------------------------------------------------------

class TestDetectNameEmailLinks:
    def test_full_name_in_local_part(self):
        n = mk_name("Alice Smith")
        e = mk_email("alicesmith@example.com")
        corrs = detect_name_email_links([n, e])
        assert len(corrs) == 1
        assert corrs[0].correlation_type == "name_email_link"

    def test_first_name_in_local_part(self):
        n = mk_name("Alice Wonderland")
        e = mk_email("alice_dev@gmail.com")
        corrs = detect_name_email_links([n, e])
        assert len(corrs) == 1

    def test_dot_separated_local_part(self):
        n = mk_name("Bob Jones")
        e = mk_email("bob.jones@company.com")
        corrs = detect_name_email_links([n, e])
        assert len(corrs) == 1

    def test_unrelated_name_no_link(self):
        n = mk_name("Charlie Brown")
        e = mk_email("xyzabc@example.com")
        corrs = detect_name_email_links([n, e])
        assert len(corrs) == 0

    def test_short_name_not_matched(self):
        """Names shorter than 3 characters should not trigger a match."""
        n = mk_name("Li")    # too short for token matching
        e = mk_email("li_something@example.com")
        corrs = detect_name_email_links([n, e])
        assert len(corrs) == 0

    def test_confidence_increases_with_more_tokens(self):
        n_single = mk_name("Alice Something")
        n_double = mk_name("Alice Smith Extra")   # 3 tokens, more will match
        e = mk_email("alicesmithextra@example.com")
        corrs_single = detect_name_email_links([n_single, e])
        corrs_double = detect_name_email_links([n_double, e])
        if corrs_single and corrs_double:
            assert corrs_double[0].confidence >= corrs_single[0].confidence


# ---------------------------------------------------------------------------
# Detector 5 – Location consistency
# ---------------------------------------------------------------------------

class TestDetectLocationConsistency:
    def test_single_location_no_correlation(self):
        loc = mk_location("London")
        corrs = detect_location_consistency([loc])
        assert len(corrs) == 0

    def test_two_same_locations_consistent(self):
        l1 = mk_location("London, UK", source="a")
        l2 = mk_location("London, UK", source="b")
        corrs = detect_location_consistency([l1, l2])
        assert len(corrs) == 1
        assert corrs[0].correlation_type == "location_consistency"
        assert corrs[0].confidence >= 0.70

    def test_two_different_locations_inconsistent(self):
        l1 = mk_location("London, UK")
        l2 = mk_location("New York, US")
        corrs = detect_location_consistency([l1, l2])
        assert len(corrs) == 1
        assert corrs[0].correlation_type == "location_inconsistency"

    def test_three_same_locations_higher_confidence(self):
        locs = [mk_location("Tokyo", source=f"src_{i}") for i in range(3)]
        corrs = detect_location_consistency(locs)
        assert len(corrs) == 1
        assert corrs[0].confidence >= 0.75


# ---------------------------------------------------------------------------
# run_all_detectors
# ---------------------------------------------------------------------------

class TestRunAllDetectors:
    def test_returns_list(self):
        entities = [mk_email(), mk_name(), mk_location()]
        corrs = run_all_detectors(entities, G=None)
        assert isinstance(corrs, list)

    def test_sorted_by_confidence_descending(self):
        l1 = mk_location("London", source="a")
        l2 = mk_location("London", source="b")
        l3 = mk_location("London", source="c")
        u1 = mk_username("alice_", platform="github", source="src_a")
        u2 = mk_username("alice",  platform="twitter", source="src_b")
        entities = [l1, l2, l3, u1, u2]
        corrs = run_all_detectors(entities, G=None)
        confs = [c.confidence for c in corrs]
        assert confs == sorted(confs, reverse=True)

    def test_no_crash_on_empty(self):
        corrs = run_all_detectors([], G=None)
        assert corrs == []

    def test_multiple_types_detected(self):
        """Verify that multiple detectors fire on a realistic entity set."""
        # Avatar reuse
        a1 = mk_avatar(url="https://cdn.x/img.png", source="discord_enrich")
        a2 = mk_avatar(url="https://cdn.x/img.png", source="gravatar")
        # Username variant
        u1 = mk_username("bob",  platform="github",  source="src_a")
        u2 = mk_username("bob_", platform="twitter", source="src_b")
        # Name-email link
        n = mk_name("Bob")
        e = mk_email("bob_dev@gmail.com")
        # Location consistency
        l1 = mk_location("Berlin", source="a")
        l2 = mk_location("Berlin", source="b")

        entities = [a1, a2, u1, u2, n, e, l1, l2]
        corrs = run_all_detectors(entities, G=None)
        types = {c.correlation_type for c in corrs}
        assert "avatar_reuse"         in types
        assert "username_variant"     in types
        assert "name_email_link"      in types
        assert "location_consistency" in types
