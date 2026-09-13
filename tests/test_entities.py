"""
tests/test_entities.py
------------------------
Unit tests for discord_osint/intelligence/entities.py
"""

import pytest

from discord_osint.intelligence.entities import (
    AvatarEntity,
    BaseEntity,
    EmailEntity,
    LocationEntity,
    NameEntity,
    PlatformProfileEntity,
    UsernameEntity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_email(value="test@example.com", source="manual_input", confidence=0.9):
    return EmailEntity(value=value, source=source, confidence=confidence)


def make_username(value="testuser", platform="github", source="scrape_github"):
    return UsernameEntity(value=value, source=source, platform=platform)


def make_profile(value="https://github.com/testuser", platform="github", source="scrape_github"):
    return PlatformProfileEntity(
        value=value, source=source, platform=platform, url=value
    )


def make_name(value="John Doe", source="discord_bio"):
    return NameEntity(value=value, source=source)


def make_location(value="London, UK", source="location_inference"):
    return LocationEntity(value=value, source=source)


def make_avatar(value="https://cdn.example.com/avatar.png", source="discord_enrich"):
    return AvatarEntity(value=value, source=source, url=value, phash="deadbeef")


# ---------------------------------------------------------------------------
# BaseEntity
# ---------------------------------------------------------------------------

class TestBaseEntity:
    def test_id_auto_generated(self):
        e1 = EmailEntity(value="a@b.com", source="test")
        e2 = EmailEntity(value="a@b.com", source="test")
        assert e1.id != e2.id, "Each entity should have a unique auto-generated ID"

    def test_id_override(self):
        e = EmailEntity(value="a@b.com", source="test", id="fixed123")
        assert e.id == "fixed123"

    def test_hash_equals_by_id(self):
        e = EmailEntity(value="a@b.com", source="test", id="same")
        f = EmailEntity(value="different@b.com", source="test", id="same")
        assert e == f
        assert hash(e) == hash(f)

    def test_different_ids_not_equal(self):
        e = EmailEntity(value="a@b.com", source="test")
        f = EmailEntity(value="a@b.com", source="test")
        assert e != f

    def test_to_dict_base_keys(self):
        e = make_email()
        d = e.to_dict()
        for key in ("id", "type", "value", "source", "confidence"):
            assert key in d, f"to_dict() missing key: {key}"

    def test_default_confidence(self):
        e = EmailEntity(value="a@b.com", source="test")
        assert e.confidence == 0.50


# ---------------------------------------------------------------------------
# EmailEntity
# ---------------------------------------------------------------------------

class TestEmailEntity:
    def test_entity_type(self):
        assert make_email().entity_type == "email"

    def test_local_part(self):
        e = make_email("john.doe@gmail.com")
        assert e.local_part == "john.doe"

    def test_domain(self):
        e = make_email("john.doe@gmail.com")
        assert e.domain == "gmail.com"

    def test_no_at_symbol(self):
        e = EmailEntity(value="notanemail", source="test")
        assert e.local_part == "notanemail"
        assert e.domain == ""

    def test_to_dict_type(self):
        assert make_email().to_dict()["type"] == "email"


# ---------------------------------------------------------------------------
# UsernameEntity
# ---------------------------------------------------------------------------

class TestUsernameEntity:
    def test_entity_type(self):
        assert make_username().entity_type == "username"

    def test_platform_stored(self):
        u = make_username(platform="twitter")
        assert u.platform == "twitter"

    def test_platform_none_by_default(self):
        u = UsernameEntity(value="user", source="test")
        assert u.platform is None

    def test_to_dict_includes_platform(self):
        u = make_username(platform="reddit")
        assert u.to_dict()["platform"] == "reddit"


# ---------------------------------------------------------------------------
# PlatformProfileEntity
# ---------------------------------------------------------------------------

class TestPlatformProfileEntity:
    def test_entity_type(self):
        assert make_profile().entity_type == "platform_profile"

    def test_url_stored(self):
        p = make_profile(value="https://github.com/bob")
        assert p.url == "https://github.com/bob"

    def test_platform_stored(self):
        p = make_profile(platform="linkedin")
        assert p.platform == "linkedin"

    def test_to_dict_includes_url_and_platform(self):
        p = make_profile(platform="github", value="https://github.com/x")
        d = p.to_dict()
        assert d["url"] == "https://github.com/x"
        assert d["platform"] == "github"


# ---------------------------------------------------------------------------
# NameEntity
# ---------------------------------------------------------------------------

class TestNameEntity:
    def test_entity_type(self):
        assert make_name().entity_type == "name"

    def test_value_stored(self):
        n = make_name("Alice Smith")
        assert n.value == "Alice Smith"


# ---------------------------------------------------------------------------
# LocationEntity
# ---------------------------------------------------------------------------

class TestLocationEntity:
    def test_entity_type(self):
        assert make_location().entity_type == "location"

    def test_value_stored(self):
        loc = make_location("Tokyo, Japan")
        assert loc.value == "Tokyo, Japan"


# ---------------------------------------------------------------------------
# AvatarEntity
# ---------------------------------------------------------------------------

class TestAvatarEntity:
    def test_entity_type(self):
        assert make_avatar().entity_type == "avatar"

    def test_url_stored(self):
        a = make_avatar(value="https://cdn.example.com/img.png")
        assert a.url == "https://cdn.example.com/img.png"

    def test_phash_stored(self):
        a = AvatarEntity(value="https://x.com/img.png", source="test", phash="abc123")
        assert a.phash == "abc123"

    def test_phash_none_by_default(self):
        a = AvatarEntity(value="https://x.com/img.png", source="test")
        assert a.phash is None

    def test_to_dict_includes_url_and_phash(self):
        a = make_avatar()
        d = a.to_dict()
        assert "url" in d
        assert "phash" in d


# ---------------------------------------------------------------------------
# Extractor smoke test (not its own file so it can reuse fixtures)
# ---------------------------------------------------------------------------

class TestExtractorSmoke:
    """
    Basic smoke test to verify that extract_entities produces entities from
    a minimal intel dict.  Full extractor tests are in test_extractor.py.
    """

    def test_extracts_email(self):
        from discord_osint.intelligence.extractor import extract_entities

        intel = {
            "emails": {
                "manual_email": {"value": "alice@example.com", "source": "manual_input"}
            }
        }
        entities = extract_entities(intel)
        emails = [e for e in entities if e.entity_type == "email"]
        assert len(emails) == 1
        assert emails[0].value == "alice@example.com"
        assert emails[0].confidence > 0.85   # manual_input → 0.92

    def test_extracts_avatar(self):
        from discord_osint.intelligence.extractor import extract_entities

        intel = {}
        avatar_urls = {"https://cdn.example.com/avatar.png"}
        entities = extract_entities(intel, avatar_urls)
        avatars = [e for e in entities if e.entity_type == "avatar"]
        assert len(avatars) == 1

    def test_deduplicates_same_email(self):
        from discord_osint.intelligence.extractor import extract_entities

        intel = {
            "emails": {
                "k1": {"value": "dup@example.com", "source": "manual_input"},
                "k2": {"value": "DUP@example.com", "source": "discord_bio"},
            }
        }
        entities = extract_entities(intel)
        emails = [e for e in entities if e.entity_type == "email"]
        assert len(emails) == 1
        # Should keep the higher-confidence one (manual_input)
        assert emails[0].confidence > 0.80
