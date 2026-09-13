"""Tests for InvestigationContext."""
from discord_osint.pipeline.context import InvestigationContext

def test_context_defaults():
    ctx = InvestigationContext(
        target_id=12345,
        config=None,
        seed_type="manual",
        seed_value="testuser"
    )
    assert ctx.target_id == 12345
    assert ctx.seed_type == "manual"
    assert ctx.seed_value == "testuser"
    assert ctx.intel == {}
    assert ctx.avatar_urls == set()
    assert ctx.discovered_emails == set()
    assert ctx.extra_targets == []

def test_context_can_set_and_read_fields():
    ctx = InvestigationContext(target_id=42, config={}, seed_type="email", seed_value="a@b.com")
    ctx.intel["emails"] = {"a@b.com": {"value": "a@b.com", "source": "manual"}}
    ctx.discovered_emails.add("a@b.com")
    assert "a@b.com" in ctx.discovered_emails
    assert ctx.intel["emails"]["a@b.com"]["value"] == "a@b.com"