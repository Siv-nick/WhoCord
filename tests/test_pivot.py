"""
tests/test_pivot.py
---------------------
Tests for discord_osint/pipeline/pivot.py (Phase 2).

Coverage:
  - PivotConfig construction (from_config + defaults)
  - SeedQueue enqueue / pop / deduplication / circuit-breaker
  - scan_for_new_seeds – extracts emails and usernames from intel dicts
  - merge_results – merges child intel into parent without key collisions
  - build_sub_pipeline – creates correct context and stage list
  - process_pending_seeds – runs sub-pipelines and merges (integration)
  - Pipeline.run() integration with pivot_config + seed_queue
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, call
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Minimal stubs so tests don't need the full discord_osint package
# ---------------------------------------------------------------------------

class _FakeIntelCore:
    """Lightweight stand-in for InvestigationCore."""

    def __init__(self, intel: dict | None = None):
        self.intel: dict = intel or {}

    def add_intel(self, category, key, value, source="test"):
        self.intel.setdefault(category, {})[key] = {"value": value, "source": source}

    def save_state(self):
        return "/tmp/fake_intel.json"


@dataclass
class _FakeCtx:
    """Minimal InvestigationContext substitute."""
    intel_core: Any     = field(default_factory=_FakeIntelCore)
    avatar_urls: set    = field(default_factory=set)
    discovery: list     = field(default_factory=list)
    depth: int          = 0
    seed_type: str      = ""
    seed_value: str     = ""
    username: str       = "testuser"
    mode: str           = "manual"
    config: Any         = None

    def add_avatar(self, url):
        if url:
            self.avatar_urls.add(url)

    def add_discovery(self, site, url):
        existing = {d["url"] for d in self.discovery}
        if url not in existing:
            self.discovery.append({"site": site, "url": url})


# ---------------------------------------------------------------------------
# Import targets
# ---------------------------------------------------------------------------

from discord_osint.pipeline.pivot import (
    PivotConfig,
    SeedQueue,
    scan_for_new_seeds,
    merge_results,
    _make_key_prefix,
    _is_valid_pivot_email,
    _is_valid_pivot_username,
)


# ===========================================================================
# PivotConfig
# ===========================================================================

class TestPivotConfig:
    def test_defaults(self):
        cfg = PivotConfig()
        assert cfg.enabled is False
        assert cfg.pivot_email is True
        assert cfg.pivot_username is True
        assert cfg.max_depth == 3
        assert cfg.max_seeds_per_depth == 5

    def test_from_config_all_present(self):
        mock_config = MagicMock()
        mock_config.ENABLE_PIVOTING       = True
        mock_config.PIVOT_EMAIL           = False
        mock_config.PIVOT_USERNAME        = True
        mock_config.PIVOT_MAX_DEPTH       = 2
        mock_config.PIVOT_MAX_SEEDS       = 10

        cfg = PivotConfig.from_config(mock_config)
        assert cfg.enabled is True
        assert cfg.pivot_email is False
        assert cfg.pivot_username is True
        assert cfg.max_depth == 2
        assert cfg.max_seeds_per_depth == 10

    def test_from_config_missing_attrs_use_defaults(self):
        """Config objects that predate Phase 2 have no pivot attrs."""
        mock_config = MagicMock(spec=[])  # no attributes at all
        cfg = PivotConfig.from_config(mock_config)
        assert cfg.enabled is False
        assert cfg.max_depth == 3

    def test_frozen(self):
        cfg = PivotConfig()
        with pytest.raises((AttributeError, TypeError)):
            cfg.enabled = True   # type: ignore[misc]

    def test_from_config_type_coercion(self):
        """Ensures int() and bool() coercions work."""
        mock_config = MagicMock()
        mock_config.ENABLE_PIVOTING = 1       # truthy int
        mock_config.PIVOT_MAX_DEPTH = "4"     # string
        mock_config.PIVOT_MAX_SEEDS = 7.0     # float
        mock_config.PIVOT_EMAIL     = ""      # falsy
        mock_config.PIVOT_USERNAME  = "yes"   # truthy string
        cfg = PivotConfig.from_config(mock_config)
        assert cfg.enabled is True
        assert cfg.max_depth == 4
        assert cfg.max_seeds_per_depth == 7
        assert cfg.pivot_email is False
        assert cfg.pivot_username is True


# ===========================================================================
# SeedQueue
# ===========================================================================

class TestSeedQueue:
    def test_enqueue_and_is_processed(self):
        q = SeedQueue()
        assert not q.is_processed("alice@example.com")
        q.mark_processed("alice@example.com")
        assert q.is_processed("alice@example.com")

    def test_enqueue_returns_true_for_new_seed(self):
        q = SeedQueue()
        assert q.enqueue("bob@example.com", "email", depth=1) is True

    def test_enqueue_returns_false_for_already_processed(self):
        q = SeedQueue()
        q.mark_processed("bob@example.com")
        assert q.enqueue("bob@example.com", "email", depth=1) is False

    def test_enqueue_returns_false_for_duplicate_pending(self):
        q = SeedQueue()
        q.enqueue("alice", "username", depth=1)
        assert q.enqueue("alice", "username", depth=1) is False

    def test_normalisation_case_insensitive(self):
        q = SeedQueue()
        q.mark_processed("Alice@Example.COM")
        assert q.is_processed("alice@example.com")

    def test_normalisation_strips_whitespace(self):
        q = SeedQueue()
        q.mark_processed("  alice  ")
        assert q.is_processed("alice")

    def test_pop_batch_returns_correct_amount(self):
        q = SeedQueue()
        for i in range(10):
            q.enqueue(f"user{i}", "username", depth=1)
        batch = q.pop_batch(depth=1, limit=5)
        assert len(batch) == 5

    def test_pop_batch_marks_seeds_processed(self):
        q = SeedQueue()
        q.enqueue("alice", "username", depth=1)
        q.pop_batch(depth=1, limit=5)
        assert q.is_processed("alice")

    def test_pop_batch_empties_depth_queue(self):
        q = SeedQueue()
        q.enqueue("alice", "username", depth=2)
        q.pop_batch(depth=2, limit=10)
        assert q.pending_count(depth=2) == 0

    def test_pop_empty_depth_returns_empty_list(self):
        q = SeedQueue()
        assert q.pop_batch(depth=99, limit=5) == []

    def test_pending_count(self):
        q = SeedQueue()
        q.enqueue("a@b.com", "email", depth=1)
        q.enqueue("c@d.com", "email", depth=1)
        assert q.pending_count(depth=1) == 2
        assert q.pending_count(depth=2) == 0

    def test_all_depths(self):
        q = SeedQueue()
        q.enqueue("a", "username", depth=1)
        q.enqueue("b", "username", depth=2)
        assert q.all_depths() == [1, 2]

    def test_processed_count(self):
        q = SeedQueue()
        q.mark_processed("a")
        q.mark_processed("b")
        assert q.processed_count == 2

    def test_enqueue_empty_string_ignored(self):
        q = SeedQueue()
        result = q.enqueue("", "email", depth=1)
        assert result is False
        assert q.pending_count(depth=1) == 0


# ===========================================================================
# Seed validation helpers
# ===========================================================================

class TestValidationHelpers:
    # --- Email ---
    @pytest.mark.parametrize("email", [
        "alice@example.com",
        "user.name+tag@domain.co.uk",
        "x@y.io",
    ])
    def test_valid_emails(self, email):
        assert _is_valid_pivot_email(email)

    @pytest.mark.parametrize("email", [
        "",
        "notanemail",
        "missing_at_sign",
        "a" * 256 + "@b.com",
    ])
    def test_invalid_emails(self, email):
        assert not _is_valid_pivot_email(email)

    # --- Username ---
    @pytest.mark.parametrize("user", [
        "alice",
        "alice_123",
        "the-real-alice",
    ])
    def test_valid_usernames(self, user):
        assert _is_valid_pivot_username(user)

    @pytest.mark.parametrize("user", [
        "",
        "a",                        # too short
        "https://example.com/user", # URL
        "x" * 51,                   # too long
    ])
    def test_invalid_usernames(self, user):
        assert not _is_valid_pivot_username(user)


# ===========================================================================
# scan_for_new_seeds
# ===========================================================================

class TestScanForNewSeeds:
    def _cfg(self, pivot_email=True, pivot_username=True):
        return PivotConfig(enabled=True, pivot_email=pivot_email,
                           pivot_username=pivot_username, max_depth=3,
                           max_seeds_per_depth=5)

    def test_scans_email_from_intel(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "manual": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        n = scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1)
        assert n == 1
        assert q.pending_count(depth=1) == 1

    def test_scans_username_from_social_profiles(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["social_profiles"] = {
            "twitter": {"value": "alice_dev", "source": "naminter"}
        }
        q = SeedQueue()
        n = scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1)
        assert n == 1

    def test_skips_url_values_in_social_profiles(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["social_profiles"] = {
            "github": {"value": "https://github.com/alice", "source": "scrape"}
        }
        q = SeedQueue()
        n = scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1)
        assert n == 0

    def test_skips_bio_keys(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["social_profiles"] = {
            "github/user/bio": {"value": "I love coding", "source": "scrape"}
        }
        q = SeedQueue()
        n = scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1)
        assert n == 0

    def test_skips_already_processed(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e1": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        q.mark_processed("alice@example.com")
        n = scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1)
        assert n == 0

    def test_respects_pivot_email_false(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e1": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        cfg = self._cfg(pivot_email=False)
        n = scan_for_new_seeds(ctx, q, cfg, target_depth=1)
        assert n == 0

    def test_respects_pivot_username_false(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["social_profiles"] = {
            "twitter": {"value": "alice", "source": "naminter"}
        }
        q = SeedQueue()
        cfg = self._cfg(pivot_username=False)
        n = scan_for_new_seeds(ctx, q, cfg, target_depth=1)
        assert n == 0

    def test_disabled_config_returns_zero(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e1": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        cfg = PivotConfig(enabled=False)
        n = scan_for_new_seeds(ctx, q, cfg, target_depth=1)
        assert n == 0

    def test_depth_exceeds_max_returns_zero(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e1": {"value": "alice@example.com", "source": "holehe"}
        }
        q   = SeedQueue()
        cfg = PivotConfig(enabled=True, max_depth=2)
        n   = scan_for_new_seeds(ctx, q, cfg, target_depth=3)
        assert n == 0

    def test_scans_discord_username(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["discord"] = {
            "username": {"value": "alice#1234", "source": "discord_api"}
        }
        q = SeedQueue()
        n = scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1)
        assert n == 1

    def test_deduplicates_across_multiple_scans(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e1": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        cfg = self._cfg()
        scan_for_new_seeds(ctx, q, cfg, target_depth=1)
        n = scan_for_new_seeds(ctx, q, cfg, target_depth=1)
        assert n == 0
        assert q.pending_count(depth=1) == 1


# ===========================================================================
# merge_results
# ===========================================================================

class TestMergeResults:
    def test_email_merged_with_prefix(self):
        parent = _FakeCtx()
        child  = _FakeCtx(
            seed_value="alice@example.com",
            seed_type="email",
            depth=1,
        )
        child.intel_core.intel["emails"] = {
            "found_email": {"value": "bob@example.com", "source": "holehe"}
        }

        merge_results(parent, child)

        prefix = _make_key_prefix("alice@example.com")
        expected_key = f"{prefix}__found_email"
        assert expected_key in parent.intel_core.intel.get("emails", {})

    def test_no_key_collision(self):
        parent = _FakeCtx()
        parent.intel_core.intel["emails"] = {
            "existing_key": {"value": "existing@example.com", "source": "manual"}
        }
        child = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.intel_core.intel["emails"] = {
            "existing_key": {"value": "child_email@example.com", "source": "holehe"}
        }

        merge_results(parent, child)

        # Original key untouched
        assert parent.intel_core.intel["emails"]["existing_key"]["value"] == "existing@example.com"
        # New prefixed key added
        prefix = _make_key_prefix("alice")
        assert f"{prefix}__existing_key" in parent.intel_core.intel["emails"]

    def test_avatar_urls_merged(self):
        parent = _FakeCtx()
        child  = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.avatar_urls.add("https://cdn.example.com/img.png")

        merge_results(parent, child)
        assert "https://cdn.example.com/img.png" in parent.avatar_urls

    def test_discovery_entries_merged(self):
        parent = _FakeCtx()
        child  = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.discovery.append({"site": "github", "url": "https://github.com/alice"})

        merge_results(parent, child)
        assert {"site": "github", "url": "https://github.com/alice"} in parent.discovery

    def test_duplicate_discovery_not_added_twice(self):
        parent = _FakeCtx()
        parent.discovery.append({"site": "github", "url": "https://github.com/alice"})
        child  = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.discovery.append({"site": "github", "url": "https://github.com/alice"})

        merge_results(parent, child)
        assert len(parent.discovery) == 1

    def test_intelligence_report_appended_to_pivot_reports(self):
        parent = _FakeCtx()
        child  = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.intel_core.intel["intelligence_report"] = {
            "entities": [], "correlations": [], "narrative": {}
        }

        merge_results(parent, child)

        pivot_reports = parent.intel_core.intel.get("pivot_reports", [])
        assert len(pivot_reports) == 1
        assert pivot_reports[0]["seed"] == "alice"
        assert pivot_reports[0]["seed_type"] == "username"
        assert pivot_reports[0]["depth"] == 1

    def test_no_intel_report_no_pivot_report_added(self):
        parent = _FakeCtx()
        child  = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        # No intelligence_report in child

        merge_results(parent, child)
        assert "pivot_reports" not in parent.intel_core.intel

    def test_multiple_children_accumulate(self):
        parent  = _FakeCtx()
        child1  = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child2  = _FakeCtx(seed_value="bob", seed_type="username", depth=1)
        child1.intel_core.intel["intelligence_report"] = {"a": 1}
        child2.intel_core.intel["intelligence_report"] = {"b": 2}

        merge_results(parent, child1)
        merge_results(parent, child2)

        assert len(parent.intel_core.intel["pivot_reports"]) == 2

    def test_empty_child_intel_no_crash(self):
        parent = _FakeCtx()
        child  = _FakeCtx(seed_value="empty", seed_type="username", depth=1)
        merge_results(parent, child)   # Should not raise


# ===========================================================================
# _make_key_prefix
# ===========================================================================

class TestMakeKeyPrefix:
    def test_email_at_replaced(self):
        prefix = _make_key_prefix("alice@example.com")
        assert "@" not in prefix
        assert "." not in prefix

    def test_starts_with_pivot(self):
        assert _make_key_prefix("alice").startswith("pivot_")

    def test_special_chars_replaced(self):
        prefix = _make_key_prefix("alice-doe_99")
        # hyphens and underscores replaced with underscores
        assert "-" not in prefix


# ===========================================================================
# Pipeline integration (with mocked stages)
# ===========================================================================

class TestPipelineIntegration:
    """
    Integration tests that exercise Pipeline.run() with real PivotConfig /
    SeedQueue but mocked stages so no network I/O occurs.
    """

    def _make_pipeline(self, intel_to_inject: dict | None = None):
        """
        Build a Pipeline with one fake stage that writes *intel_to_inject*
        into the context, then another that does nothing.
        """
        from discord_osint.pipeline.base import Pipeline, Stage
        from discord_osint.pipeline.context import InvestigationContext

        written = intel_to_inject or {}

        class WriterStage(Stage):
            name = "writer"
            def run(self_inner, ctx, emit=lambda *_: None):
                for category, data in written.items():
                    ctx.intel_core.intel.setdefault(category, {}).update(data)

        class NoopStage(Stage):
            name = "noop"
            def run(self_inner, ctx, emit=lambda *_: None):
                pass

        # Build a minimal config mock
        config = MagicMock()
        config.ENABLE_PIVOTING      = False  # off by default in integration tests
        config.GROQ_API_KEY         = ""
        config.ENABLE_AI_REPORT     = False
        config.OUTPUT_FORMAT        = "html"

        core = _FakeIntelCore()

        ctx = InvestigationContext(
            config=config,
            mode="manual",
            username="testuser",
            target_id=12345,
            intel_core=core,
            depth=0,
        )

        pipeline = Pipeline([WriterStage(), NoopStage()], ctx)
        return pipeline, ctx

    def test_pipeline_run_without_pivot(self):
        """Pipeline.run() without pivot_config should complete normally."""
        pipeline, ctx = self._make_pipeline()
        # Should not raise
        pipeline.run()

    def test_pipeline_scans_after_each_stage_with_pivot_enabled(self):
        """When pivoting is on, seeds found by the WriterStage are enqueued."""
        intel_to_inject = {
            "emails": {
                "new_email": {"value": "bob@example.com", "source": "holehe"}
            }
        }
        pipeline, ctx = self._make_pipeline(intel_to_inject)

        pivot_config = PivotConfig(
            enabled=True,
            pivot_email=True,
            pivot_username=True,
            max_depth=1,           # Only depth-1 pivots allowed
            max_seeds_per_depth=5,
        )
        seed_queue = SeedQueue()
        seed_queue.mark_processed("testuser")

        # Patch process_pending_seeds so we don't actually run sub-pipelines
        with patch("discord_osint.pipeline.pivot.process_pending_seeds") as mock_pp:
            pipeline.run(pivot_config=pivot_config, seed_queue=seed_queue)
            # process_pending_seeds should have been called once (end of stages)
            assert mock_pp.called

        # The email found by WriterStage should have been enqueued
        assert seed_queue.pending_count(depth=1) == 1

    def test_pipeline_does_not_scan_when_pivot_disabled(self):
        """No scanning happens when pivot_config is None."""
        intel_to_inject = {
            "emails": {
                "new_email": {"value": "bob@example.com", "source": "holehe"}
            }
        }
        pipeline, ctx = self._make_pipeline(intel_to_inject)
        seed_queue = SeedQueue()

        pipeline.run(pivot_config=None, seed_queue=None)

        assert seed_queue.pending_count(depth=1) == 0

    def test_circuit_breaker_max_depth(self):
        """
        Seeds at depth > max_depth should never be enqueued even if they
        appear in intel.
        """
        from discord_osint.pipeline.context import InvestigationContext
        from discord_osint.pipeline.base import Pipeline, Stage

        class WriterStage(Stage):
            name = "writer"
            def run(self_inner, ctx, emit=lambda *_: None):
                ctx.intel_core.intel.setdefault("emails", {})["e"] = {
                    "value": "deep@example.com", "source": "holehe"
                }

        config = MagicMock(spec=[])
        core   = _FakeIntelCore()
        ctx    = InvestigationContext(
            config=config, mode="manual", username="root",
            target_id=1, intel_core=core,
            depth=3,        # already AT max_depth
        )
        pipeline = Pipeline([WriterStage()], ctx)

        pivot_config = PivotConfig(enabled=True, max_depth=3)
        seed_queue   = SeedQueue()

        with patch("discord_osint.pipeline.pivot.process_pending_seeds") as mock_pp:
            pipeline.run(pivot_config=pivot_config, seed_queue=seed_queue)

        # depth+1 = 4 > max_depth=3 → nothing enqueued
        assert seed_queue.pending_count(depth=4) == 0

    def test_seed_not_reprocessed_if_already_in_queue(self):
        """A seed queued in stage 1 must not be queued again by stage 2."""
        intel_to_inject = {
            "emails": {
                "e1": {"value": "alice@example.com", "source": "s1"},
                "e2": {"value": "alice@example.com", "source": "s2"},
            }
        }
        pipeline, ctx = self._make_pipeline(intel_to_inject)
        pivot_config  = PivotConfig(enabled=True, max_depth=1)
        seed_queue    = SeedQueue()

        with patch("discord_osint.pipeline.pivot.process_pending_seeds"):
            pipeline.run(pivot_config=pivot_config, seed_queue=seed_queue)

        # Despite two entries with the same email, only 1 should be queued
        assert seed_queue.pending_count(depth=1) == 1
