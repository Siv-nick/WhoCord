"""
tests/test_pivot.py
--------------------
Tests for discord_osint/pipeline/pivot.py.

Coverage focus for this revision
--------------------------------
The SeedQueue bug: ``pop_batch`` used to pop the entire depth bucket but
only return ``all_at_depth[:limit]`` — everything past the limit was
silently discarded. The new behaviour carries the remainder over.

New tests:
- ``SeedQueue.pop_batch`` retains the excess in the pending bucket.
- ``SeedQueue.drain_depth`` atomically removes the whole bucket without
  marking seeds as processed (so the confirm gate can reject them).
- ``process_pending_seeds`` launches *every* seed at a depth, in batches
  of ``max_seeds_per_depth``, instead of dropping the tail.

Preserved tests:
- PivotConfig construction and coercion.
- scan_for_new_seeds email/username extraction.
- merge_results without key collisions.
- Pipeline.run integration with cancel_event.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Minimal stubs
# ---------------------------------------------------------------------------

class _FakeIntelCore:
    def __init__(self, intel: dict | None = None):
        self.intel: dict = intel or {}

    def add_intel(self, category, key, value, source="test"):
        self.intel.setdefault(category, {})[key] = {"value": value, "source": source}

    def save_state(self):
        return "/tmp/fake_intel.json"


@dataclass
class _FakeCtx:
    intel_core:  Any  = field(default_factory=_FakeIntelCore)
    avatar_urls: set  = field(default_factory=set)
    discovery:   list = field(default_factory=list)
    depth:       int  = 0
    seed_type:   str  = ""
    seed_value:  str  = ""
    username:    str  = "testuser"
    mode:        str  = "manual"
    config:      Any  = None

    def add_avatar(self, url):
        if url:
            self.avatar_urls.add(url)

    def add_discovery(self, site, url):
        existing = {d["url"] for d in self.discovery}
        if url not in existing:
            self.discovery.append({"site": site, "url": url})


from discord_osint.pipeline.pivot import (
    PivotConfig,
    SeedQueue,
    scan_for_new_seeds,
    merge_results,
    process_pending_seeds,
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
        assert cfg.max_depth == 3
        assert cfg.max_seeds_per_depth == 5

    def test_from_config_type_coercion(self):
        m = MagicMock()
        m.ENABLE_PIVOTING  = 1
        m.PIVOT_MAX_DEPTH  = "4"
        m.PIVOT_MAX_SEEDS  = 7.0
        m.PIVOT_EMAIL      = ""
        m.PIVOT_USERNAME   = "yes"
        cfg = PivotConfig.from_config(m)
        assert cfg.enabled is True
        assert cfg.max_depth == 4
        assert cfg.max_seeds_per_depth == 7
        assert cfg.pivot_email is False
        assert cfg.pivot_username is True

    def test_frozen(self):
        cfg = PivotConfig()
        with pytest.raises((AttributeError, TypeError)):
            cfg.enabled = True


# ===========================================================================
# SeedQueue — the carry-over bug fix
# ===========================================================================

class TestSeedQueueCarryOver:
    """
    The reported bug: `pop_batch` popped the whole bucket but only
    returned the first `limit` items — everything else was discarded
    with no log line.
    """

    def test_pop_batch_carries_over_excess(self):
        q = SeedQueue()
        for i in range(10):
            q.enqueue(f"user{i}", "username", depth=1)

        first = q.pop_batch(depth=1, limit=3)
        assert len(first) == 3
        # The remaining 7 must still be pending.
        assert q.pending_count(depth=1) == 7

        second = q.pop_batch(depth=1, limit=3)
        assert len(second) == 3
        assert q.pending_count(depth=1) == 4

        third = q.pop_batch(depth=1, limit=10)
        assert len(third) == 4
        assert q.pending_count(depth=1) == 0

    def test_no_seed_is_lost(self):
        q = SeedQueue()
        original = {f"user{i}" for i in range(10)}
        for u in original:
            q.enqueue(u, "username", depth=1)

        collected: set[str] = set()
        while q.pending_count(depth=1) > 0:
            for seed, _ in q.pop_batch(depth=1, limit=2):
                collected.add(seed)

        assert collected == original

    def test_pop_batch_marks_processed(self):
        q = SeedQueue()
        q.enqueue("alice", "username", depth=1)
        q.pop_batch(depth=1, limit=5)
        assert q.is_processed("alice")

    def test_pop_empty_depth_returns_empty(self):
        q = SeedQueue()
        assert q.pop_batch(depth=99, limit=5) == []

    def test_remainder_not_marked_processed(self):
        """Only returned seeds should be marked processed."""
        q = SeedQueue()
        for i in range(5):
            q.enqueue(f"user{i}", "username", depth=1)
        popped = q.pop_batch(depth=1, limit=2)
        popped_seeds = {s for s, _ in popped}
        for i in range(5):
            u = f"user{i}"
            if u in popped_seeds:
                assert q.is_processed(u)
            else:
                assert not q.is_processed(u)

    def test_drain_depth_returns_everything(self):
        q = SeedQueue()
        for i in range(7):
            q.enqueue(f"user{i}", "username", depth=1)
        drained = q.drain_depth(depth=1)
        assert len(drained) == 7
        assert q.pending_count(depth=1) == 0

    def test_drain_depth_does_not_mark_processed(self):
        """The confirm gate needs to be able to reject and then mark."""
        q = SeedQueue()
        q.enqueue("alice", "username", depth=1)
        q.drain_depth(depth=1)
        assert not q.is_processed("alice")

    def test_drain_empty_returns_empty(self):
        q = SeedQueue()
        assert q.drain_depth(depth=99) == []


# ===========================================================================
# Seed validation
# ===========================================================================

class TestValidationHelpers:
    @pytest.mark.parametrize("email", [
        "alice@example.com", "user.name+tag@domain.co.uk", "x@y.io",
    ])
    def test_valid_emails(self, email):
        assert _is_valid_pivot_email(email)

    @pytest.mark.parametrize("email", ["", "notanemail", "a" * 256 + "@b.com"])
    def test_invalid_emails(self, email):
        assert not _is_valid_pivot_email(email)

    @pytest.mark.parametrize("user", ["alice", "alice_123", "the-real-alice"])
    def test_valid_usernames(self, user):
        assert _is_valid_pivot_username(user)

    @pytest.mark.parametrize("user", ["", "a", "https://example.com/user", "x" * 51])
    def test_invalid_usernames(self, user):
        assert not _is_valid_pivot_username(user)


# ===========================================================================
# scan_for_new_seeds
# ===========================================================================

class TestScanForNewSeeds:
    def _cfg(self, **overrides):
        base = dict(enabled=True, pivot_email=True, pivot_username=True,
                    max_depth=3, max_seeds_per_depth=5)
        base.update(overrides)
        return PivotConfig(**base)

    def test_scans_email(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "manual": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        assert scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1) == 1

    def test_scans_username(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["social_profiles"] = {
            "twitter": {"value": "alice_dev", "source": "naminter"}
        }
        q = SeedQueue()
        assert scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1) == 1

    def test_skips_urls(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["social_profiles"] = {
            "github": {"value": "https://github.com/alice", "source": "s"}
        }
        q = SeedQueue()
        assert scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1) == 0

    def test_skips_already_processed(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        q.mark_processed("alice@example.com")
        assert scan_for_new_seeds(ctx, q, self._cfg(), target_depth=1) == 0

    def test_respects_pivot_email_false(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        assert scan_for_new_seeds(ctx, q, self._cfg(pivot_email=False), target_depth=1) == 0

    def test_disabled_config_returns_zero(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        assert scan_for_new_seeds(ctx, q, PivotConfig(enabled=False), target_depth=1) == 0

    def test_depth_exceeds_max_returns_zero(self):
        ctx = _FakeCtx()
        ctx.intel_core.intel["emails"] = {
            "e": {"value": "alice@example.com", "source": "holehe"}
        }
        q = SeedQueue()
        cfg = PivotConfig(enabled=True, max_depth=2)
        assert scan_for_new_seeds(ctx, q, cfg, target_depth=3) == 0


# ===========================================================================
# merge_results
# ===========================================================================

class TestMergeResults:
    def test_email_merged_with_prefix(self):
        parent = _FakeCtx()
        child = _FakeCtx(seed_value="alice@example.com", seed_type="email", depth=1)
        child.intel_core.intel["emails"] = {
            "found_email": {"value": "bob@example.com", "source": "holehe"}
        }
        merge_results(parent, child)
        prefix = _make_key_prefix("alice@example.com")
        assert f"{prefix}__found_email" in parent.intel_core.intel["emails"]

    def test_no_key_collision(self):
        parent = _FakeCtx()
        parent.intel_core.intel["emails"] = {
            "existing": {"value": "existing@x.com", "source": "manual"}
        }
        child = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.intel_core.intel["emails"] = {
            "existing": {"value": "child@x.com", "source": "holehe"}
        }
        merge_results(parent, child)
        assert parent.intel_core.intel["emails"]["existing"]["value"] == "existing@x.com"

    def test_avatar_urls_merged(self):
        parent = _FakeCtx()
        child = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.avatar_urls.add("https://cdn.example.com/i.png")
        merge_results(parent, child)
        assert "https://cdn.example.com/i.png" in parent.avatar_urls

    def test_intelligence_report_appended(self):
        parent = _FakeCtx()
        child = _FakeCtx(seed_value="alice", seed_type="username", depth=1)
        child.intel_core.intel["intelligence_report"] = {"entities": []}
        merge_results(parent, child)
        pr = parent.intel_core.intel.get("pivot_reports", [])
        assert len(pr) == 1
        assert pr[0]["seed"] == "alice"


# ===========================================================================
# process_pending_seeds — launches every seed across batches
# ===========================================================================

class TestProcessPendingSeedsBatching:
    """
    The old process_pending_seeds handed `pop_batch`'s truncated result to
    the loop and the rest of the depth was gone. Now the whole depth is
    drained, confirmed once, then launched in waves — every seed runs.
    """

    def _make_fake_pipeline(self, on_run=None):
        class FakePipeline:
            def __init__(self):
                self.runs = 0

            def run(self, **kwargs):
                self.runs += 1
                if on_run:
                    on_run(kwargs)
        return FakePipeline()

    def test_launches_every_seed_across_batches(self):
        ctx = _FakeCtx()
        q = SeedQueue()
        for i in range(10):
            q.enqueue(f"user{i}", "username", depth=1)

        cfg = PivotConfig(enabled=True, max_depth=3, max_seeds_per_depth=3)

        launched_seeds: list[str] = []

        def _build(seed_value, seed_type, parent_ctx, depth):
            launched_seeds.append(seed_value)
            child_ctx = _FakeCtx(seed_value=seed_value, seed_type=seed_type, depth=depth)
            return child_ctx, self._make_fake_pipeline()

        with patch("discord_osint.pipeline.pivot.build_sub_pipeline", side_effect=_build):
            launched = process_pending_seeds(ctx, q, cfg)

        assert launched == 10
        assert set(launched_seeds) == {f"user{i}" for i in range(10)}

    def test_batch_size_does_not_cap_total(self):
        """max_seeds_per_depth = 2 with 7 seeds → all 7 still run."""
        ctx = _FakeCtx()
        q = SeedQueue()
        for i in range(7):
            q.enqueue(f"user{i}", "username", depth=1)

        cfg = PivotConfig(enabled=True, max_depth=3, max_seeds_per_depth=2)
        launched = []

        def _build(seed_value, seed_type, parent_ctx, depth):
            launched.append(seed_value)
            return (_FakeCtx(seed_value=seed_value, seed_type=seed_type, depth=depth),
                    self._make_fake_pipeline())

        with patch("discord_osint.pipeline.pivot.build_sub_pipeline", side_effect=_build):
            n = process_pending_seeds(ctx, q, cfg)

        assert n == 7
        assert len(launched) == 7

    def test_empty_batch_returns_zero(self):
        ctx = _FakeCtx()
        q = SeedQueue()
        cfg = PivotConfig(enabled=True, max_depth=3, max_seeds_per_depth=5)
        assert process_pending_seeds(ctx, q, cfg) == 0

    def test_disabled_returns_zero(self):
        ctx = _FakeCtx()
        q = SeedQueue()
        q.enqueue("alice", "username", depth=1)
        cfg = PivotConfig(enabled=False)
        assert process_pending_seeds(ctx, q, cfg) == 0

    def test_depth_exceeds_max_returns_zero(self):
        ctx = _FakeCtx(depth=3)
        q = SeedQueue()
        q.enqueue("alice", "username", depth=4)
        cfg = PivotConfig(enabled=True, max_depth=3)
        # next_depth = 4 > 3 → 0
        assert process_pending_seeds(ctx, q, cfg) == 0

    def test_confirmation_rejects_subset(self):
        ctx = _FakeCtx()
        q = SeedQueue()
        for i in range(5):
            q.enqueue(f"user{i}", "username", depth=1)

        cfg = PivotConfig(enabled=True, max_depth=3, max_seeds_per_depth=3)
        launched = []

        def _confirm(seeds, depth, emit):
            # Approve just the first two.
            return seeds[:2]

        def _build(seed_value, seed_type, parent_ctx, depth):
            launched.append(seed_value)
            return (_FakeCtx(seed_value=seed_value, seed_type=seed_type, depth=depth),
                    self._make_fake_pipeline())

        with patch("discord_osint.pipeline.pivot.build_sub_pipeline", side_effect=_build):
            n = process_pending_seeds(ctx, q, cfg, confirm_fn=_confirm)

        assert n == 2
        assert set(launched) == {"user0", "user1"}
        # Rejected seeds marked processed so they can't be re-queued.
        for i in range(2, 5):
            assert q.is_processed(f"user{i}")

    def test_confirmation_returning_empty_skips_depth(self):
        ctx = _FakeCtx()
        q = SeedQueue()
        q.enqueue("alice", "username", depth=1)

        cfg = PivotConfig(enabled=True, max_depth=3, max_seeds_per_depth=3)
        launched = []

        with patch("discord_osint.pipeline.pivot.build_sub_pipeline") as mock_build:
            n = process_pending_seeds(ctx, q, cfg, confirm_fn=lambda s, d, e: [])
            mock_build.assert_not_called()
        assert n == 0
        # Even the rejected seed is marked processed.
        assert q.is_processed("alice")


# ===========================================================================
# Pipeline.run integration — cancel_event
# ===========================================================================

class TestPipelineCancellation:
    def _make_pipeline(self, intel_to_inject=None):
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

        config = MagicMock()
        config.ENABLE_PIVOTING  = False
        config.GROQ_API_KEY     = ""
        config.ENABLE_AI_REPORT = False
        config.OUTPUT_FORMAT    = "html"
        config._cancel_event    = None

        ctx = InvestigationContext(
            config=config,
            mode="manual",
            username="testuser",
            target_id=12345,
            intel_core=_FakeIntelCore(),
            depth=0,
        )
        return Pipeline([WriterStage(), NoopStage()], ctx), ctx

    def test_no_cancel_completes_normally(self):
        pipeline, _ = self._make_pipeline()
        pipeline.run()  # must not raise

    def test_cancel_event_stops_before_first_stage(self):
        from discord_osint.pipeline.base import Pipeline, Stage
        from discord_osint.pipeline.context import InvestigationContext

        ran: list[str] = []

        class SentinelStage(Stage):
            name = "sentinel"
            def run(self_inner, ctx, emit=lambda *_: None):
                ran.append("sentinel")

        config = MagicMock()
        config._cancel_event = None
        ctx = InvestigationContext(
            config=config, mode="manual", username="x",
            target_id=1, intel_core=_FakeIntelCore(),
        )
        pipeline = Pipeline([SentinelStage()], ctx)

        cancel = threading.Event()
        cancel.set()

        events: list[tuple[str, dict]] = []
        pipeline.run(
            emit=lambda t, p: events.append((t, p)),
            cancel_event=cancel,
        )

        assert ran == []
        assert any(t == "abort" for t, _ in events)

    def test_cancel_event_read_from_config_if_not_passed(self):
        """A sub-pipeline inherits cancellation via config._cancel_event."""
        from discord_osint.pipeline.base import Pipeline, Stage
        from discord_osint.pipeline.context import InvestigationContext

        ran: list[str] = []

        class SentinelStage(Stage):
            name = "sentinel"
            def run(self_inner, ctx, emit=lambda *_: None):
                ran.append("sentinel")

        cancel = threading.Event()
        cancel.set()

        config = MagicMock()
        config._cancel_event = cancel

        ctx = InvestigationContext(
            config=config, mode="manual", username="x",
            target_id=2, intel_core=_FakeIntelCore(),
        )
        pipeline = Pipeline([SentinelStage()], ctx)
        pipeline.run()  # no cancel_event kwarg — must be read from config

        assert ran == []

    def test_pipeline_emits_done_even_when_cancelled(self):
        """Partial state is still saved on cancel."""
        from discord_osint.pipeline.base import Pipeline, Stage
        from discord_osint.pipeline.context import InvestigationContext

        class SentinelStage(Stage):
            name = "sentinel"
            def run(self_inner, ctx, emit=lambda *_: None):
                pass

        cancel = threading.Event()
        cancel.set()

        config = MagicMock()
        config._cancel_event = cancel

        ctx = InvestigationContext(
            config=config, mode="manual", username="x",
            target_id=3, intel_core=_FakeIntelCore(),
        )
        events: list[tuple[str, dict]] = []
        Pipeline([SentinelStage()], ctx).run(
            emit=lambda t, p: events.append((t, p)),
        )

        # Even a cancelled run finishes with a done event so the SSE
        # stream can close cleanly.
        assert any(t == "done" for t, _ in events)