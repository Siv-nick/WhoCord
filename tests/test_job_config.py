"""
tests/test_job_config.py
------------------------
Regression tests for the concurrent-jobs fix (Tier 1, item 0.1).

The bug: web_app.py mutated the singleton ConfigService before spawning
a worker thread, so two concurrent /run requests corrupted each other's
mode, target, and flags. The fix moved per-job config into a
contextvars.ContextVar; each worker thread sets its own JobConfig, reads
its own flags, and the outer request thread sees none of it.

Change log
----------
- Initial. Covers JobConfig isolation (copy vs reference), get_flag's
  contextvar read, the CLI fallback to module globals, and the actual
  concurrent-jobs regression (two threads, independent flags).
"""

from __future__ import annotations

import threading

import pytest

from discord_osint import config as config_module
from discord_osint.config import (
    JobConfig,
    get_active_config,
    get_flag,
    reset_active_config,
    set_active_config,
    _active_job_config,
)


@pytest.fixture(autouse=True)
def clear_active_config():
    """
    Each test starts with no active JobConfig and restores whatever was
    there afterwards. Without this, an earlier test that leaked a
    set_active_config() call would contaminate the next one — the
    contextvar is process-global within a thread and pytest runs all
    tests in the same thread by default.
    """
    token = _active_job_config.set(None)
    yield
    _active_job_config.reset(token)


# ---------------------------------------------------------------------------
# JobConfig itself
# ---------------------------------------------------------------------------

class TestJobConfig:
    def test_is_a_copy_not_a_reference(self):
        """Mutating a JobConfig must not affect the dict it was built from."""
        source = {"MODE": "manual", "ENABLE_MAIGRET": True}
        cfg = JobConfig(source)
        cfg.MODE = "discord"
        assert source["MODE"] == "manual"

    def test_missing_key_raises_attribute_error(self):
        cfg = JobConfig({"MODE": "manual"})
        with pytest.raises(AttributeError, match="NOT_A_KEY"):
            _ = cfg.NOT_A_KEY

    def test_get_with_default(self):
        cfg = JobConfig({"MODE": "manual"})
        assert cfg.get("MODE") == "manual"
        assert cfg.get("MISSING") is None
        assert cfg.get("MISSING", "fallback") == "fallback"

    def test_private_attributes_round_trip(self):
        """
        Private attrs like _cancel_event are stored in the same _data dict
        so pipeline code that does getattr(cfg, "_cancel_event", None)
        finds them.
        """
        cfg = JobConfig({})
        sentinel = object()
        cfg._cancel_event = sentinel
        assert cfg._cancel_event is sentinel

    def test_to_dict_is_a_copy(self):
        cfg = JobConfig({"MODE": "manual"})
        d = cfg.to_dict()
        d["MODE"] = "mutated"
        assert cfg.MODE == "manual"


# ---------------------------------------------------------------------------
# get_flag — active config, fallback, override
# ---------------------------------------------------------------------------

class TestGetFlag:
    def test_reads_from_active_job_config(self):
        cfg = JobConfig({"ENABLE_MAIGRET": False, "ENABLE_USER_SCANNER": True})
        token = set_active_config(cfg)
        try:
            assert get_flag("ENABLE_MAIGRET") is False
            assert get_flag("ENABLE_USER_SCANNER") is True
        finally:
            reset_active_config(token)

    def test_falls_back_to_module_global_when_no_active_config(self, monkeypatch):
        monkeypatch.setattr(config_module, "ENABLE_MAIGRET", True)
        # No active config — CLI mode.
        assert config_module.get_flag("ENABLE_MAIGRET") is True

    def test_returns_default_when_neither_set(self, monkeypatch):
        monkeypatch.delattr(config_module, "NONEXISTENT_FLAG", raising=False)
        assert config_module.get_flag("NONEXISTENT_FLAG") is False
        assert config_module.get_flag("NONEXISTENT_FLAG", default=True) is True

    def test_job_config_overrides_global(self, monkeypatch):
        """A value in the active JobConfig wins over the module global."""
        monkeypatch.setattr(config_module, "ENABLE_MAIGRET", True)
        cfg = JobConfig({"ENABLE_MAIGRET": False})
        token = set_active_config(cfg)
        try:
            assert config_module.get_flag("ENABLE_MAIGRET") is False
        finally:
            reset_active_config(token)
        # After reset, the global is back in effect.
        assert config_module.get_flag("ENABLE_MAIGRET") is True

    def test_none_valued_key_falls_through_to_global(self, monkeypatch):
        """
        If a JobConfig is missing a flag entirely (rather than setting it
        to False), get_flag must fall through to the module global, not
        silently treat missing as False.
        """
        monkeypatch.setattr(config_module, "ENABLE_WAYBACK", True)
        cfg = JobConfig({"MODE": "manual"})  # no ENABLE_WAYBACK key
        token = set_active_config(cfg)
        try:
            assert config_module.get_flag("ENABLE_WAYBACK") is True
        finally:
            reset_active_config(token)


# ---------------------------------------------------------------------------
# Thread isolation — the regression test for the concurrent-jobs bug
# ---------------------------------------------------------------------------

class TestThreadIsolation:
    def test_two_threads_see_their_own_flags(self):
        """
        Two worker threads, each with its own JobConfig, must read their
        own values from get_flag. A barrier forces both to have installed
        their config before either reads — so if the isolation is broken
        (shared dict, module-level global, non-contextvar storage), both
        threads read whichever config landed last.
        """
        barrier = threading.Barrier(2)
        results: dict[str, dict] = {}
        errors: list[Exception] = []

        def worker(name: str, mode: str, flag_value: bool) -> None:
            try:
                cfg = JobConfig({
                    "MODE": mode,
                    "MANUAL_USERNAME": name,
                    "ENABLE_MAIGRET": flag_value,
                })
                token = set_active_config(cfg)
                try:
                    barrier.wait(timeout=5)
                    results[name] = {
                        "mode": cfg.MODE,
                        "flag": get_flag("ENABLE_MAIGRET"),
                    }
                finally:
                    reset_active_config(token)
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=worker, args=("alice", "discord", True))
        t2 = threading.Thread(target=worker, args=("bob",   "manual",  False))
        t1.start(); t2.start()
        t1.join(timeout=5); t2.join(timeout=5)

        assert not errors, f"workers raised: {errors}"
        assert results["alice"] == {"mode": "discord", "flag": True}
        assert results["bob"]   == {"mode": "manual",  "flag": False}

    def test_outer_thread_unaffected_by_worker(self):
        """
        A worker thread installing its own JobConfig must not change the
        outer thread's active config.
        """
        outer_cfg = JobConfig({"MODE": "outer"})
        outer_token = set_active_config(outer_cfg)
        try:
            inner_seen: list[str] = []

            def worker() -> None:
                inner = JobConfig({"MODE": "inner"})
                token = set_active_config(inner)
                try:
                    inner_seen.append(get_active_config().MODE)
                finally:
                    reset_active_config(token)

            t = threading.Thread(target=worker)
            t.start(); t.join(timeout=5)

            assert inner_seen == ["inner"]
            assert get_active_config().MODE == "outer"
        finally:
            reset_active_config(outer_token)

    def test_no_active_config_after_fixture(self):
        """The autouse fixture guarantees each test starts clean."""
        assert get_active_config() is None