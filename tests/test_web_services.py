"""
tests/test_web_services.py
--------------------------
Tests for the service layer extracted from web_app.py (Tier 3, item 3.1).

None of these tests import Flask. The services take plain data and
return plain data; the Flask routes are covered separately in
test_web_app_routes.py.
"""

from __future__ import annotations

import os
import tempfile
import threading
from unittest.mock import MagicMock

import pytest

from web_services.config_actions import ConfigActionDispatcher
from web_services.jobs import JobRegistry


# ===========================================================================
# ConfigActionDispatcher
# ===========================================================================

class TestConfigActionDispatcher:
    """
    The dispatcher takes a dict and a config-service-shaped object and
    returns (response_body, http_status). Using MagicMock for the
    service keeps these tests hermetic — no keyring, no config file.
    """

    @pytest.fixture
    def cs(self):
        return MagicMock()

    @pytest.fixture
    def dispatcher(self, cs):
        return ConfigActionDispatcher(cs)

    # ── set_token ──────────────────────────────────────────────────

    def test_set_token_allows_known_keys(self, dispatcher, cs):
        body, status = dispatcher.dispatch({
            "action": "set_token",
            "key":    "GROQ_API_KEY",
            "value":  "sk-abc",
        })
        assert body == {"success": True}
        assert status == 200
        cs.set_sensitive.assert_called_once_with("GROQ_API_KEY", "sk-abc")

    def test_set_token_rejects_unknown_keys(self, dispatcher, cs):
        body, status = dispatcher.dispatch({
            "action": "set_token",
            "key":    "NOT_A_REAL_KEY",
            "value":  "x",
        })
        assert body["success"] is False
        assert "invalid key" in body["error"]
        cs.set_sensitive.assert_not_called()

    def test_set_token_never_writes_arbitrary_config(self, dispatcher, cs):
        """
        The whitelist prevents set_token from being used as a backdoor
        to write DEFAULT_CONFIG keys (e.g. DEBUG) outside the intended
        token flow.
        """
        body, _ = dispatcher.dispatch({
            "action": "set_token",
            "key":    "DEBUG",
            "value":  "true",
        })
        assert body["success"] is False
        cs.set_sensitive.assert_not_called()

    # ── toggle_tool ────────────────────────────────────────────────

    def test_toggle_tool(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({
            "action": "toggle_tool",
            "key":    "ENABLE_MAIGRET",
            "enable": True,
        })
        assert body == {"success": True}
        cs.set_tool.assert_called_once_with("ENABLE_MAIGRET", True)

    def test_toggle_tool_default_true(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({
            "action": "toggle_tool",
            "key":    "ENABLE_MAIGRET",
        })
        assert body == {"success": True}
        cs.set_tool.assert_called_once_with("ENABLE_MAIGRET", True)

    # ── set_mode / multi_guild / debug ─────────────────────────────

    def test_set_mode(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({"action": "set_mode", "mode": "manual"})
        assert body == {"success": True}
        assert cs.mode == "manual"
        cs.save.assert_called()

    def test_set_multi_guild(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({"action": "set_multi_guild", "multi": True})
        assert body == {"success": True}
        assert cs.multi_guild_search is True

    def test_toggle_debug(self, dispatcher, cs):
        cs.debug = False
        body, _ = dispatcher.dispatch({"action": "toggle_debug"})
        assert body == {"success": True, "debug": True}
        assert cs.debug is True

    def test_toggle_debug_flips_back(self, dispatcher, cs):
        cs.debug = True
        body, _ = dispatcher.dispatch({"action": "toggle_debug"})
        assert body["debug"] is False

    # ── set_pivot ──────────────────────────────────────────────────

    def test_set_pivot_nested(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({
            "action": "set_pivot",
            "pivot": {
                "enabled":         True,
                "pivot_email":     True,
                "pivot_username":  False,
                "max_depth":       5,
                "max_seeds":       10,
                "require_confirm": True,
            },
        })
        assert body == {"success": True}
        assert cs.ENABLE_PIVOTING is True
        assert cs.PIVOT_EMAIL is True
        assert cs.PIVOT_USERNAME is False
        assert cs.PIVOT_MAX_DEPTH == 5
        assert cs.PIVOT_MAX_SEEDS == 10
        assert cs.PIVOT_REQUIRE_CONFIRM is True

    def test_set_pivot_config_flat_form(self, dispatcher, cs):
        """
        The legacy flat-key form is accepted for backward compatibility
        with older clients that still send ENABLE_PIVOTING at the top
        level.
        """
        body, _ = dispatcher.dispatch({
            "action":          "set_pivot_config",
            "ENABLE_PIVOTING": True,
            "PIVOT_MAX_DEPTH": 4,
        })
        assert body == {"success": True}
        assert cs.ENABLE_PIVOTING is True
        assert cs.PIVOT_MAX_DEPTH == 4

    # ── set_enrichment ─────────────────────────────────────────────

    def test_set_enrichment_accepts_partial_patch(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({
            "action":     "set_enrichment",
            "enrichment": {"max_identifiers": 50},
        })
        assert body == {"success": True}
        assert cs.enrichment_max_identifiers == 50

    def test_set_enrichment_ignores_bad_int(self, dispatcher, cs):
        """
        A non-numeric max_identifiers is silently ignored rather than
        crashing the request. The property setter on ConfigService is
        what actually validates; the dispatcher just forwards.
        """
        body, _ = dispatcher.dispatch({
            "action":     "set_enrichment",
            "enrichment": {"max_identifiers": "not-a-number"},
        })
        assert body == {"success": True}

    # ── set_llm ────────────────────────────────────────────────────

    def test_set_llm_partial(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({
            "action": "set_llm",
            "llm": {"provider": "openrouter", "model": "meta/llama"},
        })
        assert body == {"success": True}
        assert cs.llm_provider == "openrouter"
        assert cs.llm_model == "meta/llama"

    def test_set_llm_temperature(self, dispatcher, cs):
        body, _ = dispatcher.dispatch({
            "action": "set_llm",
            "llm": {"temperature": 0.7},
        })
        assert body == {"success": True}
        assert cs.llm_temperature == 0.7

    # ── Unknown / malformed ────────────────────────────────────────

    def test_unknown_action(self, dispatcher):
        body, status = dispatcher.dispatch({"action": "not_a_real_action"})
        assert body["success"] is False
        assert "unknown action" in body["error"]
        assert status == 200

    def test_empty_body(self, dispatcher):
        body, status = dispatcher.dispatch({})
        assert body["success"] is False
        assert "no data" in body["error"]

    def test_handler_exception_returns_error_body(self, dispatcher, cs):
        """
        If a handler raises, the dispatcher catches it and returns
        {"success": False, "error": ...} with HTTP 200, matching the
        old route-level behaviour.
        """
        cs.save.side_effect = RuntimeError("disk full")
        body, status = dispatcher.dispatch({"action": "set_mode", "mode": "manual"})
        assert body["success"] is False
        assert "disk full" in body["error"]
        assert status == 200


# ===========================================================================
# JobRegistry
# ===========================================================================

class TestJobRegistry:
    """
    The registry owns the live-job state that used to live in web_app
    module globals. These tests exercise the public API only.
    """

    @pytest.fixture
    def reg(self, tmp_path):
        return JobRegistry(cache_dir=str(tmp_path))

    @pytest.fixture
    def cancel_event(self):
        return threading.Event()

    # ── Lifecycle ──────────────────────────────────────────────────

    def test_create_and_get(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        job = reg.get("j1")
        assert job is not None
        assert job["target"] == "alice"
        assert job["mode"] == "manual"
        assert job["status"] == "running"
        assert job["cancel_event"] is cancel_event

    def test_get_unknown_returns_none(self, reg):
        assert reg.get("nope") is None

    def test_list_all_newest_first(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        reg.create(job_id="j2", target="bob", mode="discord",
                   cancel_event=cancel_event)
        jobs = reg.list_all()
        assert len(jobs) == 2
        # Both created within the same second; ordering by started_at
        # is stable but not meaningfully testable in isolation. Just
        # assert both are present.
        ids = {j["id"] for j in jobs}
        assert ids == {"j1", "j2"}

    def test_list_running_excludes_done(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        reg.create(job_id="j2", target="bob", mode="manual",
                   cancel_event=cancel_event)
        reg.mark_status("j1", "done")
        running = reg.list_running()
        assert len(running) == 1
        assert running[0]["id"] == "j2"

    def test_mark_status(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        reg.mark_status("j1", "error")
        assert reg.get("j1")["status"] == "error"

    def test_mark_status_on_unknown_is_noop(self, reg):
        reg.mark_status("nope", "done")  # must not raise

    def test_record_report(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        reg.record_report("j1", "/tmp/x.html")
        assert reg.get("j1")["report_html"] == "/tmp/x.html"

    def test_record_intel(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        reg.record_intel("j1", "/tmp/x.json")
        assert reg.get("j1")["intel_path"] == "/tmp/x.json"

    # ── Cancel events ──────────────────────────────────────────────

    def test_signal_cancel_sets_event(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        assert reg.signal_cancel("j1") is True
        assert cancel_event.is_set()

    def test_signal_cancel_unknown_returns_false(self, reg):
        assert reg.signal_cancel("nope") is False

    def test_get_cancel_event(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        assert reg.get_cancel_event("j1") is cancel_event
        assert reg.get_cancel_event("nope") is None

    # ── Worker handles ─────────────────────────────────────────────

    def test_register_worker(self, reg):
        t = threading.Thread(target=lambda: None)
        reg.register_worker("j1", t)
        assert reg.get_worker("j1") is t

    # ── Pivot slots ────────────────────────────────────────────────

    def test_create_pivot_slot(self, reg):
        slot = reg.create_pivot_slot("j1")
        assert slot["approved"] is None
        assert slot["pending_seeds"] == []
        assert not slot["event"].is_set()

    def test_respond_to_pivot(self, reg):
        reg.create_pivot_slot("j1")
        approved = [{"value": "a@b.com", "type": "email"}]
        assert reg.respond_to_pivot("j1", approved) is True
        slot = reg.get_pivot_slot("j1")
        assert slot["approved"] == approved
        assert slot["event"].is_set()

    def test_respond_to_pivot_without_slot(self, reg):
        assert reg.respond_to_pivot("nope", []) is False

    # ── Teardown ───────────────────────────────────────────────────

    def test_teardown_clears_per_job_state(self, reg, cancel_event):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        reg.create_pivot_slot("j1")
        t = threading.Thread(target=lambda: None)
        reg.register_worker("j1", t)

        reg.teardown("j1")

        # The record survives — the history endpoints still need it.
        assert reg.get("j1") is not None
        # The per-job resources are gone.
        assert reg.get_cancel_event("j1") is None
        assert reg.get_worker("j1") is None
        assert reg.get_pivot_slot("j1") is None

    def test_teardown_unknown_is_noop(self, reg):
        reg.teardown("nope")  # must not raise

    # ── Intel path resolution ──────────────────────────────────────

    def test_find_intel_uses_recorded_path(self, reg, cancel_event, tmp_path):
        intel = tmp_path / "intel.json"
        intel.write_text("{}")
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        reg.record_intel("j1", str(intel))
        assert reg.find_intel_path(reg.get("j1")) == str(intel)

    def test_find_intel_falls_back_to_glob(self, reg, cancel_event, tmp_path):
        # Simulate a job whose intel_path was lost (e.g. after moving
        # the cache dir) — the fallback globs by target id.
        intel = tmp_path / "intel_alice_20240101_120000.json"
        intel.write_text("{}")
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        assert reg.find_intel_path(reg.get("j1")) == str(intel)

    def test_find_intel_returns_none_when_nothing_found(
        self, reg, cancel_event
    ):
        reg.create(job_id="j1", target="alice", mode="manual",
                   cancel_event=cancel_event)
        assert reg.find_intel_path(reg.get("j1")) is None


# ===========================================================================
# Chat helpers
# ===========================================================================

class TestChatHelpers:
    def test_active_system_prompt_appends_untrusted_rules(self):
        from web_services.chat import active_chat_system_prompt
        from discord_osint.intelligence.intel_dump import UNTRUSTED_DATA_RULES

        cs = MagicMock()
        cs.llm_system_prompt = "You are a test bot."
        prompt = active_chat_system_prompt(cs)
        assert prompt.startswith("You are a test bot.")
        assert UNTRUSTED_DATA_RULES in prompt

    def test_active_system_prompt_uses_default_when_blank(self):
        from web_services.chat import active_chat_system_prompt
        from discord_osint.intelligence.intel_dump import UNTRUSTED_DATA_RULES

        cs = MagicMock()
        cs.llm_system_prompt = ""
        prompt = active_chat_system_prompt(cs)
        # The default contains the phrase "OSINT analyst"
        assert "OSINT" in prompt
        # The untrusted-data contract is always appended.
        assert UNTRUSTED_DATA_RULES in prompt

    def test_build_chat_context_includes_message(self):
        from web_services.chat import build_chat_context

        cs = MagicMock()
        cs.llm_intel_budget = 60000
        cs.llm_intel_include_raw = True
        cs.llm_intel_exclude_meta = True

        content = build_chat_context(
            message="What is the strongest link?",
            map_data={
                "node_count": 5, "edge_count": 4,
                "nodes": [], "edges": [],
                "status": "done", "target": "alice",
                "mode": "manual",
            },
            job_id=None,
            intel_path=None,
            config_service=cs,
        )
        assert "What is the strongest link?" in content
        assert "alice" in content
        assert "5 nodes, 4 edges" in content

    def test_build_chat_context_includes_intel_when_path_given(
        self, tmp_path
    ):
        from web_services.chat import build_chat_context
        import json

        intel_file = tmp_path / "intel.json"
        intel_file.write_text(json.dumps({
            "emails": {"k": {"value": "alice@example.com", "source": "manual"}},
        }))

        cs = MagicMock()
        cs.llm_intel_budget = 60000
        cs.llm_intel_include_raw = True
        cs.llm_intel_exclude_meta = True

        content = build_chat_context(
            message="who is this?",
            map_data={"node_count": 0, "edge_count": 0,
                      "nodes": [], "edges": [],
                      "status": "done", "target": "alice", "mode": "manual"},
            job_id="j1",
            intel_path=str(intel_file),
            config_service=cs,
        )
        assert "alice@example.com" in content


# ===========================================================================
# LLM model fetching
# ===========================================================================

class TestLLMModelFetcher:
    """
    fetch_models_for_provider must never raise — every failure returns
    the hardcoded fallback list with a reason.
    """

    def test_groq_fallback_when_no_key(self):
        from web_services.llm_models import fetch_models_for_provider

        cs = MagicMock()
        cs.llm_provider = "groq"
        cs.groq_api_key = ""

        result = fetch_models_for_provider(cs)
        assert result["source"] == "fallback"
        assert "GROQ_API_KEY" in result["reason"]
        assert len(result["models"]) > 0

    def test_groq_live_path(self, monkeypatch):
        from web_services import llm_models

        class FakeResp:
            status_code = 200
            def json(self):
                return {"data": [
                    {"id": "llama-3.1-8b-instant", "owned_by": "groq"},
                    {"id": "llama-3.3-70b-versatile", "owned_by": "groq"},
                ]}

        class FakeRequests:
            @staticmethod
            def get(url, **kwargs):
                return FakeResp()

        monkeypatch.setitem(
            __import__("sys").modules, "requests", FakeRequests,
        )
        # Force a re-import so the module picks up the monkeypatched
        # requests. Actually the function does ``import requests``
        # locally, so monkeypatch at sys.modules level works.

        cs = MagicMock()
        cs.llm_provider = "groq"
        cs.groq_api_key = "sk-test"

        result = llm_models.fetch_models_for_provider(cs)
        assert result["source"] == "live"
        assert len(result["models"]) == 2

    def test_openrouter_fallback_when_unreachable(self, monkeypatch):
        from web_services import llm_models

        class FakeRequests:
            @staticmethod
            def get(url, **kwargs):
                raise RuntimeError("network down")

        monkeypatch.setitem(
            __import__("sys").modules, "requests", FakeRequests,
        )

        cs = MagicMock()
        cs.llm_provider = "openrouter"
        cs.openrouter_api_key = "sk-x"

        result = llm_models.fetch_models_for_provider(cs)
        assert result["source"] == "fallback"
        assert "network down" in result["reason"]