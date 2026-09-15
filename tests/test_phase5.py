"""
tests/test_phase5.py
--------------------
Tests for the Phase 5 performance changes.

Covered:
- Shared HTTP session adoption in Apollo/Lusha clients (via mock).
- TTL cache in web_services.llm_models.
- Intel-dump cache in web_services.chat.

Not covered here
----------------
Mid-stage cancellation of external subprocess calls is deferred. The
prototype rewrote ``debug_subprocess`` from ``subprocess.run`` to
``Popen`` + a reader thread, which is a load-bearing function for
every external tool integration. Shipping it without a dedicated
concurrency test harness is a risk the phase does not require. It is
tracked as a follow-up and will ship with its own test file.
"""

from __future__ import annotations

import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# LLM models TTL cache
# ===========================================================================

class TestLlmModelsCache:
    @pytest.fixture(autouse=True)
    def _reset(self):
        from web_services import llm_models
        llm_models.reset_cache()
        yield
        llm_models.reset_cache()

    def _stub_requests(self, monkeypatch, calls):
        class FakeResp:
            status_code = 200
            def json(self):
                return {"data": [{"id": "test-model", "owned_by": "groq"}]}
        class FakeRequests:
            @staticmethod
            def get(url, **kw):
                calls.append(url)
                return FakeResp()
        monkeypatch.setitem(sys.modules, "requests", FakeRequests)

    def _cfg(self, provider="groq", key="k"):
        cs = MagicMock()
        cs.llm_provider = provider
        cs.groq_api_key = key
        cs.openrouter_api_key = ""
        return cs

    def test_first_call_hits_network(self, monkeypatch):
        calls = []
        self._stub_requests(monkeypatch, calls)
        from web_services import llm_models
        llm_models.fetch_models_for_provider(self._cfg())
        assert len(calls) == 1

    def test_second_call_uses_cache(self, monkeypatch):
        calls = []
        self._stub_requests(monkeypatch, calls)
        from web_services import llm_models
        cs = self._cfg()
        llm_models.fetch_models_for_provider(cs)
        llm_models.fetch_models_for_provider(cs)
        assert len(calls) == 1

    def test_key_change_invalidates(self, monkeypatch):
        calls = []
        self._stub_requests(monkeypatch, calls)
        from web_services import llm_models
        llm_models.fetch_models_for_provider(self._cfg(key="k1"))
        llm_models.fetch_models_for_provider(self._cfg(key="k2"))
        assert len(calls) == 2

    def test_provider_change_invalidates(self, monkeypatch):
        calls = []
        self._stub_requests(monkeypatch, calls)
        from web_services import llm_models
        llm_models.fetch_models_for_provider(self._cfg(provider="groq"))
        cs2 = MagicMock()
        cs2.llm_provider = "openrouter"
        cs2.groq_api_key = ""
        cs2.openrouter_api_key = "sk-x"
        llm_models.fetch_models_for_provider(cs2)
        assert len(calls) == 2

    def test_reset_cache_forces_refetch(self, monkeypatch):
        calls = []
        self._stub_requests(monkeypatch, calls)
        from web_services import llm_models
        cs = self._cfg()
        llm_models.fetch_models_for_provider(cs)
        llm_models.reset_cache()
        llm_models.fetch_models_for_provider(cs)
        assert len(calls) == 2


# ===========================================================================
# Intel dump cache
# ===========================================================================

class TestIntelDumpCache:
    @pytest.fixture(autouse=True)
    def _reset(self):
        from web_services import chat
        chat.reset_intel_cache()
        yield
        chat.reset_intel_cache()

    def _config(self):
        cs = MagicMock()
        cs.llm_intel_budget = 60000
        cs.llm_intel_include_raw = True
        cs.llm_intel_exclude_meta = True
        cs.llm_system_prompt = ""
        return cs

    def _write_intel(self, path, payload=None):
        path.write_text(json.dumps(payload or {
            "emails": {"e1": {"value": "a@b.com", "source": "manual"}},
        }))

    def _build(self, chat, intel_path, cs):
        return chat.build_chat_context(
            message="who?",
            map_data={
                "node_count": 0, "edge_count": 0,
                "nodes": [], "edges": [],
                "status": "done", "target": "alice", "mode": "manual",
            },
            job_id="j1",
            intel_path=str(intel_path),
            config_service=cs,
        )

    def test_cache_hit_avoids_reparse(self, tmp_path, monkeypatch):
        from web_services import chat
        intel = tmp_path / "intel.json"
        self._write_intel(intel)

        load_calls = [0]
        orig_load = json.load
        def counting_load(f, *a, **kw):
            load_calls[0] += 1
            return orig_load(f, *a, **kw)
        monkeypatch.setattr(json, "load", counting_load)

        cs = self._config()
        self._build(chat, intel, cs)
        assert load_calls[0] == 1
        self._build(chat, intel, cs)
        assert load_calls[0] == 1  # cached

    def test_mtime_change_invalidates(self, tmp_path, monkeypatch):
        from web_services import chat
        intel = tmp_path / "intel.json"
        self._write_intel(intel)

        load_calls = [0]
        orig_load = json.load
        def counting_load(f, *a, **kw):
            load_calls[0] += 1
            return orig_load(f, *a, **kw)
        monkeypatch.setattr(json, "load", counting_load)

        cs = self._config()
        self._build(chat, intel, cs)
        assert load_calls[0] == 1

        time.sleep(0.02)
        self._write_intel(intel, {"emails": {"e2": {"value": "c@d.com", "source": "manual"}}})
        os.utime(intel, (time.time() + 10, time.time() + 10))

        self._build(chat, intel, cs)
        assert load_calls[0] == 2

    def test_missing_file_returns_empty(self, tmp_path):
        from web_services import chat
        cs = self._config()
        content = self._build(chat, tmp_path / "nope.json", cs)
        assert "INVESTIGATION MAP" in content

    def test_cache_bounded_at_32(self, tmp_path):
        from web_services import chat
        cs = self._config()
        for i in range(40):
            p = tmp_path / f"intel_{i}.json"
            self._write_intel(p)
            self._build(chat, p, cs)
        assert len(chat._intel_cache) <= 32


# ===========================================================================
# Apollo / Lusha use the shared session
# ===========================================================================

class TestEnrichmentSharedSession:
    def test_apollo_enrich_uses_http_session(self, monkeypatch):
        from discord_osint.enrichment import apollo_client

        called = []
        class FakeResp:
            status_code = 200
            text = ""
            def json(self):
                return {"matches": [], "missing_records": 0, "credits_consumed": 0}
        class FakeSession:
            @staticmethod
            def post(*a, **kw):
                called.append(("post", a[0]))
                return FakeResp()
        monkeypatch.setattr(apollo_client, "http_session", FakeSession())

        class FakeIdent:
            kind = "email"
            value = "a@b.com"

        client = apollo_client.ApolloClient("key")
        client.enrich([FakeIdent()])
        assert any(m == "post" for m, _ in called)

    def test_lusha_enrich_uses_http_session(self, monkeypatch):
        from discord_osint.enrichment import lusha_client

        called = []
        class FakeResp:
            status_code = 200
            text = ""
            def json(self):
                return {"contacts": {}, "creditsUsed": 0}
        class FakeSession:
            @staticmethod
            def post(*a, **kw):
                called.append(("post", a[0]))
                return FakeResp()
        monkeypatch.setattr(lusha_client, "http_session", FakeSession())

        class FakeIdent:
            kind = "email"
            value = "a@b.com"

        client = lusha_client.LushaClient("key")
        client.enrich([FakeIdent()])
        assert any(m == "post" for m, _ in called)