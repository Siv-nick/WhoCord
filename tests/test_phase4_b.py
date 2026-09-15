"""
tests/test_phase4_b.py
----------------------
Tests for Phase 4 batch B: crt.sh certificate transparency and Ollama
support.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest

from discord_osint import extras


# ===========================================================================
# crt.sh subdomains
# ===========================================================================

class TestCrtShSubdomains:
    def _fake_resp(self, status=200, body=None, chunks=None):
        r = MagicMock()
        r.status_code = status
        r.headers = {}
        if chunks is not None:
            r.iter_content.return_value = iter(chunks)
        elif body is not None:
            encoded = json.dumps(body).encode("utf-8")
            r.iter_content.return_value = iter([encoded])
        else:
            r.iter_content.return_value = iter([])
        return r

    def test_empty_domain_returns_empty(self):
        assert extras.crt_sh_subdomains("") == []
        assert extras.crt_sh_subdomains("no-dot") == []

    def test_basic_extraction(self, monkeypatch):
        body = [
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "mail.example.com"},
        ]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        result = extras.crt_sh_subdomains("example.com")
        assert result == ["api.example.com", "mail.example.com", "www.example.com"]

    def test_multiline_name_value(self, monkeypatch):
        body = [
            {"name_value": "a.example.com\nb.example.com\nc.example.com"},
        ]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        result = extras.crt_sh_subdomains("example.com")
        assert "a.example.com" in result
        assert "b.example.com" in result
        assert "c.example.com" in result

    def test_wildcards_stripped(self, monkeypatch):
        body = [{"name_value": "*.example.com"}]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        # After stripping "*.", the bare domain equals the query domain,
        # so it is dropped.
        result = extras.crt_sh_subdomains("example.com")
        assert result == []

    def test_wildcard_with_subdomain_kept(self, monkeypatch):
        body = [{"name_value": "*.api.example.com"}]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        result = extras.crt_sh_subdomains("example.com")
        assert result == ["api.example.com"]

    def test_base_domain_dropped(self, monkeypatch):
        body = [{"name_value": "example.com"}]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        assert extras.crt_sh_subdomains("example.com") == []

    def test_unrelated_domain_dropped(self, monkeypatch):
        body = [{"name_value": "foo.other-domain.com"}]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        assert extras.crt_sh_subdomains("example.com") == []

    def test_duplicates_collapsed(self, monkeypatch):
        body = [
            {"name_value": "www.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "WWW.example.com"},
        ]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        result = extras.crt_sh_subdomains("example.com")
        assert result == ["www.example.com"]

    def test_404_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(status=404))),
        )
        assert extras.crt_sh_subdomains("example.com") == []

    def test_network_error_returns_empty(self, monkeypatch):
        def boom(*a, **kw):
            raise ConnectionError("no network")
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=boom),
        )
        assert extras.crt_sh_subdomains("example.com") == []

    def test_502_retried_then_empty(self, monkeypatch):
        calls = [0]
        def counting_get(*a, **kw):
            calls[0] += 1
            return self._fake_resp(status=502)
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=counting_get),
        )
        monkeypatch.setattr(extras.time, "sleep", lambda _: None)
        assert extras.crt_sh_subdomains("example.com") == []
        assert calls[0] == 2

    def test_malformed_json_returns_empty(self, monkeypatch):
        r = MagicMock()
        r.status_code = 200
        r.iter_content.return_value = iter([b"not json {"])
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=r)),
        )
        assert extras.crt_sh_subdomains("example.com") == []

    def test_non_array_response_returns_empty(self, monkeypatch):
        body = {"not": "an array"}
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        assert extras.crt_sh_subdomains("example.com") == []

    def test_url_passed_stripped(self, monkeypatch):
        body = [{"name_value": "www.example.com"}]
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=self._fake_resp(body=body))),
        )
        result = extras.crt_sh_subdomains("https://example.com/some/path")
        assert "www.example.com" in result


# ===========================================================================
# Ollama provider
# ===========================================================================

class TestOllamaProvider:
    def test_llm_endpoint_returns_ollama_url(self):
        from discord_osint.config_service import get_llm_endpoint
        cs = MagicMock()
        cs.LLM_PROVIDER = "ollama"
        base, key, headers = get_llm_endpoint(cs)
        assert base == "http://localhost:11434/v1"
        assert key == "ollama"
        assert headers == {}

    def test_provider_getter_allows_ollama(self):
        from discord_osint.config_service import ConfigService
        cfg = MagicMock()
        cfg.LLM_PROVIDER = "ollama"
        cs = ConfigService(cfg)
        assert cs.llm_provider == "ollama"

    def test_provider_setter_allows_ollama(self):
        from discord_osint.config_service import ConfigService
        from discord_osint.config import Config
        # Use a real Config so the setter writes to a real dict.
        import tempfile, os
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(b"{}")
        tf.close()
        try:
            cfg = Config(config_file=tf.name, require_keyring=False)
            cs = ConfigService(cfg)
            cs.llm_provider = "ollama"
            assert cs.llm_provider == "ollama"
        finally:
            os.unlink(tf.name)

    def test_provider_unknown_falls_back_to_groq(self):
        from discord_osint.config_service import ConfigService
        import tempfile, os
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tf.write(b"{}")
        tf.close()
        try:
            from discord_osint.config import Config
            cfg = Config(config_file=tf.name, require_keyring=False)
            cs = ConfigService(cfg)
            cs.llm_provider = "not-a-provider"
            assert cs.llm_provider == "groq"
        finally:
            os.unlink(tf.name)


class TestOllamaModelFetcher:
    @pytest.fixture(autouse=True)
    def _reset(self):
        from web_services import llm_models
        llm_models.reset_cache()
        yield
        llm_models.reset_cache()

    def _stub_requests(self, monkeypatch, response, calls=None):
        class FakeRequests:
            @staticmethod
            def get(url, **kw):
                if calls is not None:
                    calls.append(url)
                return response
        monkeypatch.setitem(sys.modules, "requests", FakeRequests)

    def test_ollama_live(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self):
                return {"models": [
                    {"name": "llama3.2:latest", "size": 1234},
                    {"name": "codellama:7b",    "size": 5678},
                ]}
        self._stub_requests(monkeypatch, FakeResp())

        from web_services import llm_models
        cs = MagicMock()
        cs.llm_provider = "ollama"

        result = llm_models.fetch_models_for_provider(cs)
        assert result["source"] == "live"
        ids = [m["id"] for m in result["models"]]
        assert "llama3.2:latest" in ids
        assert "codellama:7b" in ids

    def test_ollama_daemon_not_running(self, monkeypatch):
        class FakeRequests:
            @staticmethod
            def get(url, **kw):
                raise ConnectionError("refused")
        monkeypatch.setitem(sys.modules, "requests", FakeRequests)

        from web_services import llm_models
        cs = MagicMock()
        cs.llm_provider = "ollama"

        result = llm_models.fetch_models_for_provider(cs)
        assert result["source"] == "fallback"
        assert result["models"] == []
        assert "ollama serve" in result["reason"].lower() or "not reachable" in result["reason"].lower()

    def test_ollama_cache_key_independent_of_provider_key(self):
        from web_services import llm_models
        cs = MagicMock()
        cs.llm_provider = "ollama"
        key = llm_models._cache_key(cs)
        assert key == ("ollama", "")