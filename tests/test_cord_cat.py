"""
tests/test_cord_cat.py
----------------------
Tests for the CordCat (cord.cat) Discord enrichment client.

Every test uses a mocked ``http_session`` so nothing hits the real
API. The client's cache and rate limiter are cleared before and after
each test to keep them independent.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from discord_osint import cord_cat


@pytest.fixture(autouse=True)
def _clean_state():
    cord_cat.clear_cache()
    cord_cat._reset_rate_limit()
    yield
    cord_cat.clear_cache()
    cord_cat._reset_rate_limit()


def _fake_response(status: int, body=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    if body is None:
        r.text = ""
        r.json.side_effect = ValueError("no json")
    elif isinstance(body, (dict, list)):
        r.text = json.dumps(body)
        r.json.return_value = body
    else:
        r.text = str(body)
        r.json.side_effect = ValueError("not json")
    return r


# ===========================================================================
# Guard rails
# ===========================================================================

class TestGuards:
    def test_empty_id_rejected(self):
        r = cord_cat.lookup("", api_key="cc_x")
        assert r.ok is False
        assert "empty" in r.error

    def test_no_api_key_rejected(self):
        r = cord_cat.lookup("123", api_key="")
        assert r.ok is False
        assert "API key" in r.error

    def test_whitespace_id_rejected(self):
        r = cord_cat.lookup("   ", api_key="cc_x")
        assert r.ok is False


# ===========================================================================
# HTTP responses
# ===========================================================================

class TestResponses:
    def test_200_parses_all_sections(self, monkeypatch):
        body = {
            "userInfo": {
                "username": "alice",
                "display_name": "Alice",
                "created_at": "2015-01-01T00:00:00Z",
                "badges": ["early_supporter"],
            },
            "breach": {
                "count": 3,
                "datasets": ["combolist-2020", "deezer-2022"],
                "exposed_fields": ["email", "password_hash"],
                "geo": {"country": "DE"},
                "asn": {"number": "3320"},
            },
            "fivem": {
                "records": [
                    {"license": "abc123", "steam": "7656119", "name": "Alice"},
                ],
            },
            "statements": [
                {"facts": "Spam", "scope": "EU", "grounds": "DSA Art. 14"},
            ],
            "score": {"value": 45, "reasons": ["Breach exposure"]},
        }
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=_fake_response(200, body))),
        )

        r = cord_cat.lookup("123", api_key="cc_x")
        assert r.ok
        assert r.user_info["username"] == "alice"
        assert r.has_breach
        assert r.has_fivem
        assert r.has_statements
        assert r.score["value"] == 45

    def test_200_with_snake_case_keys(self, monkeypatch):
        """cord.cat uses camelCase in one doc and snake_case in another."""
        body = {
            "user_info": {"username": "bob"},
            "breach":    {"count": 1, "datasets": ["x"]},
            "five_m":    {"records": [{"name": "bob"}]},
            "dsa_statements": [{"facts": "test"}],
            "risk":      {"value": 10},
        }
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=_fake_response(200, body))),
        )
        r = cord_cat.lookup("456", api_key="cc_x")
        assert r.ok
        assert r.user_info["username"] == "bob"
        assert r.has_breach
        assert r.has_fivem
        assert r.has_statements

    def test_404_is_ok_with_empty_sections(self, monkeypatch):
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=_fake_response(404))),
        )
        r = cord_cat.lookup("999", api_key="cc_x")
        assert r.ok is True
        assert r.user_info == {}
        assert r.has_breach is False

    def test_401_is_auth_error(self, monkeypatch):
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=_fake_response(401))),
        )
        r = cord_cat.lookup("123", api_key="cc_bad")
        assert r.ok is False
        assert "401" in r.error

    def test_429_is_rate_limit(self, monkeypatch):
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(
                return_value=_fake_response(429, headers={"Retry-After": "60"}),
            )),
        )
        r = cord_cat.lookup("123", api_key="cc_x")
        assert r.ok is False
        assert "rate" in r.error.lower()

    def test_500_is_error(self, monkeypatch):
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=_fake_response(500, "boom"))),
        )
        r = cord_cat.lookup("123", api_key="cc_x")
        assert r.ok is False
        assert "500" in r.error

    def test_network_exception_returns_error(self, monkeypatch):
        def boom(*a, **kw):
            raise ConnectionError("nope")
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=boom),
        )
        r = cord_cat.lookup("123", api_key="cc_x")
        assert r.ok is False
        assert "network" in r.error.lower()

    def test_invalid_json_body(self, monkeypatch):
        bad = MagicMock()
        bad.status_code = 200
        bad.headers = {}
        bad.text = "not json"
        bad.json.side_effect = ValueError("bad")
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=bad)),
        )
        r = cord_cat.lookup("123", api_key="cc_x")
        assert r.ok is False
        assert "JSON" in r.error

    def test_non_object_root(self, monkeypatch):
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=_fake_response(200, [1, 2, 3]))),
        )
        r = cord_cat.lookup("123", api_key="cc_x")
        assert r.ok is False
        assert "expected object" in r.error


# ===========================================================================
# Cache
# ===========================================================================

class TestCache:
    def test_second_lookup_uses_cache(self, monkeypatch):
        calls = []
        def counting_get(*a, **kw):
            calls.append(1)
            return _fake_response(200, {"userInfo": {"username": "a"}})
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=counting_get),
        )

        cord_cat.lookup("123", api_key="cc_x")
        cord_cat.lookup("123", api_key="cc_x")
        assert len(calls) == 1

    def test_different_ids_do_not_share_cache(self, monkeypatch):
        calls = []
        def counting_get(*a, **kw):
            calls.append(1)
            return _fake_response(200, {"userInfo": {"username": "x"}})
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=counting_get),
        )
        cord_cat.lookup("111", api_key="cc_x")
        cord_cat.lookup("222", api_key="cc_x")
        assert len(calls) == 2

    def test_cache_expiry_triggers_refetch(self, monkeypatch):
        calls = []
        def counting_get(*a, **kw):
            calls.append(1)
            return _fake_response(200, {"userInfo": {"username": "a"}})
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=counting_get),
        )
        monkeypatch.setattr(cord_cat, "_CACHE_TTL_SECONDS", 0)

        cord_cat.lookup("123", api_key="cc_x")
        cord_cat.lookup("123", api_key="cc_x")
        assert len(calls) == 2

    def test_404_cached(self, monkeypatch):
        calls = []
        def counting_get(*a, **kw):
            calls.append(1)
            return _fake_response(404)
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=counting_get),
        )
        cord_cat.lookup("555", api_key="cc_x")
        cord_cat.lookup("555", api_key="cc_x")
        assert len(calls) == 1


# ===========================================================================
# Finding emission
# ===========================================================================

class TestEmitFindings:
    def _capture(self):
        events = []
        def emit(kind, payload):
            events.append((kind, payload))
        return events, emit

    def test_ok_false_emits_nothing(self):
        events, emit = self._capture()
        r = cord_cat.CordCatResult(discord_id="1", ok=False, error="x")
        cord_cat.emit_findings(r, emit)
        assert events == []

    def test_user_info_emits_user_finding(self):
        events, emit = self._capture()
        r = cord_cat.CordCatResult(
            discord_id="1", ok=True,
            user_info={"username": "alice", "display_name": "Alice"},
        )
        cord_cat.emit_findings(r, emit)
        types = [e[0] for e in events]
        assert "finding" in types
        payloads = [e[1] for e in events if e[0] == "finding"]
        assert any(p["type"] == "cordcat_user" for p in payloads)
        assert any(p.get("username") == "alice" for p in payloads)

    def test_breach_emits_breach_finding(self):
        events, emit = self._capture()
        r = cord_cat.CordCatResult(
            discord_id="1", ok=True,
            breach={"count": 5, "datasets": ["a", "b"]},
        )
        cord_cat.emit_findings(r, emit)
        findings = [e[1] for e in events if e[0] == "finding"]
        breach = [f for f in findings if f["type"] == "cordcat_breach"]
        assert len(breach) == 1
        assert breach[0]["count"] == 5

    def test_empty_breach_emits_nothing(self):
        events, emit = self._capture()
        r = cord_cat.CordCatResult(discord_id="1", ok=True, breach={})
        cord_cat.emit_findings(r, emit)
        findings = [e[1] for e in events if e[0] == "finding"]
        assert not any(f["type"] == "cordcat_breach" for f in findings)

    def test_score_emits_score_finding(self):
        events, emit = self._capture()
        r = cord_cat.CordCatResult(
            discord_id="1", ok=True,
            score={"value": 45, "reasons": ["Breach"]},
        )
        cord_cat.emit_findings(r, emit)
        findings = [e[1] for e in events if e[0] == "finding"]
        assert any(f["type"] == "cordcat_score" and f["value"] == 45 for f in findings)

    def test_dsa_statements_emit_one_per_statement(self):
        events, emit = self._capture()
        r = cord_cat.CordCatResult(
            discord_id="1", ok=True,
            statements=[
                {"facts": "a", "scope": "EU"},
                {"facts": "b", "scope": "DE"},
            ],
        )
        cord_cat.emit_findings(r, emit)
        findings = [e[1] for e in events if e[0] == "finding"]
        stmts = [f for f in findings if f["type"] == "cordcat_dsa_statement"]
        assert len(stmts) == 2

    def test_fivem_emits_fivem_finding(self):
        events, emit = self._capture()
        r = cord_cat.CordCatResult(
            discord_id="1", ok=True,
            fivem={"records": [{"name": "a"}, {"name": "b"}]},
        )
        cord_cat.emit_findings(r, emit)
        findings = [e[1] for e in events if e[0] == "finding"]
        fivem = [f for f in findings if f["type"] == "cordcat_fivem"]
        assert len(fivem) == 1
        assert fivem[0]["count"] == 2


# ===========================================================================
# Rate limiting
# ===========================================================================

class TestRateLimit:
    def test_hourly_cap_raises(self, monkeypatch):
        monkeypatch.setattr(
            cord_cat, "http_session",
            MagicMock(get=MagicMock(return_value=_fake_response(404))),
        )
        # Fill the hourly bucket directly so we do not actually sleep
        # 60 seconds during the test.
        import time as _t
        now = _t.monotonic()
        cord_cat._recent_calls.extend([now] * cord_cat._RATE_LIMIT_PER_HOUR)

        with pytest.raises(cord_cat.CordCatRateLimitError):
            cord_cat.lookup("fresh_id", api_key="cc_x")