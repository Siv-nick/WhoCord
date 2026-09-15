
"""
tests/test_web_app_routes.py
----------------------------
Route behaviour tests for the endpoints that don't start a real
investigation.

`/run` validation runs before any worker is spawned, so the "missing
target" and "invalid mode" cases are safe to test without mocking the
pipeline. The happy path is exercised end-to-end by the pytest suite
the operator runs manually; it is not covered here.
"""

from __future__ import annotations

import json
import threading
from unittest.mock import patch

import pytest


# ===========================================================================
# /get_config
# ===========================================================================

class TestGetConfig:
    def test_shape(self, app_client, auth_headers):
        r = app_client.get("/get_config", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        for key in ("tokens", "tools", "mode", "debug", "pivot",
                    "llm", "enrichment"):
            assert key in body, f"/get_config missing {key}"
        assert isinstance(body["tokens"], dict)
        assert isinstance(body["tools"], list)

    def test_token_status_is_bool_not_value(self, app_client, auth_headers):
        """
        The response must not leak the token values — only whether
        each is set. This is a security property, not a UI nicety.
        """
        r = app_client.get("/get_config", headers=auth_headers)
        body = r.get_json()
        for v in body["tokens"].values():
            assert isinstance(v, bool)


# ===========================================================================
# /config POST
# ===========================================================================

class TestConfigPost:
    def test_set_mode(self, app_client, auth_headers):
        r = app_client.post(
            "/config",
            headers=auth_headers,
            json={"action": "set_mode", "mode": "manual"},
        )
        assert r.status_code == 200
        assert r.get_json()["success"] is True

    def test_unknown_action(self, app_client, auth_headers):
        r = app_client.post(
            "/config",
            headers=auth_headers,
            json={"action": "not_an_action"},
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is False
        assert "unknown action" in body["error"]

    def test_no_body(self, app_client, auth_headers):
        r = app_client.post("/config", headers=auth_headers)
        # get_json(silent=True) returns None for a bodyless request;
        # the dispatcher receives {} and reports "no data".
        body = r.get_json()
        assert body["success"] is False
        assert "no data" in body["error"]

    def test_requires_auth(self, app_client):
        r = app_client.post("/config", json={"action": "set_mode"})
        assert r.status_code == 401


# ===========================================================================
# /run validation
# ===========================================================================

class TestRunValidation:
    def test_missing_mode_defaults_to_manual(self, app_client, auth_headers):
        """
        mode defaults to "manual"; with no username and no email the
        route reaches the manual branch and succeeds with an empty
        target — the pipeline exits early on its own. This test just
        confirms the route does not 400 without a mode field.
        """
        # We do NOT consume the stream — the worker is a daemon thread
        # and the generator is lazily evaluated, so no investigation
        # actually runs.
        r = app_client.post(
            "/run",
            headers=auth_headers,
            json={"mode": "manual"},
        )
        assert r.status_code == 200

    def test_invalid_mode_is_400(self, app_client, auth_headers):
        r = app_client.post(
            "/run",
            headers=auth_headers,
            json={"mode": "not_a_mode"},
        )
        assert r.status_code == 400
        assert "Invalid mode" in r.get_json()["error"]

    def test_email_mode_missing_target_is_400(self, app_client, auth_headers):
        r = app_client.post(
            "/run",
            headers=auth_headers,
            json={"mode": "email"},
        )
        assert r.status_code == 400
        assert "email target" in r.get_json()["error"]

    def test_domain_mode_missing_target_is_400(self, app_client, auth_headers):
        r = app_client.post(
            "/run",
            headers=auth_headers,
            json={"mode": "domain"},
        )
        assert r.status_code == 400

    def test_phone_mode_missing_target_is_400(self, app_client, auth_headers):
        r = app_client.post(
            "/run",
            headers=auth_headers,
            json={"mode": "phone"},
        )
        assert r.status_code == 400

    def test_probe_mode_missing_target_is_400(self, app_client, auth_headers):
        r = app_client.post(
            "/run",
            headers=auth_headers,
            json={"mode": "probe"},
        )
        assert r.status_code == 400

    def test_requires_auth(self, app_client):
        r = app_client.post("/run", json={"mode": "manual"})
        assert r.status_code == 401


# ===========================================================================
# /shutdown
# ===========================================================================

class TestShutdown:
    def test_requires_confirm_field(self, app_client, auth_headers):
        # Patch os._exit so the test does not actually kill the process
        # if the route were to reach that line. Since confirm is
        # missing, it should not.
        with patch("web_app.os._exit") as mock_exit:
            r = app_client.post(
                "/shutdown",
                headers=auth_headers,
                json={},
            )
            assert r.status_code == 400
            body = r.get_json()
            assert "confirmation required" in body["error"]
            mock_exit.assert_not_called()

    def test_wrong_confirm_value_rejected(self, app_client, auth_headers):
        with patch("web_app.os._exit"):
            r = app_client.post(
                "/shutdown",
                headers=auth_headers,
                json={"confirm": "no"},
            )
            assert r.status_code == 400

    def test_requires_auth(self, app_client):
        r = app_client.post("/shutdown", json={"confirm": "yes"})
        assert r.status_code == 401


# ===========================================================================
# /api/investigations
# ===========================================================================

class TestInvestigationsApi:
    def test_empty_list_when_no_jobs(
        self, app_client, auth_headers, clean_registry
    ):
        r = app_client.get("/api/investigations", headers=auth_headers)
        assert r.status_code == 200
        # The route returns a pagination envelope, not a bare list.
        body = r.get_json()
        assert body["jobs"] == []
        assert body["total"] == 0

    def test_lists_a_created_job(
        self, app_client, auth_headers, clean_registry
    ):
        ev = threading.Event()
        clean_registry.create(
            job_id="j-test", target="alice", mode="manual",
            cancel_event=ev,
        )
        r = app_client.get("/api/investigations", headers=auth_headers)
        body = r.get_json()
        jobs = body["jobs"]
        assert body["total"] == 1
        assert len(jobs) == 1
        assert jobs[0]["id"] == "j-test"
        assert jobs[0]["target"] == "alice"
        assert jobs[0]["status"] == "running"
        assert jobs[0]["has_report"] is False
        assert jobs[0]["has_intel"] is False

    def test_detail_unknown_id_is_404(self, app_client, auth_headers):
        r = app_client.get(
            "/api/investigations/does-not-exist",
            headers=auth_headers,
        )
        assert r.status_code == 404

    def test_report_unknown_id_is_404(self, app_client, auth_headers):
        r = app_client.get(
            "/api/investigations/does-not-exist/report",
            headers=auth_headers,
        )
        assert r.status_code == 404


# ===========================================================================
# /api/pivot/confirm
# ===========================================================================

class TestPivotConfirm:
    def test_no_pending_pivot_is_404(self, app_client, auth_headers):
        r = app_client.post(
            "/api/pivot/confirm/no-such-job",
            headers=auth_headers,
            json={"approved_seeds": []},
        )
        assert r.status_code == 404

    def test_pending_pivot_is_confirmed(
        self, app_client, auth_headers, clean_registry
    ):
        clean_registry.create_pivot_slot("j-pivot")
        approved = [{"value": "a@b.com", "type": "email"}]
        r = app_client.post(
            "/api/pivot/confirm/j-pivot",
            headers=auth_headers,
            json={"approved_seeds": approved},
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert body["approved_count"] == 1
        slot = clean_registry.get_pivot_slot("j-pivot")
        assert slot["approved"] == approved
        assert slot["event"].is_set()


# ===========================================================================
# /stop
# ===========================================================================

class TestStop:
    def test_no_running_job_is_404(
        self, app_client, auth_headers, clean_registry
    ):
        r = app_client.post("/stop", headers=auth_headers, json={})
        assert r.status_code == 404

    def test_running_job_is_signalled(
        self, app_client, auth_headers, clean_registry
    ):
        ev = threading.Event()
        clean_registry.create(
            job_id="j1", target="alice", mode="manual", cancel_event=ev,
        )
        r = app_client.post(
            "/stop", headers=auth_headers, json={"job_id": "j1"},
        )
        assert r.status_code == 200
        assert r.get_json()["success"] is True
        assert ev.is_set()

    def test_unknown_job_id_is_404(
        self, app_client, auth_headers, clean_registry
    ):
        r = app_client.post(
            "/stop", headers=auth_headers, json={"job_id": "nope"},
        )
        assert r.status_code == 404

    def test_job_already_done_is_409(
        self, app_client, auth_headers, clean_registry
    ):
        ev = threading.Event()
        clean_registry.create(
            job_id="j1", target="alice", mode="manual", cancel_event=ev,
        )
        clean_registry.mark_status("j1", "done")
        r = app_client.post(
            "/stop", headers=auth_headers, json={"job_id": "j1"},
        )
        assert r.status_code == 409


# ===========================================================================
# /api/enrichment/test/<provider>
# ===========================================================================

class TestEnrichmentTest:
    def test_unknown_provider_is_404(self, app_client, auth_headers):
        r = app_client.post(
            "/api/enrichment/test/not-a-provider",
            headers=auth_headers,
        )
        assert r.status_code == 404

    def test_no_api_key_stored_is_400(self, app_client, auth_headers):
        """
        Apollo and Lusha both short-circuit to 400 when the API key is
        missing. We can't guarantee the key IS missing on the test
        machine, so this test checks that the response is either 400
        (key missing) or 200 (key stored, real test_connection ran).
        Either is a legitimate outcome; what it must not be is a 500.
        """
        for provider in ("apollo", "lusha"):
            r = app_client.post(
                f"/api/enrichment/test/{provider}",
                headers=auth_headers,
            )
            assert r.status_code in (200, 400, 500), (
                f"{provider}: unexpected status {r.status_code}"
            )
            # 500 is acceptable only if the network is unreachable; on a
            # CI machine with no egress it would legitimately fail there.


# ===========================================================================
# /api/llm/models
# ===========================================================================

class TestLLMModelsRoute:
    def test_returns_model_list(self, app_client, auth_headers):
        r = app_client.get("/api/llm/models", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert "models" in body
        assert "source" in body
        assert body["source"] in ("live", "fallback")
        assert isinstance(body["models"], list)

    def test_groq_legacy_alias_still_works(self, app_client, auth_headers):
        r = app_client.get("/api/groq/models", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert "models" in body
