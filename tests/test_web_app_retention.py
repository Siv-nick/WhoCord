"""
tests/test_web_app_retention.py
-------------------------------
Tests for retention and deletion (Phase 2, item 2.4).
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from web_services.jobs import JobRegistry, secure_delete
from web_services.retention import RetentionManager


@pytest.fixture
def registry(tmp_path):
    reg = JobRegistry(cache_dir=str(tmp_path))
    # The disk scan recovers jobs from reports already on disk. This
    # test creates its jobs explicitly; the scan would only find the
    # artifacts the test itself wrote, treating them as prior history
    # and doubling every job count assertion.
    reg._scanned = True
    return reg


@pytest.fixture
def stub_config():
    """Config-shaped mock with a mutable retention_days."""
    cfg = MagicMock()
    cfg.retention_days = 0
    return cfg


def _make_job(registry, tmp_path, job_id, target, age_days, case_id=""):
    """Create a job with a report, intel, and manifest file."""
    report = tmp_path / f"report_{target}_20260101_120000.html"
    report.write_text("<html></html>")
    intel = tmp_path / f"intel_{target}_20260101_120000.json"
    intel.write_text("{}")
    manifest = tmp_path / f"manifest_{target}_20260101_120000.json"
    manifest.write_text("{}")

    ev = threading.Event()
    registry.create(job_id=job_id, target=target, mode="manual",
                    cancel_event=ev, case_id=case_id)
    registry.record_report(job_id, str(report))
    registry.record_intel(job_id, str(intel))
    registry.record_manifest(job_id, str(manifest))
    registry.mark_status(job_id, "done")

    from datetime import datetime, timezone, timedelta
    old = datetime.now(timezone.utc) - timedelta(days=age_days)
    registry._jobs[job_id]["started_at"] = old.isoformat()

    return report, intel, manifest


# ===========================================================================
# secure_delete
# ===========================================================================

class TestSecureDelete:
    def test_removes_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("sensitive")
        assert secure_delete(str(f)) is True
        assert not f.exists()

    def test_missing_file_returns_false(self, tmp_path):
        assert secure_delete(str(tmp_path / "nope.txt")) is False

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert secure_delete(str(f)) is True
        assert not f.exists()


# ===========================================================================
# delete_job
# ===========================================================================

class TestDeleteJob:
    def test_removes_files_and_record(self, registry, tmp_path):
        report, intel, manifest = _make_job(
            registry, tmp_path, "j1", "alice", age_days=1,
        )
        ok, files, err = registry.delete_job("j1")
        assert ok
        assert err == ""
        assert len(files) == 3
        assert not report.exists()
        assert not intel.exists()
        assert not manifest.exists()
        assert registry.get("j1") is None

    def test_running_job_refused(self, registry, tmp_path):
        report, _, _ = _make_job(
            registry, tmp_path, "j1", "alice", age_days=0,
        )
        registry.mark_status("j1", "running")
        ok, files, err = registry.delete_job("j1")
        assert not ok
        assert "running" in err
        assert report.exists()
        assert registry.get("j1") is not None

    def test_missing_job_refused(self, registry):
        ok, files, err = registry.delete_job("nope")
        assert not ok
        assert "not found" in err

    def test_handles_missing_files_gracefully(self, registry, tmp_path):
        _make_job(registry, tmp_path, "j1", "alice", age_days=1)
        (tmp_path / "report_alice_20260101_120000.html").unlink()
        ok, files, err = registry.delete_job("j1")
        assert ok
        assert len(files) == 2
        assert registry.get("j1") is None


# ===========================================================================
# list_jobs_older_than
# ===========================================================================

class TestListOlderThan:
    def test_selects_old_jobs(self, registry, tmp_path):
        _make_job(registry, tmp_path, "old", "alice", age_days=30)
        _make_job(registry, tmp_path, "new", "bob", age_days=1)
        jobs = registry.list_jobs_older_than(7)
        assert len(jobs) == 1
        assert jobs[0]["id"] == "old"

    def test_excludes_running_jobs(self, registry, tmp_path):
        _make_job(registry, tmp_path, "old", "alice", age_days=30)
        registry.mark_status("old", "running")
        assert registry.list_jobs_older_than(7) == []

    def test_zero_days_returns_empty(self, registry, tmp_path):
        _make_job(registry, tmp_path, "old", "alice", age_days=30)
        assert registry.list_jobs_older_than(0) == []

    def test_negative_days_returns_empty(self, registry, tmp_path):
        _make_job(registry, tmp_path, "old", "alice", age_days=30)
        assert registry.list_jobs_older_than(-1) == []

    def test_no_candidates(self, registry, tmp_path):
        _make_job(registry, tmp_path, "new", "bob", age_days=1)
        assert registry.list_jobs_older_than(7) == []


# ===========================================================================
# RetentionManager
# ===========================================================================

class TestRetentionManager:
    def test_disabled_when_zero_days(self, registry, tmp_path, stub_config):
        _make_job(registry, tmp_path, "old", "alice", age_days=365)
        mgr = RetentionManager(registry, stub_config)
        result = mgr.run_pass()
        assert result["ran"] is False
        assert result["deleted"] == 0
        assert registry.get("old") is not None

    def test_deletes_old_jobs(self, registry, tmp_path, stub_config):
        _make_job(registry, tmp_path, "old1", "alice", age_days=30)
        _make_job(registry, tmp_path, "old2", "bob",   age_days=20)
        _make_job(registry, tmp_path, "new",  "carol", age_days=1)
        stub_config.retention_days = 7
        mgr = RetentionManager(registry, stub_config)
        result = mgr.run_pass()
        assert result["ran"] is True
        assert result["deleted"] == 2
        assert result["failed"] == 0
        assert registry.get("old1") is None
        assert registry.get("old2") is None
        assert registry.get("new") is not None

    def test_audit_before_delete(self, registry, tmp_path, stub_config, monkeypatch):
        from discord_osint import audit

        captured: list[tuple[str, dict]] = []
        monkeypatch.setattr(
            audit, "write_event",
            lambda ev, **kw: captured.append((ev, kw)),
        )

        _make_job(registry, tmp_path, "old", "alice", age_days=30)
        stub_config.retention_days = 7
        mgr = RetentionManager(registry, stub_config)
        mgr.run_pass()

        deleted_events = [e for e in captured if e[0] == "investigation_deleted"]
        assert len(deleted_events) == 1
        assert deleted_events[0][1]["job_id"] == "old"

    def test_running_jobs_not_deleted(self, registry, tmp_path, stub_config):
        _make_job(registry, tmp_path, "old", "alice", age_days=30)
        registry.mark_status("old", "running")
        stub_config.retention_days = 7
        mgr = RetentionManager(registry, stub_config)
        result = mgr.run_pass()
        assert result["deleted"] == 0
        assert registry.get("old") is not None

    def test_start_once_is_idempotent(self, registry, stub_config):
        mgr = RetentionManager(registry, stub_config)
        mgr.start_once()
        first_thread = mgr._thread
        mgr.start_once()
        assert mgr._thread is first_thread
        mgr.stop()

    def test_stop_signals_thread(self, registry, stub_config):
        mgr = RetentionManager(registry, stub_config)
        mgr.start_once()
        mgr.stop()
        assert mgr._shutdown.is_set()


# ===========================================================================
# HTTP route
# ===========================================================================

class TestDeleteRoute:
    def test_delete_removes_job(
        self, app_client, auth_headers, clean_registry, tmp_path
    ):
        clean_registry._cache_dir = str(tmp_path)
        clean_registry._scanned = True
        _make_job(clean_registry, tmp_path, "j1", "alice", age_days=1)

        r = app_client.delete(
            "/api/investigations/j1", headers=auth_headers,
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["success"] is True
        assert clean_registry.get("j1") is None

    def test_delete_unknown_is_404(self, app_client, auth_headers, clean_registry):
        r = app_client.delete(
            "/api/investigations/nope", headers=auth_headers,
        )
        assert r.status_code == 404

    def test_delete_running_is_409(
        self, app_client, auth_headers, clean_registry, tmp_path
    ):
        clean_registry._cache_dir = str(tmp_path)
        clean_registry._scanned = True
        _make_job(clean_registry, tmp_path, "j1", "alice", age_days=0)
        clean_registry.mark_status("j1", "running")
        r = app_client.delete(
            "/api/investigations/j1", headers=auth_headers,
        )
        assert r.status_code == 409

    def test_delete_requires_auth(self, app_client, clean_registry):
        r = app_client.delete("/api/investigations/j1")
        assert r.status_code == 401


class TestRetentionRunRoute:
    def test_run_endpoint_returns_summary(
        self, app_client, auth_headers, clean_registry, tmp_path
    ):
        clean_registry._cache_dir = str(tmp_path)
        clean_registry._scanned = True
        r = app_client.post(
            "/api/retention/run", headers=auth_headers,
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["ran"] is False
        assert body["reason"] == "retention disabled"

    def test_run_endpoint_requires_auth(self, app_client):
        r = app_client.post("/api/retention/run")
        assert r.status_code == 401


class TestRetentionConfigSurface:
    def test_get_config_reports_retention_days(self, app_client, auth_headers):
        r = app_client.get("/get_config", headers=auth_headers)
        body = r.get_json()
        assert "retention_days" in body
        assert isinstance(body["retention_days"], int)