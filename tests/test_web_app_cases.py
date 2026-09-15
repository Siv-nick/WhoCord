
"""
tests/test_web_app_cases.py
---------------------------
Tests for case grouping (Phase 2, item 2.3).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest


@pytest.fixture
def seeded_registry(clean_registry, tmp_path):
    """
    Populate the registry with two cases and one unassigned job.
    """
    reg = clean_registry
    reg._cache_dir = str(tmp_path)

    for job_id, target, case_id, ts in [
        ("j1", "alice", "case-alpha", "2026-01-01T10:00:00+00:00"),
        ("j2", "bob",   "case-alpha", "2026-01-02T10:00:00+00:00"),
        ("j3", "carol", "case-beta",  "2026-01-03T10:00:00+00:00"),
        ("j4", "dave",  "",           "2026-01-04T10:00:00+00:00"),
    ]:
        ev = threading.Event()
        reg.create(job_id=job_id, target=target, mode="manual",
                   cancel_event=ev, case_id=case_id)
        reg._jobs[job_id]["started_at"] = ts
        reg.mark_status(job_id, "done")

    yield reg


# ===========================================================================
# Registry-level
# ===========================================================================

class TestRegistryCaseGrouping:
    def test_list_all_unfiltered_returns_every_job(self, seeded_registry):
        assert len(seeded_registry.list_all()) == 4

    def test_list_all_filter_by_case(self, seeded_registry):
        jobs = seeded_registry.list_all(case_id="case-alpha")
        assert len(jobs) == 2
        assert {j["id"] for j in jobs} == {"j1", "j2"}

    def test_list_all_filter_empty_case(self, seeded_registry):
        jobs = seeded_registry.list_all(case_id="")
        assert len(jobs) == 1
        assert jobs[0]["id"] == "j4"

    def test_list_all_unknown_case_returns_empty(self, seeded_registry):
        assert seeded_registry.list_all(case_id="does-not-exist") == []

    def test_list_cases_aggregates(self, seeded_registry):
        cases = seeded_registry.list_cases()
        assert len(cases) == 2
        by_id = {c["case_id"]: c for c in cases}
        assert "case-alpha" in by_id
        assert "case-beta" in by_id
        assert by_id["case-alpha"]["job_count"] == 2
        assert by_id["case-beta"]["job_count"] == 1

    def test_list_cases_excludes_unassigned(self, seeded_registry):
        cases = seeded_registry.list_cases()
        case_ids = {c["case_id"] for c in cases}
        assert "" not in case_ids

    def test_list_cases_includes_targets(self, seeded_registry):
        cases = seeded_registry.list_cases()
        alpha = next(c for c in cases if c["case_id"] == "case-alpha")
        assert sorted(alpha["targets"]) == ["alice", "bob"]

    def test_list_cases_ordered_by_last_started(self, seeded_registry):
        cases = seeded_registry.list_cases()
        # case-beta has the newest job; case-alpha's newest is 2026-01-02.
        assert cases[0]["case_id"] == "case-beta"


# ===========================================================================
# HTTP routes
# ===========================================================================

class TestCasesRoutes:
    def test_list_cases(self, app_client, auth_headers, seeded_registry):
        r = app_client.get("/api/cases", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert len(body) == 2

    def test_case_detail(self, app_client, auth_headers, seeded_registry):
        r = app_client.get("/api/cases/case-alpha", headers=auth_headers)
        assert r.status_code == 200
        body = r.get_json()
        # The route was paginated: case metadata moved under "case" and
        # the job list is now accompanied by total/limit/offset.
        assert body["case"]["case_id"] == "case-alpha"
        assert body["case"]["job_count"] == 2
        assert body["total"] == 2
        assert len(body["jobs"]) == 2

    def test_case_detail_unknown_is_404(self, app_client, auth_headers, seeded_registry):
        r = app_client.get("/api/cases/does-not-exist", headers=auth_headers)
        assert r.status_code == 404

    def test_investigations_filter_by_case(
        self, app_client, auth_headers, seeded_registry
    ):
        r = app_client.get(
            "/api/investigations?case_id=case-alpha", headers=auth_headers,
        )
        assert r.status_code == 200
        body = r.get_json()
        jobs = body["jobs"]
        assert body["total"] == 2
        assert len(jobs) == 2
        assert all(j["case_id"] == "case-alpha" for j in jobs)

    def test_investigations_unfiltered_returns_all(
        self, app_client, auth_headers, seeded_registry
    ):
        r = app_client.get("/api/investigations", headers=auth_headers)
        body = r.get_json()
        # This assertion used to read len(r.get_json()) and passed by
        # coincidence once the route started returning an envelope:
        # the dict happened to have four keys. Assert on the job list.
        assert body["total"] == 4
        assert len(body["jobs"]) == 4

    def test_investigations_includes_case_id(
        self, app_client, auth_headers, seeded_registry
    ):
        r = app_client.get("/api/investigations", headers=auth_headers)
        body = r.get_json()
        by_id = {j["id"]: j for j in body["jobs"]}
        assert by_id["j1"]["case_id"] == "case-alpha"
        assert by_id["j4"]["case_id"] == ""


# ===========================================================================
# case_id sanitisation
# ===========================================================================

class TestCaseIdSanitisation:
    def test_slash_is_replaced(self):
        from web_app import _sanitize_case_id
        assert _sanitize_case_id("case/with/slashes") == "case_with_slashes"

    def test_special_chars_replaced(self):
        from web_app import _sanitize_case_id
        assert _sanitize_case_id("a b!c@d") == "a_b_c_d"

    def test_length_capped(self):
        from web_app import _sanitize_case_id
        assert len(_sanitize_case_id("x" * 200)) == 64

    def test_empty_allowed(self):
        from web_app import _sanitize_case_id
        assert _sanitize_case_id("") == ""
        assert _sanitize_case_id("   ") == ""

    def test_dots_and_dashes_kept(self):
        from web_app import _sanitize_case_id
        assert _sanitize_case_id("case-2026.01.01") == "case-2026.01.01"


# ===========================================================================
# Disk scan recovers case_id from manifest
# ===========================================================================

class TestDiskScanCaseRecovery:
    def test_scan_reads_case_id_from_manifest(self, tmp_path):
        # Write a fake report and manifest.
        report = tmp_path / "report_alice_20260101_120000.html"
        report.write_text("<html></html>")
        manifest = tmp_path / "manifest_alice_20260101_120000.json"
        manifest.write_text(json.dumps({
            "version":   "1.0",
            "job_id":    "j1",
            "case_id":   "recovered-case",
            "artifacts": [],
            "signature": "fake",
        }))

        from web_services.jobs import JobRegistry
        reg = JobRegistry(cache_dir=str(tmp_path))
        jobs = reg.list_all()
        assert len(jobs) == 1
        assert jobs[0]["case_id"] == "recovered-case"

    def test_scan_handles_missing_manifest(self, tmp_path):
        report = tmp_path / "report_bob_20260101_120000.html"
        report.write_text("<html></html>")

        from web_services.jobs import JobRegistry
        reg = JobRegistry(cache_dir=str(tmp_path))
        jobs = reg.list_all()
        assert len(jobs) == 1
        assert jobs[0]["case_id"] == ""

    def test_scan_handles_malformed_manifest(self, tmp_path):
        report = tmp_path / "report_carol_20260101_120000.html"
        report.write_text("<html></html>")
        manifest = tmp_path / "manifest_carol_20260101_120000.json"
        manifest.write_text("{not json")

        from web_services.jobs import JobRegistry
        reg = JobRegistry(cache_dir=str(tmp_path))
        jobs = reg.list_all()
        assert len(jobs) == 1
        assert jobs[0]["case_id"] == ""
