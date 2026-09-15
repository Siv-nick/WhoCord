"""
tests/test_phase4_batch.py
--------------------------
Tests for Phase 4 batch mode and TinEye.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock

import pytest


# ===========================================================================
# BatchRunner
# ===========================================================================

class TestBatchRunner:
    @pytest.fixture
    def registry(self, tmp_path):
        from web_services.jobs import JobRegistry
        reg = JobRegistry(cache_dir=str(tmp_path))
        reg._scanned = True
        return reg

    @pytest.fixture
    def make_runner(self):
        """
        Build BatchRunners and guarantee they are drained.

        ThreadPoolExecutor keeps its worker threads alive after a job
        finishes, and BatchRunner never shut its executor down unless a
        new batch replaced it. A runner built in one test therefore
        outlived that test: its in-flight worker resolved
        ``discord_osint.pipeline.run_osint_pipeline`` at call time and
        picked up the *next* test's monkeypatched stub, inflating that
        test's concurrency counter. Draining here keeps each test's
        thread accounting its own.
        """
        from web_services.batch import BatchRunner
        created: list[BatchRunner] = []

        def _make(registry, config_service):
            runner = BatchRunner(registry, config_service)
            created.append(runner)
            return runner

        yield _make

        for runner in created:
            runner.shutdown(wait=True)

    @pytest.fixture
    def config_service(self):
        cs = MagicMock()
        cs.to_dict.return_value = {
            "MODE": "manual",
            "OUTPUT_FORMAT": "html",
            "ENABLE_AI_REPORT": False,
            "ENABLE_PIVOTING": False,
        }
        return cs

    def test_empty_targets_returns_empty_summary(
        self, registry, config_service, make_runner,
    ):
        runner = make_runner(registry, config_service)
        summary = runner.start(targets=[""], mode="manual", case_id="c1")
        assert summary["targets_queued"] == 0
        assert summary["job_ids"] == []
        assert "error" in summary

    def test_single_target_creates_one_job(
        self, registry, config_service, monkeypatch, make_runner,
    ):
        from web_services import batch as batch_module

        # Stub the pipeline so nothing actually runs.
        def fake_run_module(mode, cfg):
            return None
        def fake_run_osint(cfg):
            return None

        monkeypatch.setattr(
            "discord_osint.pipeline.run_module_pipeline",
            fake_run_module, raising=False,
        )
        monkeypatch.setattr(
            "discord_osint.pipeline.run_osint_pipeline",
            fake_run_osint, raising=False,
        )

        runner = make_runner(registry, config_service)
        summary = runner.start(targets=["alice"], mode="manual", case_id="c1")

        assert summary["targets_queued"] == 1
        assert len(summary["job_ids"]) == 1
        job = registry.get(summary["job_ids"][0])
        assert job is not None
        assert job["target"] == "alice"
        assert job["case_id"] == "c1"

    def test_multiple_targets_capped_concurrency(
        self, registry, config_service, monkeypatch, make_runner,
    ):
        from web_services import batch as batch_module

        active_count = [0]
        peak = [0]
        lock = threading.Lock()

        def fake_run_osint(cfg):
            with lock:
                active_count[0] += 1
                peak[0] = max(peak[0], active_count[0])
            time.sleep(0.05)
            with lock:
                active_count[0] -= 1

        monkeypatch.setattr(
            "discord_osint.pipeline.run_osint_pipeline",
            fake_run_osint, raising=False,
        )

        runner = make_runner(registry, config_service)
        summary = runner.start(
            targets=["a", "b", "c", "d", "e"],
            mode="manual",
            case_id="c1",
            max_workers=2,
        )
        assert summary["targets_queued"] == 5

        # Wait for workers to drain.
        for _ in range(100):
            if all(
                registry.get(jid) and registry.get(jid).get("status") != "running"
                for jid in summary["job_ids"]
            ):
                break
            time.sleep(0.05)

        # Peak concurrent workers must not exceed max_workers.
        assert peak[0] <= 2

    def test_get_batch(
        self, registry, config_service, monkeypatch, make_runner,
    ):
        from web_services import batch as batch_module
        monkeypatch.setattr(
            "discord_osint.pipeline.run_osint_pipeline",
            lambda cfg: None, raising=False,
        )
        runner = make_runner(registry, config_service)
        summary = runner.start(targets=["x"], mode="manual", case_id="c1")
        b = runner.get_batch(summary["batch_id"])
        assert b is not None
        assert b["case_id"] == "c1"

    def test_get_unknown_batch_returns_none(
        self, registry, config_service, make_runner,
    ):
        runner = make_runner(registry, config_service)
        assert runner.get_batch("nope") is None


# ===========================================================================
# TinEye function
# ===========================================================================

class TestTinEye:
    def test_no_key_returns_empty(self):
        from discord_osint.extras import reverse_image_search_tineye
        assert reverse_image_search_tineye("https://x/a.jpg", api_key="") == []

    def test_401_returns_empty(self, monkeypatch):
        from discord_osint import extras

        fake = MagicMock()
        fake.status_code = 401
        fake.headers = {}
        fake.text = "unauthorized"
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=fake)),
        )
        assert extras.reverse_image_search_tineye("https://x/a.jpg", api_key="k") == []

    def test_429_returns_empty(self, monkeypatch):
        from discord_osint import extras
        fake = MagicMock()
        fake.status_code = 429
        fake.headers = {"Retry-After": "60"}
        fake.text = "slow down"
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=fake)),
        )
        assert extras.reverse_image_search_tineye("https://x/a.jpg", api_key="k") == []

    def test_200_parses_domains(self, monkeypatch):
        from discord_osint import extras
        fake = MagicMock()
        fake.status_code = 200
        fake.headers = {}
        fake.json.return_value = {
            "results": {
                "matches": [
                    {"domain": "example.com", "score": 90},
                    {"domain": "cdn.other.org", "score": 80},
                ],
            },
        }
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=fake)),
        )
        result = extras.reverse_image_search_tineye(
            "https://x/a.jpg", api_key="k",
        )
        assert result == ["example.com", "cdn.other.org"]

    def test_duplicate_domains_collapsed(self, monkeypatch):
        from discord_osint import extras
        fake = MagicMock()
        fake.status_code = 200
        fake.headers = {}
        fake.json.return_value = {
            "results": {
                "matches": [
                    {"domain": "example.com"},
                    {"domain": "Example.com"},
                    {"domain": "example.com"},
                ],
            },
        }
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=fake)),
        )
        result = extras.reverse_image_search_tineye(
            "https://x/a.jpg", api_key="k",
        )
        assert result == ["example.com"]

    def test_malformed_response_returns_empty(self, monkeypatch):
        from discord_osint import extras
        fake = MagicMock()
        fake.status_code = 200
        fake.headers = {}
        fake.json.return_value = {"unexpected": "shape"}
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=MagicMock(return_value=fake)),
        )
        assert extras.reverse_image_search_tineye("https://x/a.jpg", api_key="k") == []

    def test_network_error_returns_empty(self, monkeypatch):
        from discord_osint import extras
        def boom(*a, **kw):
            raise ConnectionError("nope")
        monkeypatch.setattr(
            extras, "http_session",
            MagicMock(get=boom),
        )
        assert extras.reverse_image_search_tineye("https://x/a.jpg", api_key="k") == []