"""
tests/test_phase4_c.py
----------------------
Tests for Phase 4 batch C: activity-pattern inference and cost
tracking.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from discord_osint.intelligence.activity import (
    ActivityResult,
    infer_activity_profile,
)
from discord_osint.costs import CostAccumulator


# ===========================================================================
# Activity inference
# ===========================================================================

def _iso(dt: datetime) -> str:
    return dt.isoformat()


class TestActivityInference:
    def test_empty_intel_returns_no_signal(self):
        result = infer_activity_profile({})
        assert result.has_signal is False
        assert result.sample_size == 0
        assert result.confidence == "low"

    def test_too_few_timestamps(self):
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        intel = {
            "social_profiles": {
                "twitter/alice": {
                    "value": _iso(now),
                    "source": "scrape_twitter",
                },
            },
        }
        result = infer_activity_profile(intel)
        assert result.has_signal is False
        assert result.sample_size == 1

    def test_infers_utc_offset_from_clustered_hours(self):
        # All activity is between 09:00 and 18:00 UTC.
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        times = []
        for day in range(10):
            for hour in (9, 11, 13, 15, 17):
                times.append(base + timedelta(days=day, hours=hour))

        intel = {
            "social_profiles": {
                f"t{i}": {
                    "value": _iso(t),
                    "source": "scrape_twitter",
                }
                for i, t in enumerate(times)
            },
        }
        result = infer_activity_profile(intel)
        assert result.has_signal
        assert result.inferred_utc_offset_min is not None
        # The best offset should not be wildly wrong. All activity is
        # in the UTC 9-17 range, so any offset that shifts the bulk
        # into 8-24 waking hours is acceptable. We only assert that
        # the offset exists and the confidence is not "low" with 50
        # samples.
        assert result.confidence in ("medium", "high")

    def test_skips_whois_dates(self):
        # WHOIS dates are infrastructure events and must not be used.
        intel = {
            "whois": {
                "example.com": {
                    "value": "2020-01-01T00:00:00Z",
                    "source": "whois",
                },
            },
            "dns": {
                "example.com": {
                    "value": "2020-02-02T00:00:00Z",
                    "source": "dns_lookup",
                },
            },
        }
        result = infer_activity_profile(intel)
        assert result.sample_size == 0

    def test_skips_infra_keys(self):
        # account_created and creation_date are derived, not events.
        intel = {
            "discord": {
                "account_created": {
                    "value": "2015-01-01 12:00:00 UTC",
                    "source": "snowflake",
                },
            },
        }
        result = infer_activity_profile(intel)
        assert result.sample_size == 0

    def test_handles_naive_timestamps(self):
        # Naive timestamps are assumed to be UTC.
        intel = {
            "media": {
                "exif_date_x": {
                    "value": "2026-01-01T14:00:00",
                    "source": "exif",
                },
                "exif_date_y": {
                    "value": "2026-01-02T14:00:00",
                    "source": "exif",
                },
                "exif_date_z": {
                    "value": "2026-01-03T14:00:00",
                    "source": "exif",
                },
            },
        }
        result = infer_activity_profile(intel)
        assert result.sample_size == 3

    def test_to_dict_round_trips(self):
        result = ActivityResult(
            inferred_utc_offset_min=60,
            inferred_utc_offset_str="UTC+01:00",
            active_hours="09:00–18:00",
            posting_cadence="steady",
            sample_size=25,
            confidence="medium",
        )
        d = result.to_dict()
        assert d["inferred_utc_offset_min"] == 60
        assert d["confidence"] == "medium"
        assert d["active_hours"] == "09:00–18:00"

    def test_cadence_classification(self):
        # 100 timestamps over 1 day = heavy.
        base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        heavy = [
            {"v": _iso(base + timedelta(minutes=i * 10)), "source": "scrape_twitter"}
            for i in range(100)
        ]
        intel = {"items": [{"value": x["v"], "source": x["source"]} for x in heavy]}
        result = infer_activity_profile(intel)
        assert result.posting_cadence == "heavy"


# ===========================================================================
# Cost accumulator
# ===========================================================================

class TestCostAccumulator:
    def test_zero_rates_report_zero_cost(self):
        acc = CostAccumulator(input_rate=0.0, output_rate=0.0)
        acc.record_llm_call(
            service="groq", model="llama",
            bytes_sent=4000, bytes_received=8000,
        )
        snap = acc.snapshot()
        assert snap["llm_calls"] == 1
        assert snap["llm_bytes_in"] == 4000
        assert snap["llm_bytes_out"] == 8000
        assert snap["llm_cost_usd"] == 0.0

    def test_rates_compute_cost(self):
        # 4000 bytes in = 1000 tokens = 1 "1k unit" at $0.10/1k = $0.10
        # 8000 bytes out = 2000 tokens = 2 "1k unit" at $0.20/1k = $0.40
        # total = $0.50
        acc = CostAccumulator(input_rate=0.10, output_rate=0.20)
        acc.record_llm_call(
            service="groq", model="llama",
            bytes_sent=4000, bytes_received=8000,
        )
        snap = acc.snapshot()
        assert snap["llm_cost_usd"] == pytest.approx(0.50, abs=1e-6)

    def test_multiple_calls_accumulate(self):
        acc = CostAccumulator(input_rate=0.10, output_rate=0.20)
        for _ in range(3):
            acc.record_llm_call(
                service="groq", model="llama",
                bytes_sent=4000, bytes_received=8000,
            )
        snap = acc.snapshot()
        assert snap["llm_calls"] == 3
        assert snap["llm_cost_usd"] == pytest.approx(1.50, abs=1e-6)

    def test_enrichment_records_credits(self):
        acc = CostAccumulator()
        acc.record_enrichment(provider="apollo", credits=5.0, matched=2)
        acc.record_enrichment(provider="lusha", credits=3.5, matched=1)
        snap = acc.snapshot()
        assert snap["enrichment_calls"] == 2
        assert snap["enrichment_credits"] == pytest.approx(8.5)

    def test_breakdown_included(self):
        acc = CostAccumulator()
        acc.record_llm_call(service="groq", model="m", bytes_sent=100)
        acc.record_enrichment(provider="apollo", credits=1.0)
        snap = acc.snapshot()
        assert len(snap["breakdown"]) == 2
        assert snap["breakdown"][0]["kind"] == "llm"
        assert snap["breakdown"][1]["kind"] == "enrichment"

    def test_reset_clears_summary(self):
        acc = CostAccumulator()
        acc.record_llm_call(service="groq", model="m", bytes_sent=4000)
        acc.reset()
        snap = acc.snapshot()
        assert snap["llm_calls"] == 0
        assert snap["llm_bytes_in"] == 0

    def test_negative_bytes_clamped(self):
        acc = CostAccumulator()
        acc.record_llm_call(service="x", model="y", bytes_sent=-100, bytes_received=-50)
        snap = acc.snapshot()
        # Negative inputs are clamped to zero; the call is still counted.
        assert snap["llm_calls"] == 1
        assert snap["llm_bytes_in"] == 0
        assert snap["llm_bytes_out"] == 0


# ===========================================================================
# Job registry integration
# ===========================================================================

class TestJobRegistryCost:
    @pytest.fixture
    def registry(self, tmp_path):
        from web_services.jobs import JobRegistry
        reg = JobRegistry(cache_dir=str(tmp_path))
        reg._scanned = True
        return reg

    def test_register_and_read(self, registry):
        import threading
        ev = threading.Event()
        registry.create(
            job_id="j1", target="alice", mode="manual", cancel_event=ev,
        )
        acc = CostAccumulator(input_rate=0.10, output_rate=0.20)
        registry.register_cost_accumulator("j1", acc)

        acc.record_llm_call(service="groq", model="m",
                            bytes_sent=4000, bytes_received=8000)
        snap = registry.get_cost_snapshot("j1")
        assert snap is not None
        assert snap["llm_calls"] == 1
        assert snap["llm_cost_usd"] == pytest.approx(0.50, abs=1e-6)

    def test_missing_accumulator_returns_none(self, registry):
        assert registry.get_cost_snapshot("nope") is None

    def test_delete_job_removes_accumulator(self, registry):
        import threading
        ev = threading.Event()
        registry.create(
            job_id="j1", target="alice", mode="manual", cancel_event=ev,
        )
        acc = CostAccumulator()
        registry.register_cost_accumulator("j1", acc)
        registry.mark_status("j1", "done")

        ok, files, err = registry.delete_job("j1")
        assert ok
        assert registry.get_cost_snapshot("j1") is None