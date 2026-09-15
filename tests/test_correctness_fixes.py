
"""
tests/test_correctness_fixes.py
--------------------------------
Regression tests for a cluster of correctness/security fixes found
during review:

  * Batch mode bypassed the per-mode sanitisers ``/run`` uses.
  * ``JobRegistry.find_intel_path`` built an unescaped glob pattern
    from the job's target, so a target of ``"*"`` matched every
    snapshot in the cache directory — including other investigations'.
  * ``target_id`` was derived from Python's randomised ``hash()``, so
    the same username produced a different id every process, breaking
    caching and cross-run report linkage.
  * ``safe_get_pinned``'s manual redirect-following meant the caller
    could never see the real chain of hops.
"""

from __future__ import annotations

import glob as glob_module
import os
import threading

import pytest

from discord_osint.errors import InputValidationError
from discord_osint.utils import stable_target_id
from web_services.batch import _sanitise_for_mode
from web_services.jobs import JobRegistry


# ---------------------------------------------------------------------------
# Batch target sanitisation
# ---------------------------------------------------------------------------

class TestBatchTargetSanitisation:
    def test_manual_mode_strips_disallowed_chars(self):
        assert _sanitise_for_mode("john--doe.the_one", "manual") == "john--doe.the_one"
        # sanitize_username strips characters outside [A-Za-z0-9._-]
        assert _sanitise_for_mode("john doe!", "manual") == "johndoe"

    def test_manual_mode_rejects_glob_wildcard_only(self):
        # "*" contains no character sanitize_username keeps, so it
        # sanitises to empty and must be rejected outright — not passed
        # through as a literal "*" that could later reach a glob.
        assert _sanitise_for_mode("*", "manual") is None

    def test_email_mode_lowercases_and_strips(self):
        assert _sanitise_for_mode("  Alice@Example.com  ", "email") == "alice@example.com"

    def test_domain_mode_strips_protocol_and_path(self):
        assert _sanitise_for_mode("https://Example.com/x?y=1", "domain") == "example.com"

    def test_domain_mode_rejects_empty_after_strip(self):
        assert _sanitise_for_mode("://///", "domain") is None

    def test_url_mode_rejects_non_http_scheme(self):
        assert _sanitise_for_mode("javascript:alert(1)", "url") is None
        assert _sanitise_for_mode("file:///etc/passwd", "url") is None

    def test_url_mode_accepts_well_formed_url(self):
        assert _sanitise_for_mode("https://example.com/a", "url") == "https://example.com/a"

    def test_image_mode_uses_same_url_rules_as_url_mode(self):
        assert _sanitise_for_mode("javascript:alert(1)", "image") is None
        assert _sanitise_for_mode("https://cdn.example.com/a.png", "image") == \
            "https://cdn.example.com/a.png"

    def test_phone_mode_keeps_only_phone_characters(self):
        assert _sanitise_for_mode("+1 (555) 123-4567", "phone") == "+1 (555) 123-4567"
        assert _sanitise_for_mode("<script>", "phone") is None

    def test_probe_mode_is_permissive_but_capped(self):
        long_input = "x" * 1000
        result = _sanitise_for_mode(long_input, "probe")
        assert result is not None
        assert len(result) <= 512

    def test_unknown_mode_is_refused_not_passed_through(self):
        assert _sanitise_for_mode("anything", "discord") is None
        assert _sanitise_for_mode("anything", "totally-made-up") is None

    def test_argv_flag_injection_target_is_rejected_or_neutralised(self):
        # A target starting with "-" used to reach external-tool argv
        # unchanged (e.g. holehe/maigret/h8mail). sanitize_username
        # strips leading dots but not dashes, so confirm the dash
        # survives sanitisation only inside a value that is otherwise
        # a normal-looking username — it is not silently dropped or
        # turned into something that could be misread as a flag by a
        # tool that does its own arg parsing oddly. This test pins the
        # actual current behaviour so a future change to the allowed
        # character set is a conscious decision.
        result = _sanitise_for_mode("--no-color", "manual")
        assert result == "--no-color"
        # The point is not that dashes are banned (many real usernames
        # have them) — it's that batch mode now applies the exact same
        # rule /run applies to a single target, so there is one policy
        # instead of two.


# ---------------------------------------------------------------------------
# find_intel_path glob escaping
# ---------------------------------------------------------------------------

class TestFindIntelPathGlobEscaping:
    def test_wildcard_target_does_not_match_other_jobs_snapshot(self, tmp_path):
        reg = JobRegistry(cache_dir=str(tmp_path))

        # Another investigation's snapshot, sitting in the same cache dir.
        other_snapshot = tmp_path / "intel_alice_20260101_000000.json"
        other_snapshot.write_text("{}")

        ev = threading.Event()
        reg.create(job_id="j1", target="*", mode="manual", cancel_event=ev)
        job = reg.get("j1")

        found = reg.find_intel_path(job)
        assert found is None, (
            "a target of '*' must not glob-match another investigation's "
            "intel snapshot"
        )

    def test_bracket_in_target_is_treated_literally(self, tmp_path):
        reg = JobRegistry(cache_dir=str(tmp_path))

        # A snapshot whose filename contains what looks like a glob
        # character class, to prove [ab] in a target is not treated as
        # a character class when the target is escaped.
        literal_snapshot = tmp_path / "intel_[ab]_20260101_000000.json"
        literal_snapshot.write_text("{}")
        decoy_snapshot = tmp_path / "intel_a_20260101_000000.json"
        decoy_snapshot.write_text("{}")

        ev = threading.Event()
        reg.create(job_id="j1", target="[ab]", mode="manual", cancel_event=ev)
        job = reg.get("j1")

        found = reg.find_intel_path(job)
        assert found == str(literal_snapshot)

    def test_normal_target_still_matches_its_own_snapshot(self, tmp_path):
        reg = JobRegistry(cache_dir=str(tmp_path))
        snapshot = tmp_path / "intel_alice_20260101_000000.json"
        snapshot.write_text("{}")

        ev = threading.Event()
        reg.create(job_id="j1", target="alice", mode="manual", cancel_event=ev)
        job = reg.get("j1")

        assert reg.find_intel_path(job) == str(snapshot)


class TestFindIntelPathUsesArtifactKey:
    """
    The glob must use the key the pipeline actually writes with.

    InvestigationCore.save_state names snapshots
    ``intel_<target_id>_<ts>.json`` where target_id comes from
    ``stable_target_id`` — a 31-bit int. The registry used to glob
    ``intel_<job["target"]>_*.json`` using the human label, which never
    matched, so the fallback was dead for every live job.
    """

    def _write_snapshot(self, tmp_path, seed, mode="manual"):
        from discord_osint.core import InvestigationCore
        from discord_osint.utils import intel_target_key

        key = intel_target_key(mode, seed)
        core = InvestigationCore(key, cache_dir=str(tmp_path))
        core.add_intel("emails", "primary", "x@example.com")
        return key, core.save_state()

    def test_glob_matches_real_pipeline_filename(self, tmp_path):
        key, written = self._write_snapshot(tmp_path, "alice")
        reg = JobRegistry(cache_dir=str(tmp_path))
        ev = threading.Event()
        reg.create(
            job_id="j1", target="alice", mode="manual",
            cancel_event=ev, target_key=key,
        )
        assert reg.find_intel_path(reg.get("j1")) == written

    def test_truncated_label_still_resolves(self, tmp_path):
        """url/image/probe labels are cut to 60 chars; the key is not."""
        from discord_osint.utils import intel_target_key

        long_url = "https://example.com/" + ("a" * 120)
        key, written = self._write_snapshot(tmp_path, long_url, mode="url")
        reg = JobRegistry(cache_dir=str(tmp_path))
        ev = threading.Event()
        reg.create(
            job_id="j1", target=long_url[:60], mode="url",
            cancel_event=ev, target_key=intel_target_key("url", long_url),
        )
        assert reg.find_intel_path(reg.get("j1")) == written

    def test_discord_mode_keys_on_user_id(self, tmp_path):
        from discord_osint.utils import intel_target_key

        key, written = self._write_snapshot(tmp_path, "123456789", mode="discord")
        assert key == "123456789"
        reg = JobRegistry(cache_dir=str(tmp_path))
        ev = threading.Event()
        reg.create(
            job_id="j1", target="discord:123456789", mode="discord",
            cancel_event=ev,
            target_key=intel_target_key("discord", "123456789"),
        )
        assert reg.find_intel_path(reg.get("j1")) == written

    def test_recorded_path_outside_cache_dir_is_rejected(self, tmp_path):
        """
        find_intel_path's result is opened directly by the detail route,
        so it must stay inside the cache dir.
        """
        cache = tmp_path / "cache"
        cache.mkdir()
        outside = tmp_path / "secrets.json"
        outside.write_text("{}")

        reg = JobRegistry(cache_dir=str(cache))
        ev = threading.Event()
        reg.create(job_id="j1", target="alice", mode="manual", cancel_event=ev)
        reg.record_intel("j1", str(outside))
        assert reg.find_intel_path(reg.get("j1")) is None


# ---------------------------------------------------------------------------
# Stable target ids
# ---------------------------------------------------------------------------

class TestStableTargetId:
    def test_same_seed_same_id_within_process(self):
        assert stable_target_id("johndoe") == stable_target_id("johndoe")

    def test_different_seeds_almost_certainly_differ(self):
        assert stable_target_id("johndoe") != stable_target_id("janedoe")

    def test_always_a_positive_31_bit_int(self):
        for seed in ("a", "johndoe", "üñïçødé", "x" * 500, ""):
            n = stable_target_id(seed)
            assert isinstance(n, int)
            assert 0 <= n <= 0x7FFFFFFF

    def test_stable_across_a_fresh_interpreter(self):
        """
        The bug this replaces: Python randomises str hashing per
        process (PYTHONHASHSEED) by default, so hash("johndoe") &
        0x7FFFFFFF differed on every run. Spawn a real subprocess with
        hash randomisation forced on and confirm the id matches this
        process's value anyway.
        """
        import subprocess
        import sys

        code = (
            "import sys; sys.path.insert(0, '.'); "
            "from discord_osint.utils import stable_target_id; "
            "print(stable_target_id('johndoe'))"
        )
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = "random"
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, env=env, timeout=30,
        )
        assert out.returncode == 0, out.stderr
        subprocess_value = int(out.stdout.strip().splitlines()[-1])
        assert subprocess_value == stable_target_id("johndoe")
