"""
tests/test_perf_pass_fixes.py
-----------------------------
Regressions for the second review pass.

Covers:
  * ``sanitize_domain`` rejecting instead of silently rewriting a target.
  * ``audit._tail_lines`` / ``read_recent`` reading from the end of the
    log rather than loading the whole file.
  * ``audit.read_for_job`` still returning exactly the matching entries
    after the raw-bytes pre-filter was added.
  * ``write_manifest`` chmod'ing to 0600.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from discord_osint import audit
from discord_osint.errors import InputValidationError
from discord_osint.manifest import write_manifest
from discord_osint.utils.sanitizers import sanitize_domain


# ---------------------------------------------------------------------------
# sanitize_domain
# ---------------------------------------------------------------------------

class TestSanitizeDomainDoesNotRewriteTargets:
    """
    Deleting illegal characters turned one target into a different one.
    "example.com:8080" became "example.com8080" (a host that does not
    exist) and "a_b.com" became "ab.com" (a host that might well exist
    and belong to someone else). For an investigative tool, quietly
    investigating the wrong target is worse than refusing the input.
    """

    @pytest.mark.parametrize("raw,expected", [
        ("example.com:8080",          "example.com"),
        ("https://example.com:443/x", "example.com"),
        ("EXAMPLE.COM",               "example.com"),
        ("example.com/some/path?q=1", "example.com"),
        ("sub.example.co.uk.",        "sub.example.co.uk"),
        ("user:pw@example.com",       "example.com"),
    ])
    def test_port_and_noise_stripped(self, raw, expected):
        assert sanitize_domain(raw) == expected

    @pytest.mark.parametrize("raw", [
        "a_b.com",       # underscore: previously silently became ab.com
        "exa mple.com",  # space:      previously silently became example.com
        "ex$ample.com",
        "..example.com",
        "-example.com",
    ])
    def test_illegal_characters_rejected_not_deleted(self, raw):
        with pytest.raises(InputValidationError):
            sanitize_domain(raw)

    def test_empty_still_raises(self):
        with pytest.raises(InputValidationError):
            sanitize_domain("")


# ---------------------------------------------------------------------------
# audit tail reads
# ---------------------------------------------------------------------------

class TestAuditTailRead:
    def _write(self, path, n, pad=""):
        with open(path, "w", encoding="utf-8") as f:
            for i in range(n):
                f.write(json.dumps({"i": i, "pad": pad}) + "\n")

    @pytest.mark.parametrize("n", [0, 1, 5, 100, 5000])
    @pytest.mark.parametrize("limit", [1, 10, 100, 10000])
    def test_matches_readlines_slice(self, tmp_path, n, limit):
        p = tmp_path / "audit.log"
        self._write(p, n)
        expected = [
            json.dumps({"i": i, "pad": ""}) for i in range(n)
        ][-limit:]
        assert audit._tail_lines(str(p), limit) == expected

    def test_lines_spanning_chunk_boundary(self, tmp_path):
        """Entries larger than a fraction of the 64KB read chunk."""
        p = tmp_path / "audit.log"
        self._write(p, 200, pad="x" * 900)
        got = audit._tail_lines(str(p), 3)
        assert [json.loads(l)["i"] for l in got] == [197, 198, 199]

    def test_read_recent_returns_oldest_first(self, tmp_path, monkeypatch):
        p = tmp_path / "audit.log"
        self._write(p, 50)
        monkeypatch.setattr(audit, "_audit_path", lambda: str(p))
        out = audit.read_recent(limit=5)
        assert [e["i"] for e in out] == [45, 46, 47, 48, 49]

    def test_read_recent_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            audit, "_audit_path", lambda: str(tmp_path / "nope.log"),
        )
        assert audit.read_recent() == []

    def test_read_recent_skips_corrupt_lines(self, tmp_path, monkeypatch):
        p = tmp_path / "audit.log"
        p.write_text(
            json.dumps({"i": 1}) + "\n"
            + "{not json\n"
            + json.dumps({"i": 2}) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(audit, "_audit_path", lambda: str(p))
        assert [e["i"] for e in audit.read_recent(limit=10)] == [1, 2]


class TestAuditReadForJob:
    def test_prefilter_does_not_change_results(self, tmp_path, monkeypatch):
        p = tmp_path / "audit.log"
        with open(p, "w", encoding="utf-8") as f:
            for i in range(500):
                jid = "job-a" if i % 3 == 0 else "job-b"
                f.write(json.dumps({"job_id": jid, "i": i}) + "\n")
        monkeypatch.setattr(audit, "_audit_path", lambda: str(p))

        got = audit.read_for_job("job-a")
        assert [e["i"] for e in got] == [i for i in range(500) if i % 3 == 0]

    def test_substring_match_is_not_enough(self, tmp_path, monkeypatch):
        """
        The pre-filter is a cheap bytes test; the real comparison must
        still be on the parsed job_id field, so an entry that merely
        *mentions* the id elsewhere must not be returned.
        """
        p = tmp_path / "audit.log"
        with open(p, "w", encoding="utf-8") as f:
            f.write(json.dumps({"job_id": "abc", "i": 1}) + "\n")
            f.write(json.dumps({"job_id": "other", "note": "abc", "i": 2}) + "\n")
        monkeypatch.setattr(audit, "_audit_path", lambda: str(p))

        assert [e["i"] for e in audit.read_for_job("abc")] == [1]

    def test_limit_respected(self, tmp_path, monkeypatch):
        p = tmp_path / "audit.log"
        with open(p, "w", encoding="utf-8") as f:
            for i in range(100):
                f.write(json.dumps({"job_id": "j", "i": i}) + "\n")
        monkeypatch.setattr(audit, "_audit_path", lambda: str(p))
        assert len(audit.read_for_job("j", limit=7)) == 7

    def test_empty_job_id(self):
        assert audit.read_for_job("") == []


# ---------------------------------------------------------------------------
# manifest permissions
# ---------------------------------------------------------------------------

class TestManifestPermissions:
    def test_manifest_written_0600(self, tmp_path):
        p = tmp_path / "manifest_1_20260101_000000.json"
        write_manifest({"artifacts": [], "case_id": "c1"}, str(p))
        mode = stat.S_IMODE(os.stat(p).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
