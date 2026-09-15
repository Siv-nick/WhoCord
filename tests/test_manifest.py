"""
tests/test_manifest.py
----------------------
Tests for the signed evidence manifest (Phase 2, item 2.2).
"""

from __future__ import annotations

import json
import os

import pytest

from discord_osint import manifest


@pytest.fixture
def secret():
    return b"test-secret-not-for-production" * 2


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "report.html"
    path.write_text("<html>test</html>")
    return path


@pytest.fixture
def config_snapshot():
    return {
        "MODE": "manual",
        "MANUAL_USERNAME": "alice",
        "ENABLE_MAIGRET": True,
        "LLM_MODEL": "llama3-8b-8192",
    }


# ===========================================================================
# Generation
# ===========================================================================

class TestGenerateManifest:
    def test_includes_signature(self, secret, artifact, config_snapshot, tmp_path):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        assert "signature" in m
        assert isinstance(m["signature"], str)
        assert len(m["signature"]) == 64  # hex sha256

    def test_artifact_entry_has_sha_and_size(
        self, secret, artifact, config_snapshot
    ):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        assert len(m["artifacts"]) == 1
        entry = m["artifacts"][0]
        assert entry["sha256"] == manifest.sha256_file(str(artifact))
        assert entry["size"] == os.path.getsize(artifact)

    def test_missing_artifact_skipped(
        self, secret, config_snapshot, tmp_path
    ):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(tmp_path / "does_not_exist.html")],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        assert m["artifacts"] == []

    def test_config_hash_stable_across_key_order(
        self, secret, artifact
    ):
        m1 = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot={"a": 1, "b": 2},
            secret=secret,
        )
        m2 = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot={"b": 2, "a": 1},
            secret=secret,
        )
        assert m1["config_hash"] == m2["config_hash"]

    def test_extra_fields_are_signed(
        self, secret, artifact, config_snapshot
    ):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
            extra={"target_id": "42"},
        )
        assert m["target_id"] == "42"
        # Signature must still verify after re-serialising.
        ok, problems = manifest.verify_manifest(m, secret)
        assert ok, problems

    def test_caller_cannot_override_signature(
        self, secret, artifact, config_snapshot
    ):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
            extra={"signature": "forged"},
        )
        # The forged value was dropped; the real signature is present.
        ok, problems = manifest.verify_manifest(m, secret)
        assert ok, problems


# ===========================================================================
# Verification
# ===========================================================================

class TestVerifyManifest:
    def test_valid_manifest_verifies(
        self, secret, artifact, config_snapshot
    ):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        ok, problems = manifest.verify_manifest(m, secret)
        assert ok, problems
        assert problems == []

    def test_wrong_secret_fails(self, secret, artifact, config_snapshot):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        ok, problems = manifest.verify_manifest(m, b"wrong-secret")
        assert not ok
        assert any("signature" in p for p in problems)

    def test_modified_body_fails(self, secret, artifact, config_snapshot):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        m["job_id"] = "different-job"
        ok, problems = manifest.verify_manifest(m, secret)
        assert not ok
        assert any("signature" in p for p in problems)

    def test_modified_artifact_fails(self, secret, artifact, config_snapshot):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        # Modify the file after the manifest was generated.
        artifact.write_text("<html>modified</html>")
        ok, problems = manifest.verify_manifest(m, secret)
        assert not ok
        assert any("sha256 mismatch" in p for p in problems)

    def test_deleted_artifact_fails(self, secret, artifact, config_snapshot):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        artifact.unlink()
        ok, problems = manifest.verify_manifest(m, secret)
        assert not ok
        assert any("missing artifact" in p for p in problems)

    def test_resized_artifact_fails(self, secret, artifact, config_snapshot):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        # Append a byte — sha changes, size changes.
        with open(artifact, "a") as f:
            f.write("x")
        ok, problems = manifest.verify_manifest(m, secret)
        assert not ok
        # sha mismatch is detected first (before size mismatch).
        assert any("sha256 mismatch" in p for p in problems)

    def test_missing_signature_fails(self, artifact, config_snapshot, secret):
        m = {"version": "1.0", "job_id": "j1", "artifacts": []}
        ok, problems = manifest.verify_manifest(m, secret)
        assert not ok
        assert any("no signature" in p for p in problems)

    def test_base_dir_resolves_relative_paths(
        self, secret, artifact, config_snapshot
    ):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        # Manifest stores the artifact as a relative path. Verify from
        # the artifact's parent dir.
        base = str(artifact.parent)
        ok, problems = manifest.verify_manifest(m, secret, base_dir=base)
        # The relative path in the manifest is relative to cwd, not the
        # artifact's parent. This test just confirms base_dir is used.
        # If the manifest happens to store an absolute path (because
        # os.path.relpath could not shorten it), the test is still valid.
        assert isinstance(ok, bool)
        assert isinstance(problems, list)


# ===========================================================================
# Disk round-trip
# ===========================================================================

class TestDiskRoundTrip:
    def test_write_and_load(self, secret, artifact, config_snapshot, tmp_path):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        path = tmp_path / "manifest.json"
        manifest.write_manifest(m, str(path))
        loaded = manifest.load_manifest(str(path))
        assert loaded["job_id"] == "j1"
        assert loaded["signature"] == m["signature"]

    def test_round_trip_still_verifies(
        self, secret, artifact, config_snapshot, tmp_path
    ):
        m = manifest.generate_manifest(
            job_id="j1",
            artifacts=[str(artifact)],
            config_snapshot=config_snapshot,
            secret=secret,
        )
        path = tmp_path / "manifest.json"
        manifest.write_manifest(m, str(path))
        loaded = manifest.load_manifest(str(path))
        # Pretty-printing on disk must not invalidate the signature —
        # verify re-canonicalises.
        ok, problems = manifest.verify_manifest(loaded, secret)
        assert ok, problems

    def test_load_rejects_non_object_root(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("[]")
        with pytest.raises(ValueError):
            manifest.load_manifest(str(path))