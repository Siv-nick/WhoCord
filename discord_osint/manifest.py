"""
discord_osint/manifest.py
-------------------------
Signed evidence manifest for a single investigation.

A manifest lists every artifact the investigation produced (HTML
report, markdown report, intel snapshot, ...), the SHA-256 of each, and
a hash of the config snapshot the investigation ran under. The whole
document is HMAC-signed with the same secret as the audit log, so a
later reviewer can verify:

* The artifacts have not been modified since the manifest was written.
* The manifest itself has not been modified.
* The config the run operated under is the one the operator thinks.

What this does not prove
------------------------
The manifest does not prove that the investigation *actually produced*
these artifacts — an operator who has filesystem access could produce
a manifest for a set of files they created by hand. That is a
fundamental limitation of any local-only tool. The chain of custody is
complete when a downstream reviewer trusts the operator's machine was
not compromised at the time the manifest was generated; it is not a
cryptographic substitute for a notary.

Usage
-----
::

    from discord_osint import audit, manifest

    m = manifest.generate_manifest(
        job_id="abc-123",
        artifacts=["/cache/report_x_20260101_120000.html"],
        config_snapshot=cfg.to_dict(),
        secret=audit.load_or_create_secret(),
    )
    manifest.write_manifest(m, "/cache/manifest_x_20260101_120000.json")

    ok, problems = manifest.verify_manifest(m, secret)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone


_MANIFEST_VERSION = "1.0"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str) -> str:
    """Stream-hash a file, returning the hex digest. 64 KB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_dict(d: dict) -> str:
    """
    Hash a dict deterministically. Keys sorted, compact separators,
    ``default=str`` for values that JSON cannot serialise natively
    (bytes, datetime, Path).
    """
    body = json.dumps(
        d, sort_keys=True, default=str, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def generate_manifest(
    *,
    job_id: str,
    artifacts: list[str],
    config_snapshot: dict,
    secret: bytes,
    extra: dict | None = None,
) -> dict:
    """
    Build a signed manifest.

    Parameters
    ----------
    job_id:
        Identifier for the investigation. For web-triggered runs this
        is the job UUID; for CLI runs it is the string form of the
        target id.
    artifacts:
        Absolute paths to files to include. Non-existent paths are
        silently skipped — a missing artifact is not itself an error at
        generation time; it shows up as a missing file at verification.
    config_snapshot:
        The config the investigation ran under. Any dict-like object
        works.
    secret:
        HMAC key. Use ``audit.load_or_create_secret()``.
    extra:
        Optional additional top-level fields. Will be signed.
    """
    entries: list[dict] = []
    for path in artifacts:
        if not path or not os.path.isfile(path):
            continue
        try:
            entries.append({
                "path":   os.path.relpath(path),
                "sha256": sha256_file(path),
                "size":   os.path.getsize(path),
            })
        except OSError:
            continue

    manifest: dict = {
        "version":      _MANIFEST_VERSION,
        "job_id":       job_id,
        "generated_at": _utc_now(),
        "artifacts":    entries,
        "config_hash":  sha256_dict(config_snapshot),
    }
    if extra:
        for k, v in extra.items():
            if k in ("signature", "version", "job_id"):
                continue
            manifest[k] = v

    body = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    manifest["signature"] = hmac.new(
        secret, body, hashlib.sha256,
    ).hexdigest()
    return manifest


def write_manifest(manifest: dict, path: str) -> None:
    """
    Write a manifest to disk as pretty-printed JSON.

    Pretty-printed because a manifest is meant to be read by a human
    reviewer, not parsed by a machine in a hot loop. The signature is
    over the canonical compact form, so pretty-printing does not
    invalidate it — ``verify_manifest`` re-canonicalises before
    checking.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    # Match the 0600 that intel snapshots, debug logs, cached avatars,
    # config.json and audit.log already get. A manifest lists every
    # artifact path and carries the case id and operator name, so it is
    # not less sensitive than the things it indexes. Until now it
    # inherited the process umask and was protected only by the parent
    # directory's 0700 — fine in practice, but with no defence in depth
    # if that mode is ever relaxed or the file is copied elsewhere.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_manifest(path: str) -> dict:
    """Read a manifest from disk. Raises on parse error."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"manifest root must be an object, got {type(data).__name__}")
    return data


def verify_manifest(
    manifest: dict,
    secret: bytes,
    *,
    base_dir: str | None = None,
) -> tuple[bool, list[str]]:
    """
    Verify a manifest's signature and each artifact's SHA-256.

    Returns ``(ok, problems)`` where ``problems`` is a list of
    human-readable strings. ``ok`` is True only when the signature
    verifies *and* every artifact hash and size matches.

    Parameters
    ----------
    base_dir:
        Directory relative artifact paths are resolved against.
        Defaults to the current working directory.
    """
    problems: list[str] = []

    m = dict(manifest)
    sig = m.pop("signature", None)
    if not isinstance(sig, str) or not sig:
        return False, ["manifest has no signature"]

    body = json.dumps(
        m, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False, ["manifest signature does not verify (body modified)"]

    artifacts = m.get("artifacts", [])
    if not isinstance(artifacts, list):
        return False, ["manifest artifacts field is not a list"]

    for entry in artifacts:
        if not isinstance(entry, dict):
            problems.append("artifact entry is not an object")
            continue
        rel = entry.get("path")
        if not isinstance(rel, str):
            problems.append("artifact entry has no path")
            continue
        full = os.path.join(base_dir, rel) if base_dir else rel
        if not os.path.isfile(full):
            problems.append(f"missing artifact: {rel}")
            continue

        actual_sha = sha256_file(full)
        if actual_sha != entry.get("sha256"):
            problems.append(f"sha256 mismatch: {rel}")
            continue

        expected_size = entry.get("size")
        if expected_size is not None:
            actual_size = os.path.getsize(full)
            if actual_size != expected_size:
                problems.append(
                    f"size mismatch: {rel} "
                    f"(expected {expected_size}, got {actual_size})"
                )

    return (len(problems) == 0), problems