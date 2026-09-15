
"""
discord_osint/audit.py
----------------------
Append-only, HMAC-signed audit log.

Every state-changing action WhoCord takes — starting an investigation,
stopping one, contacting a third party, changing config, shutting down
— is written here. Each entry is signed with a per-install secret and
chained to its predecessor, so:

* A modified entry invalidates its own signature.
* A deleted interior entry invalidates every entry after it.
* An inserted entry cannot be signed without the secret.

Threat model
------------
The audit log is tamper-evident against a third party *without* the
secret. It is not tamper-proof against the operator, who has filesystem
access and could rewrite the whole file with their own secret. The
point is that a downstream reviewer — a colleague, a client, a ticket
auditor — can verify the log was not altered after the fact, given
they trust the secret was never compromised.

Log format
----------
One JSON object per line, sorted keys, compact separators:

    {"ts": "...", "event": "...", "pid": 12345, "prev": "hex...", ...,
     "sig": "hex..."}

``sig`` covers the rest of the entry (including ``prev``), computed as::

    HMAC-SHA256(secret, json.dumps(entry_without_sig,
                                   sort_keys=True,
                                   separators=(",", ":")).encode("utf-8"))

Verification
------------
``verify_log()`` walks the file, recomputes each entry's signature, and
checks that each entry's ``prev`` field matches the previous entry's
``sig``. Returns ``(valid_count, list_of_tampered_line_numbers)``.

Deletion of the *last* entry is not detected without a published head
hash. This is inherent to any hash chain without an external anchor and
is documented as a known limitation.

Configuration
-------------
``WHOCORD_AUDIT_DIR``           — override the directory (default
                                  ``~/.whocord``)
``WHOCORD_AUDIT_SECRET_PATH``   — override the secret file path
``WHOCORD_AUDIT_SECRET``        — override the secret value directly
                                  (for tests and containers)
``WHOCORD_AUDIT_TAIL_BYTES``    — how many bytes of the tail to scan
                                  when looking for the previous
                                  signature. Default 64 KB, enough
                                  for any realistic entry.

Operator attribution
--------------------
Every entry carries ``operator`` (the OS account that ran the process)
and ``host`` (the machine hostname). ``getpass.getuser()`` reads
``$USER`` / ``$LOGNAME`` / the passwd database — it identifies the OS
account, not an authenticated WhoCord user. WhoCord's auth model is a
single shared secret for the whole install; attribution is therefore
"which OS user ran the process," which is exactly what the current
auth model supports. Per-user WhoCord accounts are a separate change.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
from datetime import datetime, timezone


_DEFAULT_DIR         = os.path.expanduser("~/.whocord")
_DEFAULT_SECRET_PATH = os.path.join(_DEFAULT_DIR, "audit_secret")
_DEFAULT_LOG_NAME    = "audit.log"

_AUDIT_TAIL_BYTES = int(os.environ.get("WHOCORD_AUDIT_TAIL_BYTES", "65536"))

_lock = threading.Lock()
_secret_cache: bytes | None = None
_secret_lock = threading.Lock()

# Attribution captured once at module load. getpass.getuser() can be
# slow on some networked filesystems, and the answer never changes for
# the lifetime of the process.
try:
    _OPERATOR = getpass.getuser()
except Exception:
    _OPERATOR = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

try:
    _HOSTNAME = socket.gethostname()
except Exception:
    _HOSTNAME = "unknown"

# Set once, on first secret load, so the clock attestation fires a
# single time per process.
_clock_attested = False
_clock_lock     = threading.Lock()


def _audit_dir() -> str:
    return os.environ.get("WHOCORD_AUDIT_DIR", _DEFAULT_DIR)


def _secret_path() -> str:
    return os.environ.get("WHOCORD_AUDIT_SECRET_PATH", _DEFAULT_SECRET_PATH)


def _audit_path() -> str:
    return os.path.join(_audit_dir(), _DEFAULT_LOG_NAME)


def reset_cache() -> None:
    """Clear the in-memory secret cache. For tests only."""
    global _secret_cache
    with _secret_lock:
        _secret_cache = None


def _attest_clock_once() -> None:
    """
    Best-effort check that the system clock is NTP-synchronised, and
    write one audit entry recording the result.

    Never blocks: if the check is unavailable or fails, the result is
    recorded as "unknown" and the process continues. The purpose is to
    give a downstream reviewer a signed statement about the clock at
    the moment the audit log was opened, not to enforce sync.
    """
    # The flag is checked and set under its own lock so two threads
    # racing the first write_event cannot both emit an attestation.
    # This lock is never held while calling write_event.
    global _clock_attested
    with _clock_lock:
        if _clock_attested:
            return
        _clock_attested = True

    synced = False
    detail = "no NTP check available"

    try:
        out = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            synced = out.stdout.strip().lower() in ("yes", "true", "1")
            detail = out.stdout.strip()[:200]
    except Exception as exc:
        detail = f"timedatectl unavailable: {type(exc).__name__}"

    try:
        write_event(
            "audit_clock_attestation",
            ntp_synchronized=synced,
            detail=detail,
            utc_now=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        pass


def _load_or_create_secret_locked() -> bytes:
    """
    Return the audit HMAC secret, generating and persisting one on
    first use.

    Precedence:

    1. ``WHOCORD_AUDIT_SECRET`` env var (used verbatim, no persistence).
    2. ``WHOCORD_AUDIT_SECRET_PATH`` file.
    3. Fresh 32-byte token written to the default path with mode 0600.

    Cached in memory after the first call so the common case (every
    ``write_event``) does not hit the disk on each write.

    Permission handling
    -------------------
    If the secret file exists but has group- or world-readable bits,
    this function **fixes the mode to 0600 and warns on stderr** rather
    than refusing to start. Refusing would break every existing install
    whose secret file was created under a permissive umask. Only if
    the chmod itself fails does it refuse.
    """
    global _secret_cache
    with _secret_lock:
        if _secret_cache is not None:
            return _secret_cache

        env = os.environ.get("WHOCORD_AUDIT_SECRET")
        if env:
            _secret_cache = env.encode("utf-8")
            return _secret_cache

        path = _secret_path()
        if os.path.isfile(path):
            try:
                st = os.stat(path)
            except OSError as exc:
                raise RuntimeError(
                    f"could not stat {path}: {exc}"
                ) from exc

            if st.st_mode & 0o077:
                print(
                    f"[audit] WARNING: {path} has mode "
                    f"{oct(st.st_mode & 0o777)}; fixing to 0600",
                    file=sys.stderr,
                )
                try:
                    os.chmod(path, 0o600)
                except OSError as exc:
                    raise RuntimeError(
                        f"refusing to use {path}: mode "
                        f"{oct(st.st_mode & 0o777)} and chmod failed: {exc}"
                    ) from exc

            with open(path, "rb") as f:
                _secret_cache = f.read().strip()
                return _secret_cache

        parent = os.path.dirname(path) or "."
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

        secret = secrets.token_bytes(32)
        with open(path, "wb") as f:
            f.write(secret)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        _secret_cache = secret
        return secret


def load_or_create_secret() -> bytes:
    """
    Public entry point: resolve the secret, then attest the clock.

    Deadlock note
    -------------
    The clock attestation used to be invoked from inside
    ``_secret_lock``, at all three return points of the loader. It
    calls ``write_event``, which calls back into this function, which
    tries to re-acquire the same non-reentrant ``threading.Lock`` — so
    the *first* audit write of every process blocked forever. In the
    app that meant the retention thread hung on startup and any route
    that audits hung with it.

    Attestation is now performed after the lock is released. The
    ``_clock_attested`` flag still makes it run at most once, and the
    inner ``write_event`` re-enters this function only after the
    secret is cached, so it returns from the fast path.
    """
    secret = _load_or_create_secret_locked()
    _attest_clock_once()
    return secret


def _sign(body: bytes, secret: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _read_last_sig() -> str:
    """
    Return the last complete entry's signature for chain linkage, or
    an empty string when the log is empty.

    Reads the last ``_AUDIT_TAIL_BYTES`` bytes, scans backward for the
    first line that parses as JSON, and returns its ``sig`` field. A
    partial leading line (from a mid-entry seek) is skipped by the
    JSON parse failure.

    The tail size is configurable via ``WHOCORD_AUDIT_TAIL_BYTES``. The
    default (64 KB) comfortably exceeds any realistic single entry;
    entries with very long error strings or target URLs could exceed
    8 KB, which is why the original 8 KB default was raised.
    """
    path = _audit_path()
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read_size = min(_AUDIT_TAIL_BYTES, size)
            f.seek(size - read_size)
            tail = f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""

    lines = [l.strip() for l in tail.splitlines() if l.strip()]
    for raw in reversed(lines):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        sig = entry.get("sig")
        if isinstance(sig, str):
            return sig
    return ""


def write_event(event_type: str, **fields) -> None:
    """
    Append one signed entry to the audit log.

    Failing to write — disk full, permissions, malformed secret file —
    prints a warning to stderr and returns. Audit-log failure must
    never abort an investigation.
    """
    try:
        secret = load_or_create_secret()
    except Exception as exc:
        print(f"[audit] WARNING: could not load secret: {exc}", file=sys.stderr)
        return

    entry: dict = {
        "ts":       datetime.now(timezone.utc).isoformat(),
        "event":    event_type,
        "pid":      os.getpid(),
        "operator": _OPERATOR,
        "host":     _HOSTNAME,
    }
    # Caller fields cannot overwrite the core fields.
    for k, v in fields.items():
        if k in ("ts", "event", "pid", "operator", "host", "prev", "sig"):
            continue
        entry[k] = v

    with _lock:
        try:
            prev_sig = _read_last_sig()
            entry["prev"] = prev_sig

            body = json.dumps(
                entry, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            entry["sig"] = _sign(body, secret)

            line = json.dumps(entry, sort_keys=True).encode("utf-8") + b"\n"

            os.makedirs(_audit_dir(), mode=0o700, exist_ok=True)
            try:
                os.chmod(_audit_dir(), 0o700)
            except OSError:
                pass

            fd = os.open(
                _audit_path(),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
        except Exception as exc:
            print(f"[audit] WARNING: could not write entry: {exc}",
                  file=sys.stderr)


_TAIL_CHUNK = 64 * 1024


def _tail_lines(path: str, limit: int) -> list[str]:
    """
    Return the last *limit* lines of *path*, oldest-first, without
    reading the whole file.

    ``audit.log`` is append-only and deliberately never rotated, so it
    grows for the life of an install — every state-changing action,
    every third-party call, every config edit adds a line. The previous
    ``f.readlines()`` pulled the entire log into memory on every call to
    the Audit view, so a UI panel an operator clicks during normal use
    degraded toward O(total log size). Seeking from the end makes the
    cost proportional to what is actually displayed.

    Reads fixed-size chunks backwards until enough newlines have been
    seen. Opened in binary so the seek arithmetic is byte-exact, then
    decoded once at the end.
    """
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        pos = end
        buf = b""
        # limit + 1 because the final chunk boundary usually lands
        # mid-line; the leading partial line is discarded below.
        while pos > 0 and buf.count(b"\n") <= limit:
            step = min(_TAIL_CHUNK, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf

    text = buf.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if pos > 0 and lines:
        # The first line is probably truncated by the chunk boundary.
        lines = lines[1:]
    return lines[-limit:]


def read_recent(limit: int = 100) -> list[dict]:
    """
    Return the last *limit* parseable entries, oldest-first.

    Unparseable lines are skipped silently — this is the read path for
    the UI, not the verification path. Use ``verify_log`` to find them.
    """
    path = _audit_path()
    if not os.path.isfile(path):
        return []
    if limit <= 0:
        return []
    try:
        lines = _tail_lines(path, limit)
    except OSError:
        return []

    out: list[dict] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


def read_for_job(job_id: str, limit: int = 10000) -> list[dict]:
    """
    Return every entry whose ``job_id`` matches, oldest-first. Used by
    the per-job disclosure view and the case-read audit.
    """
    if not job_id:
        return []
    path = _audit_path()
    if not os.path.isfile(path):
        return []

    # Cheap pre-filter: the job id is a uuid4 string, so a line that
    # does not contain it literally cannot decode to a matching entry.
    # Substring testing the raw bytes avoids running json.loads over
    # every unrelated line in the log, which is the bulk of the cost on
    # a mature install. Still a linear scan — a real fix is a
    # job_id -> offset side index maintained on write — but it removes
    # the per-line parse, which dominates.
    needle = job_id.encode("utf-8", errors="replace")

    out: list[dict] = []
    try:
        with open(path, "rb") as f:
            for raw in f:
                if needle not in raw:
                    continue
                try:
                    entry = json.loads(raw.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    continue
                if entry.get("job_id") == job_id:
                    out.append(entry)
                    if len(out) >= limit:
                        break
    except OSError:
        return out
    return out


def verify_log(secret: bytes | None = None) -> tuple[int, list[int]]:
    """
    Walk the log and verify each entry's signature and chain linkage.

    Returns ``(valid_count, tampered_line_numbers)``. A tampered line is
    one whose signature does not verify or whose ``prev`` does not match
    the preceding entry's ``sig``.

    On a chain break, verification does *not* attempt to recover — the
    broken line and every line after it are flagged. This is the
    conservative choice: a broken chain means the log cannot be trusted
    from that point forward, and pretending otherwise would hide a real
    tamper signal.
    """
    if secret is None:
        try:
            secret = load_or_create_secret()
        except Exception:
            return 0, []

    path = _audit_path()
    if not os.path.isfile(path):
        return 0, []

    valid   = 0
    bad:    list[int] = []
    prev_sig = ""
    chain_broken = False

    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue

            if chain_broken:
                bad.append(lineno)
                continue

            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                bad.append(lineno)
                chain_broken = True
                continue

            if not isinstance(entry, dict):
                bad.append(lineno)
                chain_broken = True
                continue

            sig = entry.pop("sig", None)
            entry_prev = entry.get("prev", "")

            body = json.dumps(
                entry, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            expected = _sign(body, secret)

            if not sig or not hmac.compare_digest(sig, expected):
                bad.append(lineno)
                chain_broken = True
                continue

            if entry_prev != prev_sig:
                bad.append(lineno)
                chain_broken = True
                continue

            valid += 1
            prev_sig = sig

    return valid, bad
