
"""
web_services/jobs.py
--------------------
Owner of every piece of live job state.

Responsibilities:

- The job registry itself.
- Cancel events, worker thread handles, pending pivot responses.
- Per-job ``CostAccumulator`` instances.
- Lazy disk scan for historical reports.
- Deletion of a job and its artifacts.

Change log
----------
- ``report_html`` replaced with ``report_path`` + ``report_format``.
  The old design put the markdown path into the ``report_html`` field
  when the run produced markdown, which then served markdown with the
  HTML mime type and the report sandbox CSP. ``report_html`` is kept
  as a read-only alias for callers that have not been updated, but
  every writer now goes through ``record_report(job_id, path, fmt)``.
- Every dict on the registry is now guarded by an explicit lock. The
  cancel-event and worker-handle dicts were previously unguarded.
- Disk scan infers a real mode from the target string instead of
  hardcoding ``"unknown"``.
- ``get_cost_accumulator`` is public; the chat route reads it to feed
  LLM call bytes into the running job's accumulator.
"""

from __future__ import annotations

import glob
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from discord_osint.costs import CostAccumulator
from discord_osint.utils import CACHE_DIR


_REPORT_FILE_RE   = re.compile(r"^report_(.+?)_(\d{8}_\d{6})\.html$")
_MANIFEST_FILE_RE = re.compile(r"^manifest_(.+?)_(\d{8}_\d{6})\.json$")

_EMAIL_LIKE_RE   = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
_PHONE_LIKE_RE   = re.compile(r"^\+?\d[\d\s\-()]{6,}$")
_DOMAIN_LIKE_RE  = re.compile(r"^[a-z0-9\-]+(\.[a-z0-9\-]+)+$")
_URL_LIKE_RE     = re.compile(r"^https?://", re.IGNORECASE)
_DISCORD_TAG_RE  = re.compile(r"^discord:", re.IGNORECASE)


def secure_delete(path: str) -> bool:
    """Overwrite a file with random bytes, fsync, then unlink."""
    try:
        size = os.path.getsize(path)
        with open(path, "wb") as f:
            if size > 0:
                f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
        os.unlink(path)
        return True
    except OSError:
        return False


def _infer_mode(target: str) -> str:
    """
    Best-effort mode inference for a job recovered from disk.

    Historical jobs whose report predates the current process have no
    recorded mode. Guessing from the target string is a heuristic, but
    it is strictly better than hardcoding ``"unknown"`` for every
    recovered job, which made mode-based filtering useless.
    """
    t = (target or "").strip()
    if not t:
        return "unknown"
    if _URL_LIKE_RE.match(t):
        # Not every URL is a url-module run — an image module target is
        # also a URL — but url is the closest correct answer without
        # reading the report.
        return "url"
    if _DISCORD_TAG_RE.match(t):
        return "discord"
    if _EMAIL_LIKE_RE.match(t):
        return "email"
    if _PHONE_LIKE_RE.match(t):
        return "phone"
    if _DOMAIN_LIKE_RE.match(t):
        return "domain"
    return "manual"


class JobRegistry:
    """Thread-safe registry of live and historical investigations."""

    def __init__(self, cache_dir: Optional[str] = None) -> None:
        self._cache_dir = cache_dir or CACHE_DIR

        self._jobs: dict[str, dict] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._workers: dict[str, threading.Thread] = {}
        self._pivot_responses: dict[str, dict] = {}
        self._costs: dict[str, CostAccumulator] = {}

        self._jobs_lock   = threading.RLock()
        self._cancel_lock = threading.Lock()
        self._worker_lock = threading.Lock()
        self._pivot_lock  = threading.Lock()
        self._cost_lock   = threading.Lock()

        self._scanned     = False

    # ------------------------------------------------------------------ #
    # Job lifecycle
    # ------------------------------------------------------------------ #

    def create(
        self,
        *,
        job_id: str,
        target: str,
        mode: str,
        cancel_event: threading.Event,
        case_id: str = "",
        target_key: str = "",
    ) -> dict:
        """
        Register a new job.

        ``target`` is the operator-facing label (may be truncated for
        display). ``target_key`` is the artifact filename key from
        ``utils.intel_target_key`` — the value the pipeline actually
        embeds in ``intel_*.json`` / ``report_*.html``. Callers that
        know the untruncated seed must pass it; ``find_intel_path``
        falls back to ``target`` only for legacy records.
        """
        record = {
            "id":            job_id,
            "target":        target,
            "target_key":    str(target_key or ""),
            "mode":          mode,
            "case_id":       case_id or "",
            "started_at":    datetime.now(timezone.utc).isoformat(),
            "status":        "running",
            "report_path":   None,
            "report_format": "",
            "report_html":   None,     # read-only alias; see _write_report_fields
            "intel_path":    None,
            "manifest_path": None,
            "cancel_event":  cancel_event,
        }
        with self._jobs_lock:
            self._jobs[job_id] = record
        with self._cancel_lock:
            self._cancel_events[job_id] = cancel_event
        return record

    def get(self, job_id: str) -> Optional[dict]:
        with self._jobs_lock:
            return self._jobs.get(job_id)

    def list_all(
        self,
        *,
        case_id: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> list[dict]:
        self._ensure_scanned()
        with self._jobs_lock:
            jobs = list(self._jobs.values())
        if case_id is not None:
            jobs = [j for j in jobs if j.get("case_id") == case_id]
        jobs.sort(key=lambda j: j.get("started_at", ""), reverse=True)
        if offset is not None:
            jobs = jobs[offset:]
        if limit is not None:
            jobs = jobs[:limit]
        return jobs

    def count_all(self, *, case_id: Optional[str] = None) -> int:
        self._ensure_scanned()
        with self._jobs_lock:
            jobs = list(self._jobs.values())
        if case_id is not None:
            jobs = [j for j in jobs if j.get("case_id") == case_id]
        return len(jobs)

    def list_running(self) -> list[dict]:
        with self._jobs_lock:
            return [j for j in self._jobs.values() if j.get("status") == "running"]

    def list_jobs_older_than(self, days: int) -> list[dict]:
        if days <= 0:
            return []
        cutoff = datetime.now(timezone.utc).timestamp() - (days * 86400)
        out: list[dict] = []
        self._ensure_scanned()
        with self._jobs_lock:
            for job in self._jobs.values():
                if job.get("status") == "running":
                    continue
                started = job.get("started_at", "")
                if not started:
                    continue
                try:
                    ts = datetime.fromisoformat(started).timestamp()
                except ValueError:
                    continue
                if ts < cutoff:
                    out.append(job)
        return out

    def mark_status(self, job_id: str, status: str) -> None:
        with self._jobs_lock:
            if job_id in self._jobs:
                self._jobs[job_id]["status"] = status

    # ------------------------------------------------------------------ #
    # Artifact recording
    # ------------------------------------------------------------------ #

    def record_report(self, job_id: str, path: str, fmt: str = "html") -> None:
        """
        Record the primary report artifact.

        ``fmt`` is one of ``"html"``, ``"markdown"``, or ``"json"``.
        ``report_html`` is maintained as a read-only compatibility
        alias when the format is html, so older callers that read that
        field still get a path for the common case.
        """
        with self._jobs_lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["report_path"]   = path
            job["report_format"] = fmt
            if fmt == "html":
                job["report_html"] = path

    def record_intel(self, job_id: str, path: str) -> None:
        with self._jobs_lock:
            if job_id in self._jobs:
                self._jobs[job_id]["intel_path"] = path

    def record_manifest(self, job_id: str, path: str) -> None:
        with self._jobs_lock:
            if job_id in self._jobs:
                self._jobs[job_id]["manifest_path"] = path

    # ------------------------------------------------------------------ #
    # Cost tracking
    # ------------------------------------------------------------------ #

    def register_cost_accumulator(
        self,
        job_id: str,
        accumulator: CostAccumulator,
    ) -> None:
        """Attach a cost accumulator to a job."""
        with self._cost_lock:
            self._costs[job_id] = accumulator

    def get_cost_accumulator(self, job_id: str) -> Optional[CostAccumulator]:
        with self._cost_lock:
            return self._costs.get(job_id)

    def get_cost_snapshot(self, job_id: str) -> Optional[dict]:
        """Return a serialisable cost summary for a job, or None."""
        acc = self.get_cost_accumulator(job_id)
        if acc is None:
            return None
        return acc.snapshot()

    # ------------------------------------------------------------------ #
    # Deletion
    # ------------------------------------------------------------------ #

    def delete_job(
        self,
        job_id: str,
        *,
        secure: bool = True,
    ) -> tuple[bool, list[str], str]:
        with self._jobs_lock:
            job = self._jobs.get(job_id)
        if job is None:
            return False, [], "job not found"
        if job.get("status") == "running":
            return False, [], "job is running; stop it first"

        removed: list[str] = []
        seen: set[str] = set()
        for key in ("report_path", "report_html", "intel_path", "manifest_path"):
            path = job.get(key)
            if not path or path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            ok = secure_delete(path) if secure else self._unlink(path)
            if ok:
                removed.append(path)

        with self._jobs_lock:
            self._jobs.pop(job_id, None)
        with self._cost_lock:
            self._costs.pop(job_id, None)
        self.teardown(job_id)
        return True, removed, ""

    @staticmethod
    def _unlink(path: str) -> bool:
        try:
            os.unlink(path)
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------ #
    # Case aggregation
    # ------------------------------------------------------------------ #

    def list_cases(self) -> list[dict]:
        self._ensure_scanned()
        with self._jobs_lock:
            jobs = list(self._jobs.values())

        by_case: dict[str, list[dict]] = {}
        for j in jobs:
            cid = j.get("case_id") or ""
            if not cid:
                continue
            by_case.setdefault(cid, []).append(j)

        out: list[dict] = []
        for cid, cjobs in by_case.items():
            cjobs.sort(key=lambda j: j.get("started_at", ""))
            out.append({
                "case_id":       cid,
                "job_count":     len(cjobs),
                "first_started": cjobs[0].get("started_at", ""),
                "last_started":  cjobs[-1].get("started_at", ""),
                "targets":       [j.get("target", "") for j in cjobs],
                "job_ids":       [j["id"] for j in cjobs],
            })
        out.sort(key=lambda c: c["last_started"], reverse=True)
        return out

    # ------------------------------------------------------------------ #
    # Cancel events
    # ------------------------------------------------------------------ #

    def get_cancel_event(self, job_id: str) -> Optional[threading.Event]:
        with self._cancel_lock:
            return self._cancel_events.get(job_id)

    def signal_cancel(self, job_id: str) -> bool:
        with self._cancel_lock:
            ev = self._cancel_events.get(job_id)
        if ev is None:
            return False
        ev.set()
        return True

    # ------------------------------------------------------------------ #
    # Worker thread handles
    # ------------------------------------------------------------------ #

    def register_worker(self, job_id: str, thread: threading.Thread) -> None:
        with self._worker_lock:
            self._workers[job_id] = thread

    def get_worker(self, job_id: str) -> Optional[threading.Thread]:
        with self._worker_lock:
            return self._workers.get(job_id)

    # ------------------------------------------------------------------ #
    # Pivot confirmation
    # ------------------------------------------------------------------ #

    def create_pivot_slot(self, job_id: str) -> dict:
        slot = {
            "event":         threading.Event(),
            "pending_seeds": [],
            "approved":      None,
        }
        with self._pivot_lock:
            self._pivot_responses[job_id] = slot
        return slot

    def get_pivot_slot(self, job_id: str) -> Optional[dict]:
        with self._pivot_lock:
            return self._pivot_responses.get(job_id)

    def respond_to_pivot(self, job_id: str, approved: list) -> bool:
        with self._pivot_lock:
            slot = self._pivot_responses.get(job_id)
        if slot is None:
            return False
        slot["approved"] = approved
        slot["event"].set()
        return True

    # ------------------------------------------------------------------ #
    # Teardown
    # ------------------------------------------------------------------ #

    def teardown(self, job_id: str) -> None:
        with self._cancel_lock:
            self._cancel_events.pop(job_id, None)
        with self._worker_lock:
            self._workers.pop(job_id, None)
        with self._pivot_lock:
            self._pivot_responses.pop(job_id, None)

    # ------------------------------------------------------------------ #
    # Intel lookup
    # ------------------------------------------------------------------ #

    def _within_cache(self, path: str) -> bool:
        """
        True when *path* resolves inside the cache directory.

        ``find_intel_path``'s result is handed straight to ``open()`` by
        ``/api/investigations/<job_id>``. Recorded paths come from the
        pipeline today, but confining the result keeps that route from
        becoming an arbitrary-file-read primitive if a future writer
        ever records an attacker-influenced path. ``realpath`` on both
        sides so a symlink cannot escape.
        """
        try:
            root = os.path.realpath(self._cache_dir)
            real = os.path.realpath(path)
        except OSError:
            return False
        return real == root or real.startswith(root + os.sep)

    def find_intel_path(self, job: dict) -> Optional[str]:
        intel_path = job.get("intel_path")
        if (
            intel_path
            and self._within_cache(intel_path)
            and os.path.isfile(intel_path)
        ):
            return intel_path

        # Fall back to globbing the cache dir. This must use the
        # artifact filename key the pipeline wrote with, NOT the
        # human-facing label: the pipeline names snapshots
        # intel_<stable_target_id(seed)>_<ts>.json, while ``target`` is
        # a display string ("discord:123", an email, a URL cut to 60
        # chars). Globbing the label matched nothing for every live
        # job, so this whole branch was dead code.
        #
        # ``target`` remains the last resort for legacy records written
        # before target_key existed, and for disk-recovered jobs whose
        # label *is* the key.
        target = job.get("target_key") or job.get("target", "")
        if not target:
            return None
        # glob.escape neutralises *, ?, and [ ] in the target before it
        # becomes a glob pattern. Without it, a target containing one of
        # those characters (batch mode's target sanitisation was added
        # separately, but this is the fallback path and should not rely
        # on every caller having gone through it) turns "the file for
        # this job" into "any file matching this pattern" — a target of
        # literal "*" matched every intel snapshot in the cache dir,
        # including other investigations'.
        pattern = os.path.join(self._cache_dir, f"intel_{glob.escape(target)}_*.json")
        candidates = sorted(
            glob.glob(pattern),
            key=os.path.getmtime,
            reverse=True,
        )
        return candidates[0] if candidates else None

    # ------------------------------------------------------------------ #
    # Lazy disk scan
    # ------------------------------------------------------------------ #

    def _ensure_scanned(self) -> None:
        if self._scanned:
            return
        with self._jobs_lock:
            if self._scanned:
                return
            self._scan_disk()
            self._scanned = True

    def _scan_disk(self) -> None:
        html_files = sorted(
            glob.glob(os.path.join(self._cache_dir, "report_*.html")),
            key=os.path.getmtime,
        )
        for html_path in html_files:
            base = os.path.basename(html_path)
            m = _REPORT_FILE_RE.match(base)
            if not m:
                continue
            target_id = m.group(1)
            ts_str    = m.group(2)
            job_id    = str(uuid.uuid5(uuid.NAMESPACE_URL, html_path))

            intel_files = sorted(
                glob.glob(os.path.join(self._cache_dir, f"intel_{target_id}_*.json")),
                key=os.path.getmtime,
            )
            intel_path = intel_files[-1] if intel_files else None

            manifest_path = os.path.join(
                self._cache_dir, f"manifest_{target_id}_{ts_str}.json",
            )
            if not os.path.isfile(manifest_path):
                manifest_path = None

            case_id = self._read_case_from_manifest(manifest_path)

            try:
                started_at = datetime.strptime(ts_str, "%Y%m%d_%H%M%S").replace(
                    tzinfo=timezone.utc,
                ).isoformat()
            except ValueError:
                started_at = datetime.fromtimestamp(
                    os.path.getmtime(html_path), tz=timezone.utc,
                ).isoformat()

            self._jobs[job_id] = {
                "id":            job_id,
                "target":        target_id,
                # For disk-recovered jobs the label and the key are the
                # same string — it was parsed out of the report
                # filename — but record it explicitly so the glob does
                # not depend on that coincidence.
                "target_key":    target_id,
                "mode":          _infer_mode(target_id),
                "case_id":       case_id,
                "started_at":    started_at,
                "status":        "done",
                "report_path":   html_path,
                "report_format": "html",
                "report_html":   html_path,
                "intel_path":    intel_path,
                "manifest_path": manifest_path,
            }

    @staticmethod
    def _read_case_from_manifest(manifest_path: Optional[str]) -> str:
        if not manifest_path or not os.path.isfile(manifest_path):
            return ""
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return ""
        cid = data.get("case_id") if isinstance(data, dict) else None
        return str(cid) if cid else ""
