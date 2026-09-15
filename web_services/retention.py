"""
web_services/retention.py
-------------------------
Background retention pass.

Reads ``RETENTION_DAYS`` from the config. When non-zero, once per
24 hours, deletes every non-running job whose ``started_at`` is older
than that many days. Deleting means removing the job record and
secure-deleting its artifacts (report, intel snapshot, manifest).

Design notes
------------
- The first pass runs on the first HTTP request, not at import time.
  This avoids running during tests, and it works whether the app is
  started via ``python web_app.py`` or via a WSGI server.
- The interval is fixed at 24 hours. Shortening it would hammer the
  disk for no benefit — retention is a slow-moving policy, not a
  real-time action.
- Every deletion writes an ``investigation_deleted`` audit event
  *before* the file is unlinked, so the audit trail outlives the data.
- Shutdown is via a ``threading.Event`` the caller sets from an
  ``atexit`` handler, so a clean process exit stops the thread.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from discord_osint import audit


_INTERVAL_SECONDS = 24 * 60 * 60  # 24 hours


class RetentionManager:
    """
    Coordinates the background retention pass.

    Parameters
    ----------
    registry:
        A JobRegistry instance.
    config_service:
        Anything with a ``.retention_days`` int property.
    """

    def __init__(self, registry: Any, config_service: Any) -> None:
        self._registry       = registry
        self._config_service = config_service
        self._shutdown       = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started        = False
        self._lock           = threading.Lock()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start_once(self) -> None:
        """
        Start the background thread if it is not already running.

        Safe to call from a ``before_request`` handler on every
        request — the lock ensures only the first call spawns the
        thread.
        """
        with self._lock:
            if self._started:
                return
            self._started = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="whocord-retention",
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the thread to exit and wait briefly for it to do so."""
        self._shutdown.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------ #
    # Pass logic
    # ------------------------------------------------------------------ #

    def run_pass(self) -> dict:
        """
        Execute one retention pass. Returns a summary dict.

        Called by the background loop and, in tests, directly. Public
        so tests can exercise the logic without waiting 24 hours.
        """
        try:
            days = int(getattr(self._config_service, "retention_days", 0) or 0)
        except (TypeError, ValueError):
            days = 0

        if days <= 0:
            return {
                "ran":     False,
                "reason":  "retention disabled",
                "deleted": 0,
                "failed":  0,
            }

        candidates = self._registry.list_jobs_older_than(days)
        deleted = 0
        failed  = 0
        details: list[dict] = []

        for job in candidates:
            job_id = job.get("id", "")
            target = job.get("target", "")
            started = job.get("started_at", "")

            # Audit *before* deletion. If the process dies between the
            # audit write and the unlink, the audit log correctly says
            # the job was deleted even though the file still exists.
            audit.write_event(
                "investigation_deleted",
                job_id=job_id,
                target=target,
                started_at=started,
                reason=f"retention>{days}d",
            )

            ok, files, err = self._registry.delete_job(job_id, secure=True)
            if ok:
                deleted += 1
                details.append({
                    "job_id": job_id,
                    "files_removed": len(files),
                })
            else:
                failed += 1
                details.append({
                    "job_id": job_id,
                    "error":  err,
                })

        audit.write_event(
            "retention_pass_completed",
            retention_days=days,
            candidates=len(candidates),
            deleted=deleted,
            failed=failed,
        )

        return {
            "ran":     True,
            "days":    days,
            "deleted": deleted,
            "failed":  failed,
            "details": details,
        }

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _loop(self) -> None:
        # First pass immediately, then every 24 hours until shutdown.
        while not self._shutdown.is_set():
            try:
                self.run_pass()
            except Exception as exc:
                # A retention failure must not kill the thread. Log it
                # to the audit stream so it is at least visible.
                audit.write_event(
                    "retention_pass_error",
                    error=f"{type(exc).__name__}: {exc}",
                )
            if self._shutdown.wait(timeout=_INTERVAL_SECONDS):
                return