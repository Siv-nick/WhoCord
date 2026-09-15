
"""
web_services/batch.py
---------------------
Batch mode: run the same pipeline module against a list of targets.

Design
------
A batch is N ordinary investigations sharing a case_id. Each target
gets its own job in the registry, but the worker threads are drawn
from a single ``ThreadPoolExecutor`` bounded by ``max_workers``.
The previous implementation created one OS thread per target and
blocked all excess threads on a semaphore — a 500-target batch
spawned 500 Python threads, each consuming stack and RSS while
waiting. The executor bounds both concurrency and resource use.

Concurrency
-----------
Two caps apply to a batch worker:

  * A per-batch cap (``max_workers``, default 3) enforced by the
    executor itself.
  * A process-wide cap (``global_semaphore``, passed by web_app.py)
    shared with /run, acquired with a cancellable wait.

The global acquire blocks in 1-second slices so the worker can
observe its cancel event between polls. A queued batch job stays
cancellable instead of blocking indefinitely.

Worker handle registration
--------------------------
The registry's ``get_worker(job_id)`` is expected to return the
thread currently running a job. With the executor, that thread is a
pool worker, not a dedicated one. The ``_worker`` method registers
``threading.current_thread()`` on entry so the handle is present
for the job's lifetime.

Pivot confirmation
------------------
Batch runs set no ``_pivot_confirm_fn``, which makes the pipeline's
confirm callback a no-op. Combined with the fail-closed pivot timeout,
a batch job never blocks on user input.

Spend caps
----------
Each batch job gets its own ``CostAccumulator`` built from the same
config keys the /run route uses, so ``MAX_LLM_SPEND_USD`` and
``MAX_ENRICHMENT_CREDITS`` apply to batch mode as well.
"""

from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from discord_osint.errors import InputValidationError
from discord_osint.utils.sanitizers import (
    sanitize_domain,
    sanitize_email,
    sanitize_phone,
    sanitize_url,
    sanitize_username,
)


_DEFAULT_MAX_WORKERS = 3


def _sanitise_for_mode(raw: str, mode: str) -> Optional[str]:
    """
    Route a batch target through the same per-mode sanitiser ``/run``
    uses, and return the cleaned value — or ``None`` if it doesn't
    survive sanitisation.

    Why this exists
    ----------------
    ``/run`` validates its single target through
    ``discord_osint.utils.sanitizers`` before it ever reaches a
    ``JobConfig``. Batch mode built its ``JobConfig`` straight from
    ``str(t)`` for every target in the list, so the same string was
    trusted or rejected depending on which endpoint it arrived through.

    That gap was reachable, not theoretical: an unsanitised target
    flows into external-tool argv (a target starting with ``-`` becomes
    a flag to ``holehe`` / ``maigret`` / ``h8mail``), and into
    ``JobRegistry.find_intel_path``, which globs
    ``intel_{target}_*.json`` — so a batch target of ``*`` matched
    other investigations' snapshots and returned them cross-case.

    ``probe`` and ``discord`` are intentionally not special-cased here:
    ``probe`` accepts a short opaque string by design (the stage
    auto-detects its type), and batch mode already refuses ``discord``
    targets before this function is reached.
    """
    if mode == "manual":
        try:
            return sanitize_username(raw)
        except InputValidationError:
            return None
    if mode == "email":
        cleaned = sanitize_email(raw)
        return cleaned or None
    if mode == "domain":
        try:
            return sanitize_domain(raw)
        except InputValidationError:
            return None
    if mode == "phone":
        cleaned = sanitize_phone(raw)
        return cleaned or None
    if mode in ("url", "image"):
        try:
            return sanitize_url(raw)
        except InputValidationError:
            return None
    if mode == "probe":
        # Same cap web_app._sanitize_probe applies: strip and truncate,
        # no character-set restriction — the stage auto-detects type
        # from arbitrary-looking input by design.
        cleaned = raw.strip()[:512]
        return cleaned or None
    # Unknown mode: refuse rather than pass through unsanitised.
    return None


class BatchRunner:
    """
    Creates and runs a batch of jobs.

    Parameters
    ----------
    registry:
        A JobRegistry instance.
    config_service:
        The process-wide ConfigService.
    global_semaphore:
        Shared semaphore that bounds total concurrent investigations
        (including /run). When None, a private one is created with the
        default capacity — useful for tests.
    """

    def __init__(
        self,
        registry: Any,
        config_service: Any,
        global_semaphore: Optional[threading.Semaphore] = None,
    ) -> None:
        self._registry       = registry
        self._config_service = config_service
        self._global_sem     = global_semaphore or threading.Semaphore(4)
        self._lock           = threading.Lock()
        self._batches: dict[str, dict] = {}
        self._executor: Optional[ThreadPoolExecutor] = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def start(
        self,
        targets: list[str],
        mode: str,
        case_id: str,
        *,
        max_workers: int = _DEFAULT_MAX_WORKERS,
    ) -> dict:
        """
        Spawn one job per target.

        Returns a summary dict: ``batch_id``, ``case_id``, ``job_ids``,
        ``targets_queued``, ``targets_skipped``.
        """
        batch_id = str(uuid.uuid4())

        cleaned: list[str] = []
        skipped: list[str] = []
        for t in targets:
            s = (t or "").strip()
            if not s:
                skipped.append(s)
                continue
            # The /run route sanitises every target through
            # utils.sanitizers before it reaches a JobConfig. Batch mode
            # did not, so the same input was trusted or rejected
            # depending on which endpoint it arrived at.
            #
            # That gap was load-bearing: an unsanitised target flows into
            # external tool argv (a leading "-" becomes a flag to holehe /
            # maigret / h8mail) and into JobRegistry.find_intel_path,
            # which globs intel_{target}_*.json — so a target of "*"
            # matched other investigations' snapshots and returned them.
            sanitised = _sanitise_for_mode(s, mode)
            if sanitised is None:
                skipped.append(s)
                continue
            cleaned.append(sanitised)

        if not cleaned:
            return {
                "batch_id":         batch_id,
                "case_id":          case_id,
                "job_ids":          [],
                "targets_queued":   0,
                "targets_skipped":  len(skipped),
                "error":            "no valid targets",
            }

        concurrency = max(1, int(max_workers))
        executor = ThreadPoolExecutor(
            max_workers=concurrency,
            thread_name_prefix="whocord-batch",
        )
        with self._lock:
            previous       = self._executor
            self._executor = executor

        # Starting a second batch used to overwrite self._executor and
        # drop the old one on the floor. Nothing then joined those
        # threads: max_workers became a *per-executor* cap rather than a
        # real one, so overlapping batches ran up to N×max_workers jobs
        # (bounded only by the global semaphore), and the abandoned pool
        # leaked its threads for the life of the process.
        #
        # Drain queued-but-unstarted work from the old pool and stop
        # accepting new work. wait=False so an in-flight investigation
        # is allowed to finish without blocking this request.
        if previous is not None:
            try:
                previous.shutdown(wait=False, cancel_futures=True)
            except TypeError:  # cancel_futures is 3.9+
                previous.shutdown(wait=False)

        job_ids: list[str] = []
        pending: list[tuple[str, str, Any, threading.Event]] = []

        for target in cleaned:
            job_id = str(uuid.uuid4())
            cancel_event = threading.Event()

            from discord_osint.utils import intel_target_key

            self._registry.create(
                job_id=job_id,
                target=target,
                mode=mode,
                # Batch targets are already sanitised and untruncated,
                # so the target doubles as the seed here.
                target_key=intel_target_key(mode, target),
                cancel_event=cancel_event,
                case_id=case_id,
            )
            self._registry.create_pivot_slot(job_id)
            job_ids.append(job_id)

            base = self._config_service.to_dict()
            base["MODE"] = mode
            if mode == "discord":
                base["TARGET_USER_ID"] = target if target.isdigit() else None
            elif mode == "manual":
                base["MANUAL_USERNAME"] = target
            elif mode == "email":
                base["MANUAL_EMAIL"] = target
            elif mode == "domain":
                base["MANUAL_DOMAIN"] = target
            elif mode == "phone":
                base["MANUAL_PHONE"] = target
            elif mode == "url":
                base["MANUAL_URL"] = target
            elif mode == "image":
                base["MANUAL_IMAGE_URL"] = target
            elif mode == "probe":
                base["PROBE_STRING"] = target

            from discord_osint.config import JobConfig
            from discord_osint.costs import CostAccumulator

            job_config = JobConfig(base)
            job_config._cancel_event     = cancel_event
            job_config._job_id           = job_id
            job_config._case_id          = case_id
            job_config._phase3_emit      = None
            job_config._pivot_confirm_fn = None

            input_rate  = float(getattr(self._config_service, "LLM_COST_PER_1K_INPUT", 0) or 0)
            output_rate = float(getattr(self._config_service, "LLM_COST_PER_1K_OUTPUT", 0) or 0)
            max_usd     = float(getattr(self._config_service, "MAX_LLM_SPEND_USD", 0) or 0)
            max_credits = float(getattr(self._config_service, "MAX_ENRICHMENT_CREDITS", 0) or 0)
            cost_acc = CostAccumulator(
                input_rate=input_rate,
                output_rate=output_rate,
                max_usd=max_usd,
                max_credits=max_credits,
            )
            job_config._cost_accumulator = cost_acc
            self._registry.register_cost_accumulator(job_id, cost_acc)

            pending.append((job_id, mode, job_config, cancel_event))

        with self._lock:
            self._batches[batch_id] = {
                "batch_id":   batch_id,
                "case_id":    case_id,
                "mode":       mode,
                "job_ids":    list(job_ids),
                "targets":    list(cleaned),
                "started_at": None,
            }

        # Submit every target. The executor queues the excess; it does
        # not create more than `concurrency` OS threads.
        for job_id, mode, job_config, cancel_event in pending:
            executor.submit(
                self._worker_entry,
                job_id, mode, job_config, cancel_event,
            )

        return {
            "batch_id":         batch_id,
            "case_id":          case_id,
            "job_ids":          job_ids,
            "targets_queued":   len(job_ids),
            "targets_skipped":  len(skipped),
        }

    def get_batch(self, batch_id: str) -> Optional[dict]:
        with self._lock:
            return self._batches.get(batch_id)

    def list_batches(self) -> list[dict]:
        with self._lock:
            return list(self._batches.values())

    def shutdown(self, wait: bool = False) -> None:
        """
        Stop the current executor. Called from web_app's atexit hook.

        ``cancel_futures=True`` means queued jobs that have not yet
        started are discarded; running jobs are allowed to finish
        unless ``wait=False`` and the process exits before they do.
        """
        with self._lock:
            ex = self._executor
            self._executor = None
        if ex is not None:
            try:
                ex.shutdown(wait=wait, cancel_futures=True)
            except TypeError:
                # cancel_futures was added in 3.9; fall back to a plain
                # shutdown on older runtimes.
                ex.shutdown(wait=wait)

    # ------------------------------------------------------------------ #
    # Worker
    # ------------------------------------------------------------------ #

    def _worker_entry(
        self,
        job_id: str,
        mode: str,
        job_config: Any,
        cancel_event: threading.Event,
    ) -> None:
        """
        Executor entry point. Registers the running thread as the
        job's worker handle before handing off to ``_worker``.

        Without this, ``registry.get_worker(job_id)`` returns None for
        every batch job — a capability regression relative to the
        pre-pool implementation where each job had a dedicated thread.
        """
        self._registry.register_worker(job_id, threading.current_thread())
        try:
            self._worker(job_id, mode, job_config, cancel_event)
        finally:
            try:
                self._registry.teardown(job_id)
            except Exception:
                pass

    def _worker(
        self,
        job_id: str,
        mode: str,
        job_config: Any,
        cancel_event: threading.Event,
    ) -> None:
        """
        Run one batch job to completion.

        Acquires the global semaphore with a cancellable wait, then
        executes the pipeline. The per-batch concurrency cap is
        enforced by the executor itself; there is no second semaphore.
        """
        from discord_osint.config import set_active_config, reset_active_config
        from discord_osint import audit

        acquired_global = False
        while not acquired_global:
            if cancel_event.is_set():
                self._set_status(job_id, "cancelled")
                audit.write_event(
                    "investigation_finished",
                    job_id=job_id,
                    status="cancelled",
                    reason="cancelled while waiting for global slot",
                )
                return
            acquired_global = self._global_sem.acquire(timeout=1.0)

        try:
            self._set_status(job_id, "running")
            audit.write_event(
                "investigation_started",
                job_id=job_id,
                mode=mode,
                target=job_config.get("MANUAL_USERNAME", "") or "",
                case_id=job_config.get("_case_id", ""),
                batch=True,
            )

            def _emitter(event_type: str, payload: dict) -> None:
                try:
                    if event_type == "report_ready":
                        fmt  = payload.get("format", "")
                        path = payload.get("path", "")
                        if not os.path.isfile(path):
                            return
                        if fmt in ("html", "markdown", "json"):
                            self._registry.record_report(job_id, path, fmt)
                        elif fmt == "manifest":
                            self._registry.record_manifest(job_id, path)
                        elif fmt == "intel":
                            self._registry.record_intel(job_id, path)
                    elif event_type == "done":
                        intel_path = payload.get("intel_path", "")
                        if intel_path:
                            self._registry.record_intel(job_id, intel_path)
                    elif event_type == "third_party_contacted":
                        acc = self._registry.get_cost_accumulator(job_id)
                        if acc is not None:
                            try:
                                acc.record_llm_call(
                                    service=str(payload.get("service", "")),
                                    model=str(payload.get("model", "")),
                                    bytes_sent=int(payload.get("bytes_sent", 0) or 0),
                                    bytes_received=int(payload.get("bytes_received", 0) or 0),
                                    ok=bool(payload.get("ok", True)),
                                )
                            except Exception:
                                pass
                        audit.write_event(
                            "third_party_contacted",
                            job_id=job_id,
                            **{k: v for k, v in payload.items() if k != "job_id"},
                        )
                except Exception:
                    pass

            job_config._phase3_emit = _emitter

            token = set_active_config(job_config)
            try:
                from discord_osint.pipeline import (
                    run_module_pipeline,
                    run_osint_pipeline,
                )
                _MODULE_MODES = frozenset({
                    "email", "domain", "phone", "image", "url", "probe",
                })
                if mode in _MODULE_MODES:
                    run_module_pipeline(mode, job_config)
                else:
                    run_osint_pipeline(job_config)
            except Exception as exc:
                import traceback as _tb
                _tb.print_exc()
                audit.write_event(
                    "investigation_finished",
                    job_id=job_id,
                    status="error",
                    error=f"{type(exc).__name__}: {exc}",
                )
                self._set_status(job_id, "error")
                return
            finally:
                reset_active_config(token)

            final_status = "cancelled" if cancel_event.is_set() else "done"
            audit.write_event(
                "investigation_finished",
                job_id=job_id,
                status=final_status,
            )
            self._set_status(job_id, final_status)

        finally:
            self._global_sem.release()

    def _set_status(self, job_id: str, status: str) -> None:
        try:
            self._registry.mark_status(job_id, status)
        except Exception:
            pass
