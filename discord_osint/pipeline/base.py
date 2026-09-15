"""
discord_osint/pipeline/base.py
-------------------------------
Stage ABC and Pipeline runner.

Cancellation
------------
``Pipeline.run()`` accepts an optional ``cancel_event`` (a
``threading.Event``). When set, the pipeline stops at the next stage
boundary and emits an ``abort`` event.

Evidence snapshot
-----------------
After ``save_state()``, the runner records the returned path on
``context.intel_snapshot_path``. The reporting stage reads it to
include the raw intel JSON in the signed evidence manifest.

Spend cap
---------
Between stages, if the job config carries a ``CostAccumulator`` whose
``exceeded()`` returns True, the pipeline aborts with a
``spend_cap`` reason. This is a checkpoint — the LLM call sites also
check the cap directly so a single expensive call cannot overshoot by
more than one call's worth.
"""

from __future__ import annotations

import traceback
from abc import ABC, abstractmethod
from typing import Callable, Optional, TYPE_CHECKING

from .context import InvestigationContext
from ..errors import PipelineAbortError

if TYPE_CHECKING:
    from .pivot import PivotConfig, SeedQueue, ConfirmFn

EmitFn = Callable[[str, dict], None]


def _noop_emit(event_type: str, payload: dict) -> None:
    pass


class Stage(ABC):
    name: str = "unnamed_stage"

    @abstractmethod
    def run(self, ctx: InvestigationContext, emit: EmitFn = _noop_emit) -> None: ...

    def __repr__(self) -> str:
        return f"<Stage: {self.name}>"


class Pipeline:
    """
    Executes a list of Stage objects in order against a shared context.
    """

    def __init__(self, stages: list[Stage], context: InvestigationContext) -> None:
        self.stages  = stages
        self.context = context

    def run(
        self,
        emit: EmitFn = _noop_emit,
        pivot_config: Optional["PivotConfig"] = None,
        seed_queue: Optional["SeedQueue"]     = None,
        pivot_confirm_fn: Optional["ConfirmFn"] = None,
        cancel_event=None,
    ) -> None:
        if cancel_event is None:
            cancel_event = getattr(self.context.config, "_cancel_event", None)

        cost_acc = getattr(self.context.config, "_cost_accumulator", None)

        _pivot_active = (
            pivot_config is not None
            and seed_queue is not None
            and pivot_config.enabled
        )

        depth_label = f" [d={self.context.depth}]" if self.context.depth else ""

        aborted = False

        for stage in self.stages:
            # --- Cancellation check between stages ---
            if cancel_event is not None and cancel_event.is_set():
                print(
                    f"\n[!] Cancellation requested before stage '{stage.name}'"
                    f"{depth_label} — stopping."
                )
                emit("abort", {
                    "stage":  stage.name,
                    "depth":  self.context.depth,
                    "reason": "cancelled by user",
                })
                aborted = True
                break

            # --- Spend cap check between stages ---
            if cost_acc is not None:
                try:
                    exceeded, reason = cost_acc.exceeded()
                except Exception:
                    exceeded, reason = False, ""
                if exceeded:
                    print(
                        f"\n[!] Spend cap reached before stage '{stage.name}'"
                        f"{depth_label} — stopping. {reason}"
                    )
                    emit("abort", {
                        "stage":  stage.name,
                        "depth":  self.context.depth,
                        "reason": f"spend_cap: {reason}",
                    })
                    aborted = True
                    break

            try:
                emit("stage_start", {"stage": stage.name, "depth": self.context.depth})
                stage.run(self.context, emit)
                emit("stage_done",  {"stage": stage.name, "depth": self.context.depth})

            except PipelineAbortError as exc:
                print(
                    f"\n[!] Pipeline aborted at '{stage.name}'"
                    + depth_label
                    + f": {exc.reason}"
                )
                emit("abort", {
                    "stage":  stage.name,
                    "depth":  self.context.depth,
                    "reason": exc.reason,
                })
                aborted = True
                break

            except Exception as exc:
                print(
                    f"\n[!] Stage '{stage.name}'"
                    + depth_label
                    + f" raised an unexpected error – continuing.\n    {exc}"
                )
                traceback.print_exc()
                emit("stage_error", {
                    "stage": stage.name,
                    "depth": self.context.depth,
                    "error": str(exc),
                })
                if _pivot_active:
                    self._scan_seeds(pivot_config, seed_queue)
                continue

            if _pivot_active:
                n = self._scan_seeds(pivot_config, seed_queue)
                if n:
                    print(
                        f"  [PIVOT] {n} new seed(s) queued at depth "
                        f"{self.context.depth + 1} after '{stage.name}'"
                    )

        # ------------------------------------------------------------------ #
        # Save (even on abort — partial state is still useful)               #
        # ------------------------------------------------------------------ #
        saved = self.context.intel_core.save_state()
        self.context.intel_snapshot_path = saved

        cancelled = (
            aborted
            and cancel_event is not None
            and cancel_event.is_set()
        )
        status_word = "cancelled" if cancelled else ("aborted" if aborted else "complete")

        print(f"\n== Pipeline{depth_label} {status_word} – intel saved to {saved} ==")
        emit("done", {"intel_path": saved, "depth": self.context.depth})

        if _pivot_active and not aborted:
            self._process_pivot_seeds(pivot_config, seed_queue, emit, pivot_confirm_fn)

    def _scan_seeds(self, pivot_config: "PivotConfig", seed_queue: "SeedQueue") -> int:
        from .pivot import scan_for_new_seeds
        return scan_for_new_seeds(
            ctx=self.context,
            seed_queue=seed_queue,
            pivot_config=pivot_config,
            target_depth=self.context.depth + 1,
        )

    def _process_pivot_seeds(
        self,
        pivot_config: "PivotConfig",
        seed_queue: "SeedQueue",
        emit: EmitFn,
        pivot_confirm_fn: Optional["ConfirmFn"] = None,
    ) -> None:
        from .pivot import process_pending_seeds
        process_pending_seeds(
            ctx=self.context,
            seed_queue=seed_queue,
            pivot_config=pivot_config,
            emit=emit,
            confirm_fn=pivot_confirm_fn,
        )