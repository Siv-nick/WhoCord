"""
discord_osint/pipeline/base.py
-------------------------------
Stage ABC and Pipeline runner.

Phase 3 edit
------------
``Pipeline.run()`` gains an optional ``pivot_confirm_fn`` parameter that is
threaded down to ``process_pending_seeds()``.  The confirm function is passed
recursively into every sub-pipeline so deep pivots also pause for confirmation.
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
    ) -> None:
        """
        Run all stages sequentially.

        Parameters
        ----------
        emit:
            Structured event callback.
        pivot_config:
            Phase 2 pivot settings.
        seed_queue:
            Shared seed registry.
        pivot_confirm_fn:
            Optional callable; when supplied and ``pivot_config.require_confirm``
            is True, it is called before each pivot depth batch to let the user
            approve or filter the seeds.  Passed recursively to sub-pipelines.
        """
        _pivot_active = (
            pivot_config is not None
            and seed_queue is not None
            and pivot_config.enabled
        )

        # ------------------------------------------------------------------ #
        # Stage loop                                                           #
        # ------------------------------------------------------------------ #
        aborted = False
        for stage in self.stages:
            try:
                emit("stage_start", {"stage": stage.name, "depth": self.context.depth})
                stage.run(self.context, emit)
                emit("stage_done",  {"stage": stage.name, "depth": self.context.depth})

            except PipelineAbortError as exc:
                print(
                    f"\n[!] Pipeline aborted at '{stage.name}'"
                    + (f" [d={self.context.depth}]" if self.context.depth else "")
                    + f": {exc.reason}"
                )
                emit("abort", {"stage": stage.name, "depth": self.context.depth, "reason": exc.reason})
                aborted = True
                break

            except Exception as exc:
                print(
                    f"\n[!] Stage '{stage.name}'"
                    + (f" [d={self.context.depth}]" if self.context.depth else "")
                    + f" raised an unexpected error – continuing.\n    {exc}"
                )
                traceback.print_exc()
                emit("stage_error", {"stage": stage.name, "depth": self.context.depth, "error": str(exc)})
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
        # Save                                                                 #
        # ------------------------------------------------------------------ #
        saved       = self.context.intel_core.save_state()
        depth_label = f" [d={self.context.depth}]" if self.context.depth else ""
        print(f"\n== Pipeline{depth_label} complete – intel saved to {saved} ==")
        emit("done", {"intel_path": saved, "depth": self.context.depth})

        # ------------------------------------------------------------------ #
        # Pivot processing                                                     #
        # ------------------------------------------------------------------ #
        if _pivot_active and not aborted:
            self._process_pivot_seeds(pivot_config, seed_queue, emit, pivot_confirm_fn)

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

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
