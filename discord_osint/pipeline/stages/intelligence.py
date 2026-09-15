"""
discord_osint/pipeline/stages/intelligence.py
-----------------------------------------------
IntelligenceStage – run the IntelligenceEngine and store the result in
``ctx.intel_core.intel["intelligence_report"]``.

Per-job LLM config and structured logging
-----------------------------------------
The engine is constructed with ``ctx.config`` and its ``run`` is given
``ctx.log`` so LLM settings come from the job and third-party contact
events are captured.
"""

from __future__ import annotations

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...intelligence.engine import IntelligenceEngine


class IntelligenceStage(Stage):
    name = "intelligence"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        groq_api_key: str = getattr(ctx.config, "GROQ_API_KEY", "") or ""

        ctx.log.info("== Intelligence Engine ==")
        emit("progress", {"message": "Starting intelligence analysis"})

        engine = IntelligenceEngine(
            groq_api_key=groq_api_key,
            config=ctx.config,
        )

        try:
            report = engine.run(
                intel=ctx.intel_core.intel,
                avatar_urls=ctx.avatar_urls,
                emit=emit,
                log=ctx.log,
            )
        except Exception as exc:
            ctx.log.error(f"[!] IntelligenceEngine raised an unexpected error: {exc}")
            import traceback
            traceback.print_exc()
            report = {
                "entities":      [],
                "entity_counts": {},
                "graph_summary": {},
                "correlations":  [],
                "narrative":     {},
                "error":         str(exc),
            }

        ctx.intel_core.intel["intelligence_report"] = report

        entity_count      = len(report.get("entities", []))
        correlation_count = len(report.get("correlations", []))
        has_narrative     = bool(report.get("narrative"))

        emit("finding", {
            "type":              "intelligence_report",
            "entity_count":      entity_count,
            "correlation_count": correlation_count,
            "has_narrative":     has_narrative,
        })

        ctx.log.info(
            f"== Intelligence stage complete – {entity_count} entities, "
            f"{correlation_count} correlations, "
            f"narrative={'yes' if has_narrative else 'no'}"
        )