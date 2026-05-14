"""
discord_osint/pipeline/stages/intelligence.py
-----------------------------------------------
IntelligenceStage – run the :class:`IntelligenceEngine` and store the
result in ``ctx.intel_core.intel["intelligence_report"]``.

Position in the pipeline (builder.py):
  AnalysisStage → **IntelligenceStage** → EmailIntelStage → ReportingStage

This placement means:
- The stage has access to all social-profile data, names, emails,
  location clues, and WHOIS / Wayback results gathered so far.
- The email-intel stage (Holehe, HIBP, GHunt …) runs afterwards, so
  breach data is NOT yet in the graph.  That is intentional: Phase 2
  can re-run the engine after email-intel for a richer second pass.

Reads from ctx
--------------
ctx.intel_core.intel  – all data produced by earlier stages
ctx.avatar_urls       – image URLs collected during scraping/discord fetch
ctx.config.GROQ_API_KEY – Groq API key (optional; skips narrative if absent)

Writes to ctx
-------------
ctx.intel_core.intel["intelligence_report"] – dict with keys:
    entities, entity_counts, graph_summary, correlations, narrative
"""

from __future__ import annotations

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...intelligence.engine import IntelligenceEngine


class IntelligenceStage(Stage):
    """
    Knowledge-graph construction, correlation detection, and AI narrative.
    """

    name = "intelligence"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        groq_api_key: str = getattr(ctx.config, "GROQ_API_KEY", "") or ""

        print("\n" + "=" * 60)
        print("== Intelligence Engine")
        print("=" * 60)
        emit("progress", {"message": "Starting intelligence analysis"})

        engine = IntelligenceEngine(groq_api_key=groq_api_key)

        try:
            report = engine.run(
                intel=ctx.intel_core.intel,
                avatar_urls=ctx.avatar_urls,
                emit=emit,
            )
        except Exception as exc:
            # Surface the error but don't abort – reporting still needs to run.
            print(f"  [!] IntelligenceEngine raised an unexpected error: {exc}")
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

        # Store in intel so ReportingStage can render it
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

        print(
            f"\n== Intelligence stage complete – "
            f"{entity_count} entities, "
            f"{correlation_count} correlations, "
            f"narrative={'yes' if has_narrative else 'no'}"
        )
