"""
discord_osint/intelligence/engine.py
--------------------------------------
``IntelligenceEngine`` – orchestrates the four-step intelligence pipeline:

  1. **Extract**     – parse raw intel into typed entities
  2. **Graph**       – build a networkx knowledge graph
  3. **Correlations**– run all detector functions
  4. **Narrative**   – generate an AI intelligence report via Groq

Usage
-----
::

    engine = IntelligenceEngine(groq_api_key=cfg.GROQ_API_KEY)
    report = engine.run(
        intel=ctx.intel_core.intel,
        avatar_urls=ctx.avatar_urls,
        emit=emit,
        cancel_event=getattr(cfg, "_cancel_event", None),
    )
    # report is a plain dict – safe to store in intel_core

Cancellation
------------
The engine checks ``cancel_event`` before each of the four steps. The
most useful check is the one before step 4 — if the user hit Stop while
the graph was being built, we skip the ~45 s Groq narrative roundtrip
rather than burning the call. The returned report is a partial dict with
whatever steps completed.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Set

from .entities import BaseEntity
from .extractor import extract_entities
from .graph import build_graph, graph_summary
from .correlations import run_all_detectors, Correlation
from ..utils import log_trace

# Type alias matching the pipeline emit signature
EmitFn = Callable[[str, dict], None]
_NOOP: EmitFn = lambda *_: None


class IntelligenceEngine:
    """
    Orchestrate entity extraction → graph construction →
    correlation detection → AI narrative generation.

    Parameters
    ----------
    groq_api_key:
        Groq API key.  When empty the narrative step is skipped
        (no error; report will have an empty ``"narrative"`` dict).
    """

    def __init__(self, groq_api_key: str = "") -> None:
        self.groq_api_key = groq_api_key

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    def run(
        self,
        intel: dict[str, Any],
        avatar_urls: Optional[Set[str]] = None,
        emit: EmitFn = _NOOP,
        cancel_event: Any = None,
    ) -> dict[str, Any]:
        """
        Execute the full intelligence pipeline.

        Parameters
        ----------
        intel:
            ``InvestigationCore.intel`` – the raw collected data.
        avatar_urls:
            ``InvestigationContext.avatar_urls`` – image URLs.
        emit:
            Pipeline event callback; called with structured progress events.
        cancel_event:
            Optional ``threading.Event``. When set, remaining steps are
            skipped and the partial report is returned. If not supplied,
            the engine falls back to
            ``getattr(ctx.config, "_cancel_event", None)`` via the caller
            (the stage already does this) — passing it explicitly here is
            the recommended path.

        Returns
        -------
        dict
            Serialisable report with keys:

            - ``"entities"``       – list of entity dicts
            - ``"entity_counts"``  – counts per entity type
            - ``"graph_summary"``  – networkx graph statistics
            - ``"correlations"``   – list of correlation dicts
            - ``"narrative"``      – AI narrative dict (may be ``{}``)
            - ``"cancelled"``      – True if the pipeline stopped early
        """
        avatar_urls = avatar_urls or set()
        cancelled = False

        def _is_cancelled() -> bool:
            return cancel_event is not None and cancel_event.is_set()

        # ---------------------------------------------------------------- #
        # Step 1 – Entity extraction                                         #
        # ---------------------------------------------------------------- #
        emit("progress", {"message": "Intelligence: extracting entities"})
        entities: list[BaseEntity] = extract_entities(intel, avatar_urls)

        entity_counts: dict[str, int] = {}
        for e in entities:
            entity_counts[e.entity_type] = entity_counts.get(e.entity_type, 0) + 1

        print(
            f"\n  Intelligence – entities extracted: {len(entities)}"
            + (
                f"  ({', '.join(f'{v} {k}' for k, v in entity_counts.items())})"
                if entity_counts else ""
            )
        )

        # ---------------------------------------------------------------- #
        # Step 2 – Knowledge graph                                           #
        # ---------------------------------------------------------------- #
        G = None
        g_summary: dict = {}

        if _is_cancelled():
            cancelled = True
            print("  Intelligence – cancelled after extraction.")
        else:
            emit("progress", {"message": "Intelligence: building knowledge graph"})
            try:
                G = build_graph(entities)
                g_summary = graph_summary(G)
                print(
                    f"  Intelligence – graph: "
                    f"{g_summary.get('total_nodes', 0)} nodes, "
                    f"{g_summary.get('total_edges', 0)} edges, "
                    f"density={g_summary.get('density', 0.0):.4f}"
                )
            except ImportError:
                print("  Intelligence – networkx not installed; graph step skipped.")
            except Exception as exc:
                print(f"  Intelligence – graph error (continuing): {exc}")
                log_trace(f"IntelligenceEngine graph step failed: "
                          f"{type(exc).__name__}: {exc}")

        # ---------------------------------------------------------------- #
        # Step 3 – Correlation detection                                     #
        # ---------------------------------------------------------------- #
        correlations: list[Correlation] = []

        if cancelled or _is_cancelled():
            cancelled = True
            print("  Intelligence – cancelled before correlation step.")
        else:
            emit("progress", {"message": "Intelligence: running correlation detectors"})
            correlations = run_all_detectors(entities, G)

            print(f"  Intelligence – correlations found: {len(correlations)}")
            for c in correlations[:5]:
                print(f"    [{c.correlation_type}] conf={c.confidence:.2f}  "
                      f"{c.description[:80]}{'…' if len(c.description) > 80 else ''}")

            if correlations:
                emit("finding", {
                    "type":         "correlations",
                    "count":        len(correlations),
                    "top_type":     correlations[0].correlation_type,
                    "top_conf":     correlations[0].confidence,
                })

        # ---------------------------------------------------------------- #
        # Step 4 – AI narrative                                             #
        # ---------------------------------------------------------------- #
        narrative: dict = {}

        if cancelled or _is_cancelled():
            cancelled = True
            # Skipping the narrative is the whole point of the check
            # here — the Groq call takes up to 45 seconds and cannot be
            # interrupted once in flight.
            print("  Intelligence – cancelled; skipping AI narrative step.")
            emit("progress", {"message": "Intelligence: narrative skipped (cancelled)"})
        elif self.groq_api_key:
            emit("progress", {"message": "Intelligence: generating AI narrative"})
            try:
                from .narrative import generate_narrative
                narrative = generate_narrative(
                    graph_summary=g_summary,
                    correlations=correlations,
                    entities=entities,
                    intel=intel,
                    groq_api_key=self.groq_api_key,
                )
                if narrative:
                    print("  Intelligence – AI narrative generated successfully.")
                    emit("finding", {"type": "intelligence_narrative"})
                else:
                    print("  Intelligence – narrative returned empty (LLM parse issue).")
            except Exception as exc:
                print(f"  Intelligence – narrative generation failed: {exc}")
                log_trace(f"IntelligenceEngine narrative step failed: "
                          f"{type(exc).__name__}: {exc}")
        else:
            print("  Intelligence – no Groq API key; narrative step skipped.")

        # ---------------------------------------------------------------- #
        # Package results into a serialisable dict                          #
        # ---------------------------------------------------------------- #
        return {
            "entities":      self._serialise_entities(entities),
            "entity_counts": entity_counts,
            "graph_summary": g_summary,
            "correlations":  [c.to_dict() for c in correlations],
            "narrative":     narrative,
            "cancelled":     cancelled,
        }

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _serialise_entities(entities: list[BaseEntity]) -> list[dict]:
        """Convert entity objects to plain dicts for JSON storage."""
        return [e.to_dict() for e in entities]