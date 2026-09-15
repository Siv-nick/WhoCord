"""
discord_osint/intelligence/engine.py
--------------------------------------
``IntelligenceEngine`` – orchestrates the four-step intelligence pipeline.

Per-job config
--------------
``run()`` accepts an optional ``config`` object, threaded into
``generate_narrative`` so per-job LLM settings are used.

Structured logging
------------------
``run()`` also accepts an optional ``log`` (StructuredLogger). When
supplied, the engine's own progress messages become structured events
and the third-party contact event from the narrative call inherits
the same log.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Set

from .entities import BaseEntity
from .extractor import extract_entities
from .graph import build_graph, graph_summary
from .correlations import run_all_detectors, Correlation
from ..utils import log_trace

EmitFn = Callable[[str, dict], None]
_NOOP: EmitFn = lambda *_: None


class IntelligenceEngine:
    """
    Orchestrate entity extraction → graph construction →
    correlation detection → AI narrative generation.
    """

    def __init__(self, groq_api_key: str = "", config: Any = None) -> None:
        self.groq_api_key = groq_api_key
        self.config       = config

    def run(
        self,
        intel: dict[str, Any],
        avatar_urls: Optional[Set[str]] = None,
        emit: EmitFn = _NOOP,
        cancel_event: Any = None,
        config: Any = None,
        log: Any = None,
    ) -> dict[str, Any]:
        """
        Execute the full intelligence pipeline.

        ``log`` is an optional StructuredLogger. When supplied, the
        engine emits structured progress lines and forwards the logger
        to the narrative step so its third-party contact event is
        captured.
        """
        avatar_urls = avatar_urls or set()
        effective_config = config if config is not None else self.config
        cancelled = False

        def _is_cancelled() -> bool:
            return cancel_event is not None and cancel_event.is_set()

        def _info(msg: str) -> None:
            print(msg)
            if log is not None:
                try:
                    log.info(msg)
                except Exception:
                    pass

        # ---------------------------------------------------------------- #
        # Step 1 – Entity extraction                                         #
        # ---------------------------------------------------------------- #
        emit("progress", {"message": "Intelligence: extracting entities"})
        entities: list[BaseEntity] = extract_entities(intel, avatar_urls)

        entity_counts: dict[str, int] = {}
        for e in entities:
            entity_counts[e.entity_type] = entity_counts.get(e.entity_type, 0) + 1

        _info(
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
            _info("  Intelligence – cancelled after extraction.")
        else:
            emit("progress", {"message": "Intelligence: building knowledge graph"})
            try:
                G = build_graph(entities)
                g_summary = graph_summary(G)
                _info(
                    f"  Intelligence – graph: "
                    f"{g_summary.get('total_nodes', 0)} nodes, "
                    f"{g_summary.get('total_edges', 0)} edges, "
                    f"density={g_summary.get('density', 0.0):.4f}"
                )
            except ImportError:
                _info("  Intelligence – networkx not installed; graph step skipped.")
            except Exception as exc:
                _info(f"  Intelligence – graph error (continuing): {exc}")
                log_trace(f"IntelligenceEngine graph step failed: "
                          f"{type(exc).__name__}: {exc}")

        # ---------------------------------------------------------------- #
        # Step 3 – Correlation detection                                     #
        # ---------------------------------------------------------------- #
        correlations: list[Correlation] = []

        if cancelled or _is_cancelled():
            cancelled = True
            _info("  Intelligence – cancelled before correlation step.")
        else:
            emit("progress", {"message": "Intelligence: running correlation detectors"})
            correlations = run_all_detectors(entities, G)

            _info(f"  Intelligence – correlations found: {len(correlations)}")
            for c in correlations[:5]:
                _info(f"    [{c.correlation_type}] conf={c.confidence:.2f}  "
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
            _info("  Intelligence – cancelled; skipping AI narrative step.")
            emit("progress", {"message": "Intelligence: narrative skipped (cancelled)"})
        else:
            key_available = False
            if effective_config is not None:
                from ..config_service import get_llm_endpoint
                _, key, _ = get_llm_endpoint(effective_config)
                key_available = bool(key)
            else:
                key_available = bool(self.groq_api_key)

            if key_available:
                emit("progress", {"message": "Intelligence: generating AI narrative"})
                try:
                    from .narrative import generate_narrative
                    narrative = generate_narrative(
                        graph_summary=g_summary,
                        correlations=correlations,
                        entities=entities,
                        intel=intel,
                        groq_api_key=self.groq_api_key,
                        config=effective_config,
                        log=log,
                    )
                    if narrative:
                        _info("  Intelligence – AI narrative generated successfully.")
                        emit("finding", {"type": "intelligence_narrative"})
                    else:
                        _info("  Intelligence – narrative returned empty (LLM parse issue).")
                except Exception as exc:
                    _info(f"  Intelligence – narrative generation failed: {exc}")
                    log_trace(f"IntelligenceEngine narrative step failed: "
                              f"{type(exc).__name__}: {exc}")
            else:
                _info("  Intelligence – no LLM API key; narrative step skipped.")

        return {
            "entities":      self._serialise_entities(entities),
            "entity_counts": entity_counts,
            "graph_summary": g_summary,
            "correlations":  [c.to_dict() for c in correlations],
            "narrative":     narrative,
            "cancelled":     cancelled,
        }

    @staticmethod
    def _serialise_entities(entities: list[BaseEntity]) -> list[dict]:
        return [e.to_dict() for e in entities]