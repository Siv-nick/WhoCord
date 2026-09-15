"""
web_services/chat.py
--------------------
Builders for the AI chat prompt.

Change log
----------
- Phase 5: intel dumps are cached by (path, mtime). A chat session
  issues one call per user message; without caching, a 1 MB intel
  snapshot gets re-read from disk and re-serialised on every turn.
  The cache is bounded at 32 entries and evicts the oldest entry
  when full.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional


_CHAT_SYSTEM_DEFAULT = (
    "You are an elite OSINT analyst assistant embedded in the WhoCord "
    "investigation canvas. The user shares their current map and the "
    "complete investigation dump. Be concise, structured, and analytical. "
    "Use bullet points for multiple findings. Never invent data not "
    "present in the dump."
)


_INTEL_CACHE_MAX = 32
_intel_cache: dict[str, tuple[float, str]] = {}


def reset_intel_cache() -> None:
    """Clear the intel dump cache. For tests."""
    _intel_cache.clear()


def active_chat_system_prompt(config_service: Any) -> str:
    from discord_osint.intelligence.intel_dump import UNTRUSTED_DATA_RULES

    custom = (config_service.llm_system_prompt or "").strip()
    base = custom if custom else _CHAT_SYSTEM_DEFAULT
    return base + "\n\n" + UNTRUSTED_DATA_RULES


def _load_intel_dump(
    intel_path: Optional[str],
    config_service: Any,
    budget: int,
) -> str:
    """
    Return the serialised intel dump for *intel_path*, using the
    (path, mtime) cache when the file has not changed.
    """
    if not intel_path or not os.path.isfile(intel_path):
        return ""

    try:
        mtime = os.path.getmtime(intel_path)
    except OSError:
        return ""

    cached = _intel_cache.get(intel_path)
    if cached is not None:
        cached_mtime, cached_dump = cached
        if cached_mtime == mtime:
            return cached_dump

    from discord_osint.intelligence.intel_dump import build_intel_dump

    try:
        with open(intel_path, encoding="utf-8") as f:
            intel = json.load(f)
        dump = build_intel_dump(
            intel,
            budget=budget,
            include_raw=config_service.llm_intel_include_raw,
            exclude_meta=config_service.llm_intel_exclude_meta,
        )
    except Exception as exc:
        print(f"  chat: could not load intel for {intel_path}: {exc}")
        return ""

    _intel_cache[intel_path] = (mtime, dump)
    if len(_intel_cache) > _INTEL_CACHE_MAX:
        oldest = min(_intel_cache.items(), key=lambda kv: kv[1][0])
        _intel_cache.pop(oldest[0], None)

    return dump


def build_chat_context(
    *,
    message: str,
    map_data: dict,
    job_id: Optional[str],
    intel_path: Optional[str],
    config_service: Any,
) -> str:
    """
    Build the user-content block for a chat request.

    See module docstring for the caching behaviour.
    """
    from discord_osint.intelligence.intel_dump import build_canvas_dump

    node_count = int(map_data.get("node_count", 0) or 0)
    edge_count = int(map_data.get("edge_count", 0) or 0)
    nodes      = map_data.get("nodes", []) or []
    edges      = map_data.get("edges", []) or []

    total_budget  = config_service.llm_intel_budget
    canvas_budget = max(1_500, min(8_000, int(total_budget * 0.5)))
    intel_budget  = max(1_500, total_budget - canvas_budget)

    canvas = build_canvas_dump(
        nodes=nodes,
        edges=edges,
        status=str(map_data.get("status", "idle")),
        current_stage=map_data.get("currentStage"),
        target=str(map_data.get("target", "") or ""),
        mode=str(map_data.get("mode", "") or ""),
        job_id=job_id or map_data.get("jobId"),
        pivot_depth=int(map_data.get("pivotDepth", 0) or 0),
        pivots=map_data.get("pivots", []) or [],
        logs=map_data.get("logs", []) or [],
        findings=map_data.get("findings", []) or [],
        budget=canvas_budget,
    )

    intel_block = _load_intel_dump(intel_path, config_service, intel_budget)

    header = f"=== INVESTIGATION MAP ({node_count} nodes, {edge_count} edges) ==="

    sections = [header, "", canvas]
    if intel_block:
        sections.extend(["", intel_block])
    sections.extend(["", "=== USER QUESTION ===", message])
    return "\n".join(sections)