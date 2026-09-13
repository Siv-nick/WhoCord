"""
discord_osint/pipeline/events.py
----------------------------------
Structured event emission for Phase 3 streaming.

Design
------
``EventEmitter`` wraps a single ``callback(event_type: str, payload: dict)``
function and exposes typed convenience methods for every event the pipeline
can produce.  Stages call these methods instead of bare ``emit()`` calls or
``print()`` statements.

When no callback is supplied (CLI usage, tests) the emitter falls back to
``print()`` so existing behaviour is preserved without any conditional logic
inside stages.

SSE event protocol
------------------
The web_app.py ``/run`` endpoint passes an emit callback that serialises
events into JSON and writes them to a ``queue.Queue``.  The SSE generator
reads from that queue and sends::

    data: {"type": "stage_start", "payload": {"stage": "discovery", "depth": 0}}\\n\\n

This makes the frontend event parser trivial: always parse ``event.data``
as JSON, branch on ``type``.

Event type reference
--------------------
``stage_start``    – pipeline stage is beginning
``stage_done``     – pipeline stage has completed successfully
``stage_error``    – pipeline stage raised an unexpected exception
``abort``          – PipelineAbortError raised; pipeline stopping
``progress``       – a tool or sub-task has started / is running
``finding``        – a concrete piece of intelligence was discovered
``report_ready``   – a report file was written to disk
``pivot_start``    – recursive pivot sub-investigation starting
``pivot_done``     – pivot sub-investigation complete and merged
``pivot_error``    – pivot sub-investigation failed
``log``            – raw stdout line (captured from print() calls)
``done``           – investigation fully complete; report URL included
``error``          – fatal error (investigation cannot continue)
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional


EmitFn = Callable[[str, dict], None]

# ---------------------------------------------------------------------------
# Stdout fallback formatter
# ---------------------------------------------------------------------------

_STAGE_ICONS: dict[str, str] = {
    "discord_mode":  "🔵",
    "discovery":     "🔍",
    "scraping":      "🕷",
    "media":         "🖼",
    "analysis":      "📊",
    "intelligence":  "🧠",
    "email_intel":   "📧",
    "reporting":     "📋",
}

_FINDING_ICONS: dict[str, str] = {
    "email":               "✉️",
    "name_clue":           "👤",
    "avatar_url":          "🖼",
    "connected_account":   "🔗",
    "discord_handle":      "💬",
    "holehe":              "🔒",
    "hibp":                "⚠️",
    "h8mail":              "💾",
    "gravatar":            "🌐",
    "ghunt":               "🔍",
    "emailrep":            "📊",
    "exif_gps":            "📍",
    "reverse_image":       "🖼",
    "correlations":        "🔗",
    "intelligence_report": "🧠",
    "persona_summary":     "👤",
    "wayback":             "⏮",
    "whois":               "📋",
}


def _print_event(event_type: str, payload: dict) -> None:
    """Human-readable stdout fallback for CLI use."""
    if event_type == "stage_start":
        stage = payload.get("stage", "")
        icon  = _STAGE_ICONS.get(stage, "▶")
        depth = payload.get("depth", 0)
        depth_str = f" [d={depth}]" if depth else ""
        print(f"\n{icon} [{stage.upper()}{depth_str}] starting…")

    elif event_type == "stage_done":
        stage = payload.get("stage", "")
        depth = payload.get("depth", 0)
        depth_str = f" [d={depth}]" if depth else ""
        print(f"  ✓ [{stage.upper()}{depth_str}] done")

    elif event_type in ("stage_error", "error"):
        print(f"  ✗ {payload.get('stage', '')} error: {payload.get('error', '')}")

    elif event_type == "abort":
        print(f"  ⛔ pipeline aborted at {payload.get('stage', '')}: {payload.get('reason', '')}")

    elif event_type == "progress":
        msg  = payload.get("message", "")
        tool = payload.get("tool", "")
        line = f"  … {tool}: {msg}" if tool else f"  … {msg}"
        print(line)

    elif event_type == "finding":
        ftype = payload.get("type", "")
        icon  = _FINDING_ICONS.get(ftype, "•")
        val   = (
            payload.get("value")
            or payload.get("email")
            or payload.get("url")
            or payload.get("domain")
            or str(payload.get("count", ""))
        )
        if val:
            print(f"  {icon} [{ftype}] {val}")

    elif event_type == "report_ready":
        fmt  = payload.get("format", "")
        path = payload.get("path", "")
        print(f"  📁 report ({fmt}) → {path}")

    elif event_type == "done":
        path = payload.get("intel_path", "")
        print(f"\n✅ Investigation complete. Intel: {path}")

    elif event_type in ("pivot_start", "pivot_done", "pivot_error"):
        seed  = payload.get("seed", "")
        depth = payload.get("depth", "?")
        if event_type == "pivot_start":
            print(f"\n  [PIVOT d={depth}] starting: {seed!r}")
        elif event_type == "pivot_done":
            print(f"  [PIVOT d={depth}] ✓ merged: {seed!r}")
        else:
            print(f"  [PIVOT d={depth}] ✗ failed: {seed!r} – {payload.get('error', '')}")

    elif event_type == "log":
        pass  # raw stdout is already printed; avoid double output


# ---------------------------------------------------------------------------
# EventEmitter
# ---------------------------------------------------------------------------

class EventEmitter:
    """
    Typed wrapper around an emit callback.

    Parameters
    ----------
    callback:
        ``callback(event_type: str, payload: dict)`` – the function that
        receives structured events.  Pass ``None`` to fall back to stdout
        printing for CLI / test usage.
    also_print:
        When *True* (the default when no callback is given), events are
        also printed to stdout via ``_print_event()``.  Set to *False*
        when the SSE stream is the sole output channel (web_app usage)
        to avoid noisy console output inside the thread.
    """

    def __init__(
        self,
        callback: Optional[EmitFn] = None,
        also_print: Optional[bool] = None,
    ) -> None:
        self._callback    = callback
        self._also_print  = also_print if also_print is not None else (callback is None)

    # ------------------------------------------------------------------ #
    # Raw emit – all typed methods delegate here
    # ------------------------------------------------------------------ #

    def emit(self, event_type: str, payload: dict) -> None:
        """Dispatch one event through the callback and/or stdout."""
        if self._callback is not None:
            try:
                self._callback(event_type, payload)
            except Exception:
                pass   # never let an emit failure crash a stage

        if self._also_print:
            _print_event(event_type, payload)

    # ------------------------------------------------------------------ #
    # Typed convenience methods
    # ------------------------------------------------------------------ #

    def stage_start(self, name: str, depth: int = 0) -> None:
        self.emit("stage_start", {"stage": name, "depth": depth})

    def stage_done(self, name: str, depth: int = 0) -> None:
        self.emit("stage_done", {"stage": name, "depth": depth})

    def stage_error(self, name: str, error: str, depth: int = 0) -> None:
        self.emit("stage_error", {"stage": name, "error": error, "depth": depth})

    def abort(self, name: str, reason: str, depth: int = 0) -> None:
        self.emit("abort", {"stage": name, "reason": reason, "depth": depth})

    def progress(self, message: str, tool: str = "") -> None:
        self.emit("progress", {"message": message, "tool": tool})

    def finding(self, finding_type: str, **kwargs: Any) -> None:
        self.emit("finding", {"type": finding_type, **kwargs})

    def report_ready(self, path: str, fmt: str) -> None:
        self.emit("report_ready", {"path": path, "format": fmt})

    def pivot_start(self, seed: str, seed_type: str, depth: int) -> None:
        self.emit("pivot_start", {"seed": seed, "seed_type": seed_type, "depth": depth})

    def pivot_done(self, seed: str, seed_type: str, depth: int) -> None:
        self.emit("pivot_done", {"seed": seed, "seed_type": seed_type, "depth": depth})

    def pivot_error(self, seed: str, error: str, depth: int) -> None:
        self.emit("pivot_error", {"seed": seed, "error": error, "depth": depth})

    def log(self, line: str) -> None:
        self.emit("log", {"line": line.rstrip()})

    def done(self, intel_path: str = "", report_url: str = "", depth: int = 0) -> None:
        self.emit("done", {
            "intel_path": intel_path,
            "report_url": report_url,
            "depth":      depth,
        })

    def error(self, message: str, stage: str = "") -> None:
        self.emit("error", {"message": message, "stage": stage})

    # ------------------------------------------------------------------ #
    # Callable protocol – stages can pass emitter as an EmitFn directly
    # ------------------------------------------------------------------ #

    def __call__(self, event_type: str, payload: dict) -> None:
        """Allow the emitter to be used anywhere an ``EmitFn`` is expected."""
        self.emit(event_type, payload)

    # ------------------------------------------------------------------ #
    # Factory helpers
    # ------------------------------------------------------------------ #

    @classmethod
    def for_queue(cls, q: Any, also_print: bool = False) -> "EventEmitter":
        """
        Create an emitter that writes structured JSON payloads to a
        ``queue.Queue`` for SSE consumption.

        Parameters
        ----------
        q:
            A ``queue.Queue`` instance.  Each put is a dict::

                {"type": event_type, "payload": payload_dict}

        also_print:
            Mirror events to stdout (useful during development).
        """
        def _callback(event_type: str, payload: dict) -> None:
            q.put({"type": event_type, "payload": payload})

        return cls(callback=_callback, also_print=also_print)

    @classmethod
    def noop(cls) -> "EventEmitter":
        """Create an emitter that silently discards all events."""
        return cls(callback=lambda *_: None, also_print=False)

    @classmethod
    def stdout_only(cls) -> "EventEmitter":
        """Create an emitter that only prints to stdout (CLI mode)."""
        return cls(callback=None, also_print=True)


# ---------------------------------------------------------------------------
# SSE serialisation helper (used by web_app.py)
# ---------------------------------------------------------------------------

def to_sse_line(event_type: str, payload: dict) -> str:
    """
    Serialise one event into an SSE line ready to yield from a Flask
    streaming response.

    All events are carried on the *default* SSE message channel (no
    ``event:`` field) so the frontend's ``EventSource.onmessage`` fires
    for every event; the ``type`` field inside the JSON disambiguates.

    Example output::

        data: {"type": "stage_start", "payload": {"stage": "discovery", "depth": 0}}\\n\\n
    """
    body = json.dumps({"type": event_type, "payload": payload}, ensure_ascii=False)
    return f"data: {body}\n\n"
