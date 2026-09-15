"""
discord_osint/utils/logger.py
-----------------------------
Centralised logging configuration for WhoCord.

Change log
----------
- Adds ``StructuredLogger``: a typed wrapper around an ``EmitFn``
  (``(event_type: str, payload: dict) -> None``) that exposes
  ``event()`` / ``info()`` / ``warn()`` / ``error()`` / ``debug()``.
  Stages reach it via ``ctx.log``. The stdout router still catches any
  remaining ``print()`` calls, so print-to-structured migration can be
  incremental.
- ``setup_logging`` is safe to call repeatedly. Library noisy loggers
  are quieted once — idempotent.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any, Callable, Optional

LOG_FORMAT  = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured_level: int | None = None
_file_handler: logging.Handler | None = None

_NOISY_LOGGERS = (
    "urllib3", "requests", "aiohttp", "charset_normalizer",
    "PIL", "asyncio", "matplotlib",
)


def _quiet_noisy_loggers() -> None:
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def setup_logging(debug: bool = False, log_file: str | None = None) -> None:
    """Initialise logging. Safe to call multiple times."""
    global _configured_level, _file_handler

    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()

    for h in list(root.handlers):
        if isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stderr:
            root.removeHandler(h)
        elif _file_handler is not None and h is _file_handler:
            root.removeHandler(h)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)

    if log_file:
        try:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                str(path), maxBytes=10 * 1024 * 1024,
                backupCount=5, encoding="utf-8",
            )
            fh.setLevel(level)
            fh.setFormatter(formatter)
            root.addHandler(fh)
            _file_handler = fh
        except Exception as exc:
            print(
                f"[logger] WARNING: could not open log file {log_file!r}: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )

    root.setLevel(level)
    _configured_level = level
    _quiet_noisy_loggers()


def get_logger(name: str) -> logging.Logger:
    """Return a logger for the given module name."""
    return logging.getLogger(name)


# ──────────────────────────────────────────────────────────────────────
# StructuredLogger
# ──────────────────────────────────────────────────────────────────────
#
# A thin facade over the pipeline's ``EmitFn``. Stages get one via
# ``ctx.log`` and use it instead of ``print()`` for anything that should
# survive as a structured event — including audit-relevant records like
# "this investigation sent data to a third party".
#
# Design notes:
# - The sink is any callable with the EmitFn signature. In web mode it is
#   the EventEmitter (which is itself callable). In CLI mode there is no
#   emitter, so ``StructuredLogger.stdout()`` prints instead.
# - A failing sink never crashes the caller. If the SSE queue is closed
#   mid-write, the message is dropped and the caller continues — losing
#   a log line is preferable to aborting an investigation.

EmitSink = Callable[[str, dict], None]


class StructuredLogger:
    """
    Typed emit facade.

    Parameters
    ----------
    sink:
        ``callable(event_type, payload)``. May be the pipeline's
        EventEmitter, a queue-backed callback, or None.
    also_stdout:
        When True, each call also prints a human-readable line to
        stdout. Used in CLI mode (where there is no SSE consumer) and
        can be enabled alongside a sink for debugging.
    """

    def __init__(
        self,
        sink: Optional[EmitSink] = None,
        also_stdout: bool = False,
    ) -> None:
        self._sink = sink
        self._also_stdout = also_stdout

    # ---------------------------------------------------------------- #
    # Emit path
    # ---------------------------------------------------------------- #

    def _emit(self, event_type: str, payload: dict) -> None:
        if self._sink is not None:
            try:
                self._sink(event_type, payload)
            except Exception:
                # A dead SSE queue must not abort the investigation.
                pass

        if self._also_stdout:
            line = payload.get("line")
            if line is None:
                line = f"[{event_type}] {payload}"
            try:
                print(line)
            except Exception:
                pass

    # ---------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------- #

    def event(self, event_type: str, **fields: Any) -> None:
        """
        Emit a structured event of arbitrary type.

        Used for machine-readable records — ``third_party_contacted``,
        ``pivot_skipped``, ``config_changed``. Unlike ``info()`` the
        event_type is passed through verbatim, so the frontend's SSE
        dispatcher can branch on it.
        """
        self._emit(event_type, dict(fields))

    def info(self, message: str, **fields: Any) -> None:
        """Emit a log line at info level."""
        self._emit("log", {"line": message, "level": "info", **fields})

    def warn(self, message: str, **fields: Any) -> None:
        """Emit a log line at warn level."""
        self._emit("log", {"line": message, "level": "warn", **fields})

    def error(self, message: str, **fields: Any) -> None:
        """Emit a log line at error level."""
        self._emit("log", {"line": message, "level": "error", **fields})

    def debug(self, message: str, **fields: Any) -> None:
        """Emit a log line at debug level."""
        self._emit("log", {"line": message, "level": "debug", **fields})

    # ---------------------------------------------------------------- #
    # Factories
    # ---------------------------------------------------------------- #

    @classmethod
    def stdout(cls) -> "StructuredLogger":
        """Logger that only prints to stdout — used in CLI mode."""
        return cls(sink=None, also_stdout=True)

    @classmethod
    def noop(cls) -> "StructuredLogger":
        """Logger that discards everything — used in tests."""
        return cls(sink=None, also_stdout=False)