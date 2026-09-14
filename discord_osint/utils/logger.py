"""
discord_osint/utils/logger.py
-----------------------------
Centralised logging configuration for WhoCord.

Change log
----------
- ``setup_logging`` is now safe to call repeatedly. It resets the level
  and format on every call so that ``--debug`` toggles and menu-driven
  debug flips take effect immediately (previously the first call won
  and later calls were no-ops).
- Added an optional ``log_file`` parameter so the CLI can mirror logs
  to disk without depending on the OS-level stream redirection used by
  the web app. When set, a rotating file handler is attached at the
  same level as the stderr handler.
- Library noisy loggers (urllib3, aiohttp, requests, PIL) are quieted
  once — idempotent.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

LOG_FORMAT  = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Track the file handler so we can replace it if setup_logging is called
# again with a different path.
_configured_level: int | None = None
_file_handler: logging.Handler | None = None


# Noisy third-party loggers that should never sit at DEBUG in an
# investigation run — they produce thousands of lines per request.
_NOISY_LOGGERS = (
    "urllib3",
    "requests",
    "aiohttp",
    "charset_normalizer",
    "PIL",
    "asyncio",
    "matplotlib",
)


def _quiet_noisy_loggers() -> None:
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def setup_logging(debug: bool = False, log_file: str | None = None) -> None:
    """
    Initialise logging.

    Safe to call multiple times. The root logger level and format are
    reset on each call, and a rotating file handler is attached when
    *log_file* is provided.

    Parameters
    ----------
    debug:
        When True, the root logger runs at DEBUG. Otherwise INFO.
    log_file:
        Optional path. When set, a RotatingFileHandler is attached at
        the same level as the stderr handler. Paths are created if the
        parent directory doesn't exist.
    """
    global _configured_level, _file_handler

    level = logging.DEBUG if debug else logging.INFO

    root = logging.getLogger()

    # Reset handlers so repeated calls don't stack duplicates. We only
    # remove handlers we recognise (stderr StreamHandler + our own file
    # handler) to avoid clobbering handlers installed by a hosting
    # environment.
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
                str(path),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            fh.setLevel(level)
            fh.setFormatter(formatter)
            root.addHandler(fh)
            _file_handler = fh
        except Exception as exc:
            # Don't crash the app over a logging setup failure — warn
            # once and continue with stderr only.
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