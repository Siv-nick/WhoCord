"""
discord_osint/logger.py
-----------------------
Backwards-compatibility shim.

`discord_osint/__main__.py` historically imported ``setup_logging`` from
this module, but the actual implementation lives in
``discord_osint/utils/logger.py``.  This file re-exports it so both
import paths work identically.
"""

from .utils.logger import setup_logging, get_logger

__all__ = ["setup_logging", "get_logger"]