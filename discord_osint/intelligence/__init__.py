"""
discord_osint/intelligence/__init__.py
----------------------------------------
Public surface of the intelligence sub-package.

Import the high-level engine and the main entity / correlation types
so callers can do::

    from discord_osint.intelligence import IntelligenceEngine, Correlation

Everything else (graph internals, extractor, narrative) is intentionally
kept internal to the sub-package.
"""

from .engine import IntelligenceEngine
from .correlations import Correlation, run_all_detectors
from .entities import (
    AvatarEntity,
    EmailEntity,
    LocationEntity,
    NameEntity,
    PlatformProfileEntity,
    UsernameEntity,
)

__all__ = [
    # Engine
    "IntelligenceEngine",
    # Correlations
    "Correlation",
    "run_all_detectors",
    # Entity types
    "AvatarEntity",
    "EmailEntity",
    "LocationEntity",
    "NameEntity",
    "PlatformProfileEntity",
    "UsernameEntity",
]
