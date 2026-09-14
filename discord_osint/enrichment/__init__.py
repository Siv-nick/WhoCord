"""
discord_osint/enrichment
-------------------------
Opt-in contact-enrichment providers (Apollo.io, Lusha).

Nothing in this package runs unless the analyst has explicitly enabled a
provider AND stored a valid API key. Both providers consume paid credits,
so every identifier that reaches them first passes through the shared
trust filter in :mod:`trust_filter`.
"""

from .trust_filter import (
    FilterDecision,
    Identifier,
    collect_context,
    evaluate,
    evaluate_many,
)

__all__ = [
    "FilterDecision",
    "Identifier",
    "collect_context",
    "evaluate",
    "evaluate_many",
]