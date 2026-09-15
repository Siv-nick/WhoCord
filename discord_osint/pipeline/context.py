
"""
discord_osint/pipeline/context.py
----------------------------------
InvestigationContext – the single mutable object passed between stages.

Phase 4 additions
-----------------
New optional fields for the six investigation modules:

  manual_domain    : str  – domain name for the Domain module
  manual_phone     : str  – phone number for the Phone module
  manual_image_url : str  – image URL for the Image module
  manual_url       : str  – arbitrary URL for the URL module
  probe_string     : str  – raw input for the Data Probe auto-detect module
  module_mode      : str  – active module ID

Evidence snapshot path
----------------------
``intel_snapshot_path`` is set by ``Pipeline.run`` immediately after
``intel_core.save_state()``. The reporting stage reads it to include
the raw intel JSON in the signed evidence manifest — the primary
evidence artifact must be tamper-evident, not just the derived reports.

Structured logging
------------------
``ctx.log`` returns a StructuredLogger bound to the pipeline's emitter
(or a stdout fallback in CLI mode).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..utils.logger import StructuredLogger


@dataclass
class InvestigationContext:
    # ``mode``, ``username`` and ``target_id`` carry defaults because a
    # module-mode run (email / domain / phone / image / url / probe) has
    # no username, and callers were passing dummy values to satisfy the
    # signature. Every production call site uses keyword arguments, so
    # adding defaults is source-compatible.
    config: Any = None
    mode: str = ""
    username: str = ""
    target_id: Any = 0

    target_user_id: Any = None
    target_guild_id: Any = None
    manual_email: str = ""
    extra_targets: list = field(default_factory=list)

    # Per-stage scratch space. Stages that want to hand structured
    # output to a later stage without going through intel_core (which
    # is serialised into the report) write here instead.
    results: dict = field(default_factory=dict, repr=False)

    intel_core: Any = field(default=None, repr=False)
    avatar_urls: set = field(default_factory=set, repr=False)
    discovery: list = field(default_factory=list, repr=False)
    all_urls: list = field(default_factory=list, repr=False)
    messages: list = field(default_factory=list, repr=False)

    depth: int = 0
    seed_type: str = ""
    seed_value: str = ""

    manual_domain: str = ""
    manual_phone: str = ""
    manual_image_url: str = ""
    manual_url: str = ""
    probe_string: str = ""
    module_mode: str = ""
    discovery_done: bool = False

    # Path to the intel JSON snapshot written by Pipeline.run. Set after
    # save_state(); consumed by ReportingStage for the manifest.
    intel_snapshot_path: str = ""

    def __post_init__(self) -> None:
        if self.intel_core is None:
            from ..core import InvestigationCore
            self.intel_core = InvestigationCore(self.target_id)

    # ------------------------------------------------------------------ #
    # Structured logger
    # ------------------------------------------------------------------ #

    @property
    def log(self) -> StructuredLogger:
        cached = getattr(self, "_log_cache", None)
        if cached is not None:
            return cached

        emit = getattr(self.config, "_phase3_emit", None)
        logger = (
            StructuredLogger(sink=emit)
            if emit is not None
            else StructuredLogger.stdout()
        )
        self._log_cache = logger
        return logger

    # ------------------------------------------------------------------ #
    # Convenience helpers
    # ------------------------------------------------------------------ #

    @property
    def intel(self) -> dict:
        """
        The live intel dict owned by ``intel_core``.

        Stages that only need to read or poke a category should not have
        to know that the store is wrapped. This is the same object, not
        a copy — mutating it mutates the investigation.
        """
        return self.intel_core.intel

    @property
    def discovered_emails(self) -> set:
        """
        Mutable set of emails discovered so far.

        Backed by a plain set on the context rather than derived from
        ``intel_core`` on each access, because callers add to it
        (``ctx.discovered_emails.add(...)``) and a derived set would
        silently discard those writes. ``all_known_emails()`` remains
        the validated, intel-backed view.
        """
        existing = getattr(self, "_discovered_emails", None)
        if existing is None:
            existing = set()
            object.__setattr__(self, "_discovered_emails", existing)
        return existing

    def add_avatar(self, url: str) -> None:
        if url and isinstance(url, str) and url.startswith("http"):
            self.avatar_urls.add(url)

    def add_discovery(self, site: str, url: str) -> None:
        existing = {d["url"] for d in self.discovery}
        if url and url.startswith("http") and url not in existing:
            self.discovery.append({"site": site, "url": url})

    def all_known_emails(self) -> set[str]:
        from ..scraping import is_valid_email
        return {
            v.get("value", "")
            for v in self.intel_core.intel.get("emails", {}).values()
            if is_valid_email(v.get("value", ""))
        }

    @property
    def is_root(self) -> bool:
        return self.depth == 0

    @property
    def pivot_label(self) -> str:
        if self.is_root:
            return "root"
        return f"{self.seed_type}:{self.seed_value} [d={self.depth}]"

    @property
    def effective_target(self) -> str:
        if self.module_mode == "email":
            return self.manual_email
        if self.module_mode == "domain":
            return self.manual_domain
        if self.module_mode == "phone":
            return self.manual_phone
        if self.module_mode == "image":
            return self.manual_image_url
        if self.module_mode == "url":
            return self.manual_url
        if self.module_mode == "probe":
            return self.probe_string
        return self.username or self.manual_email
