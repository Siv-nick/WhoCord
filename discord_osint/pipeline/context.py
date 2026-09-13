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
  module_mode      : str  – active module ID so stages can self-identify
                            ("manual" | "discord" | "email" | "domain" |
                             "phone" | "image" | "url" | "probe")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvestigationContext:
    """
    Shared state for one investigation run.

    Fields set by the caller (pipeline/__init__.py)
    ------------------------------------------------
    config      : Config / ConfigService object with all feature flags
    mode        : "discord" | "manual"
    username    : seed username (discord handle or manual input)
    target_id   : int | str  – Discord snowflake or hash(username)

    Fields pre-populated or optional
    ---------------------------------
    target_user_id  : raw Discord user ID (only discord mode)
    target_guild_id : guild ID used for profile fetch / message search
    manual_email    : email supplied via --email or UI
    extra_targets   : additional usernames / emails from config

    Phase 4 module fields
    ----------------------
    manual_domain    : domain name for Domain module
    manual_phone     : phone number for Phone module
    manual_image_url : image URL for Image module
    manual_url       : arbitrary URL for URL module
    probe_string     : raw input for Data Probe (auto-detect)
    module_mode      : which Phase 4 module is active (or "" for legacy modes)

    Phase 2 pivot metadata (read-only after construction)
    ------------------------------------------------------
    depth       : recursion depth (0 = root)
    seed_type   : "email" | "username" | ""
    seed_value  : the seed that spawned this sub-pipeline
    """

    # --- Required ---
    config: Any
    mode: str
    username: str
    target_id: Any

    # --- Optional / discord-specific ---
    target_user_id: Any = None
    target_guild_id: Any = None
    manual_email: str = ""
    extra_targets: list = field(default_factory=list)

    # --- Mutable stage outputs ---
    intel_core: Any = field(default=None, repr=False)
    avatar_urls: set = field(default_factory=set, repr=False)
    discovery: list = field(default_factory=list, repr=False)
    all_urls: list = field(default_factory=list, repr=False)
    messages: list = field(default_factory=list, repr=False)

    # --- Phase 2: pivot metadata ---
    depth: int = 0
    seed_type: str = ""
    seed_value: str = ""

    # --- Phase 4: module-specific inputs ---
    manual_domain: str = ""
    """Target domain name for the Domain investigation module."""

    manual_phone: str = ""
    """Target phone number for the Phone investigation module."""

    manual_image_url: str = ""
    """Image URL or path for the Image Analysis module."""

    manual_url: str = ""
    """Arbitrary URL for the URL Analysis module."""

    probe_string: str = ""
    """Raw user-supplied string for the Data Probe auto-detect module."""

    module_mode: str = ""
    """
    Active Phase 4 module ID.  One of:
    "email" | "domain" | "phone" | "image" | "url" | "probe"
    Empty string for legacy manual/discord pipelines.
    """
    discovery_done: bool = False

    def __post_init__(self) -> None:
        if self.intel_core is None:
            from ..core import InvestigationCore
            self.intel_core = InvestigationCore(self.target_id)

    # ------------------------------------------------------------------ #
    # Convenience helpers
    # ------------------------------------------------------------------ #

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

    # --- Phase 2 helpers ---

    @property
    def is_root(self) -> bool:
        return self.depth == 0

    @property
    def pivot_label(self) -> str:
        if self.is_root:
            return "root"
        return f"{self.seed_type}:{self.seed_value} [d={self.depth}]"

    # --- Phase 4 helpers ---

    @property
    def effective_target(self) -> str:
        """
        Return the primary target value regardless of module mode.
        Useful for logging and report headers.
        """
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
