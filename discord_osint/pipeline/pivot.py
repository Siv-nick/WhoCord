"""
discord_osint/pipeline/pivot.py
---------------------------------
Adaptive recursive pivoting – Phase 2 (updated for Phase 3 edits).

New in this version
-------------------
``SeedQueue.pop_batch`` no longer discards seeds beyond the batch limit.
The old implementation popped the entire depth bucket but only returned
the first ``limit`` items — everything past that vanished silently. Any
target with more than ``max_seeds_per_depth`` discovered emails/usernames
would lose the excess with no log line and no chance to investigate them
in a later pass.

Fix summary
-----------
* ``SeedQueue.pop_batch``         — returns a batch and *keeps* the
                                    remainder in the pending bucket.
* ``SeedQueue.drain_depth``       — new helper that atomically removes
                                    and returns ALL pending seeds at a
                                    depth (used when we want to plan
                                    the whole depth before launching).
* ``process_pending_seeds``       — now drains the full depth, confirms
                                    once over the whole set (if
                                    confirmation is enabled), then
                                    launches sub-investigations in
                                    batches of ``max_seeds_per_depth``.
                                    Nothing is dropped.

Sub-pipelines now also run :class:`EnrichmentStage` so a pivot off a
discovered email can also benefit from Apollo / Lusha when those
providers are enabled. The stage is a no-op when neither provider is
enabled, so this is purely additive.
"""

from __future__ import annotations

import re
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

EmitFn       = Callable[[str, dict], None]
ConfirmFn    = Callable[
    [List[Tuple[str, str]], int, EmitFn],
    List[Tuple[str, str]],
]
_NOOP: EmitFn = lambda *_: None


# ---------------------------------------------------------------------------
# PivotConfig
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PivotConfig:
    """
    Immutable pivot settings.

    Attributes
    ----------
    enabled:              Master toggle.
    pivot_email:          Follow newly discovered email addresses.
    pivot_username:       Follow newly discovered plain usernames.
    max_depth:            Maximum recursion depth (root = 0).
    max_seeds_per_depth:  Batch size per launch wave. The full depth set
                          is now processed across multiple waves rather
                          than truncated to this number.
    require_confirm:      When True, pause before each depth and wait for
                          user approval via confirm_fn.
    """

    enabled:             bool = False
    pivot_email:         bool = True
    pivot_username:      bool = True
    max_depth:           int  = 3
    max_seeds_per_depth: int  = 5
    require_confirm:     bool = False

    @classmethod
    def from_config(cls, config: Any) -> "PivotConfig":
        return cls(
            enabled=             bool(getattr(config, "ENABLE_PIVOTING",         False)),
            pivot_email=         bool(getattr(config, "PIVOT_EMAIL",             True)),
            pivot_username=      bool(getattr(config, "PIVOT_USERNAME",          True)),
            max_depth=           int( getattr(config, "PIVOT_MAX_DEPTH",         3)),
            max_seeds_per_depth= int( getattr(config, "PIVOT_MAX_SEEDS",         5)),
            require_confirm=     bool(getattr(config, "PIVOT_REQUIRE_CONFIRM",   False)),
        )


# ---------------------------------------------------------------------------
# SeedQueue
# ---------------------------------------------------------------------------

class SeedQueue:
    """
    Shared deduplication registry for the entire investigation tree.
    """

    def __init__(self) -> None:
        self._processed: set[str] = set()
        self._pending: dict[int, list[tuple[str, str]]] = {}

    def _norm(self, seed: str) -> str:
        return seed.lower().strip()

    def mark_processed(self, seed: str) -> None:
        self._processed.add(self._norm(seed))

    def is_processed(self, seed: str) -> bool:
        return self._norm(seed) in self._processed

    def enqueue(self, seed: str, seed_type: str, depth: int) -> bool:
        norm = self._norm(seed)
        if not norm or self.is_processed(norm):
            return False
        bucket   = self._pending.setdefault(depth, [])
        existing = {s for s, _ in bucket}
        if norm in existing:
            return False
        bucket.append((norm, seed_type))
        return True

    def pop_batch(self, depth: int, limit: int) -> list[tuple[str, str]]:
        """
        Return up to *limit* seeds from *depth*.

        Anything beyond *limit* stays in the pending bucket for a later
        call — it is NOT discarded. Seeds in the returned batch are
        marked as processed.
        """
        all_at_depth = self._pending.get(depth, [])
        if not all_at_depth:
            return []

        batch    = all_at_depth[:limit]
        leftover = all_at_depth[limit:]

        if leftover:
            self._pending[depth] = leftover
        else:
            self._pending.pop(depth, None)

        for seed, _ in batch:
            self.mark_processed(seed)
        return batch

    def drain_depth(self, depth: int) -> list[tuple[str, str]]:
        """
        Remove and return ALL pending seeds at *depth*.

        Returned seeds are NOT marked as processed — the caller is
        expected to mark them (or gate them through confirmation first).
        """
        return self._pending.pop(depth, [])

    def pending_count(self, depth: int) -> int:
        return len(self._pending.get(depth, []))

    def all_depths(self) -> list[int]:
        return sorted(self._pending.keys())

    @property
    def processed_count(self) -> int:
        return len(self._processed)


# ---------------------------------------------------------------------------
# Seed scanning helpers
# ---------------------------------------------------------------------------

_EMAIL_RE      = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_SKIP_KEY_FRAGS = frozenset({"socid_raw", "bio", "desc", "/bio", "/blog", "generic_"})
_MIN_USERNAME_LEN = 2
_MAX_USERNAME_LEN = 50


def _is_valid_pivot_email(val: str) -> bool:
    return bool(val and "@" in val and _EMAIL_RE.match(val) and len(val) <= 254)


def _is_valid_pivot_username(val: str) -> bool:
    if not val or val.startswith("http"):
        return False
    return _MIN_USERNAME_LEN <= len(val) <= _MAX_USERNAME_LEN


def _unpack_intel_value(entry: Any) -> str:
    if isinstance(entry, dict):
        val = entry.get("value", "")
        if not isinstance(val, str):
            val = str(val) if val else ""
    else:
        val = str(entry) if entry else ""
    return val.strip()


def scan_for_new_seeds(
    ctx: Any,
    seed_queue: SeedQueue,
    pivot_config: PivotConfig,
    target_depth: int,
) -> int:
    if not pivot_config.enabled:
        return 0
    if target_depth > pivot_config.max_depth:
        return 0

    intel  = ctx.intel_core.intel
    queued = 0

    if pivot_config.pivot_email:
        for _key, entry in intel.get("emails", {}).items():
            val = _unpack_intel_value(entry).lower()
            if _is_valid_pivot_email(val) and seed_queue.enqueue(val, "email", target_depth):
                queued += 1

    if pivot_config.pivot_username:
        for key, entry in intel.get("social_profiles", {}).items():
            if any(frag in key for frag in _SKIP_KEY_FRAGS):
                continue
            val = _unpack_intel_value(entry)
            if _is_valid_pivot_username(val) and seed_queue.enqueue(val, "username", target_depth):
                queued += 1

        for key, entry in intel.get("discord", {}).items():
            if key != "username":
                continue
            val = _unpack_intel_value(entry)
            if _is_valid_pivot_username(val) and seed_queue.enqueue(val, "username", target_depth):
                queued += 1

    return queued


# ---------------------------------------------------------------------------
# Sub-pipeline builder
# ---------------------------------------------------------------------------

def build_sub_pipeline(
    seed_value: str,
    seed_type: str,
    parent_ctx: Any,
    depth: int,
) -> tuple[Any, Any]:
    from .context import InvestigationContext
    from .base import Pipeline
    from ..core import InvestigationCore
    from .stages import (
        DiscoveryStage, ScrapingStage, MediaStage,
        AnalysisStage, IntelligenceStage, EmailIntelStage,
    )
    from ..enrichment.stage import EnrichmentStage

    cfg          = parent_ctx.config
    username     = seed_value.split("@")[0] if seed_type == "email" else seed_value
    manual_email = seed_value if seed_type == "email" else ""
    target_id    = hash(seed_value) & 0x7FFFFFFF
    intel_core   = InvestigationCore(target_id)

    sub_ctx = InvestigationContext(
        config=cfg,
        mode="manual",
        username=username,
        target_id=target_id,
        manual_email=manual_email,
        intel_core=intel_core,
        depth=depth,
        seed_type=seed_type,
        seed_value=seed_value,
    )

    stages = [
        DiscoveryStage(), ScrapingStage(), MediaStage(),
        AnalysisStage(), IntelligenceStage(), EmailIntelStage(),
        EnrichmentStage(),
    ]
    pipeline = Pipeline(stages, sub_ctx)
    return sub_ctx, pipeline


# ---------------------------------------------------------------------------
# Result merging
# ---------------------------------------------------------------------------

_MERGE_CATEGORIES = (
    "emails", "social_profiles", "identity_clues", "breaches",
    "whois", "wayback", "media", "ghunt", "emailrep",
    "email_verification", "name_analysis",
    "phone", "enrichment_profiles", "enrichment_decisions",
    "enrichment_spend", "enrichment_balance",
)


def _make_key_prefix(seed_value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9]", "_", seed_value)
    return f"pivot_{safe}"


def merge_results(parent_ctx: Any, child_ctx: Any) -> None:
    child_intel  = child_ctx.intel_core.intel
    parent_intel = parent_ctx.intel_core.intel
    prefix       = _make_key_prefix(child_ctx.seed_value)

    for category in _MERGE_CATEGORIES:
        child_data = child_intel.get(category)
        if not child_data:
            continue
        parent_data = parent_intel.setdefault(category, {})
        for key, value in child_data.items():
            merged_key = f"{prefix}__{key}"
            if merged_key not in parent_data:
                parent_data[merged_key] = value

    parent_ctx.avatar_urls.update(child_ctx.avatar_urls)

    existing_urls = {d["url"] for d in parent_ctx.discovery}
    for entry in child_ctx.discovery:
        if entry.get("url") and entry["url"] not in existing_urls:
            parent_ctx.discovery.append(entry)
            existing_urls.add(entry["url"])

    child_report = child_intel.get("intelligence_report")
    if child_report:
        pivot_reports = parent_intel.setdefault("pivot_reports", [])
        pivot_reports.append({
            "seed":      child_ctx.seed_value,
            "seed_type": child_ctx.seed_type,
            "depth":     child_ctx.depth,
            "report":    child_report,
        })


# ---------------------------------------------------------------------------
# Main pivot processing step
# ---------------------------------------------------------------------------

def process_pending_seeds(
    ctx: Any,
    seed_queue: SeedQueue,
    pivot_config: PivotConfig,
    emit: EmitFn = _NOOP,
    confirm_fn: Optional[ConfirmFn] = None,
) -> int:
    """
    Run sub-pipelines for all seeds pending at ``ctx.depth + 1``.
    """
    if not pivot_config.enabled:
        return 0

    next_depth = ctx.depth + 1
    if next_depth > pivot_config.max_depth:
        return 0

    all_seeds = seed_queue.drain_depth(next_depth)
    if not all_seeds:
        return 0

    print(
        f"\n{'=' * 60}\n"
        f"[PIVOT] Depth {next_depth}: {len(all_seeds)} seed(s) queued\n"
        f"{'=' * 60}"
    )

    # ------------------------------------------------------------------ #
    # Confirmation gate (once per depth, over the whole seed set)         #
    # ------------------------------------------------------------------ #
    if confirm_fn is not None:
        try:
            approved = confirm_fn(all_seeds, next_depth, emit)
        except Exception as exc:
            print(f"  [PIVOT] confirm_fn raised {exc} – proceeding with full set")
            approved = all_seeds

        approved_set = {s for s, _ in approved}
        for seed, stype in all_seeds:
            if seed not in approved_set:
                seed_queue.mark_processed(seed)
                emit("pivot_skipped", {
                    "seed": seed, "seed_type": stype, "depth": next_depth,
                })
                print(f"  [PIVOT d={next_depth}] skipped by user: {stype}={seed!r}")

        all_seeds = [s for s in all_seeds if s[0] in approved_set]

    if not all_seeds:
        print(f"\n  [PIVOT d={next_depth}] all seeds skipped.")
        return 0

    batch_size = max(1, pivot_config.max_seeds_per_depth)
    launched   = 0

    for batch_start in range(0, len(all_seeds), batch_size):
        batch = all_seeds[batch_start : batch_start + batch_size]

        print(
            f"\n  [PIVOT d={next_depth}] launching batch "
            f"{batch_start // batch_size + 1} "
            f"({len(batch)} seed(s))"
        )

        for seed_value, seed_type in batch:
            seed_queue.mark_processed(seed_value)

            print(f"\n  [PIVOT d={next_depth}] {seed_type}={seed_value!r}")
            emit("pivot_start", {
                "seed":      seed_value,
                "seed_type": seed_type,
                "depth":     next_depth,
            })

            try:
                sub_ctx, sub_pipeline = build_sub_pipeline(
                    seed_value, seed_type, ctx, next_depth
                )
                sub_pipeline.run(
                    emit=emit,
                    pivot_config=pivot_config,
                    seed_queue=seed_queue,
                    pivot_confirm_fn=confirm_fn,
                )
                merge_results(ctx, sub_ctx)
                launched += 1

                emit("pivot_done", {
                    "seed":      seed_value,
                    "seed_type": seed_type,
                    "depth":     next_depth,
                    "merged":    True,
                })
                print(f"  [PIVOT d={next_depth}] ✓ merged: {seed_value!r}")

            except Exception as exc:
                print(
                    f"  [PIVOT d={next_depth}] ✗ failed for "
                    f"{seed_type}={seed_value!r}: {exc}"
                )
                traceback.print_exc()
                emit("pivot_error", {
                    "seed":    seed_value,
                    "error":   str(exc),
                    "depth":   next_depth,
                })

    return launched