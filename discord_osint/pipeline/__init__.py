"""
discord_osint/pipeline/__init__.py
------------------------------------
Public entry point for the investigation pipeline.

Bug 12 fix: when manual mode has only an email, the mode switch is
            handled by web_app.py before dispatch. This function no
            longer silently reroutes; if it is invoked directly with
            only an email, it reports and delegates.
"""

from __future__ import annotations

import os

from .context import InvestigationContext
from .builder import build_pipeline, build_module_pipeline
from ..utils import CACHE_DIR

_MODULE_MODES = frozenset({"email", "domain", "phone", "image", "url", "probe"})


def _common_setup(config) -> tuple:
    from .. import utils
    utils.DEBUG_MODE = getattr(config, "DEBUG", False)
    if utils.DEBUG_MODE:
        print("[DEBUG] Debug mode active")

    from .pivot import PivotConfig, SeedQueue
    pivot_config = PivotConfig.from_config(config)
    seed_queue   = SeedQueue()

    emitter = getattr(config, "_phase3_emit", None)
    return pivot_config, seed_queue, emitter


def run_osint_pipeline(config=None) -> None:
    """
    Main entry point for manual / Discord investigations.
    """
    if config is None:
        from ..config import config as default_config
        config = default_config

    pivot_config, seed_queue, emitter = _common_setup(config)

    mode         = config.MODE
    manual_email = getattr(config, "MANUAL_EMAIL", "").strip() or \
                   os.environ.get("MANUAL_EMAIL", "").strip()

    if mode == "discord":
        target_user_id  = config.TARGET_USER_ID
        target_guild_id = config.TARGET_GUILD_ID
        username        = str(target_user_id)
        target_id       = target_user_id

    elif mode == "manual":
        username = (config.MANUAL_USERNAME or "").strip()
        manual_email = getattr(config, "MANUAL_EMAIL", "").strip()
        if not username and not manual_email:
            print("MANUAL_USERNAME is empty and no email supplied. Exiting.")
            return
        # Bug 12 fix: if we somehow get here with only an email, switch
        # explicitly and record the change so the caller sees the actual mode.
        if not username and manual_email:
            print("Only email provided – switching to email module.")
            config.MODE = "email"
            run_module_pipeline("email", config)
            return
        target_id = hash(username) & 0x7FFFFFFF
        target_user_id = None
        target_guild_id = None

    else:
        run_module_pipeline(mode, config)
        return

    from .. import utils
    if utils.DEBUG_MODE:
        utils.init_debug_log(target_id)

    from ..core import InvestigationCore
    intel_core = InvestigationCore(target_id)
    if config.ENABLE_CACHING:
        previous = intel_core.load_latest_state()
        if previous:
            print(f"  [✓] Loaded cached intel ({len(previous.get('timeline', []))} events).")
            intel_core.intel = previous
            intel_core.intel.pop("scraped_urls", None)

    if mode == "discord":
        seed_queue.mark_processed(str(target_user_id))
    if username:
        seed_queue.mark_processed(username)
    if manual_email:
        seed_queue.mark_processed(manual_email)

    if pivot_config.enabled:
        print(
            f"[PIVOT] Enabled – max_depth={pivot_config.max_depth}, "
            f"max_seeds={pivot_config.max_seeds_per_depth}"
        )

    ctx = InvestigationContext(
        config=config,
        mode=mode,
        username=username,
        target_id=target_id,
        target_user_id=target_user_id,
        target_guild_id=target_guild_id,
        manual_email=manual_email,
        extra_targets=list(getattr(config, "EXTRA_TARGETS", []) or []),
        intel_core=intel_core,
        depth=0,
        seed_type="",
        seed_value="",
    )

    confirm_fn = getattr(config, "_pivot_confirm_fn", None)

    pipeline = build_pipeline(ctx)
    pipeline.run(
        emit=emitter or (lambda *_: None),
        pivot_config=pivot_config,
        seed_queue=seed_queue,
        pivot_confirm_fn=confirm_fn,
    )

    if pivot_config.enabled:
        pivot_reports = ctx.intel_core.intel.get("pivot_reports", [])
        print(
            f"\n[PIVOT] Complete – {seed_queue.processed_count} seeds processed, "
            f"{len(pivot_reports)} sub-report(s) merged."
        )

    from .stages.reporting_stage import ReportingStage
    ReportingStage().run(ctx, emit=emitter or (lambda *_: None))


def run_module_pipeline(mode: str, config=None) -> None:
    if config is None:
        from ..config import config as default_config
        config = default_config

    if mode not in _MODULE_MODES:
        print(f"[pipeline] Unknown module mode {mode!r}. Falling back to manual pipeline.")
        run_osint_pipeline(config)
        return

    pivot_config, seed_queue, emitter = _common_setup(config)

    target_value = _resolve_target(mode, config)
    target_id    = hash(target_value) & 0x7FFFFFFF

    from .. import utils
    if utils.DEBUG_MODE:
        utils.init_debug_log(target_id)

    from ..core import InvestigationCore
    intel_core = InvestigationCore(target_id)

    ctx = InvestigationContext(
        config=config,
        mode="manual",
        username=target_value,
        target_id=target_id,
        intel_core=intel_core,
        module_mode=mode,
        manual_email=     (target_value if mode == "email"  else ""),
        manual_domain=    (target_value if mode == "domain" else ""),
        manual_phone=     (target_value if mode == "phone"  else ""),
        manual_image_url= (target_value if mode == "image"  else ""),
        manual_url=       (target_value if mode == "url"    else ""),
        probe_string=     (target_value if mode == "probe"  else ""),
        depth=0,
        seed_type="",
        seed_value="",
    )

    print(f"\n{'=' * 60}")
    print(f"== WhoCord Module: {mode.upper()} → {target_value[:60]}")
    print(f"{'=' * 60}")

    confirm_fn = getattr(config, "_pivot_confirm_fn", None)

    pipeline = build_module_pipeline(mode, ctx)
    pipeline.run(
        emit=emitter or (lambda *_: None),
        pivot_config=pivot_config,
        seed_queue=seed_queue,
        pivot_confirm_fn=confirm_fn,
    )

    from .stages.reporting_stage import ReportingStage
    ReportingStage().run(ctx, emit=emitter or (lambda *_: None))


def _resolve_target(mode: str, config) -> str:
    mapping = {
        "email":  "MANUAL_EMAIL",
        "domain": "MANUAL_DOMAIN",
        "phone":  "MANUAL_PHONE",
        "image":  "MANUAL_IMAGE_URL",
        "url":    "MANUAL_URL",
        "probe":  "PROBE_STRING",
    }
    attr = mapping.get(mode, "")
    if attr:
        val = getattr(config, attr, "") or ""
        if val.strip():
            return val.strip()

    for fallback in ("MANUAL_USERNAME", "MANUAL_EMAIL"):
        val = getattr(config, fallback, "") or ""
        if val.strip():
            return val.strip()

    return "unknown"