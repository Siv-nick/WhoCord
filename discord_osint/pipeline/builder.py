"""
discord_osint/pipeline/builder.py
-----------------------------------
Pipeline builders for all investigation modes.

Fix
---
``IntelligenceStage`` is now part of every pipeline, so the knowledge
graph / correlation / AI narrative step actually runs.

`ReportingStage` is intentionally **not** included here:
  * it must run *after* adaptive pivoting finishes, so it can embed
    pivot sub-reports in the final HTML, and
  * pivot processing happens inside ``Pipeline.run()`` *after* the stage
    loop, which means a stage list ending in ReportingStage would render
    the report before pivots were merged.

The root ``run_osint_pipeline()`` / ``run_module_pipeline()`` functions
call ``ReportingStage().run(ctx, emit)`` explicitly once everything
(including pivots) is complete.
"""

from __future__ import annotations

from .base import Pipeline
from .context import InvestigationContext
from .stages import (
    DiscordModeStage,
    DiscoveryStage,
    ScrapingStage,
    MediaStage,
    AnalysisStage,
    IntelligenceStage,
    EmailIntelStage,
)


def build_pipeline(ctx: InvestigationContext) -> Pipeline:
    """
    Full investigation pipeline.

    Discord mode:
        DiscordModeStage → Discovery → Scraping → Media
        → Analysis → Intelligence → EmailIntel

    Manual mode:
        Discovery → Scraping → Media
        → Analysis → Intelligence → EmailIntel
    """
    stages = []

    if ctx.mode == "discord":
        stages.append(DiscordModeStage())

    stages.extend([
        DiscoveryStage(),
        ScrapingStage(),
        MediaStage(),
        AnalysisStage(),
        IntelligenceStage(),
        EmailIntelStage(),
    ])
    return Pipeline(stages, ctx)


def build_sub_pipeline(ctx: InvestigationContext) -> Pipeline:
    """
    Lightweight sub-pipeline.

    Note: the pivot runner in ``pivot.py`` builds its own sub-pipeline
    from scratch.  This function is kept so callers who want a
    ``Pipeline`` object without a Discord fetch have a public entry
    point, and it mirrors what pivot.py builds.
    """
    stages = [
        DiscoveryStage(),
        ScrapingStage(),
        MediaStage(),
        AnalysisStage(),
        IntelligenceStage(),
        EmailIntelStage(),
    ]
    return Pipeline(stages, ctx)


def build_email_pipeline(ctx: InvestigationContext) -> Pipeline:
    from .stages.email_investigation import EmailInvestigationStage
    stages = [
        EmailInvestigationStage(),
        ScrapingStage(),
        IntelligenceStage(),
    ]
    return Pipeline(stages, ctx)


def build_domain_pipeline(ctx: InvestigationContext) -> Pipeline:
    from .stages.domain_investigation import DomainInvestigationStage
    stages = [
        DomainInvestigationStage(),
        IntelligenceStage(),
    ]
    return Pipeline(stages, ctx)


def build_phone_pipeline(ctx: InvestigationContext) -> Pipeline:
    from .stages.phone_investigation import PhoneInvestigationStage
    stages = [
        PhoneInvestigationStage(),
        IntelligenceStage(),
    ]
    return Pipeline(stages, ctx)


def build_image_pipeline(ctx: InvestigationContext) -> Pipeline:
    from .stages.image_analysis import ImageAnalysisStage
    stages = [
        ImageAnalysisStage(),
        IntelligenceStage(),
    ]
    return Pipeline(stages, ctx)


def build_url_pipeline(ctx: InvestigationContext) -> Pipeline:
    from .stages.url_analysis import URLAnalysisStage
    stages = [
        URLAnalysisStage(),
        ScrapingStage(),
        IntelligenceStage(),
    ]
    return Pipeline(stages, ctx)


def build_probe_pipeline(ctx: InvestigationContext) -> Pipeline:
    from .stages.data_probe import DataProbeStage
    stages = [
        DataProbeStage(),
        IntelligenceStage(),
    ]
    return Pipeline(stages, ctx)


_MODULE_BUILDERS = {
    "email":  build_email_pipeline,
    "domain": build_domain_pipeline,
    "phone":  build_phone_pipeline,
    "image":  build_image_pipeline,
    "url":    build_url_pipeline,
    "probe":  build_probe_pipeline,
}


def build_module_pipeline(module_mode: str, ctx: InvestigationContext) -> Pipeline:
    builder = _MODULE_BUILDERS.get(module_mode)
    if builder is None:
        raise ValueError(
            f"Unknown module_mode {module_mode!r}. "
            f"Valid values: {sorted(_MODULE_BUILDERS)}"
        )
    ctx.module_mode = module_mode
    return builder(ctx)