"""
discord_osint/pipeline/stages/data_probe.py
--------------------------------------------
DataProbeStage – Phase 4 auto-detect investigation router.

This stage examines ``ctx.probe_string``, classifies it as email /
domain / phone / URL / username, then builds and runs the appropriate
module sub-pipeline in-process.

Design notes
------------
- DataProbeStage is the ONLY stage in the probe pipeline (followed by
  ReportingStage).  It creates an entirely new InvestigationContext
  configured for the detected module and runs that pipeline end-to-end.
- Results from the child pipeline are merged back into the parent
  context so the reporting stage renders a single, unified report.
- The probe_string and the detected type are stored in intel so the
  report can display the classification decision.

Detection priority (first match wins):
  1. Starts with http → URL
  2. Contains @, matches email pattern → Email
  3. Matches phone pattern (starts with +, or 8+ consecutive digits) → Phone
  4. Contains dot, no spaces, ≥4 chars → Domain
  5. Everything else → Username (manual pipeline)
"""

from __future__ import annotations

import re

from ..base import Stage, EmitFn
from ..context import InvestigationContext

# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_PHONE_RE = re.compile(r"^(\+\d[\d\s\-\(\)]{6,14}|\d{8,15})$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


def classify_probe(raw: str) -> str:
    """
    Return the detected type string:
    "url" | "email" | "phone" | "domain" | "username"
    """
    s = raw.strip()
    if s.startswith("http://") or s.startswith("https://"):
        return "url"
    if "@" in s and _EMAIL_RE.match(s):
        return "email"
    stripped = re.sub(r"[\s\-\(\)\.]", "", s)
    if _PHONE_RE.match(stripped) or (s.startswith("+") and len(stripped) >= 7):
        return "phone"
    if "." in s and " " not in s and len(s) >= 4 and _DOMAIN_RE.match(s):
        return "domain"
    return "username"


# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

class DataProbeStage(Stage):
    """
    Auto-detect the input type and execute the appropriate module pipeline.
    """

    name = "data_probe"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        raw = ctx.probe_string.strip()

        if not raw:
            print("  [DataProbe] Empty probe_string – skipping.")
            return

        detected_type = classify_probe(raw)

        print(f"\n{'=' * 60}")
        print(f"== Data Probe: {raw[:60]!r}")
        print(f"== Detected type: {detected_type.upper()}")
        print(f"{'=' * 60}")

        ctx.intel_core.add_intel("probe", "input",  raw,           source="manual_input")
        ctx.intel_core.add_intel("probe", "type",   detected_type, source="data_probe")

        emit("finding", {
            "type":          "probe_classification",
            "value":         raw,
            "detected_type": detected_type,
        })

        # ------------------------------------------------------------------ #
        # Route to the correct module                                         #
        # ------------------------------------------------------------------ #
        if detected_type == "url":
            self._run_url(ctx, raw, emit)
        elif detected_type == "email":
            self._run_email(ctx, raw, emit)
        elif detected_type == "phone":
            self._run_phone(ctx, raw, emit)
        elif detected_type == "domain":
            self._run_domain(ctx, raw, emit)
        else:  # username
            self._run_username(ctx, raw, emit)

        print(f"\n== Data Probe routing complete ==")

    # ------------------------------------------------------------------ #
    # Module runners – each sets the relevant ctx field and delegates     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _run_email(ctx: InvestigationContext, email: str, emit: EmitFn) -> None:
        from .email_investigation import EmailInvestigationStage
        ctx.manual_email = email
        emit("progress", {"message": f"Data Probe → Email module: {email}"})
        EmailInvestigationStage().run(ctx, emit)

    @staticmethod
    def _run_domain(ctx: InvestigationContext, domain: str, emit: EmitFn) -> None:
        from .domain_investigation import DomainInvestigationStage
        ctx.manual_domain = domain
        emit("progress", {"message": f"Data Probe → Domain module: {domain}"})
        DomainInvestigationStage().run(ctx, emit)

    @staticmethod
    def _run_phone(ctx: InvestigationContext, phone: str, emit: EmitFn) -> None:
        from .phone_investigation import PhoneInvestigationStage
        ctx.manual_phone = phone
        emit("progress", {"message": f"Data Probe → Phone module: {phone}"})
        PhoneInvestigationStage().run(ctx, emit)

    @staticmethod
    def _run_url(ctx: InvestigationContext, url: str, emit: EmitFn) -> None:
        from .url_analysis import URLAnalysisStage
        ctx.manual_url = url
        emit("progress", {"message": f"Data Probe → URL module: {url[:50]}"})
        URLAnalysisStage().run(ctx, emit)

    @staticmethod
    def _run_username(ctx: InvestigationContext, username: str, emit: EmitFn) -> None:
        """
        Username → run the standard discovery + scraping stages in-place.
        The context is already in manual mode; just set the username and
        invoke the stages directly.
        """
        from .discovery import DiscoveryStage
        from .scraping_stage import ScrapingStage
        from .analysis import AnalysisStage
        from .intelligence import IntelligenceStage
        from .email_intel_stage import EmailIntelStage

        ctx.username = username
        emit("progress", {"message": f"Data Probe → Username module: {username}"})

        for stage_cls in (DiscoveryStage, ScrapingStage, AnalysisStage,
                          IntelligenceStage, EmailIntelStage):
            try:
                stage_cls().run(ctx, emit)
            except Exception as exc:
                print(f"  [DataProbe] {stage_cls.__name__} error: {exc}")
