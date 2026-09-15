"""
discord_osint/pipeline/stages/reporting_stage.py
-------------------------------------------------
ReportingStage – generate the AI persona summary, optional AI markdown
report, the HTML output file, and a signed evidence manifest.

Manifest scope
--------------
The manifest now covers the raw intel JSON produced by
``Pipeline.run``'s ``save_state()`` call — the primary evidence
artifact. Previously only the derived reports were hashed, so a
post-hoc edit of the intel snapshot did not invalidate the manifest.
The intel snapshot is added to ``artifacts`` *before*
``generate_manifest`` and registered into ``report_paths`` *after*,
so the snapshot does not appear twice.

Redaction and watermark
-----------------------
``REDACTED_FINDINGS`` in the config is a list of finding ``type``
strings stripped before the HTML is rendered. A non-empty case id
becomes a diagonal watermark on the report. Both are applied at
render time — the redacted values never reach the served file.
"""

from __future__ import annotations

import datetime
import getpass
import os

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import CACHE_DIR, log_trace
from ...reporting import (
    generate_persona_summary,
    generate_ai_report,
    format_ai_report_markdown,
)
from ...errors import ReportGenerationError
from ... import audit, manifest as manifest_module


class ReportingStage(Stage):
    name = "reporting"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        cfg        = ctx.config
        intel_core = ctx.intel_core
        target_id  = ctx.target_id
        ts         = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log        = ctx.log

        job_id  = getattr(cfg, "_job_id",  None) or str(target_id)
        case_id = getattr(cfg, "_case_id", "") or ""

        cancel_event = getattr(cfg, "_cancel_event", None)
        cost_acc     = getattr(cfg, "_cost_accumulator", None)

        def _is_cancelled() -> bool:
            return cancel_event is not None and cancel_event.is_set()

        def _spend_exceeded() -> tuple[bool, str]:
            if cost_acc is None:
                return False, ""
            try:
                return cost_acc.exceeded()
            except Exception:
                return False, ""

        report_paths: dict[str, str] = {}

        # ------------------------------------------------------------------ #
        # 1. AI persona summary                                               #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_AI_REPORT and getattr(cfg, "GROQ_API_KEY", ""):
            if _is_cancelled():
                log.info("  Persona summary skipped (pipeline cancelled).")
                log_trace("ReportingStage: persona summary skipped — cancelled.")
            else:
                over, reason = _spend_exceeded()
                if over:
                    log.warn(f"  Persona summary skipped: {reason}")
                    log_trace(f"ReportingStage: persona summary skipped — {reason}")
                else:
                    log.info("\n-- Generating Persona Summary --")
                    emit("progress", {"message": "Generating AI persona summary"})
                    try:
                        persona = generate_persona_summary(
                            intel_core.intel,
                            cfg.GROQ_API_KEY,
                            config=cfg,
                            log=log,
                        )
                        if persona:
                            intel_core.add_intel("persona_summary", "persona",
                                                 persona, source="ai_persona")
                            emit("finding", {"type": "persona_summary"})
                    except Exception as exc:
                        log.error(f"  Persona summary error: {exc}")
                        log_trace(f"ReportingStage: persona summary failed: "
                                  f"{type(exc).__name__}: {exc}")

        # ------------------------------------------------------------------ #
        # 2. AI structured report (markdown)                                  #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_AI_REPORT and getattr(cfg, "GROQ_API_KEY", ""):
            if _is_cancelled():
                log.info("  AI report skipped (pipeline cancelled).")
                log_trace("ReportingStage: AI markdown report skipped — cancelled.")
            else:
                over, reason = _spend_exceeded()
                if over:
                    log.warn(f"  AI report skipped: {reason}")
                    log_trace(f"ReportingStage: AI markdown report skipped — {reason}")
                else:
                    log.info("\n-- Generating AI report --")
                    emit("progress", {"message": "Generating AI structured report"})
                    try:
                        structured = generate_ai_report(
                            intel_core,
                            cfg.GROQ_API_KEY,
                            config=cfg,
                            log=log,
                        )
                        if structured:
                            md = format_ai_report_markdown(structured)
                            rp = os.path.join(CACHE_DIR,
                                              f"report_{target_id}_{ts}.md")
                            with open(rp, "w", encoding="utf-8") as f:
                                f.write(md)
                            try:
                                os.chmod(rp, 0o600)
                            except OSError:
                                pass
                            log.info(f"  AI report saved to {rp}")
                            emit("report_ready", {"path": rp, "format": "markdown"})
                            report_paths["markdown"] = rp
                            audit.write_event(
                                "report_generated",
                                job_id=job_id,
                                path=rp,
                                format="markdown",
                            )
                    except Exception as exc:
                        log.error(f"  AI report error: {exc}")
                        log_trace(f"ReportingStage: AI markdown report failed: "
                                  f"{type(exc).__name__}: {exc}")

        # ------------------------------------------------------------------ #
        # 3. HTML report                                                      #
        # ------------------------------------------------------------------ #
        output_format = getattr(cfg, "OUTPUT_FORMAT", "html")

        # Redaction list from config.
        redacted = set()
        try:
            raw_red = getattr(cfg, "REDACTED_FINDINGS", None) or []
            if isinstance(raw_red, list):
                redacted = {str(x) for x in raw_red if str(x).strip()}
        except Exception:
            redacted = set()

        watermark = ""
        if case_id:
            try:
                watermark = f"CASE {case_id} · {getpass.getuser()}"
            except Exception:
                watermark = f"CASE {case_id}"

        if output_format == "html":
            log.info("\n-- Generating HTML report --")
            emit("progress", {"message": "Generating HTML report"})
            try:
                from ...intelligence.html_report import generate_html_report as _gen_html

                html_path    = os.path.join(CACHE_DIR,
                                            f"report_{target_id}_{ts}.html")
                html_content = _gen_html(
                    intel_core, target_id,
                    redacted_types=frozenset(redacted),
                    watermark=watermark,
                )

                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                try:
                    os.chmod(html_path, 0o600)
                except OSError:
                    pass

                log.info(f"  HTML report saved to {html_path}")
                emit("report_ready", {"path": html_path, "format": "html"})
                report_paths["html"] = html_path
                audit.write_event(
                    "report_generated",
                    job_id=job_id,
                    path=html_path,
                    format="html",
                    redacted_types=sorted(redacted),
                    watermarked=bool(watermark),
                )
            except Exception as exc:
                log_trace(f"ReportingStage: HTML report failed: "
                          f"{type(exc).__name__}: {exc}")
                raise ReportGenerationError(str(exc)) from exc

        # ------------------------------------------------------------------ #
        # 4. Signed evidence manifest                                         #
        # ------------------------------------------------------------------ #
        if report_paths:
            try:
                secret = audit.load_or_create_secret()
                config_snapshot = (
                    cfg.to_dict() if hasattr(cfg, "to_dict") else {}
                )

                # Include the raw intel snapshot in the tamper-evident
                # set. This is the primary evidence artifact; a manifest
                # that covers only the derived reports protects the
                # wrong thing.
                artifacts = list(report_paths.values())
                snap = getattr(ctx, "intel_snapshot_path", "") or ""
                if snap and os.path.isfile(snap):
                    artifacts.append(snap)

                try:
                    operator = getpass.getuser()
                except Exception:
                    operator = "unknown"

                manifest_data = manifest_module.generate_manifest(
                    job_id=job_id,
                    artifacts=artifacts,
                    config_snapshot=config_snapshot,
                    secret=secret,
                    extra={
                        "target_id": str(target_id),
                        "case_id":   case_id,
                        "operator":  operator,
                        "redacted_findings": sorted(redacted),
                        "watermarked": bool(watermark),
                    },
                )
                manifest_path = os.path.join(
                    CACHE_DIR, f"manifest_{target_id}_{ts}.json",
                )
                manifest_module.write_manifest(manifest_data, manifest_path)
                report_paths["manifest"] = manifest_path
                log.info(f"  Evidence manifest saved to {manifest_path}")
                emit("report_ready", {"path": manifest_path, "format": "manifest"})
                audit.write_event(
                    "manifest_created",
                    job_id=job_id,
                    path=manifest_path,
                    artifact_count=len(manifest_data.get("artifacts", [])),
                )

                # Register the intel snapshot in report_paths *after*
                # the manifest is generated, so the snapshot does not
                # appear twice in artifacts.
                if snap and os.path.isfile(snap):
                    report_paths["intel"] = snap
                    emit("report_ready", {"path": snap, "format": "intel"})
            except Exception as exc:
                log_trace(f"ReportingStage: manifest generation failed: "
                          f"{type(exc).__name__}: {exc}")
                log.warn(f"  Evidence manifest generation failed: {exc}")

        if report_paths:
            intel_core.intel["report_paths"] = report_paths

        intel_core.intel.pop("scraped_urls", None)
        log.info("== Reporting stage complete ==")