"""
discord_osint/pipeline/stages/email_intel_stage.py
----------------------------------------------------
EmailIntelStage – run all email-based intelligence tools against every
email address discovered so far.

Uses the shared `enrich_email()` function from email_intel.py so that
manual/username investigations get the same rich data as the dedicated
email module.
"""

from __future__ import annotations

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...scraping import is_valid_email
from ...email_intel import enrich_email

_MAX_EMAILS = 10  # cap to avoid very long runs


class EmailIntelStage(Stage):
    name = "email_intel"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        # Collect all valid emails gathered so far
        all_emails: set[str] = set()
        for _k, v in ctx.intel_core.intel.get("emails", {}).items():
            val = v.get("value", "")
            if is_valid_email(val):
                all_emails.add(val)

        if not all_emails:
            print("\n-- Email intelligence: no emails to process --")
            return

        print(f"\n-- Email intelligence ({len(all_emails)} address(es)) --")
        emit("progress", {"message": f"Running email intel on {len(all_emails)} address(es)"})

        for email in list(all_emails)[:_MAX_EMAILS]:
            print(f"  Intel on {email}...")
            enrich_email(ctx, email, emit)

        print("  Email intelligence complete.")
