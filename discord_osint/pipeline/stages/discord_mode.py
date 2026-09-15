"""
discord_osint/pipeline/stages/discord_mode.py
----------------------------------------------
DiscordModeStage – fetch and enrich a Discord user profile.

Only executes when ctx.mode == "discord".  In manual mode this stage
adds a minimal intel entry and exits immediately.

Change log
----------
- Phase 4: CordCat enrichment. When ``ENABLE_CORD_CAT`` is on and a
  ``CORD_CAT_API_KEY`` is stored, the stage calls cord.cat after the
  Discord profile is fetched and emits findings for every section
  that has data. The raw result is stored under
  ``intel["cordcat"]["lookup"]`` for the report renderer.
- On failure to fetch the profile, raises PipelineAbortError.
"""

from __future__ import annotations

import re
from ...scraping import is_valid_personal_email, is_email_linked_to_target
from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...errors import PipelineAbortError
from ...discord_api import (
    get_discord_user_profile,
    enrich_discord_profile,
    snowflake_to_datetime,
)
from ...scraping import is_valid_personal_email
from ...utils import log_trace

# CordCat is imported lazily inside the stage run so a missing module
# (should not happen, but for safety) does not break CLI imports.
from ...config import get_flag as _flag


class DiscordModeStage(Stage):
    name = "discord_mode"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        if ctx.mode != "discord":
            ctx.intel_core.add_intel(
                "discord", "username", ctx.username, source="manual_input"
            )
            return

        # ------------------------------------------------------------------ #
        # 1. Fetch profile from guild                                         #
        # ------------------------------------------------------------------ #
        print(f"==> Fetching Discord user {ctx.target_user_id}...")
        emit("progress", {"message": f"Fetching Discord profile {ctx.target_user_id}"})

        profile = get_discord_user_profile(
            ctx.config.DISCORD_TOKEN,
            ctx.target_user_id,
            ctx.target_guild_id,
        )
        if not profile:
            raise PipelineAbortError(
                self.name,
                "Failed to fetch Discord profile. "
                "Check that the token is valid and the user is in the guild.",
            )

        username = profile["username"]
        disc = profile.get("discriminator", "0")
        handle = f"{username}#{disc}" if disc != "0" else username
        print(f"Discord: {handle}")
        emit("finding", {"type": "discord_handle", "value": handle})

        ctx.username = username
        ctx.intel_core.add_intel(
            "discord", "username", username, source="discord_api"
        )

        # ------------------------------------------------------------------ #
        # 2. Enrich profile (bio, connected accounts, avatar, banner)         #
        # ------------------------------------------------------------------ #
        enriched = enrich_discord_profile(
            ctx.config.DISCORD_TOKEN, ctx.target_user_id
        )
        if enriched:
            ctx.intel_core.add_intel(
                "discord", "banner_hash", enriched.get("banner"),
                source="discord_enrich"
            )
            ctx.intel_core.add_intel(
                "discord", "accent_color", enriched.get("accent_color"),
                source="discord_enrich"
            )
            bio = enriched.get("bio", "") or ""
            ctx.intel_core.add_intel(
                "discord", "bio", bio, source="discord_enrich"
            )

            for acc in enriched.get("connected_accounts", []):
                acc_type = acc.get("type", "")
                acc_name = acc.get("name", "")
                if acc_name:
                    ctx.intel_core.add_intel(
                        "social_profiles",
                        f"discord_connected_{acc_type}",
                        acc_name,
                        source="discord_enrich",
                    )
                    emit("finding", {
                        "type": "connected_account",
                        "platform": acc_type,
                        "value": acc_name,
                    })

            if bio:
                emails = re.findall(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", bio
                )
                for email in emails:
                    if is_valid_personal_email(email) and is_email_linked_to_target(email, ctx.username):
                        ctx.intel_core.add_intel(
                            "emails", email, email, source="discord_bio"
                        )
                        emit("finding", {"type": "email", "value": email})

                name_match = re.search(
                    r"^([A-Z][a-z]+)\s+([A-Z][a-z]+)", bio.split("\n")[0]
                )
                if name_match:
                    ctx.intel_core.add_intel(
                        "identity_clues",
                        "name_discord_bio",
                        name_match.group(0),
                        source="discord_bio",
                    )
                    emit("finding", {
                        "type": "name_clue",
                        "value": name_match.group(0),
                        "source": "discord_bio",
                    })

            avatar_hash = enriched.get("avatar")
            if avatar_hash:
                cdn_url = (
                    f"https://cdn.discordapp.com/avatars/"
                    f"{ctx.target_user_id}/{avatar_hash}.png?size=1024"
                )
                ctx.intel_core.add_intel(
                    "discord", "avatar_cdn", cdn_url, source="discord_enrich"
                )
                ctx.add_avatar(cdn_url)
                emit("finding", {"type": "avatar_url", "value": cdn_url})

        # ------------------------------------------------------------------ #
        # 3. Account age from snowflake                                       #
        # ------------------------------------------------------------------ #
        account_age = snowflake_to_datetime(int(ctx.target_user_id))
        ctx.intel_core.add_intel(
            "discord", "account_created", account_age, source="snowflake"
        )
        print(f"  Account created: {account_age}")

        # ------------------------------------------------------------------ #
        # 4. CordCat enrichment (Phase 4)                                     #
        # ------------------------------------------------------------------ #
        self._maybe_cordcat(ctx, emit)

    # ------------------------------------------------------------------ #
    # CordCat
    # ------------------------------------------------------------------ #

    @staticmethod
    def _maybe_cordcat(ctx: InvestigationContext, emit: EmitFn) -> None:
        """
        Run a CordCat lookup if enabled and configured.

        Never raises — a CordCat failure is logged and the
        investigation continues. The Discord profile fetch is the
        load-bearing step; CordCat is enrichment.
        """
        if not _flag("ENABLE_CORD_CAT"):
            return

        api_key = getattr(ctx.config, "CORD_CAT_API_KEY", "") or ""
        if not api_key:
            print("  CordCat: ENABLE_CORD_CAT is on but no API key stored — skipping.")
            return

        try:
            from ... import cord_cat
        except ImportError as exc:
            log_trace(f"cord_cat: import failed: {exc}")
            return

        print("  CordCat lookup…")
        emit("progress", {"message": "CordCat: Discord enrichment"})

        try:
            result = cord_cat.lookup(
                str(ctx.target_user_id),
                api_key=api_key,
            )
        except cord_cat.CordCatRateLimitError as exc:
            print(f"  CordCat: {exc}")
            log_trace(f"cord_cat: rate limit hit for {ctx.target_user_id}: {exc}")
            return
        except Exception as exc:
            log_trace(f"cord_cat: unexpected exception: {type(exc).__name__}: {exc}")
            print(f"  CordCat: unexpected error — {exc}")
            return

        if not result.ok:
            print(f"  CordCat: {result.error}")
            log_trace(f"cord_cat: lookup failed for {ctx.target_user_id}: {result.error}")
            return

        # Store the raw result for the report renderer.
        try:
            ctx.intel_core.add_intel(
                "cordcat", "lookup", result.to_dict(), source="cord_cat",
            )
        except Exception as exc:
            log_trace(f"cord_cat: could not store result: {exc}")

        # Emit findings. A malformed section inside emit_findings is
        # the caller's problem — we let exceptions propagate to the
        # outer handler rather than swallowing per-section.
        try:
            cord_cat.emit_findings(result, emit)
        except Exception as exc:
            log_trace(f"cord_cat: emit_findings raised: {type(exc).__name__}: {exc}")

        # Brief console summary for the operator.
        bits: list[str] = []
        if result.has_breach:
            try:
                count = int(result.breach.get("count") or 0)
            except (TypeError, ValueError):
                count = 0
            bits.append(f"breach={count}")
        if result.has_fivem:
            bits.append("fivem=yes")
        if result.has_statements:
            bits.append(f"dsa={len(result.statements)}")
        if result.score:
            bits.append(f"score={result.score.get('value') or '?'}")
        if bits:
            print(f"  CordCat: {', '.join(bits)}")
        else:
            print("  CordCat: no data for this ID.")