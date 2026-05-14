"""
discord_osint/pipeline/stages/discord_mode.py
----------------------------------------------
DiscordModeStage – fetch and enrich a Discord user profile.

Only executes when ctx.mode == "discord".  In manual mode this stage
adds a minimal intel entry and exits immediately.

On failure to fetch the profile (invalid token / user not in guild)
this stage raises PipelineAbortError so the rest of the pipeline
doesn't run with no data to work from.
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


class DiscordModeStage(Stage):
    name = "discord_mode"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        if ctx.mode != "discord":
            # Manual mode: just record the username and move on
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

        # Update context username with the resolved value
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

            # Connected social accounts (public)
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

            # Emails mentioned in bio
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

                # Try to extract a real name from the first line of bio
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

            # Avatar CDN URL
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
