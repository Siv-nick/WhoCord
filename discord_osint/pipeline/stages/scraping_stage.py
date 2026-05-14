"""
discord_osint/pipeline/stages/scraping_stage.py
------------------------------------------------
ScrapingStage – concurrently scrape known-platform profiles and
generic profile URLs discovered by DiscoveryStage.

Reads from ctx
--------------
ctx.all_urls      – built by DiscoveryStage

Writes to ctx
-------------
ctx.intel_core    – names, emails, bios, socid, avatar URLs
ctx.avatar_urls   – any avatar image URLs found during scraping
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from ...scraping import is_valid_personal_email, is_email_linked_to_target
from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import MAX_SCRAPE_WORKERS
from ...discord_api import classify_url
from ...scraping import (
    scrape_profile_info,
    scrape_generic_url,
    is_likely_profile_url_v2,
    looks_like_real_name_v2,
    is_valid_personal_email,
)


class ScrapingStage(Stage):
    name = "scraping"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        cfg = ctx.config

        # ------------------------------------------------------------------ #
        # Split URLs into known-platform vs generic                           #
        # ------------------------------------------------------------------ #
        scrape_tasks: list[tuple[str, str]] = []  # (platform, slug)
        generic_urls: list[str] = []
        seen: set[str] = set()

        _skip_platforms = {
            "facebook", "instagram", "tiktok", "pinterest", "snapchat", "linkedin"
        }

        for url in ctx.all_urls:
            if url in seen:
                continue
            seen.add(url)
            plat, slug = classify_url(url)
            if plat and slug and plat not in _skip_platforms:
                scrape_tasks.append((plat, slug))
            elif is_likely_profile_url_v2(url):
                generic_urls.append(url)

        print(
            f"\nEnriching {len(scrape_tasks)} known & "
            f"{len(generic_urls)} generic profiles..."
        )
        emit("progress", {
            "message": f"Scraping {len(scrape_tasks)} known + {len(generic_urls)} generic profiles"
        })

        # ------------------------------------------------------------------ #
        # Platform-specific scraping                                          #
        # ------------------------------------------------------------------ #
        scraped: list[tuple[str, str, dict]] = []
        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures = {
                ex.submit(scrape_profile_info, p, s): (p, s)
                for p, s in scrape_tasks
            }
            for fut in as_completed(futures):
                p, s = futures[fut]
                try:
                    info = fut.result()
                    if info:
                        scraped.append((p, s, info))
                except Exception as exc:
                    print(f"  Scrape failed {p}/{s}: {exc}")

        # ------------------------------------------------------------------ #
        # Generic URL scraping                                                #
        # ------------------------------------------------------------------ #
        generic_scraped: list[tuple[str, dict]] = []
        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures = {ex.submit(scrape_generic_url, url): url for url in generic_urls}
            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    info = fut.result()
                    if info:
                        generic_scraped.append((url, info))
                except Exception as exc:
                    print(f"  Generic scrape failed {url}: {exc}")

        # ------------------------------------------------------------------ #
        # Store platform-scrape results                                       #
        # ------------------------------------------------------------------ #
        for plat, slug, info in scraped:
            name = info.get("name") or ""
            email = info.get("email") or ""

            if name and looks_like_real_name_v2(name):
                ctx.intel_core.add_intel(
                    "identity_clues", f"name_{plat}/{slug}",
                    name, source=f"scrape_{plat}",
                )
                emit("finding", {"type": "name_clue", "value": name, "source": plat})

            if email and is_valid_personal_email(email) and is_email_linked_to_target(email, ctx.username):
                ctx.intel_core.add_intel(
                    "emails", email, email, source=f"scrape_{plat}"
                )
                emit("finding", {"type": "email", "value": email, "source": plat})

            if info.get("bio"):
                ctx.intel_core.add_intel(
                    "social_profiles", f"{plat}/{slug}/bio",
                    info["bio"][:200], source=f"scrape_{plat}",
                )

            if info.get("blog"):
                ctx.intel_core.add_intel(
                    "social_profiles", f"{plat}/{slug}/blog",
                    info["blog"], source=f"scrape_{plat}",
                )

            socid_data = info.get("socid")
            if socid_data:
                if isinstance(socid_data, dict):
                    fullname = socid_data.get("fullname", "")
                    if fullname and looks_like_real_name_v2(fullname):
                        ctx.intel_core.add_intel(
                            "identity_clues",
                            f"name_socid_{plat}/{slug}",
                            fullname, source="socid-extractor",
                        )
                    image = socid_data.get("image", "")
                    if image and image.startswith("http"):
                        ctx.add_avatar(image)
                ctx.intel_core.add_intel(
                    "social_profiles",
                    f"{plat}/{slug}/socid_raw",
                    json.dumps(socid_data),
                    source="socid-extractor",
                )

            if info.get("avatar"):
                ctx.add_avatar(info["avatar"])

        # ------------------------------------------------------------------ #
        # Store generic-scrape results                                        #
        # ------------------------------------------------------------------ #
        for url, info in generic_scraped:
            email = info.get("email") or ""
            if email and is_valid_personal_email(email) and is_email_linked_to_target(email, ctx.username):
                ctx.intel_core.add_intel(
                    "emails", email, email, source="generic_scrape"
                )
                emit("finding", {"type": "email", "value": email, "source": "generic_scrape"})

            socid_data = info.get("socid")
            if socid_data:
                if isinstance(socid_data, dict):
                    fullname = socid_data.get("fullname", "")
                    if fullname and looks_like_real_name_v2(fullname):
                        ctx.intel_core.add_intel(
                            "identity_clues",
                            f"name_socid_generic_{url[:40]}",
                            fullname, source="socid-extractor",
                        )
                    image = socid_data.get("image", "")
                    if image and image.startswith("http"):
                        ctx.add_avatar(image)
                ctx.intel_core.add_intel(
                    "social_profiles",
                    f"generic_{url[:40]}/socid_raw",
                    json.dumps(socid_data),
                    source="socid-extractor",
                )

            if info.get("avatar"):
                ctx.add_avatar(info["avatar"])

        # Store avatar URLs for the HTML report
        for plat, slug, info in scraped:
            avatar = info.get("avatar")
            if avatar and avatar.startswith("http"):
                # The profile URL is already in the intel; we don't need to reconstruct.
                # We'll store by the unique combination of platform and slug.
                ctx.intel_core.add_intel(
                    "profile_avatars", f"{plat}/{slug}",
                    avatar, source=f"scrape_{plat}"
                )

        for url, info in generic_scraped:
            avatar = info.get("avatar")
            if avatar and avatar.startswith("http"):
                ctx.intel_core.add_intel(
                    "profile_avatars", url,
                    avatar, source="generic_scrape"
                )

        print(f"  Scraping complete. "
              f"{len(scraped)} platform + {len(generic_scraped)} generic results stored.")
