"""
discord_osint/pipeline/stages/scraping_stage.py
------------------------------------------------
ScrapingStage – concurrently scrape known-platform profiles and
generic profile URLs discovered by DiscoveryStage.

Phase 5 addition
----------------
After storing scraped data into intel_core, this stage now emits a
``profile_enrichment`` event for every scraped profile that has useful
data (bio, avatar, name, extra fields).  This allows the Investigation
Canvas frontend to update the already-created ``profile_url`` nodes
with rich details in real time.

``profile_enrichment`` payload::

    {
      "type":       "profile_enrichment",
      "url":        "https://github.com/OneOfOne",      # matches the profile_url node
      "site":       "github",
      "username":   "OneOfOne",
      "name":       "Ahmed W.",
      "bio":        "Coder and gamer.",
      "blog":       "https://oneofone.dev",
      "avatar_url": "https://avatars.githubusercontent.com/u/1080443?v=4",
      "location":   "Texas, USA",
      "company":    "@AlpineIQ",
      "followers":  "127",
      "created_at": "2011-09-26T11:58:18Z",
      "twitter":    "10F1",
      "extra":      {"public_repos": "149", ...}
    }

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
        scrape_tasks: list[tuple[str, str, str]] = []  # (platform, slug, original_url)
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
                scrape_tasks.append((plat, slug, url))
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
        scraped: list[tuple[str, str, str, dict]] = []  # (plat, slug, url, info)
        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures = {
                ex.submit(scrape_profile_info, p, s): (p, s, u)
                for p, s, u in scrape_tasks
            }
            for fut in as_completed(futures):
                p, s, u = futures[fut]
                try:
                    info = fut.result()
                    if info:
                        scraped.append((p, s, u, info))
                except Exception as exc:
                    print(f"  Scrape failed {p}/{s}: {exc}")

        # ------------------------------------------------------------------ #
        # Generic URL scraping                                                #
        # ------------------------------------------------------------------ #
        generic_scraped: list[tuple[str, dict]] = []
        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures_g = {ex.submit(scrape_generic_url, url): url for url in generic_urls}
            for fut in as_completed(futures_g):
                url = futures_g[fut]
                try:
                    info = fut.result()
                    if info:
                        generic_scraped.append((url, info))
                except Exception as exc:
                    print(f"  Generic scrape failed {url}: {exc}")

        # ------------------------------------------------------------------ #
        # Store platform-scrape results + emit enrichment events             #
        # ------------------------------------------------------------------ #
        for plat, slug, original_url, info in scraped:
            name  = info.get("name")  or ""
            email = info.get("email") or ""

            if name and looks_like_real_name_v2(name):
                ctx.intel_core.add_intel(
                    "identity_clues", f"name_{plat}/{slug}",
                    name, source=f"scrape_{plat}",
                )
                emit("finding", {"type": "name_clue", "value": name, "source": plat})

            if email and is_valid_personal_email(email):
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

            avatar_url = info.get("avatar", "")
            if avatar_url:
                ctx.add_avatar(avatar_url)
                # Store in profile_avatars so the enrichment event can include it
                ctx.intel_core.add_intel(
                    "profile_avatars", f"{plat}/{slug}",
                    avatar_url, source=f"scrape_{plat}",
                )

            # ── Emit enrichment event so the canvas can update the node ───
            self._emit_enrichment(
                emit=emit,
                url=original_url,
                plat=plat,
                slug=slug,
                info=info,
                name=name,
                avatar_url=avatar_url,
            )

        # ------------------------------------------------------------------ #
        # Store generic-scrape results + emit enrichment events              #
        # ------------------------------------------------------------------ #
        for url, info in generic_scraped:
            email = info.get("email") or ""
            if email and is_valid_personal_email(email):
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

            avatar_url = info.get("avatar", "")
            if avatar_url:
                ctx.add_avatar(avatar_url)
                ctx.intel_core.add_intel(
                    "profile_avatars", url,
                    avatar_url, source="generic_scrape",
                )

            # Emit enrichment event for generic scraped URLs too
            self._emit_enrichment(
                emit=emit,
                url=url,
                plat="generic",
                slug="",
                info=info,
                name=info.get("name", ""),
                avatar_url=avatar_url,
            )

        print(f"  Scraping complete. "
              f"{len(scraped)} platform + {len(generic_scraped)} generic results stored.")

    # ------------------------------------------------------------------ #
    # Helper: emit profile_enrichment                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _emit_enrichment(
        emit: EmitFn,
        url: str,
        plat: str,
        slug: str,
        info: dict,
        name: str,
        avatar_url: str,
    ) -> None:
        """
        Emit a ``profile_enrichment`` event if there is anything useful
        to show beyond the bare URL.  The frontend listens for this to
        update existing ``profile_url`` nodes.
        """
        bio      = info.get("bio",      "")
        blog     = info.get("blog",     "")
        location = info.get("location", "")
        company  = info.get("company",  "")
        followers= info.get("followers","")
        created  = info.get("created_at","")
        twitter  = info.get("twitter_username", "")
        repos    = info.get("public_repos", "")
        gists    = info.get("public_gists", "")

        # Build extra dict for any remaining useful fields
        extra: dict = {}
        if repos:    extra["public_repos"]  = str(repos)
        if gists:    extra["public_gists"]  = str(gists)
        if twitter:  extra["twitter"]       = str(twitter)

        # Derive the canonical human URL (strip API prefix)
        human_url = url
        if "api.github.com/users/" in url:
            user = url.split("/users/")[-1].split("/")[0]
            human_url = f"https://github.com/{user}"

        # Only emit if we have at least one useful piece of data
        has_data = any([name, bio, avatar_url, location, company, blog, followers])
        if not has_data:
            return

        emit("profile_enrichment", {
            "url":        url,        # matches the profile_url node label
            "human_url":  human_url,  # cleaned URL for display
            "site":       plat,
            "username":   slug,
            "name":       name or "",
            "bio":        bio[:300] if bio else "",
            "avatar_url": avatar_url or "",
            "blog":       blog or "",
            "location":   location or "",
            "company":    company or "",
            "followers":  str(followers) if followers else "",
            "created_at": created or "",
            "extra":      extra,
        })
