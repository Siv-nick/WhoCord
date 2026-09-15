"""
discord_osint/pipeline/stages/scraping_stage.py
------------------------------------------------
ScrapingStage – concurrently scrape known-platform profiles and
generic profile URLs discovered by DiscoveryStage.

Change log
----------
- Platform routing now reads from :mod:`discord_osint.platforms`. The
  old hardcoded ``_skip_platforms`` set is replaced with
  ``Platform.scrape_skip``. The routing decision also now falls
  through to generic scraping for platforms the registry knows about
  but which have no dedicated scraper (twitch, steam, gitlab, ...) —
  previously those URLs were classified and then silently dropped.
- ``ThreadPoolExecutor`` submit sites wrap the callable with
  ``contextvars.copy_context().run`` so ``_flag()`` inside the
  workers sees the active JobConfig.
"""

from __future__ import annotations

import contextvars
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import MAX_SCRAPE_WORKERS
from ...platforms import PLATFORMS
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

        scrape_tasks: list[tuple[str, str, str]] = []
        generic_urls: list[str] = []
        seen: set[str] = set()

        for url in ctx.all_urls:
            if url in seen:
                continue
            seen.add(url)
            plat, slug = classify_url(url)
            if plat and slug:
                p = PLATFORMS.get(plat)
                if p is not None:
                    if p.scrape_skip:
                        continue
                    if p.scrape_supported:
                        scrape_tasks.append((plat, slug, url))
                        continue
            if is_likely_profile_url_v2(url):
                generic_urls.append(url)

        print(
            f"\nEnriching {len(scrape_tasks)} known & "
            f"{len(generic_urls)} generic profiles..."
        )
        emit("progress", {
            "message": f"Scraping {len(scrape_tasks)} known + {len(generic_urls)} generic profiles"
        })

        scraped: list[tuple[str, str, str, dict]] = []

        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures = {}
            for p, s, u in scrape_tasks:
                worker_ctx = contextvars.copy_context()
                futures[ex.submit(worker_ctx.run, scrape_profile_info, p, s)] = (p, s, u)
            for fut in as_completed(futures):
                p, s, u = futures[fut]
                try:
                    info = fut.result()
                    if info:
                        scraped.append((p, s, u, info))
                except Exception as exc:
                    print(f"  Scrape failed {p}/{s}: {exc}")

        generic_scraped: list[tuple[str, dict]] = []
        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures_g = {}
            for url in generic_urls:
                worker_ctx = contextvars.copy_context()
                futures_g[ex.submit(worker_ctx.run, scrape_generic_url, url)] = url
            for fut in as_completed(futures_g):
                url = futures_g[fut]
                try:
                    info = fut.result()
                    if info:
                        generic_scraped.append((url, info))
                except Exception as exc:
                    print(f"  Generic scrape failed {url}: {exc}")

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
                ctx.intel_core.add_intel(
                    "profile_avatars", f"{plat}/{slug}",
                    avatar_url, source=f"scrape_{plat}",
                )

            self._emit_enrichment(
                emit=emit,
                url=original_url,
                plat=plat,
                slug=slug,
                info=info,
                name=name,
                avatar_url=avatar_url,
            )

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
        bio      = info.get("bio",      "")
        blog     = info.get("blog",     "")
        location = info.get("location", "")
        company  = info.get("company",  "")
        followers= info.get("followers","")
        created  = info.get("created_at","")
        twitter  = info.get("twitter_username", "")
        repos    = info.get("public_repos", "")
        gists    = info.get("public_gists", "")

        extra: dict = {}
        if repos:    extra["public_repos"]  = str(repos)
        if gists:    extra["public_gists"]  = str(gists)
        if twitter:  extra["twitter"]       = str(twitter)

        human_url = url
        if "api.github.com/users/" in url:
            user = url.split("/users/")[-1].split("/")[0]
            human_url = f"https://github.com/{user}"

        has_data = any([name, bio, avatar_url, location, company, blog, followers])
        if not has_data:
            return

        emit("profile_enrichment", {
            "url":        url,
            "human_url":  human_url,
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