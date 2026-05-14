"""
discord_osint/pipeline/stages/discovery.py
-------------------------------------------
DiscoveryStage – find the target's social profiles via username-search
tools, Discord message mining, and tracking-link resolution.

Outputs written to ctx
-----------------------
ctx.discovery   – list[{site, url}] from all tools
ctx.all_urls    – flat de-duped list ready for scraping
ctx.messages    – raw Discord messages (discord mode only)
"""

from __future__ import annotations

import os
import shutil
import time
from ...scraping import is_valid_personal_email, is_email_linked_to_target
from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import (
    clean_username, CACHE_DIR, tool_available
)
from ...scraping import (
    looks_like_real_name_v2, is_valid_personal_email, is_valid_email
)
from ...discord_api import (
    multi_guild_message_search,
    extract_links_from_messages,
    extract_tracking_links,
    resolve_tracking_links,
    cluster_links_by_username,
    find_target_cluster,
    classify_url,
)
from ...username_search import (
    run_naminter, run_sherlock, run_social_analyzer,
    run_sociopath, run_linkook, run_maigret, run_blackbird,
)
from ...extras import socialscan_filter


class DiscoveryStage(Stage):
    name = "discovery"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        # Prevent duplicate runs for the same context
        if ctx.discovery_done:
            print("  Discovery already completed – skipping duplicate run.")
            return
        ctx.discovery_done = True

        clean_user = clean_username(ctx.username)
        cfg = ctx.config
        # ------------------------------------------------------------------ #
        # 0. Clean stale Blackbird cache before this run                      #
        # ------------------------------------------------------------------ #
        bb_cache = os.path.join(CACHE_DIR, "blackbird_output")
        if os.path.exists(bb_cache):
            shutil.rmtree(bb_cache)
        os.makedirs(bb_cache, exist_ok=True)
        bb_t0 = time.time()

        # ------------------------------------------------------------------ #
        # 1. Username enumeration tools                                       #
        # ------------------------------------------------------------------ #

        if cfg.ENABLE_NAMINTER:
            try:
                print(f"\n-- naminter on: {clean_user} --")
                emit("progress", {"message": f"naminter: {clean_user}"})
                results = run_naminter(clean_user) or []
                print(f"  naminter found {len(results)} profiles.")
                for r in results:
                    ctx.add_discovery(r.get("site", "naminter"), r.get("url", ""))
            except Exception as e:
                print(f"  naminter error: {e}")

        if cfg.ENABLE_SHERLOCK:
            try:
                print(f"\n-- sherlock on: {clean_user} --")
                emit("progress", {"message": f"sherlock: {clean_user}"})
                results = run_sherlock(clean_user) or []
                print(f"  Sherlock found {len(results)} profiles.")
                for r in results:
                    ctx.add_discovery(r.get("site", "sherlock"), r.get("url", ""))
            except Exception as e:
                print(f"  sherlock error: {e}")

        # social-analyzer only runs when the other tools found nothing
        if not ctx.discovery and cfg.ENABLE_SOCIAL_ANALYZER:
            try:
                print("\n-- social-analyzer (fast sites) --")
                emit("progress", {"message": "social-analyzer fallback"})
                results = run_social_analyzer(clean_user) or []
                for r in results:
                    ctx.add_discovery(r.get("site", "social_analyzer"), r.get("url", ""))
            except Exception as e:
                print(f"  social-analyzer error: {e}")

        if cfg.ENABLE_LINKOOK:
            try:
                print("\n-- linkook --")
                emit("progress", {"message": "linkook"})
                urls = run_linkook(clean_user) or []
                for u in urls:
                    ctx.add_discovery("linkook", u)
            except Exception as e:
                print(f"  linkook error: {e}")

        if cfg.ENABLE_SOCIOPATH:
            print("\n-- sociopath --")
            emit("progress", {"message": "sociopath"})
            snapshot = list(ctx.discovery[:20])
            for item in snapshot:
                try:
                    print(f"  Spidering: {item['url'][:60]}...")
                    spiders = run_sociopath(item["url"]) or []
                    for sp in spiders:
                        url = sp.get("url", "")
                        ctx.add_discovery("sociopath", url)

                        # Capture identity clues from sociopath enrichment
                        display = sp.get("display_name", "")
                        if not display:
                            page_title = sp.get("PageTitle", "")
                            if "|" in page_title:
                                display = page_title.split("|")[0].strip()
                            elif "-" in page_title:
                                display = page_title.rsplit("-", 1)[0].strip()
                        if display and looks_like_real_name_v2(display):
                            ctx.intel_core.add_intel(
                                "identity_clues",
                                f"name_sociopath_{item['url'][:40]}",
                                display,
                                source="sociopath",
                            )

                        email = sp.get("email", "")
                        if email and is_valid_personal_email(email) and is_email_linked_to_target(email, ctx.username):
                            ctx.intel_core.add_intel(
                                "emails", f"sociopath_{email}", email,
                                source="sociopath"
                            )

                        enrichment = {}
                        if display:
                            enrichment["display_name"] = display
                        if email:
                            enrichment["email"] = email
                        desc = sp.get("description", "") or sp.get("Bio", "")
                        if desc:
                            enrichment["bio"] = desc[:200]
                        if url and enrichment:
                            ctx.intel_core.add_intel(
                                "social_enrichment", url, enrichment, source="sociopath"
                            )
                except Exception as e:
                    print(f"  Sociopath error on {item['url']}: {e}")

        if cfg.ENABLE_MAIGRET:
            try:
                if not tool_available("maigret"):
                    print("  [!] maigret not installed – skipping.")
                else:
                    print(f"\n-- maigret on: {clean_user} --")
                    emit("progress", {"message": f"maigret: {clean_user}"})
                    results = run_maigret(clean_user) or []
                    for item in results:
                        url = item.get("url", "")
                        ctx.add_discovery(f"maigret_{item.get('site','')}", url)
                        name = item.get("name", "")
                        if name and looks_like_real_name_v2(name):
                            ctx.intel_core.add_intel(
                                "identity_clues",
                                f"name_maigret_{item.get('site','')}",
                                name, source="maigret",
                            )
                        bio = item.get("bio", "")
                        if bio:
                            ctx.intel_core.add_intel(
                                "social_profiles",
                                f"maigret_bio_{item.get('site','')}",
                                bio[:200], source="maigret",
                            )
                        location = item.get("location", "")
                        if location:
                            ctx.intel_core.add_intel(
                                "identity_clues",
                                f"location_maigret_{item.get('site','')}",
                                location, source="maigret",
                            )
            except Exception as e:
                print(f"  maigret error: {e}")

        # ------------------------------------------------------------------ #
        # 2. Blackbird (username)                                             #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_BLACKBIRD:
            try:
                print(f"\n-- blackbird on: {clean_user} --")
                emit("progress", {"message": f"blackbird username: {clean_user}"})
                bb = run_blackbird(clean_user, mode="username") or []
                print(f"  Blackbird found {len(bb)} profiles.")
                for r in bb:
                    ctx.add_discovery(r.get("site", "blackbird"), r.get("url", ""))
            except Exception as e:
                print(f"  blackbird username error: {e}")

        # Blackbird email search for manual_email
        manual_email = ctx.manual_email
        if manual_email and is_valid_email(manual_email):
            try:
                print(f"\n-- blackbird email search on: {manual_email} --")
                emit("progress", {"message": f"blackbird email: {manual_email}"})
                bb_email = run_blackbird(manual_email, mode="email") or []
                for r in bb_email:
                    ctx.add_discovery(r.get("site", "blackbird"), r.get("url", ""))
                if is_email_linked_to_target(manual_email, ctx.username):
                    ctx.intel_core.add_intel(
                        "emails", manual_email, manual_email, source="manual_input"
                    )
            except Exception as e:
                print(f"  blackbird email search error: {e}")

        # Copy Blackbird JSON output files to cache
        self._copy_blackbird_outputs(cfg, bb_t0, ctx)

        # ------------------------------------------------------------------ #
        # 3. Persist every discovered URL into intel_core right now          #
        # ------------------------------------------------------------------ #
        for item in ctx.discovery:
            url = item.get("url", "")
            if url:
                ctx.intel_core.add_intel(
                    "social_profiles",
                    f"discovery_{item.get('site','unknown')}_{url[:60]}",
                    url, source="discovery",
                )
                emit("finding", {"type": "profile_url", "url": url, "site": item.get("site")})

        # ------------------------------------------------------------------ #
        # 4. Discord message search (only in discord mode)                    #
        # ------------------------------------------------------------------ #
        target_urls: list[str] = []
        if ctx.mode == "discord":
            try:
                print("\n-- Searching messages for links --")
                emit("progress", {"message": "Searching Discord messages for links"})
                messages = multi_guild_message_search(
                    cfg.DISCORD_TOKEN, ctx.target_user_id, ctx.target_guild_id
                )
                ctx.messages = messages
                links = extract_links_from_messages(messages)
                print(f"  Found {len(links)} links in messages.")

                tracking = extract_tracking_links(messages, ctx.target_user_id)
                for plat, urls in tracking.items():
                    if urls:
                        print(f"  {plat}: {len(urls)} tracked link(s)")

                if cfg.ENABLE_SHARETRACE and any(tracking.values()):
                    resolved = resolve_tracking_links(tracking)
                    for plat, res in resolved.items():
                        for identity in res:
                            name = identity.get("username") or identity.get("display_name", "")
                            print(f"  Resolved {plat} sharer: {name}")
                            ctx.intel_core.add_intel(
                                "social_profiles",
                                f"sharetrace_{plat}_{name}",
                                identity, source="sharetrace",
                            )

                clusters = cluster_links_by_username(links)
                slug, cluster_urls = find_target_cluster(clusters, ctx.username)
                if slug:
                    print(f"  Target's link cluster '{slug}': {len(cluster_urls)} URLs")
                target_urls = list(cluster_urls)
            except Exception as e:
                print(f"  Discord message search error: {e}")

        # ------------------------------------------------------------------ #
        # 5. Build all_urls + optional socialscan filtering                   #
        # ------------------------------------------------------------------ #
        raw_urls = list({
            *[e["url"] for e in ctx.discovery if e.get("url")],
            *target_urls,
        })

        if cfg.ENABLE_SOCIALSCAN and tool_available("socialscan"):
            try:
                print("\n-- socialscan filtering --")
                emit("progress", {"message": "socialscan URL filtering"})
                raw_urls = socialscan_filter(raw_urls)
                self._copy_socialscan_outputs()
            except Exception as e:
                print(f"  socialscan error: {e}")

        ctx.all_urls = raw_urls

        # ------------------------------------------------------------------ #
        # 6. Extra targets (additional usernames / emails from config)        #
        # ------------------------------------------------------------------ #
        for t in ctx.extra_targets:
            try:
                if is_valid_email(t):
                    print(f"\n-- blackbird email on extra target: {t} --")
                    bb = run_blackbird(t, mode="email") or []
                    # Only store the email if it is actually linked to the target username
                    if is_email_linked_to_target(t, ctx.username):
                        ctx.intel_core.add_intel("emails", t, t, source="manual_input")
                else:
                    print(f"\n-- blackbird username on extra target: {t} --")
                    bb = run_blackbird(t, mode="username") or []
                for r in bb:
                    ctx.add_discovery(r.get("site", "blackbird"), r.get("url", ""))
            except Exception as e:
                print(f"  extra target error: {e}")

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _copy_blackbird_outputs(cfg, bb_t0: float, ctx: InvestigationContext) -> None:
        """Copy Blackbird JSON files created during this run into cache."""
        bb_output_dir = os.path.join(CACHE_DIR, "blackbird_output")
        os.makedirs(bb_output_dir, exist_ok=True)
        for root, _dirs, files in os.walk(cfg.BLACKBIRD_DIR):
            for fname in files:
                if not fname.endswith("_blackbird.json"):
                    continue
                src = os.path.join(root, fname)
                try:
                    mtime = os.path.getmtime(src)
                    if mtime >= bb_t0:
                        dst = os.path.join(bb_output_dir, fname)
                        shutil.copy2(src, dst)
                        ctx.intel_core.add_intel(
                            "raw_tool_output",
                            f"blackbird_{fname}",
                            dst, source="blackbird",
                        )
                except OSError:
                    pass

    @staticmethod
    def _copy_socialscan_outputs() -> None:
        """Archive socialscan JSON results into cache."""
        socialscan_dir = os.path.join(CACHE_DIR, "socialscan_tmp")
        if not os.path.isdir(socialscan_dir):
            return
        scan_output_dir = os.path.join(CACHE_DIR, "socialscan_output")
        os.makedirs(scan_output_dir, exist_ok=True)
        for sf in os.listdir(socialscan_dir):
            if sf.startswith("scan_") and sf.endswith(".json"):
                shutil.copy2(
                    os.path.join(socialscan_dir, sf),
                    os.path.join(scan_output_dir, sf),
                )
