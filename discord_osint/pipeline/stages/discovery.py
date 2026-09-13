"""
discord_osint/pipeline/stages/discovery.py
-------------------------------------------
DiscoveryStage – find the target's social profiles.

Every discovered URL — human or API — goes through
`_fetch_api_responses`, which derives additional JSON endpoints and
emits one `api_response` finding per success.

`_fetch_api_responses` is fully instrumented: every attempt, skip, and
success is written to the active debug log via `log_trace()`.

NOTE: `api_response` findings no longer carry the raw `data` blob in
the SSE payload — only `key_fields`. The raw JSON is still persisted in
`intel["api_data"]` and rendered in reports. This prevents the SSE
stream from drowning the frontend on large investigation graphs.

Change log
----------
Step 8 now splits the discovery list into two buckets:

* Plausible *profile* URLs → ``intel["social_profiles"]``
* Everything else          → ``intel["discovered_urls"]``

Previously every hit — API endpoints, signup pages, short links — was
stored as a "platform profile" and then dumped into the intelligence
graph, where the co-occurrence rule made them a fully-connected clique.
"""

from __future__ import annotations

import os
import shutil
import time
from urllib.parse import urlparse

from ...scraping import is_valid_personal_email, is_email_linked_to_target
from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import clean_username, CACHE_DIR, tool_available, log_trace
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
    run_user_scanner,
    run_maigret,
    run_sociopath,
    run_linkook,
    run_blackbird,
)
from ...wmn_scanner import run_wmn_scan
from ...extras import socialscan_filter
from ...api_extractor import (
    looks_like_api, is_useful_response, human_label, fetch_api,
    extract_key_fields, derive_api_candidates,
)


def _site_from_url(url: str, fallback: str = "unknown") -> str:
    """Return a short, human-readable site name for a URL."""
    try:
        host = urlparse(url).netloc.lower()
        if host:
            if host.startswith("www."):
                host = host[4:]
            return host.split(":")[0]
    except Exception:
        pass
    return fallback


# ---------------------------------------------------------------------------
# Junk-URL classifier (module-level so it can be unit-tested)
# ---------------------------------------------------------------------------

_SKIP_PROFILE_HOSTS = (
    "account.proton.me",
    "discord.com",
    "matrix.to",
    "bit.ly",
    "t.co",
    "youtu.be",
)

_SKIP_PROFILE_PATH_FRAGMENTS = (
    "/oembed",
    "/lookup",
    "?validate=",
    "checkusername",
    "email_available",
    "username_available",
    "/signup/",
    "/public/users",
    "/public/v1/",
    "/rest/v",
)


def _looks_like_profile(url: str) -> bool:
    """
    Return True when *url* looks like a real, user-facing profile page.

    Filters out:
      * bare-domain and root-path URLs,
      * known non-profile hosts (signup pages, short-link services),
      * JSON API endpoints (via ``looks_like_api``),
      * utility endpoints like ``/lookup``, ``/validate``, ``/oembed``,
      * query-string-only "profiles" like ``example.com/user?id=x``.
    """
    if not url or not url.startswith("http"):
        return False
    try:
        p = urlparse(url)
    except Exception:
        return False

    host = p.netloc.lower()
    path = (p.path or "").lower()

    if any(host == h or host.endswith("." + h) for h in _SKIP_PROFILE_HOSTS):
        return False

    # Bare domain or root
    if not path or path == "/":
        return False

    # Known API endpoints
    if looks_like_api(url):
        return False

    if any(seg in path for seg in _SKIP_PROFILE_PATH_FRAGMENTS):
        return False

    # Query-string-only profiles (e.g. news.ycombinator.com/user?id=x)
    if "?" in url and "id=" in url:
        return False

    return True


# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

class DiscoveryStage(Stage):
    name = "discovery"

    _MAX_API_FETCHES = 60

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        if ctx.discovery_done:
            print("  Discovery already completed – skipping duplicate run.")
            return
        ctx.discovery_done = True

        clean_user = clean_username(ctx.username)
        cfg = ctx.config

        bb_cache = os.path.join(CACHE_DIR, "blackbird_output")
        if os.path.exists(bb_cache):
            shutil.rmtree(bb_cache)
        os.makedirs(bb_cache, exist_ok=True)
        bb_t0 = time.time()

        # ── 1. user-scanner (375+ platforms) ──────────────────────────
        if getattr(cfg, "ENABLE_USER_SCANNER", True):
            try:
                print(f"\n-- user-scanner on: {clean_user} --")
                emit("progress", {"message": f"user-scanner: {clean_user}"})
                us_results = run_user_scanner(clean_user, mode="username") or []
                print(f"  user-scanner found {len(us_results)} profiles.")
                for r in us_results:
                    url = r.get("url", "")
                    if url:
                        ctx.add_discovery(_site_from_url(url, r.get("site", "user-scanner")), url)
                        extra = r.get("extra")
                        if isinstance(extra, dict) and extra:
                            ctx.intel_core.add_intel(
                                "social_enrichment",
                                url,
                                extra,
                                source="user-scanner",
                            )
            except Exception as e:
                print(f"  user-scanner error: {e}")

        # ── 2. Blackbird username mode (optional) ────────────────────
        if getattr(cfg, "ENABLE_BLACKBIRD", False):
            try:
                print(f"\n-- blackbird username search on: {clean_user} --")
                emit("progress", {"message": f"blackbird username: {clean_user}"})
                bb_user = run_blackbird(clean_user, mode="username") or []
                for r in bb_user:
                    url = r.get("url", "")
                    if url:
                        ctx.add_discovery(_site_from_url(url, r.get("site", "blackbird")), url)
                print(f"  blackbird found {len(bb_user)} endpoint(s).")
            except Exception as e:
                print(f"  blackbird username search error: {e}")

        # ── 3. WhatsMyName dataset (600+ API endpoints) ──────────────
        if getattr(cfg, "ENABLE_WMN", True):
            try:
                print(f"\n-- WhatsMyName scan on: {clean_user} --")
                emit("progress", {"message": f"WMN scan: {clean_user}"})
                wmn_results = run_wmn_scan(clean_user, emit=emit) or []
                for r in wmn_results:
                    url = r.get("url", "")
                    if url:
                        site_label = r.get("site") or _site_from_url(url, "wmn")
                        ctx.add_discovery(site_label, url)
                        pretty = r.get("pretty_url", "")
                        if pretty and pretty != url:
                            ctx.add_discovery(site_label, pretty)
                print(f"  WMN added {len(wmn_results)} endpoint(s).")
            except Exception as e:
                print(f"  WMN scan error: {e}")

        # ── 4. Maigret fallback ──────────────────────────────────────
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
                        ctx.add_discovery(_site_from_url(url, f"maigret_{item.get('site','')}"), url)
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

        # ── 5. Linkook (deep URL discovery) ──────────────────────────
        if cfg.ENABLE_LINKOOK:
            try:
                print("\n-- linkook --")
                emit("progress", {"message": "linkook"})
                urls = run_linkook(clean_user) or []
                for u in urls:
                    ctx.add_discovery(_site_from_url(u, "linkook"), u)
            except Exception as e:
                print(f"  linkook error: {e}")

        # ── 6. Sociopath (URL spider) ────────────────────────────────
        if getattr(cfg, "ENABLE_SOCIOPATH", False):
            print("\n-- sociopath --")
            emit("progress", {"message": "sociopath"})
            snapshot = list(ctx.discovery[:20])
            for item in snapshot:
                try:
                    print(f"  Spidering: {item['url'][:60]}...")
                    spiders = run_sociopath(item["url"]) or []
                    for sp in spiders:
                        url = sp.get("url", "")
                        ctx.add_discovery(_site_from_url(url, "sociopath"), url)

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
                except Exception as e:
                    print(f"  Sociopath error on {item['url']}: {e}")

        # ── 7. Blackbird email mode ──────────────────────────────────
        manual_email = ctx.manual_email
        if manual_email and is_valid_email(manual_email):
            try:
                print(f"\n-- blackbird email search on: {manual_email} --")
                emit("progress", {"message": f"blackbird email: {manual_email}"})
                bb_email = run_blackbird(manual_email, mode="email") or []
                for r in bb_email:
                    url = r.get("url", "")
                    ctx.add_discovery(_site_from_url(url, r.get("site", "blackbird")), url)
                if is_email_linked_to_target(manual_email, ctx.username):
                    ctx.intel_core.add_intel(
                        "emails", manual_email, manual_email, source="manual_input"
                    )
            except Exception as e:
                print(f"  blackbird email search error: {e}")

        self._copy_blackbird_outputs(cfg, bb_t0, ctx)

        # ── 8. Persist discovered URLs into intel_core + emit nodes ──
        #
        # Only real-looking profile URLs go into ``social_profiles``.
        # API endpoints, signup pages, short links, and query-string
        # URLs go into a separate ``discovered_urls`` bucket so the
        # profile count stays honest and the intelligence graph doesn't
        # explode.
        profiles_kept = 0
        urls_kept     = 0

        for item in ctx.discovery:
            url = item.get("url", "")
            if not url:
                continue
            site = item.get("site", "unknown")

            if _looks_like_profile(url):
                ctx.intel_core.add_intel(
                    "social_profiles",
                    f"discovery_{site}_{url[:60]}",
                    url, source="discovery",
                )
                emit("finding", {"type": "profile_url", "url": url, "site": site})
                profiles_kept += 1
            else:
                ctx.intel_core.add_intel(
                    "discovered_urls",
                    f"{site}_{url[:60]}",
                    url, source="discovery",
                )
                urls_kept += 1

        print(
            f"  Discovery persisted: {profiles_kept} profile URL(s), "
            f"{urls_kept} raw URL(s) → discovered_urls"
        )

        # ── 9. Discord message search (discord mode only) ────────────
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
                        print(f"  {plat}: {len(tracking[plat])} tracked link(s)")

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

        # ── 10. Build all_urls + optional socialscan filtering ───────
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

        # ── 11. Extra targets ────────────────────────────────────────
        for t in ctx.extra_targets:
            try:
                if is_valid_email(t):
                    print(f"\n-- blackbird email on extra target: {t} --")
                    bb = run_blackbird(t, mode="email") or []
                    if is_email_linked_to_target(t, ctx.username):
                        ctx.intel_core.add_intel("emails", t, t, source="manual_input")
                else:
                    print(f"\n-- user-scanner on extra target: {t} --")
                    us = run_user_scanner(t, mode="username") or []
                    for r in us:
                        url = r.get("url", "")
                        if url:
                            ctx.add_discovery(_site_from_url(url, r.get("site", "user-scanner")), url)
            except Exception as e:
                print(f"  extra target error: {e}")

        # ── 12. Fetch JSON from discovered URLs (direct + derived) ───
        self._fetch_api_responses(ctx, emit)

    # ── Private helpers ────────────────────────────────────────────────

    @classmethod
    def _fetch_api_responses(cls, ctx: InvestigationContext, emit: EmitFn) -> None:
        """
        Fetch JSON from every discovered URL and emit an ``api_response``
        finding for each success.

        Every decision — skip, attempt, success, failure — is written to
        the active debug log via ``log_trace()``.
        """
        seen_candidates:  set[str] = set()
        emitted                   = 0
        direct_attempts           = 0
        derived_urls              = 0
        derived_attempts          = 0

        total = len(ctx.discovery)
        print(f"\n== [_fetch_api_responses] ENTERING with {total} discovery entries ==")
        emit("progress", {"message": "Fetching JSON from discovered URLs"})
        log_trace("=" * 60)
        log_trace(f"_fetch_api_responses: ENTER, {total} discovery entries, "
                  f"max_fetches={cls._MAX_API_FETCHES}")

        # ── Pass 1: direct API URLs ──────────────────────────────────
        log_trace("--- PASS 1: direct API URLs ---")
        for item in ctx.discovery:
            if emitted >= cls._MAX_API_FETCHES:
                log_trace(f"pass1: cap reached ({cls._MAX_API_FETCHES}), stopping")
                break
            url = item.get("url", "")
            if not url:
                continue
            if url in seen_candidates:
                continue
            seen_candidates.add(url)

            if not looks_like_api(url):
                continue

            direct_attempts += 1
            data = fetch_api(url)
            if data is None:
                log_trace(f"pass1: fetch returned None for {url}")
                continue
            if not is_useful_response(data):
                log_trace(f"pass1: USELESS data for {url} — {repr(data)[:120]}")
                continue
            if cls._emit_api_finding(ctx, emit, url, data, item.get("site", "")):
                emitted += 1

        direct_hits = emitted
        log_trace(f"--- PASS 1 DONE: {direct_attempts} attempts, {direct_hits} hits ---")

        # ── Pass 2: derive API candidates from human profile URLs ────
        log_trace("--- PASS 2: derived from profile URLs ---")
        for item in ctx.discovery:
            if emitted >= cls._MAX_API_FETCHES:
                log_trace(f"pass2: cap reached ({cls._MAX_API_FETCHES}), stopping")
                break
            url = item.get("url", "")
            if not url or looks_like_api(url):
                continue
            derived_urls += 1

            candidates = derive_api_candidates(url)
            log_trace(f"pass2: {url}")
            log_trace(f"       → {len(candidates)} candidate(s): {candidates}")

            for cand in candidates:
                if emitted >= cls._MAX_API_FETCHES:
                    break
                if cand in seen_candidates:
                    log_trace(f"       cand already seen: {cand}")
                    continue
                seen_candidates.add(cand)
                derived_attempts += 1

                data = fetch_api(cand)
                if data is None:
                    continue
                if not is_useful_response(data):
                    log_trace(f"       USELESS: {cand} — {repr(data)[:120]}")
                    continue
                if cls._emit_api_finding(
                    ctx, emit, cand, data, item.get("site", ""),
                    source_url=url,
                ):
                    emitted += 1

        derived_hits = emitted - direct_hits
        log_trace(f"--- PASS 2 DONE: {derived_urls} urls, "
                  f"{derived_attempts} candidate attempts, {derived_hits} hits ---")
        log_trace(f"--- TOTAL: {emitted} api_response finding(s) ---")
        log_trace("=" * 60)

        print(f"  pass1: {direct_attempts} api-like url(s), {direct_hits} hit(s)")
        print(f"  pass2: {derived_urls} profile url(s), {derived_attempts} candidate fetches, {derived_hits} hit(s)")
        print(f"  total: {emitted} api_response finding(s)")
        if emitted == 0:
            print("  (nothing emitted — see debug_logs/ for per-fetch reasons)")

    @staticmethod
    def _emit_api_finding(
        ctx: InvestigationContext,
        emit: EmitFn,
        api_url: str,
        data,
        site: str,
        source_url: str | None = None,
    ) -> bool:
        try:
            label      = human_label(api_url)
            key_fields = extract_key_fields(data, api_url)
        except Exception as exc:
            log_trace(f"_emit_api_finding: EXCEPTION {type(exc).__name__}: {exc}")
            return False

        # NOTE: 'data' is intentionally NOT included in the SSE payload.
        # The full JSON is persisted in intel["api_data"] and is available
        # for reports. Sending it over SSE flooded the browser with
        # multi-KB messages per finding, freezing the UI on large
        # investigations.
        emit("finding", {
            "type":       "api_response",
            "url":        api_url,
            "label":      label,
            "site":       site,
            "key_fields": key_fields,
            "source":     "api_fetch",
            "source_url": source_url or api_url,
        })

        ctx.intel_core.add_intel(
            "api_data",
            f"api_{api_url[:60]}",
            data,
            source="api_fetch",
        )

        derived = " (derived)" if source_url and source_url != api_url else ""
        log_trace(f"EMIT api_response: {label} — {len(key_fields)} field(s){derived}")
        print(f"  [API] {label} — {len(key_fields)} key field(s){derived}")
        return True

    @staticmethod
    def _copy_blackbird_outputs(cfg, bb_t0: float, ctx: InvestigationContext) -> None:
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