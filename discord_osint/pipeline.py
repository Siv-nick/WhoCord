import re
import time
import json
import shutil
import os
import sys
import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import (
    http_session, github_session, clean_username,
    MAX_SCRAPE_WORKERS, REQUEST_DELAY, CACHE_DIR, tool_available
)
from .core import InvestigationCore
from .discord_api import (
    get_discord_user_profile,
    enrich_discord_profile,
    snowflake_to_datetime,
    multi_guild_message_search,
    extract_links_from_messages,
    extract_tracking_links,
    resolve_tracking_links,
    cluster_links_by_username,
    find_target_cluster,
    classify_url
)
from .scraping import (
    scrape_profile_info,
    scrape_generic_url,
    is_likely_profile_url_v2,
    looks_like_real_name_v2,
    is_valid_email,
    is_valid_personal_email,
    run_gitfive,
    is_likely_github_user
)
from .email_intel import (
    run_holehe, run_h8mail, run_ghunt, run_scylla,
    check_hibp, check_emailrep
)
from .username_search import (
    run_naminter, run_sherlock, run_social_analyzer,
    run_sociopath, run_linkook, run_maigret, run_blackbird
)
from .extras import (
    download_avatar, reverse_image_search, extract_metadata,
    whois_domain, wayback_available, infer_location, detect_language,
    socialscan_filter
)
from .reporting import (
    calculate_identity_confidence, run_name_analysis,
    generate_ai_report, format_ai_report_markdown,
    generate_html_report
)


def run_osint_pipeline(config=None):
    if config is None:
        from .config import config as default_config
        config = default_config

    # –– Debug mode activation ––
    from . import utils
    utils.DEBUG_MODE = getattr(config, 'DEBUG', False)

    mode = config.MODE
    target_user_id = config.TARGET_USER_ID
    target_guild_id = config.TARGET_GUILD_ID
    manual_username = config.MANUAL_USERNAME

    if mode == "discord":
        print(f"==> Fetching Discord user {target_user_id}...")
        profile = get_discord_user_profile(config.DISCORD_TOKEN, target_user_id, target_guild_id)
        if not profile:
            print("Failed to fetch Discord profile. Exiting."); return
        username = profile["username"]
        disc = profile.get('discriminator','0')
        d_handle = f"{username}#{disc}" if disc != '0' else username
        print(f"Discord: {d_handle}")
        target_id = target_user_id
    elif mode == "manual":
        username = manual_username.strip()
        if not username:
            print("MANUAL_USERNAME is empty. Exiting."); return
        print(f"==> Manual mode – investigating username: {username}")
        target_id = hash(username) & 0x7FFFFFFF
    else:
        print("Unknown MODE."); return

    if utils.DEBUG_MODE:
        utils.init_debug_log(target_id)

    intel_core = InvestigationCore(target_id)
    avatar_urls = set()
    clean_user = clean_username(username)
    manual_email = getattr(config, 'MANUAL_EMAIL', '').strip()

    if config.ENABLE_CACHING:
        previous = intel_core.load_latest_state()
        if previous:
            print(f"  [✓] Loaded previous intel snapshot ({len(previous.get('timeline',[]))} events).")
            intel_core.intel = previous
            if intel_core.intel.get("scraped_urls"):
                intel_core.intel.pop("scraped_urls", None)

    if mode == "discord":
        intel_core.add_intel("discord","username",username,source="discord_api")
        enriched = enrich_discord_profile(config.DISCORD_TOKEN, target_user_id)
        if enriched:
            intel_core.add_intel("discord","banner_hash", enriched.get("banner"), source="discord_enrich")
            intel_core.add_intel("discord","accent_color", enriched.get("accent_color"), source="discord_enrich")
            intel_core.add_intel("discord","bio", enriched.get("bio",""), source="discord_enrich")
            for acc in enriched.get("connected_accounts", []):
                acc_type = acc.get("type","")
                acc_name = acc.get("name","")
                if acc_name:
                    intel_core.add_intel("social_profiles", f"discord_connected_{acc_type}", acc_name, source="discord_enrich")
            bio = enriched.get("bio","")
            if bio:
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', bio)
                for email in emails:
                    if is_valid_personal_email(email):
                        intel_core.add_intel("emails",email,email,source="discord_bio")
                name_match = re.search(r'^([A-Z][a-z]+)\s+([A-Z][a-z]+)', bio.split('\n')[0])
                if name_match:
                    intel_core.add_intel("identity_clues","name_discord_bio", name_match.group(0), source="discord_bio")
            avatar_hash = enriched.get("avatar")
            if avatar_hash:
                cdn_url = f"https://cdn.discordapp.com/avatars/{target_user_id}/{avatar_hash}.png?size=1024"
                intel_core.add_intel("discord","avatar_cdn", cdn_url, source="discord_enrich")
        account_age = snowflake_to_datetime(target_user_id)
        intel_core.add_intel("discord","account_created", account_age, source="snowflake")
    else:
        intel_core.add_intel("discord","username",username,source="manual_input")

    try:
        discovery = []
        if config.ENABLE_NAMINTER:
            print(f"\n-- naminter on: {clean_user} --")
            nam_results = run_naminter(clean_user)
            if nam_results:
                print(f"naminter found {len(nam_results)} profiles.")
                discovery.extend(nam_results)

        if config.ENABLE_SHERLOCK:
            print(f"\n-- sherlock on: {clean_user} --")
            sherlock_results = run_sherlock(clean_user)
            if sherlock_results:
                print(f"Sherlock found {len(sherlock_results)} profiles.")
                existing_urls = {d["url"] for d in discovery}
                for r in sherlock_results:
                    if r["url"] not in existing_urls:
                        discovery.append(r)
                        existing_urls.add(r["url"])

        if not discovery and config.ENABLE_SOCIAL_ANALYZER:
            print(f"\n-- social-analyzer (fast sites) --")
            sa = run_social_analyzer(clean_user)
            if sa:
                for e in sa:
                    if e["url"] not in {d["url"] for d in discovery}: discovery.append(e)

        if config.ENABLE_LINKOOK:
            print(f"\n-- linkook --")
            urls = run_linkook(clean_user)
            for u in urls:
                if u not in {d["url"] for d in discovery}: discovery.append({"site":"linkook","url":u})

        if config.ENABLE_SOCIOPATH:
            print(f"\n-- sociopath --")
            for item in discovery[:20]:
                print(f"  Spidering: {item['url'][:60]}...")
                spiders = run_sociopath(item["url"])
                for sp in spiders:
                    url = sp.get("url")
                    if url and url.startswith("http") and url not in {d["url"] for d in discovery}:
                        discovery.append({"site": "sociopath", "url": url})
                    # ---- capture identity clues ----
                    display = sp.get("display_name", "")
                    if not display:
                        page_title = sp.get("PageTitle", "")
                        if "|" in page_title:
                            display = page_title.split("|")[0].strip()
                        elif "-" in page_title:
                            display = page_title.rsplit("-", 1)[0].strip()
                    if display and looks_like_real_name_v2(display):
                        intel_core.add_intel("identity_clues",
                                             f"name_sociopath_{item['url'][:40]}",
                                             display, source="sociopath")
                    email = sp.get("email", "")
                    if email and is_valid_personal_email(email):
                        intel_core.add_intel("emails",
                                             f"sociopath_{email}", email,
                                             source="sociopath")
                    desc = sp.get("description", "") or sp.get("Bio", "")
                    if desc:
                        intel_core.add_intel("social_profiles",
                                             f"sociopath_desc_{item['url'][:40]}",
                                             desc[:200], source="sociopath")

        if config.ENABLE_MAIGRET:
            if not tool_available("maigret"):
                print("  [!] maigret is not installed. Skipping.")
            else:
                print(f"\n-- maigret on: {clean_user} --")
                maigret_results = run_maigret(clean_user)
                for item in maigret_results:
                    url = item.get("url")
                    if url and url.startswith("http") and url not in {d["url"] for d in discovery}:
                        discovery.append({"site": f"maigret_{item['site']}", "url": url})
                    name = item.get("name")
                    if name and looks_like_real_name_v2(name):
                        intel_core.add_intel("identity_clues", f"name_maigret_{item['site']}", name, source="maigret")
                    bio = item.get("bio")
                    if bio:
                        intel_core.add_intel("social_profiles", f"maigret_bio_{item['site']}", bio[:200], source="maigret")
                    location = item.get("location")
                    if location:
                        intel_core.add_intel("identity_clues", f"location_maigret_{item['site']}", location, source="maigret")

        if config.ENABLE_BLACKBIRD:
            print(f"\n-- blackbird on: {clean_user} --")
            bb = run_blackbird(clean_user, mode="username")
            if bb:
                print(f"Blackbird found {len(bb)} profiles.")
                existing = {d["url"] for d in discovery}
                for r in bb:
                    if r.get("url", "") not in existing:
                        discovery.append(r)
                        existing.add(r["url"])

        if manual_email and is_valid_email(manual_email):
            print(f"\n-- blackbird email search on: {manual_email} --")
            bb_email = run_blackbird(manual_email, mode="email")
            if bb_email:
                existing = {d["url"] for d in discovery}
                for r in bb_email:
                    if r.get("url", "") not in existing:
                        discovery.append(r)
                        existing.add(r["url"])
            intel_core.add_intel("emails", manual_email, manual_email, source="manual_input")

        bb_output_dir = os.path.join(CACHE_DIR, "blackbird_output")
        os.makedirs(bb_output_dir, exist_ok=True)
        for fname in os.listdir(config.BLACKBIRD_DIR):
            if fname.endswith("_blackbird.json"):
                src = os.path.join(config.BLACKBIRD_DIR, fname)
                dst = os.path.join(bb_output_dir, fname)
                shutil.copy2(src, dst)
                intel_core.add_intel("raw_tool_output", f"blackbird_{fname}", dst, source="blackbird")

        if mode == "discord":
            print("\n-- Searching messages for links (across all visible guilds) --")
            messages = multi_guild_message_search(config.DISCORD_TOKEN, target_user_id, target_guild_id)
            links = extract_links_from_messages(messages)
            print(f"Found {len(links)} links in messages.")
            tracking = extract_tracking_links(messages, target_user_id)
            for plat,urls in tracking.items():
                if urls: print(f"  {plat}: {len(urls)} tracked link(s)")
            if config.ENABLE_SHARETRACE and any(tracking.values()):
                resolved = resolve_tracking_links(tracking)
                for plat,res in resolved.items():
                    for identity in res:
                        name = identity.get("username") or identity.get("display_name","")
                        print(f"  Resolved {plat} sharer: {name}")
                        intel_core.add_intel("social_profiles",f"sharetrace_{plat}_{name}",identity,source="sharetrace")
            clusters = cluster_links_by_username(links)
            slug, target_urls = find_target_cluster(clusters, username)
            if slug: print(f"\nTarget's cluster '{slug}': {len(target_urls)} URLs")
            else: target_urls = []
        else:
            links = set(); target_urls = []

        all_urls = list(set([e["url"] for e in discovery] + list(target_urls)))
        if config.ENABLE_SOCIALSCAN and tool_available("socialscan"):
            all_urls = socialscan_filter(all_urls)
            socialscan_dir = os.path.join(CACHE_DIR, "socialscan_tmp")
            if os.path.isdir(socialscan_dir):
                scan_output_dir = os.path.join(CACHE_DIR, "socialscan_output")
                os.makedirs(scan_output_dir, exist_ok=True)
                for sf in os.listdir(socialscan_dir):
                    if sf.startswith("scan_") and sf.endswith(".json"):
                        src = os.path.join(socialscan_dir, sf)
                        dst = os.path.join(scan_output_dir, sf)
                        shutil.copy2(src, dst)
                        intel_core.add_intel("raw_tool_output", f"socialscan_{sf}", dst, source="socialscan")
        scrape_tasks = []; generic_urls = []; seen = set()

        print(f"\nEnriching {len(scrape_tasks)} known & {len(generic_urls)} generic profiles...")
        scraped = []
        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures = {ex.submit(scrape_profile_info,p,s):(p,s) for p,s in scrape_tasks}
            for fut in as_completed(futures):
                p,s = futures[fut]
                try:
                    info = fut.result()
                    if info: scraped.append((p,s,info))
                except Exception as e: print(f"  Scrape failed {p}/{s}: {e}")
        generic_scraped = []
        with ThreadPoolExecutor(max_workers=MAX_SCRAPE_WORKERS) as ex:
            futures = {ex.submit(scrape_generic_url,url):url for url in generic_urls}
            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    info = fut.result()
                    if info: generic_scraped.append((url,info))
                except Exception as e: print(f"  Generic scrape failed {url}: {e}")

        for plat,slug,info in scraped:
            name = info.get("name") or ""
            email = info.get("email") or ""
            if name and looks_like_real_name_v2(name):
                intel_core.add_intel("identity_clues",f"name_{plat}/{slug}",name,source=f"scrape_{plat}")
            if email and is_valid_personal_email(email):
                intel_core.add_intel("emails",email,email,source=f"scrape_{plat}")
            if info.get("bio"):
                intel_core.add_intel("social_profiles",f"{plat}/{slug}/bio",info["bio"][:200],source=f"scrape_{plat}")
            if info.get("blog"):
                intel_core.add_intel("social_profiles",f"{plat}/{slug}/blog",info["blog"],source=f"scrape_{plat}")
            if info.get("socid"):
                socid_data = info["socid"]
                if isinstance(socid_data, dict):
                    fullname = socid_data.get("fullname","")
                    if fullname and looks_like_real_name_v2(fullname):
                        intel_core.add_intel("identity_clues",f"name_socid_{plat}/{slug}",fullname,source="socid-extractor")
                    image = socid_data.get("image","")
                    if image and image.startswith("http"):
                        avatar_urls.add(image)
                intel_core.add_intel("social_profiles",f"{plat}/{slug}/socid_raw",json.dumps(socid_data),source="socid-extractor")
            if info.get("avatar"):
                avatar_urls.add(info["avatar"])

        for url,info in generic_scraped:
            email = info.get("email") or ""
            if email and is_valid_personal_email(email):
                intel_core.add_intel("emails",email,email,source="generic_scrape")
            if info.get("socid"):
                socid_data = info["socid"]
                if isinstance(socid_data, dict):
                    fullname = socid_data.get("fullname","")
                    if fullname and looks_like_real_name_v2(fullname):
                        intel_core.add_intel("identity_clues",f"name_socid_generic_{url[:40]}",fullname,source="socid-extractor")
                    image = socid_data.get("image","")
                    if image and image.startswith("http"):
                        avatar_urls.add(image)
                intel_core.add_intel("social_profiles",f"generic_{url[:40]}/socid_raw",json.dumps(socid_data),source="socid-extractor")
            if info.get("avatar"):
                avatar_urls.add(info["avatar"])

        extra_targets = getattr(config, 'EXTRA_TARGETS', [])
        for t in extra_targets:
            if is_valid_email(t):
                print(f"\n-- blackbird email search on: {t} --")
                bb = run_blackbird(t, mode="email")
            else:
                print(f"\n-- blackbird username search on: {t} --")
                bb = run_blackbird(t, mode="username")
            existing = {d["url"] for d in discovery}
            for r in bb:
                if r.get("url", "") not in existing:
                    discovery.append(r)
                    existing.add(r.get("url", ""))
            if is_valid_email(t):
                intel_core.add_intel("emails", t, t, source="manual_input")
        # ================================================================
        #             MID‑PIPELINE: all post‑scraping analysis
        # ================================================================

        print("\n-- EXIF & reverse image --")
        avatar_files = []
        for avatar_url in avatar_urls:
            fpath = download_avatar(avatar_url, os.path.join(CACHE_DIR, "avatars"))
            if fpath:
                avatar_files.append(fpath)
        for fpath in avatar_files:
            meta = extract_metadata(fpath)
            if meta:
                if meta.get("gps"):
                    intel_core.add_intel("media", f"exif_gps_{os.path.basename(fpath)}",
                                         meta["gps"], source="exif")
                if meta.get("date_taken"):
                    intel_core.add_intel("media", f"exif_date_{os.path.basename(fpath)}",
                                         meta["date_taken"], source="exif")
            if config.ENABLE_REVERSE_IMG:
                results = reverse_image_search(fpath)
                if results:
                    intel_core.add_intel("media", f"reverse_img_{os.path.basename(fpath)}",
                                         results, source="saucenao")

        print("\n-- WHOIS on blog domains --")
        blogs = []
        for k, v in intel_core.intel.get("social_profiles", {}).items():
            if "blog" in k and v.get("value", "").startswith("http"):
                blogs.append(v["value"])
        for blog_url in set(blogs):
            try:
                domain = urlparse(blog_url).netloc
                if domain:
                    w = whois_domain(domain)
                    if w:
                        intel_core.add_intel("whois", domain, w, source="whois")
            except: pass

        print("\n-- Wayback Machine --")
        for url in all_urls:
            if config.ENABLE_WAYBACK:
                snap = wayback_available(url)
                if snap:
                    intel_core.add_intel("wayback", url, snap, source="wayback")

        print("\n-- GitFive on GitHub usernames --")
        github_slugs = set()
        for url in all_urls:
            pl, sl = classify_url(url)
            if pl == "github" and sl and is_likely_github_user(sl):
                github_slugs.add(sl)
        for slug in github_slugs:
            print(f"  GitFive on {slug}...")
            gf = run_gitfive(slug)
            if gf:
                emails = gf.get("emails", [])
                for email in emails:
                    if is_valid_personal_email(email.get("email", "")):
                        intel_core.add_intel("emails", f"gitfive_{email['email']}",
                                             email["email"], source="gitfive")
                name = gf.get("name")
                if name and looks_like_real_name_v2(name):
                    intel_core.add_intel("identity_clues", f"name_gitfive_{slug}",
                                         name, source="gitfive")

        print("\n-- Name analysis --")
        name_set = set()
        for k, v in intel_core.intel.get("identity_clues", {}).items():
            if k.startswith("name_") and v.get("value"):
                name_set.add(v["value"])
        if name_set and config.ENABLE_NAME_ANALYSIS:
            analysis = run_name_analysis(list(name_set))
            intel_core.intel["name_analysis"] = analysis
            for name, origin in analysis.get("name_origins", {}).items():
                intel_core.add_intel("name_analysis", f"origin_{name}", origin,
                                     source="nametrace")

        print("\n-- Email intelligence --")

        all_emails = set()
        for k, v in intel_core.intel.get("emails", {}).items():
            val = v.get("value", "")
            if is_valid_email(val):
                all_emails.add(val)
        for email in list(all_emails)[:10]:
            print(f"  Intel on {email}...")
            if config.ENABLE_HOLEHE:
                sites = run_holehe(email)
                if sites:
                    intel_core.add_intel("breaches", f"holehe_{email}",
                                         {"used_on": sites}, source="holehe")
            if config.ENABLE_H8MAIL:
                h8 = run_h8mail(email)
                if h8:
                    intel_core.add_intel("breaches", f"h8mail_{email}", h8,
                                         source="h8mail")
            if config.ENABLE_HIBP:
                hibp = check_hibp(email)
                if hibp:
                    intel_core.add_intel("breaches", f"hibp_{email}", hibp,
                                         source="hibp")
            if config.ENABLE_EMAILREP:
                rep = check_emailrep(email)
                if rep:
                    intel_core.add_intel("emailrep", email, rep,
                                         source="emailrep")
            if email.endswith("@gmail.com") and config.ENABLE_GHUNT:
                gh = run_ghunt(email)
                if gh:
                    intel_core.add_intel("ghunt", email, gh, source="ghunt")

        print("\n-- Scylla breach DB --")
        for email in all_emails:
            scylla_data = run_scylla(email)
            if scylla_data:
                intel_core.add_intel("breaches", f"scylla_{email}",
                                     scylla_data, source="scylla")

        print("\n-- Location / Language --")
        all_text = ""
        for k, v in intel_core.intel.get("social_profiles", {}).items():
            if "bio" in k or "desc" in k:
                all_text += v.get("value", "") + " "
        if all_text.strip():
            if config.ENABLE_LOCATION:
                loc = infer_location(all_text)
                if loc:
                    intel_core.add_intel("identity_clues", "inferred_location", loc,
                                         source="location_inference")
            if config.ENABLE_LANGDETECT:
                lang = detect_language(all_text)
                if lang:
                    intel_core.add_intel("identity_clues", "language", lang,
                                         source="langdetect")

        print("\n-- Confidence scoring --")
        intel_core.intel["confidence_scores"] = calculate_identity_confidence(intel_core.intel)

        # Clean up scraped_urls from the final snapshot (already used)
        intel_core.intel.pop("scraped_urls", None)

        # ================================================================
        #                   Report generation
        # ================================================================
        if config.ENABLE_AI_REPORT and config.GROQ_API_KEY:
            print("\n-- Generating AI report --")
            structured = generate_ai_report(intel_core, config.GROQ_API_KEY)
            if structured:
                md = format_ai_report_markdown(structured)
                rp = os.path.join(CACHE_DIR, f"report_{target_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
                with open(rp, 'w') as f: f.write(md)
                print(f"AI report saved to {rp}")

        if hasattr(config, 'OUTPUT_FORMAT') and config.OUTPUT_FORMAT == 'html':
            html_path = os.path.join(CACHE_DIR, f"report_{target_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            html_content = generate_html_report(intel_core, target_id)
            with open(html_path, 'w') as f: f.write(html_content)
            print(f"HTML report saved to {html_path}")

    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        intel_core.save_state()

    print("\n== OSINT pipeline complete ==")
    final = intel_core.save_state()
    print(f"Full intelligence report saved to {final}")
