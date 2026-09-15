"""
discord_osint/discord_api.py
--------------------------
Discord API wrappers and URL classification.

Change log
----------
- ``search_user_messages`` and ``get_all_user_guilds`` write an
  ``elevated_risk_discord_search`` audit event before contacting the
  private ``guilds/<id>/messages/search`` endpoint with a user token.
  This is a self-bot pattern that violates Discord's Terms of Service
  and can result in account termination; every use is recorded so the
  audit log reflects the disclosure surface and the operational risk.
- ``resolve_tracking_links`` runs the per-URL ShareTrace invocations in
  a small worker pool.
"""

import re
import time
import json
import sys
import os
import subprocess as _sp
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from datetime import datetime, timezone
from urllib.parse import urlparse
from . import utils
from .utils import http_session, REQUEST_DELAY, clean_username, log_trace
from .platforms import PLATFORMS, INVALID_SLUGS
from . import audit as _audit

from .config import get_flag as _flag


def _audit_elevated_risk(endpoint: str, **fields) -> None:
    """
    Record one self-bot user-token call.

    Best-effort: an audit failure must never abort the API call. The
    event name is fixed so an operator can grep for it in the log.
    """
    try:
        _audit.write_event(
            "elevated_risk_discord_search",
            endpoint=endpoint,
            reason="self-bot user-token against private endpoint",
            **fields,
        )
    except Exception:
        pass


def get_discord_user_profile(token, uid, gid):
    h = {"Authorization": token, "User-Agent": "Mozilla/5.0"}
    try:
        r = http_session.get(
            f"https://discord.com/api/v9/guilds/{gid}/members/{uid}", headers=h,
        )
        if r.status_code == 200:
            return r.json().get("user")
        log_trace(
            f"get_discord_user_profile: HTTP {r.status_code} for uid={uid} gid={gid}"
        )
    except Exception as exc:
        log_trace(f"get_discord_user_profile: {type(exc).__name__}: {exc}")
    return None


def enrich_discord_profile(token, uid):
    headers = {
        "Authorization": f"Bot {token}" if not token.startswith("Bot ") else token,
        "User-Agent": "Mozilla/5.0",
    }
    try:
        r = http_session.get(
            f"https://discord.com/api/v9/users/{uid}/profile", headers=headers,
        )
        if r.status_code == 200:
            return r.json()
        log_trace(f"enrich_discord_profile: HTTP {r.status_code} for uid={uid}")
    except Exception as exc:
        log_trace(f"enrich_discord_profile: {type(exc).__name__}: {exc}")
    return {}


def snowflake_to_datetime(snowflake: int):
    timestamp = ((snowflake >> 22) + 1420070400000) / 1000.0
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def get_all_user_guilds(token):
    _audit_elevated_risk("users/@me/guilds")
    headers = {"Authorization": token}
    guilds = []
    try:
        r = http_session.get("https://discord.com/api/v9/users/@me/guilds", headers=headers)
        if r.status_code == 200:
            for g in r.json():
                if "id" in g:
                    guilds.append(g["id"])
        else:
            log_trace(f"get_all_user_guilds: HTTP {r.status_code}")
    except Exception as exc:
        log_trace(f"get_all_user_guilds: {type(exc).__name__}: {exc}")
    return guilds


def search_user_messages(token, gid, uid, quiet: bool = False):
    _audit_elevated_risk(
        "guilds/{gid}/messages/search",
        guild_id=str(gid),
        target_id=str(uid),
    )
    h = {"Authorization": token, "Content-Type": "application/json",
         "User-Agent": "Mozilla/5.0"}
    base = f"https://discord.com/api/v9/guilds/{gid}/messages/search"
    all_msgs, offset, limit, mret = [], 0, 25, 3
    while True:
        params = {"author_id": uid, "has": ["link"], "offset": offset, "limit": limit}
        data = None
        for attempt in range(mret):
            try:
                r = http_session.get(base, headers=h, params=params)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 5))
                    if not quiet:
                        print(f"Rate limited – waiting {wait}s")
                    time.sleep(wait)
                    continue
                if r.status_code != 200:
                    if attempt < mret - 1:
                        time.sleep(2)
                        continue
                    break
                data = r.json()
                break
            except requests.exceptions.ConnectionError as e:
                if not quiet:
                    print(f"Connection error: {e}, retrying ({attempt + 1}/{mret})...")
                time.sleep(2)
            except Exception as e:
                if not quiet:
                    print(f"Unexpected error: {e}, retrying ({attempt + 1}/{mret})...")
                time.sleep(2)
        if data is None:
            break
        for grp in data.get("messages", []):
            all_msgs.extend(grp)
        total = data.get("total_results", 0)
        if not quiet:
            print(f"Progress: {min(offset + limit, total)} / {total}", end="\r")
        if offset + limit >= total:
            break
        offset += limit
        time.sleep(REQUEST_DELAY)
    if not quiet:
        print()
    return all_msgs


def multi_guild_message_search(token, uid, preferred_gid=None):
    if preferred_gid and not _flag("MULTI_GUILD_SEARCH"):
        return search_user_messages(token, preferred_gid, uid)

    guilds = get_all_user_guilds(token)
    if not guilds:
        if preferred_gid:
            return search_user_messages(token, preferred_gid, uid)
        return []

    if preferred_gid and preferred_gid not in guilds:
        guilds = [preferred_gid] + list(guilds)

    max_workers = min(5, max(1, len(guilds)))
    print(f"  Searching {len(guilds)} guild(s) with {max_workers} worker(s)…")

    all_messages: list = []
    _print_lock = threading.Lock()

    def _search_one(gid: str):
        try:
            msgs = search_user_messages(token, gid, uid, quiet=True)
            return gid, msgs or []
        except Exception as e:
            with _print_lock:
                print(f"  Guild {gid} search failed: {e}")
            return gid, []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_search_one, gid): gid for gid in guilds}
        for fut in as_completed(futures):
            gid, msgs = fut.result()
            if msgs:
                all_messages.extend(msgs)
                with _print_lock:
                    print(f"  Guild {gid}: {len(msgs)} message(s) matched")

    return all_messages


def extract_links_from_messages(msgs):
    links = set()
    for msg in msgs:
        for url in re.findall(r'(?:<)?(https?://[^\s<>]+)(?:>)?', msg.get("content", "")):
            links.add(url.rstrip("."))
        for embed in msg.get("embeds", []):
            if embed.get("url"):
                links.add(embed["url"])
            if embed.get("provider") and embed["provider"].get("url"):
                links.add(embed["provider"]["url"])
    return links


TRACKING_PARAM_PATTERNS = {
    "instagram": re.compile(r'(https?://(?:www\.)?instagram\.com/[^\s?]+\?[^\s]*igsh(?:id)?=[a-zA-Z0-9_-]+[^\s]*)'),
    "tiktok":    re.compile(r'(https?://(?:www\.|vm\.)?tiktok\.com/[^\s?]+\?[^\s]*(?:ttclid|_t|utm_source)[^\s]*)'),
    "facebook":  re.compile(r'(https?://(?:www\.)?(?:facebook\.com|fb\.(?:me|com|watch))/[^\s?]+\?[^\s]*(?:fbclid|mibextid)[^\s]*)'),
    "twitter":   re.compile(r'(https?://(?:www\.)?(?:twitter\.com|x\.com)/[^\s?]+\?[^\s]*utm_[^\s]*)'),
}


def extract_tracking_links(messages, uid):
    tracked = {"instagram": [], "tiktok": [], "facebook": [], "twitter": []}
    for msg in messages:
        if str(msg.get("author", {}).get("id", "")) != str(uid):
            continue
        for plat, pat in TRACKING_PARAM_PATTERNS.items():
            for m in pat.finditer(msg.get("content", "")):
                tracked[plat].append(m.group(1))
    return tracked


def _resolve_one_tracking_link(plat: str, url: str, sharetrace_dir: str):
    print(f"  Resolving {plat} link: {url[:60]}...")
    if getattr(sys, 'frozen', False):
        python_exe = utils._get_frozen_python()
        sharetrace_script = os.path.join(os.path.dirname(sys.executable), "sharetrace")
        cmd = [python_exe, sharetrace_script, url, "--json"]
    else:
        cmd = [sys.executable, "-m", "sharetrace", url, "--json"]
    try:
        if utils.DEBUG_MODE:
            utils.debug_subprocess(cmd, cwd=sharetrace_dir, timeout=30)
            return plat, None
        res = _sp.run(cmd, capture_output=True, text=True, timeout=30, cwd=sharetrace_dir)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            data["url"] = url
            return plat, data
    except Exception as e:
        print(f"    ShareTrace error: {e}")
    return plat, None


def resolve_tracking_links(tracked):
    resolved: dict[str, list] = {}
    project_root   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sharetrace_dir = os.path.join(project_root, "sharetrace")

    tasks: list[tuple[str, str]] = []
    for plat, urls in tracked.items():
        if plat == "facebook":
            continue
        for url in urls:
            tasks.append((plat, url))

    if not tasks:
        return resolved

    max_workers = min(5, len(tasks))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_resolve_one_tracking_link, plat, url, sharetrace_dir): (plat, url)
            for plat, url in tasks
        }
        for fut in as_completed(futures):
            try:
                plat, data = fut.result()
            except Exception as exc:
                log_trace(f"resolve_tracking_links: worker raised "
                          f"{type(exc).__name__}: {exc}")
                continue
            if data is not None:
                resolved.setdefault(plat, []).append(data)

    return resolved


def classify_url(url):
    if not url or not url.startswith("http"):
        return None, None
    for platform in PLATFORMS.values():
        for pattern in platform.url_patterns:
            m = re.match(pattern, url, re.IGNORECASE)
            if not m:
                continue
            slug = m.group("slug").lower()
            if slug in INVALID_SLUGS:
                continue
            return platform.key, slug
    return None, None


def cluster_links_by_username(links):
    clusters = {}
    for link in links:
        _, slug = classify_url(link)
        if slug:
            clusters.setdefault(slug.lower(), []).append(link)
    return clusters


def find_target_cluster(clusters, target_username):
    clean = clean_username(target_username).lower()
    if clean in clusters:
        return clean, clusters[clean]
    raw_lower = target_username.lower()
    if raw_lower in clusters:
        return raw_lower, clusters[raw_lower]
    return None, []