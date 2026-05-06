import re
import time
import json
import sys
import os
import subprocess as _sp
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from . import utils
from .utils import http_session, REQUEST_DELAY, clean_username
from .config import USER_TOKEN, MULTI_GUILD_SEARCH, ENABLE_SHARETRACE, TARGET_USER_ID, TARGET_GUILD_ID

def get_discord_user_profile(token, uid, gid):
    h = {"Authorization":token,"User-Agent":"Mozilla/5.0"}
    try:
        r = http_session.get(f"https://discord.com/api/v9/guilds/{gid}/members/{uid}", headers=h)
        if r.status_code==200: return r.json().get("user")
    except: pass
    return None

def enrich_discord_profile(token, uid):
    headers = {"Authorization": f"Bot {token}" if not token.startswith("Bot ") else token,
               "User-Agent": "Mozilla/5.0"}
    try:
        r = http_session.get(f"https://discord.com/api/v9/users/{uid}/profile", headers=headers)
        if r.status_code == 200:
            return r.json()
    except: pass
    return {}

def snowflake_to_datetime(snowflake: int):
    timestamp = ((snowflake >> 22) + 1420070400000) / 1000.0
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def get_all_user_guilds(token):
    headers = {"Authorization": token}
    guilds = []
    try:
        r = http_session.get("https://discord.com/api/v9/users/@me/guilds", headers=headers)
        if r.status_code == 200:
            for g in r.json():
                if "id" in g:
                    guilds.append(g["id"])
    except: pass
    return guilds

def search_user_messages(token, gid, uid):
    h = {"Authorization":token,"Content-Type":"application/json","User-Agent":"Mozilla/5.0"}
    base = f"https://discord.com/api/v9/guilds/{gid}/messages/search"
    all_msgs, offset, limit, mret = [], 0, 25, 3
    while True:
        params = {"author_id":uid,"has":["link"],"offset":offset,"limit":limit}
        data = None
        for attempt in range(mret):
            try:
                r = http_session.get(base, headers=h, params=params)
                if r.status_code==429:
                    wait = int(r.headers.get("Retry-After",5))
                    print(f"Rate limited – waiting {wait}s"); time.sleep(wait); continue
                if r.status_code!=200:
                    if attempt<mret-1: time.sleep(2); continue
                    break
                data = r.json(); break
            except requests.exceptions.ConnectionError as e:
                print(f"Connection error: {e}, retrying ({attempt+1}/{mret})..."); time.sleep(2)
            except Exception as e:
                print(f"Unexpected error: {e}, retrying ({attempt+1}/{mret})..."); time.sleep(2)
        if data is None:
            break
        for grp in data.get("messages",[]): all_msgs.extend(grp)
        total = data.get("total_results",0)
        print(f"Progress: {min(offset+limit,total)} / {total}", end="\r")
        if offset+limit >= total: break
        offset += limit
        time.sleep(REQUEST_DELAY)
    print()
    return all_msgs

def multi_guild_message_search(token, uid, preferred_gid=None):
    if preferred_gid and not MULTI_GUILD_SEARCH:
        return search_user_messages(token, preferred_gid, uid)
    guilds = get_all_user_guilds(token)
    if not guilds:
        if preferred_gid:
            return search_user_messages(token, preferred_gid, uid)
        return []
    guilds_to_search = guilds
    all_messages = []
    for gid in guilds_to_search:
        print(f"  Searching guild {gid}...")
        try:
            msgs = search_user_messages(token, gid, uid)
            if msgs:
                all_messages.extend(msgs)
        except Exception as e:
            print(f"  Guild {gid} search failed: {e}")
        time.sleep(5)
    return all_messages

def extract_links_from_messages(msgs):
    links = set()
    for msg in msgs:
        for url in re.findall(r'(?:<)?(https?://[^\s<>]+)(?:>)?', msg.get("content","")):
            links.add(url.rstrip("."))
        for embed in msg.get("embeds",[]):
            if embed.get("url"): links.add(embed["url"])
            if embed.get("provider") and embed["provider"].get("url"): links.add(embed["provider"]["url"])
    return links

TRACKING_PARAM_PATTERNS = {
    "instagram": re.compile(r'(https?://(?:www\.)?instagram\.com/[^\s?]+\?[^\s]*igsh(?:id)?=[a-zA-Z0-9_-]+[^\s]*)'),
    "tiktok":    re.compile(r'(https?://(?:www\.|vm\.)?tiktok\.com/[^\s?]+\?[^\s]*(?:ttclid|_t|utm_source)[^\s]*)'),
    "facebook":  re.compile(r'(https?://(?:www\.)?(?:facebook\.com|fb\.(?:me|com|watch))/[^\s?]+\?[^\s]*(?:fbclid|mibextid)[^\s]*)'),
    "twitter":   re.compile(r'(https?://(?:www\.)?(?:twitter\.com|x\.com)/[^\s?]+\?[^\s]*utm_[^\s]*)'),
}
def extract_tracking_links(messages, uid):
    tracked = {"instagram":[],"tiktok":[],"facebook":[],"twitter":[]}
    for msg in messages:
        if str(msg.get("author",{}).get("id","")) != str(uid): continue
        for plat, pat in TRACKING_PARAM_PATTERNS.items():
            for m in pat.finditer(msg.get("content","")): tracked[plat].append(m.group(1))
    return tracked

def resolve_tracking_links(tracked):
    resolved = {}
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sharetrace_dir = os.path.join(project_root, "sharetrace")
    for plat, urls in tracked.items():
        if plat == "facebook":
            continue
        pr = []
        for url in urls:
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
                else:
                    res = _sp.run(cmd, capture_output=True, text=True, timeout=30, cwd=sharetrace_dir)
                    if res.returncode == 0 and res.stdout.strip():
                        data = json.loads(res.stdout)
                        data["url"] = url
                        pr.append(data)
            except Exception as e:
                print(f"    ShareTrace error: {e}")
        if pr:
            resolved[plat] = pr
            time.sleep(2)
    return resolved

PLATFORM_MAP = {"twitter.com":"twitter","x.com":"twitter","instagram.com":"instagram","github.com":"github",
                "tiktok.com":"tiktok","twitch.tv":"twitch","youtube.com":"youtube","reddit.com":"reddit",
                "steamcommunity.com":"steam","facebook.com":"facebook"}
INVALID_SLUGS = {"r","i","c","user","watch","play","wiki","blog","channel","u","explore","search","status","share","groups"}

def classify_url(url):
    if not url or not url.startswith("http"): return None, None
    try: parsed = urlparse(url)
    except ValueError: return None, None
    domain = parsed.netloc.lower().replace("www.","")
    if domain not in PLATFORM_MAP: return None, None
    platform = PLATFORM_MAP[domain]
    parts = parsed.path.strip("/").split("/")
    if platform=="reddit":
        if len(parts)>=2 and parts[0] in ("user","u"):
            slug = parts[1].lower()
            return (platform, slug) if slug not in INVALID_SLUGS else (None, None)
        return None, None
    if platform in ("twitter","instagram","tiktok","twitch","github","youtube"):
        if not parts: return None, None
        slug = parts[0].lower()
        if slug in INVALID_SLUGS or slug.startswith("?") or slug.startswith("#"): return None, None
        if platform == "github":
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', slug):
                return None, None
        return platform, slug
    if platform=="facebook":
        if "profile.php" in url:
            m = re.search(r'id=(\d+)', url)
            if m: return platform, m.group(1)
        if parts:
            slug = parts[0]
            if slug and slug not in ("pages","groups","events","help","settings","watch","share"): return platform, slug
        return None, None
    if platform=="steam":
        if "id" in parts:
            idx = parts.index("id")+1
            if idx<len(parts): return platform, parts[idx]
        if "profiles" in parts:
            idx = parts.index("profiles")+1
            if idx<len(parts): return platform, parts[idx]
        return None, None
    return None, None

def cluster_links_by_username(links):
    clusters = {}
    for link in links:
        _, slug = classify_url(link)
        if slug: clusters.setdefault(slug.lower(), []).append(link)
    return clusters

def find_target_cluster(clusters, target_username):
    clean = clean_username(target_username).lower()
    if clean in clusters: return clean, clusters[clean]
    raw_lower = target_username.lower()
    if raw_lower in clusters: return raw_lower, clusters[raw_lower]
    return None, []
