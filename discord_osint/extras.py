import os
import re
import subprocess as _sp
import json
import time
import sys
from urllib.parse import urlparse
from collections import Counter
from .utils import http_session, tool_available, REQUEST_DELAY, CACHE_DIR
from . import utils
from .config import (
    ENABLE_REVERSE_IMG, ENABLE_EXIF, ENABLE_WHOIS, ENABLE_WAYBACK,
    ENABLE_LOCATION, ENABLE_LANGDETECT
)
from .discord_api import classify_url   # needed by socialscan_filter
from .scraping import is_likely_profile_url_v2

def download_avatar(url, save_dir):
    try:
        r = http_session.get(url, timeout=10)
        if r.status_code==200 and len(r.content)>1024:
            ext = url.rsplit(".",1)[-1].split("?")[0]
            if ext not in ("jpg","jpeg","png","webp","gif"): ext = "jpg"
            fname = os.path.join(save_dir, f"avatar_{hash(url) & 0x7FFFFFFF}.{ext}")
            with open(fname,'wb') as f: f.write(r.content)
            return fname
    except: pass
    return None

def reverse_image_search(image_url):
    if not ENABLE_REVERSE_IMG: return []
    if any(x in image_url.lower() for x in ["default","logo","placeholder","gravatar.com/avatar/00000000000000000000000000000000"]):
        return []
    try:
        params = {"url": image_url, "output_type": 2, "numres": 5, "db": 999, "testmode": 1}
        r = http_session.get("https://saucenao.com/search.php", params=params, timeout=15)
        if r.status_code == 200 and r.text.strip():
            data = r.json()
            results = data.get("results", [])
            domains = []
            for res in results:
                ext_urls = res.get("data", {}).get("ext_urls", [])
                for url in ext_urls:
                    try: domains.append(urlparse(url).netloc.lower())
                    except: pass
            return [d for d, _ in Counter(domains).most_common(10)]
    except Exception as e:
        print(f"  Reverse image search error: {e}")
    return []

def extract_metadata(filepath):
    try: import exifread
    except ImportError: return {}
    try:
        with open(filepath, 'rb') as f: tags = exifread.process_file(f, details=False)
        gps = {}
        if "GPS GPSLatitude" in tags and "GPS GPSLongitude" in tags:
            try:
                lat = float(tags["GPS GPSLatitude"].values[0]) + float(tags["GPS GPSLatitude"].values[1])/60 + float(tags["GPS GPSLatitude"].values[2])/3600
                lon = float(tags["GPS GPSLongitude"].values[0]) + float(tags["GPS GPSLongitude"].values[1])/60 + float(tags["GPS GPSLongitude"].values[2])/3600
                gps["latitude"] = lat; gps["longitude"] = lon
            except: pass
        return {"gps": gps, "camera": str(tags.get("Image Model", "")), "date_taken": str(tags.get("EXIF DateTimeOriginal", ""))}
    except: return {}

def whois_domain(domain):
    try:
        res = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            raw = res.stdout
            name = email = creation = ""
            for line in raw.splitlines():
                line_lower = line.lower()
                if "registrant name" in line_lower or "organisation" in line_lower:
                    name = line.split(":", 1)[-1].strip()
                if "registrant email" in line_lower or "e-mail" in line_lower:
                    candidate = line.split(":", 1)[-1].strip()
                    if re.match(r'[^@]+@[^@]+\.[^@]+', candidate):
                        email = candidate
                if "creation date" in line_lower or "created" in line_lower:
                    creation = line.split(":", 1)[-1].strip()
            return {"registrant_name": name, "registrant_email": email, "creation_date": creation}
    except Exception: pass
    return {}

def wayback_available(url):
    try:
        r = http_session.get("https://archive.org/wayback/available?url=" + url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            snapshots = data.get("archived_snapshots", {})
            if snapshots and "closest" in snapshots:
                return snapshots["closest"].get("url")
    except: pass
    return None

import re as _re
LOCATION_REGEX = _re.compile(r'(?:from|in|located\sin|based\sin)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)')
def infer_location(text):
    if not text: return None
    match = LOCATION_REGEX.search(text)
    return match.group(1) if match else None

def detect_language(text):
    try: from langdetect import detect_langs
    except ImportError: return None
    try:
        langs = detect_langs(text)
        if langs: return langs[0].lang, langs[0].prob
    except: pass
    return None

# … (all previous code)

def socialscan_filter(urls):
    if not tool_available("socialscan"):
        return urls
    username = None
    for url in urls:
        pl, sl = classify_url(url)
        if pl and sl:
            username = sl
            break
    if not username:
        for url in urls:
            try:
                path = urlparse(url).path.strip('/').split('/')[-1]
                if len(path) > 1:
                    username = path
                    break
            except:
                pass
    if not username:
        return urls

    temp_dir = os.path.join(CACHE_DIR, "socialscan_tmp")
    os.makedirs(temp_dir, exist_ok=True)
    outfile = os.path.join(temp_dir, f"scan_{username}.json")

    if getattr(sys, 'frozen', False):
        python_exe = utils._get_frozen_python()
        script = os.path.join(os.path.dirname(sys.executable), "socialscan")
        cmd = [python_exe, script, username, "--json", outfile]
    else:
        cmd = ["socialscan", username, "--json", outfile]
    if utils.DEBUG_MODE:
        utils.debug_subprocess(cmd, timeout=60)
        # debug mode: skip parsing, return all URLs
        return urls
    else:
        res = _sp.run(cmd, capture_output=True, text=True, timeout=60)
        if res.returncode != 0 or not os.path.exists(outfile):
            print("  socialscan failed, keeping all URLs")
            return urls
        with open(outfile, 'r') as f:
            data = json.load(f)
        os.unlink(outfile)

        available_platforms = set()
        unavailable_platforms = set()
        for query, results in data.items():
            if not isinstance(results, list): continue
            for entry in results:
                if not isinstance(entry, dict): continue
                platform = entry.get("platform", "").lower()
                success = entry.get("success", "False")
                available = entry.get("available", "False")
                if success == "True":
                    if available == "True":
                        available_platforms.add(platform)
                    else:
                        unavailable_platforms.add(platform)

        platform_to_domain = {
            "twitter": "twitter.com",
            "x": "x.com",
            "instagram": "instagram.com",
            "github": "github.com",
            "gitlab": "gitlab.com",
            "reddit": "reddit.com",
            "tumblr": "tumblr.com",
            "youtube": "youtube.com",
            "twitch": "twitch.tv",
            "tiktok": "tiktok.com",
            "facebook": "facebook.com",
            "pinterest": "pinterest.com",
        }

        filtered = []
        for url in urls:
            if not is_likely_profile_url_v2(url):
                filtered.append(url); continue
            domain = urlparse(url).netloc.lower().replace("www.", "")
            matching_platform = None
            for plat, plat_domain in platform_to_domain.items():
                if domain.endswith(plat_domain):
                    matching_platform = plat; break
            if matching_platform is None:
                filtered.append(url)
            elif matching_platform in available_platforms:
                filtered.append(url)
            elif matching_platform in unavailable_platforms:
                print(f"    Skipping {url} (socialscan says not available)")
            else:
                filtered.append(url)
        # Never return an empty list; fall back to the original URLs
        return filtered if filtered else urls
