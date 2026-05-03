import os
import sys
import io
import json
import glob
import time
import tempfile
import shutil
import subprocess as _sp
import warnings
import concurrent.futures
import re
from datetime import datetime
from importlib import import_module
from . import utils
from .utils import resilient_task, tool_available, clean_username, CACHE_DIR
from .config import ENABLE_NAMINTER, ENABLE_SHERLOCK, ENABLE_SOCIAL_ANALYZER, ENABLE_LINKOOK, ENABLE_SOCIOPATH, ENABLE_MAIGRET
from .scraping import is_likely_profile_url_v2

def _normalize_naminter_results(data):
    if isinstance(data, list): results = data
    elif isinstance(data, dict) and "results" in data: results = data["results"]
    else: return []
    return [
        {"site": e.get("name") or e.get("site", "unknown"),
         "url": e.get("uri_pretty") or e.get("url", "")}
        for e in results if e.get("status") == "exists" and (e.get("uri_pretty") or e.get("url"))
    ]

@resilient_task(max_retries=1)
def run_naminter(raw_username):
    if not tool_available("naminter"): return []
    user = clean_username(raw_username)
    cmd = ["naminter", "-u", user, "--json", "--filter-exists"]
    res, _, _ = utils.debug_subprocess(cmd, timeout=300)
    results_files = sorted(glob.glob("results_*.json"), key=os.path.getmtime, reverse=True)
    for rf in results_files:
        try:
            with open(rf, "r") as f: data = json.load(f)
            profiles = _normalize_naminter_results(data)
            if profiles:
                print(f"  Loaded {len(profiles)} profiles from {rf}")
                return profiles
        except: continue
    print("  No valid naminter results file found.")
    return []

@resilient_task(max_retries=1)
def run_sherlock(raw_username):
    if not tool_available("sherlock") or not ENABLE_SHERLOCK:
        return []
    user = clean_username(raw_username)
    cmd = ["sherlock", user, "--print-found", "--no-color", "--timeout", "10"]
    _, stdout, _ = utils.debug_subprocess(cmd, timeout=300)
    if stdout is None:
        return []
    results = []
    for line in stdout.splitlines():
        if line.startswith("[+]"):
            parts = line[4:].split(":", 1)
            site = parts[0].strip()
            url = parts[1].strip() if len(parts) > 1 else ""
            if url.startswith("http"):
                results.append({"site": site, "url": url})
    return results

@resilient_task(max_retries=1)
def run_social_analyzer(raw_username):
    if not ENABLE_SOCIAL_ANALYZER: return []
    username = clean_username(raw_username)
    if not username: return []
    if utils.DEBUG_MODE: print(f"[DEBUG] social-analyzer on {username}")
    filter_sites = ["twitter", "instagram", "reddit", "github", "facebook",
                    "youtube", "twitch", "pinterest", "tiktok", "tumblr"]
    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        warnings.filterwarnings("ignore")
        try:
            from bs4 import XMLParsedAsHTMLWarning
            warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        except ImportError: pass
        sa = import_module("social-analyzer").SocialAnalyzer(silent=True)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(sa.run_as_object, username=username, filter=filter_sites, silent=True)
            try:
                results = future.result(timeout=120)
                if results:
                    return [{"site": r.get("site", "unknown"), "url": r.get("url", "")}
                            for r in results if r.get("url")]
            except concurrent.futures.TimeoutError:
                print("  social-analyzer timed out after 120 seconds")
    except Exception as e:
        print(f"  social-analyzer error: {e}")
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
    return []

def run_sociopath(seed_url, recursive=0):
    if not ENABLE_SOCIOPATH:
        return []
    # Use the current Python to run sociopath as a module – ensures venv is used
    cmd = [sys.executable, "-m", "sociopath", seed_url, "--json", "-r", str(recursive)]
    _, stdout, _ = utils.debug_subprocess(cmd, timeout=60)
    # ... rest of function stays identical
    if stdout is None:
        return []

    # Isolate the JSON array (sociopath prints log lines before the JSON)
    json_start = stdout.find('[')
    if json_start == -1:
        return []
    json_str = stdout[json_start:]
    bracket_count = 0
    json_end = -1
    for i, ch in enumerate(json_str):
        if ch == '[': bracket_count += 1
        elif ch == ']': bracket_count -= 1
        if bracket_count == 0:
            json_end = i + 1
            break
    if json_end == -1:
        return []
    json_str = json_str[:json_end]

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"  sociopath JSON error: {e}")
        return []

    results = data if isinstance(data, list) else data.get("results", [])
    enriched = []
    for r in results:
        url = r.get("URL", "")
        if not url or not is_likely_profile_url_v2(url):
            continue
        item = {
            "url": url,
            "display_name": r.get("DisplayName", ""),
            "email": r.get("Fields", {}).get("email", ""),
            "description": r.get("Bio", ""),
            "source_type": r.get("Platform", "website"),
            "PageTitle": r.get("PageTitle", ""),   # needed for fallback
        }
        enriched.append(item)
    return enriched

@resilient_task(max_retries=1)
def run_linkook(username):
    if not tool_available("linkook"):
        return []
    cmd = ["linkook", username]
    _, stdout, _ = utils.debug_subprocess(cmd, timeout=60)
    if stdout is None:
        return []
    urls = []
    for line in stdout.splitlines():
        match = re.search(r'Profile\s+URL:\s*(https?://[^\s]+)', line, re.IGNORECASE)
        if match:
            url = match.group(1).rstrip('.').rstrip('/')
            if url and is_likely_profile_url_v2(url):
                urls.append(url)
            continue
        match2 = re.search(r'^\s*\+?\s*([A-Za-z]+):\s*(https?://[^\s]+)', line)
        if match2:
            platform = match2.group(1).lower()
            if platform in ('facebook','instagram','twitter','github','gitlab','reddit','youtube','tiktok','linkedin'):
                url2 = match2.group(2).rstrip('.').rstrip('/')
                if url2 and is_likely_profile_url_v2(url2):
                    urls.append(url2)
    return list(set(urls))

@resilient_task(max_retries=1)
def run_maigret(username):
    if not tool_available("maigret"): return []
    cmd = ["maigret", username, "--all-sites", "--json", "simple", "--timeout", "15"]
    _, stdout, _ = utils.debug_subprocess(cmd, timeout=600)
    if stdout is None: return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        print(f"  maigret returned invalid JSON (first 200 chars): {stdout[:200]}")
        return []
    results = []
    for site, info in data.items():
        if info.get("status") and info["status"].get("exists"):
            results.append({
                "site": site,
                "url": info.get("url_user", ""),
                "name": info.get("username", ""),
                "bio": info.get("bio", ""),
                "location": info.get("location", "")
            })
    return results

@resilient_task(max_retries=1)
def run_blackbird(target, mode="username"):
    """
    Run Blackbird on a username or email.
    Blackbird must be cloned into ./blackbird/.
    Returns a list of dicts: [{"site": ..., "url": ...}].
    
    Blackbird's --json flag is a boolean (no filename argument).
    Results are saved to: blackbird/results/<target>_<date>_blackbird/<target>_<date>_blackbird.json
    """
    from .config import ENABLE_BLACKBIRD, BLACKBIRD_DIR
    if not ENABLE_BLACKBIRD:
        return []
    blackbird_py = os.path.join(BLACKBIRD_DIR, "blackbird.py")
    if not os.path.isfile(blackbird_py):
        print(f"  [!] Blackbird not found at {blackbird_py}. Skipping.")
        print(f"  Clone it: git clone https://github.com/p1ngul1n0/blackbird")
        return []

    # --- Blackbird data file: auto-download if missing ---
    wmn_data = os.path.join(BLACKBIRD_DIR, "data", "wmn-data.json")
    if not os.path.isfile(wmn_data):
        print("  Blackbird data file not found – downloading (one‑time, ~1 MB) …")
        try:
            import urllib.request
            os.makedirs(os.path.dirname(wmn_data), exist_ok=True)
            urllib.request.urlretrieve(
                "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
                wmn_data
            )
            print("  Done – data file downloaded successfully.")
        except Exception as e:
            print(f"  Auto‑download failed: {e}")
            print(f"  Please manually place wmn-data.json into: {os.path.dirname(wmn_data)}")
            return []

    # Record time BEFORE running so we can find files created after this
    t0 = time.time()

    if mode == "email":
        cmd = [sys.executable, blackbird_py, "--email", target, "--json",
               "--no-update", "--no-nsfw", "--timeout", "15"]
    else:
        cmd = [sys.executable, blackbird_py, "--username", target, "--json",
               "--no-update", "--no-nsfw", "--timeout", "15"]

    # Run from the Blackbird directory so it finds its data files
    _, stdout, _ = utils.debug_subprocess(cmd, timeout=600, cwd=BLACKBIRD_DIR)

    # Give the filesystem a moment to finish writing
    time.sleep(1)

    # Blackbird saves JSON to: blackbird/results/<target>_<date>_blackbird/<target>_<date>_blackbird.json
    results_dir = os.path.join(BLACKBIRD_DIR, "results")
    
    # Find the most recently created JSON file matching our target
    best_path = None
    best_mtime = 0
    if os.path.isdir(results_dir):
        for dirpath, dirnames, filenames in os.walk(results_dir):
            for fname in filenames:
                if fname.endswith("_blackbird.json"):
                    fpath = os.path.join(dirpath, fname)
                    try:
                        mtime = os.path.getmtime(fpath)
                        if mtime >= t0 and mtime > best_mtime:
                            best_mtime = mtime
                            best_path = fpath
                    except OSError:
                        continue

    # Fallback: also check the Blackbird root directory for standalone JSON files
    if not best_path:
        for fname in os.listdir(BLACKBIRD_DIR):
            if fname.endswith("_blackbird.json"):
                fpath = os.path.join(BLACKBIRD_DIR, fname)
                try:
                    mtime = os.path.getmtime(fpath)
                    if mtime >= t0 and mtime > best_mtime:
                        best_mtime = mtime
                        best_path = fpath
                except OSError:
                    continue

    if not best_path:
        return []

    try:
        with open(best_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  Blackbird JSON read error: {e}")
        return []

    results = []
    if isinstance(data, list):
        for entry in data:
            url = entry.get("url", "")
            if url and url.startswith("http"):
                results.append({
                    "site": entry.get("name", entry.get("site", "unknown")),
                    "url": url
                })
    elif isinstance(data, dict):
        for key, val in data.items():
            if isinstance(val, list):
                for entry in val:
                    if isinstance(entry, dict):
                        url = entry.get("url", "")
                        if url and url.startswith("http"):
                            results.append({
                                "site": entry.get("name", entry.get("site", key)),
                                "url": url
                            })
    return results
