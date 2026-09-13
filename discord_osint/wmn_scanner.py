"""
discord_osint/wmn_scanner.py
-----------------------------
Lightweight scanner built on the community-maintained WhatsMyName
dataset (github.com/WebBreacher/WhatsMyName).

Loads ``wmn-data.json`` (downloaded on first use, cached locally,
refreshed weekly), probes each site's ``uri_check`` endpoint with the
target username, and returns the ones that respond affirmatively.

Unlike Blackbird this:
  • has no local repo dependency (no `git clone`)
  • caches the dataset in investigation_cache/ with a 7-day TTL
  • runs concurrently with a modest worker pool
  • returns the raw ``uri_check`` URL — many of them ARE JSON APIs that
    the existing api_response pipeline can fetch and mine for data
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

from .utils import CACHE_DIR


# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

_WMN_URL          = ("https://raw.githubusercontent.com/WebBreacher/"
                     "WhatsMyName/main/wmn-data.json")
_WMN_CACHE_PATH   = os.path.join(CACHE_DIR, "wmn-data.json")
_WMN_TTL_SECONDS  = 7 * 24 * 3600   # refresh weekly

_DEFAULT_TIMEOUT  = 8               # seconds per request
_DEFAULT_WORKERS  = 30

# Sites we never probe: they always fail or return false positives.
_SKIP_PROTECTIONS = ("cloudflare", "captcha", "recaptcha")


# ──────────────────────────────────────────────────────────────────────
# Dataset loading
# ──────────────────────────────────────────────────────────────────────

_load_lock = threading.Lock()
_cached_data: dict | None = None


def _download_wmn_data() -> dict | None:
    """Fetch a fresh copy and store it in the cache dir."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        req = urllib.request.Request(
            _WMN_URL,
            headers={"User-Agent": "Mozilla/5.0 WhoCord/1.1"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
        # Sanity check: must be valid JSON with a "sites" list
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("sites"), list):
            print("  WMN: downloaded dataset is malformed – ignoring.")
            return None
        with open(_WMN_CACHE_PATH, "wb") as f:
            f.write(raw)
        print(f"  WMN: downloaded {len(data['sites'])} sites "
              f"({len(raw) // 1024} KB).")
        return data
    except Exception as exc:
        print(f"  WMN: download failed ({exc}).")
        return None


def _load_wmn_data() -> dict | None:
    """
    Return the parsed wmn-data.json, using the cache when it's fresh.

    Refresh policy:
      • Cache missing         → download
      • Cache older than TTL  → download (fall back to cache on failure)
      • Cache valid           → use cache
    """
    global _cached_data
    with _load_lock:
        if _cached_data is not None:
            return _cached_data

        # Fresh cache?
        if os.path.isfile(_WMN_CACHE_PATH):
            try:
                age = time.time() - os.path.getmtime(_WMN_CACHE_PATH)
                if age < _WMN_TTL_SECONDS:
                    with open(_WMN_CACHE_PATH, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict) and isinstance(data.get("sites"), list):
                        _cached_data = data
                        return data
                else:
                    # Stale — try to refresh, fall back to disk
                    fresh = _download_wmn_data()
                    if fresh:
                        _cached_data = fresh
                        return fresh
                    with open(_WMN_CACHE_PATH, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        _cached_data = data
                        return data
            except Exception as exc:
                print(f"  WMN: cache read error ({exc}); re-downloading.")

        # No cache — download
        fresh = _download_wmn_data()
        if fresh:
            _cached_data = fresh
            return fresh
        return None


# ──────────────────────────────────────────────────────────────────────
# Single-site probe
# ──────────────────────────────────────────────────────────────────────

def _is_hit(resp, site: dict) -> bool:
    """
    Decide whether *resp* means 'username exists on this site'.

    Uses the site's e_string/m_string (body substrings) and
    e_code/m_code (HTTP status codes). Miss signals take priority over
    hit signals so a page that says "not found" but happens to contain
    the hit substring still resolves as a miss.
    """
    body     = resp.text or ""
    e_string = site.get("e_string") or ""
    m_string = site.get("m_string") or ""
    e_code   = site.get("e_code")
    m_code   = site.get("m_code")

    # Explicit miss signals
    if m_code is not None and resp.status_code == m_code:
        return False
    if m_string and m_string in body:
        return False

    # Explicit hit signals
    if e_string and e_string in body:
        return True
    if e_code is not None and resp.status_code == e_code:
        # When e_code is 200 we only trust it if there's no e_string to
        # confirm against; otherwise require the e_string match above.
        return not e_string

    return False


def _probe_site(site: dict, username: str, timeout: int) -> dict | None:
    """Return a hit dict or None."""
    # Skip POST-only and protected sites
    method = str(site.get("request_method") or "GET").upper()
    if method != "GET":
        return None
    protection = str(site.get("protection") or "").lower()
    if any(p in protection for p in _SKIP_PROTECTIONS):
        return None

    uri_check = site.get("uri_check") or ""
    if "{account}" not in uri_check:
        return None

    uri_pretty = site.get("uri_pretty") or uri_check

    url    = uri_check.replace("{account}", username)
    pretty = uri_pretty.replace("{account}", username)

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept":     "application/json, text/html;q=0.9, */*;q=0.8",
    }
    site_headers = site.get("headers")
    if isinstance(site_headers, dict):
        for k, v in site_headers.items():
            if isinstance(k, str) and isinstance(v, str):
                headers.setdefault(k, v.replace("{account}", username))

    try:
        import requests
        resp = requests.get(url, headers=headers, timeout=timeout,
                            allow_redirects=True)
    except Exception:
        return None

    if not _is_hit(resp, site):
        return None

    return {
        "site":       site.get("name") or "unknown",
        "url":        url,
        "pretty_url": pretty,
        "category":   site.get("cat") or "",
        "status":     resp.status_code,
    }


# ──────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────

def run_wmn_scan(
    username: str,
    max_workers: int = _DEFAULT_WORKERS,
    timeout: int = _DEFAULT_TIMEOUT,
    emit: Optional[Callable[[str, dict], None]] = None,
) -> list[dict]:
    """
    Scan *username* across every site in the WhatsMyName dataset.

    Returns a list of hit dicts:
        {"site": str, "url": str, "pretty_url": str,
         "category": str, "status": int}
    """
    if not username:
        return []

    data = _load_wmn_data()
    if not data:
        print("  WMN: dataset unavailable – skipping scan.")
        return []

    sites = data.get("sites") or []
    if not sites:
        return []

    print(f"  WMN: probing {len(sites)} sites with {max_workers} workers "
          f"(timeout {timeout}s) …")
    if emit:
        emit("progress", {"message": f"WMN scan: {len(sites)} sites"})

    hits: list[dict] = []
    total     = len(sites)
    completed = 0
    t0        = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe_site, s, username, timeout): s for s in sites}
        for fut in as_completed(futures):
            completed += 1
            try:
                result = fut.result()
                if result:
                    hits.append(result)
            except Exception:
                pass

            # Progress every 50 checks
            if completed % 50 == 0 and emit:
                emit("progress", {
                    "message": f"WMN: {completed}/{total} checked "
                               f"({len(hits)} hits)",
                })

    elapsed = time.time() - t0
    print(f"  WMN: finished in {elapsed:.1f}s – "
          f"{len(hits)} hit(s) out of {total} site(s).")
    return hits