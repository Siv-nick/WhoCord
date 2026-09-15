
"""
discord_osint/wmn_scanner.py
-----------------------------
Lightweight scanner built on the community-maintained WhatsMyName
dataset (github.com/WebBreacher/WhatsMyName).

Change log
----------
- ``_probe_site`` routes requests through the shared ``http_session``
  instead of a bare ``requests.get``. The WMN scan probes hundreds of
  sites per run; connection reuse and the retry adapter are worth
  having. It also keeps this module inside the "no bare requests
  outside the allowlist" invariant enforced by
  ``tests/test_ssrf_routing.py``.
"""

from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

from .utils import CACHE_DIR, http_session


_WMN_URL          = ("https://raw.githubusercontent.com/WebBreacher/"
                     "WhatsMyName/main/wmn-data.json")
_WMN_CACHE_PATH   = os.path.join(CACHE_DIR, "wmn-data.json")
_WMN_TTL_SECONDS  = 7 * 24 * 3600

_DEFAULT_TIMEOUT  = 8
_DEFAULT_WORKERS  = 30

# Hard cap on the downloaded dataset (it is ~1 MB in practice).
_WMN_MAX_BYTES    = 16 * 1024 * 1024

_SKIP_PROTECTIONS = ("cloudflare", "captcha", "recaptcha")


_load_lock = threading.Lock()
_cached_data: dict | None = None


def fetch_wmn_dataset_bytes() -> bytes | None:
    """
    Download the WhatsMyName dataset and return the raw bytes, or None.

    Public because ``username_search.run_blackbird`` needs the same
    file in Blackbird's own data directory. It previously used
    ``urllib.request.urlretrieve``, which writes whatever the server
    returns — including a 404 page — straight to disk with no status
    check and no size limit.

    Guarantees for the caller:
      * HTTP status was 200.
      * The body is under ``_WMN_MAX_BYTES``.
      * The body parses as JSON with a ``sites`` list.

    urllib.request.urlopen bypassed both the shared session and the
    SSRF routing check. The host is fixed, so ``http_session`` is the
    right level: connection reuse, the retry adapter, and a call site
    the routing test can see.
    """
    try:
        resp = http_session.get(
            _WMN_URL,
            headers={"User-Agent": "WhoCord-OSINT/1.1"},
            timeout=30,
            stream=True,
        )
    except Exception as exc:
        print(f"  WMN: download failed ({exc}).")
        return None

    if resp.status_code != 200:
        print(f"  WMN: download failed (HTTP {resp.status_code}).")
        return None

    # The dataset is ~1 MB. Cap the read so a compromised or
    # misbehaving host cannot stream an unbounded body into memory.
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total > _WMN_MAX_BYTES:
                print(
                    f"  WMN: dataset exceeded "
                    f"{_WMN_MAX_BYTES // (1024 * 1024)} MB – refusing to load."
                )
                return None
    except Exception as exc:
        print(f"  WMN: read failed ({exc}).")
        return None

    raw = b"".join(chunks)

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"  WMN: downloaded dataset is not valid JSON ({exc}).")
        return None

    if not isinstance(data, dict) or not isinstance(data.get("sites"), list):
        print("  WMN: downloaded dataset is malformed – ignoring.")
        return None

    return raw


def _download_wmn_data() -> dict | None:
    try:
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
        try:
            os.chmod(CACHE_DIR, 0o700)
        except OSError:
            pass

        raw = fetch_wmn_dataset_bytes()
        if raw is None:
            return None

        data = json.loads(raw.decode("utf-8"))

        # Write to a temp file and rename, so an interrupted download
        # cannot leave a truncated cache file that the TTL check will
        # then happily treat as fresh for the next seven days.
        tmp_path = _WMN_CACHE_PATH + ".part"
        with open(tmp_path, "wb") as f:
            f.write(raw)
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, _WMN_CACHE_PATH)

        print(f"  WMN: downloaded {len(data['sites'])} sites "
              f"({len(raw) // 1024} KB).")
        return data
    except Exception as exc:
        print(f"  WMN: download failed ({exc}).")
        return None


def _load_wmn_data() -> dict | None:
    global _cached_data
    with _load_lock:
        if _cached_data is not None:
            return _cached_data

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

        fresh = _download_wmn_data()
        if fresh:
            _cached_data = fresh
            return fresh
        return None


def _is_hit(resp, site: dict) -> bool:
    body     = resp.text or ""
    e_string = site.get("e_string") or ""
    m_string = site.get("m_string") or ""
    e_code   = site.get("e_code")
    m_code   = site.get("m_code")

    if m_code is not None and resp.status_code == m_code:
        return False
    if m_string and m_string in body:
        return False

    if e_string and e_string in body:
        return True
    if e_code is not None and resp.status_code == e_code:
        return not e_string

    return False


def _probe_site(site: dict, username: str, timeout: int) -> dict | None:
    """Return a hit dict or None. Uses the shared http_session."""
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
        resp = http_session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
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


def run_wmn_scan(
    username: str,
    max_workers: int = _DEFAULT_WORKERS,
    timeout: int = _DEFAULT_TIMEOUT,
    emit: Optional[Callable[[str, dict], None]] = None,
) -> list[dict]:
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

            if completed % 50 == 0 and emit:
                emit("progress", {
                    "message": f"WMN: {completed}/{total} checked "
                               f"({len(hits)} hits)",
                })

    elapsed = time.time() - t0
    print(f"  WMN: finished in {elapsed:.1f}s – "
          f"{len(hits)} hit(s) out of {total} site(s).")
    return hits
