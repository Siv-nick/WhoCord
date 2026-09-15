"""
discord_osint/extras.py
-----------------------
Supplementary OSINT helpers.

Change log
----------
- ``download_avatar`` chmod's the written file to 0600. Avatar images
  often carry EXIF GPS metadata and are cached on disk; on a shared
  workstation they must not be readable by other local users.
- (Already present from an earlier pass) ``download_avatar`` routes
  through ``safe_get_pinned`` and uses a stable ``sha256`` of the URL
  as the cache filename.
- ``socialscan_filter``'s URL-parsing loop records failures via
  ``log_trace`` rather than swallowing them silently.
- ``wayback_available`` builds its query via ``params=``.
"""

import hashlib
import os
import re
import subprocess as _sp
import json
import time
import sys
from urllib.parse import urlparse
from collections import Counter

from .utils import http_session, tool_available, REQUEST_DELAY, CACHE_DIR, log_trace
from . import utils
from .utils.url_safety import safe_get_pinned, UnsafeURLError

from .config import get_flag as _flag

from .discord_api import classify_url
from .scraping import is_likely_profile_url_v2


def download_avatar(url, save_dir):
    """
    Download an avatar image, guarded by SSRF pinning.

    The written file is chmod'd to 0600 — cached avatars contain the
    target's photographs and sometimes EXIF GPS coordinates.
    """
    try:
        r = safe_get_pinned(url, timeout=10)
        if r.status_code == 200 and len(r.content) > 1024:
            ext = url.rsplit(".", 1)[-1].split("?")[0]
            if ext not in ("jpg", "jpeg", "png", "webp", "gif"):
                ext = "jpg"
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
            fname = os.path.join(save_dir, f"avatar_{digest}.{ext}")
            with open(fname, 'wb') as f:
                f.write(r.content)
            try:
                os.chmod(fname, 0o600)
            except OSError:
                pass
            return fname
        log_trace(f"download_avatar: HTTP {r.status_code} or body too small "
                  f"({len(r.content)} bytes) for {url[:80]}")
    except UnsafeURLError as exc:
        log_trace(f"download_avatar: SSRF BLOCKED {url[:80]} — {exc}")
    except Exception as exc:
        log_trace(f"download_avatar: EXCEPTION {type(exc).__name__}: {exc} "
                  f"for {url[:80]}")
    return None


def reverse_image_search(image_url):
    """
    SauceNAO reverse image search. Strong on anime and illustrations,
    weak on photographs. Returns a list of matching domain names.
    """
    if not _flag("ENABLE_REVERSE_IMG"):
        return []
    if any(x in image_url.lower() for x in ["default", "logo", "placeholder",
                                            "gravatar.com/avatar/00000000000000000000000000000000"]):
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
                    try:
                        domains.append(urlparse(url).netloc.lower())
                    except Exception:
                        pass
            return [d for d, _ in Counter(domains).most_common(10)]
        log_trace(f"reverse_image_search: HTTP {r.status_code} for {image_url[:80]}")
    except Exception as e:
        print(f"  Reverse image search error: {e}")
        log_trace(f"reverse_image_search: EXCEPTION {type(e).__name__}: {e}")
    return []


def reverse_image_search_tineye(image_url: str, api_key: str = "",
                                timeout: int = 20) -> list[str]:
    """
    TinEye reverse image search. Complementary to SauceNAO.
    """
    if not api_key:
        log_trace("reverse_image_search_tineye: no API key configured.")
        return []

    try:
        r = http_session.get(
            "https://api.tineye.com/rest/search/",
            headers={
                "X-API-Key":  api_key,
                "User-Agent": "WhoCord-OSINT/1.1",
                "Accept":     "application/json",
            },
            params={
                "image_url": image_url,
                "sort":      "score",
                "order":     "desc",
                "limit":     "10",
            },
            timeout=timeout,
        )
    except Exception as exc:
        log_trace(f"reverse_image_search_tineye: network error: "
                  f"{type(exc).__name__}: {exc}")
        return []

    if r.status_code == 401:
        log_trace("reverse_image_search_tineye: API key rejected (401).")
        return []

    if r.status_code == 429:
        retry_after = r.headers.get("Retry-After", "?")
        log_trace(f"reverse_image_search_tineye: rate limited "
                  f"(Retry-After={retry_after}).")
        return []

    if r.status_code != 200:
        log_trace(f"reverse_image_search_tineye: HTTP {r.status_code} — "
                  f"{r.text[:160]}")
        return []

    try:
        data = r.json()
    except Exception as exc:
        log_trace(f"reverse_image_search_tineye: JSON parse error: {exc}")
        return []

    results = data.get("results") if isinstance(data, dict) else None
    matches = results.get("matches") if isinstance(results, dict) else None
    if not isinstance(matches, list):
        log_trace("reverse_image_search_tineye: unexpected response shape.")
        return []

    seen: set[str] = set()
    domains: list[str] = []
    for m in matches:
        if not isinstance(m, dict):
            continue
        domain = m.get("domain") or ""
        if not isinstance(domain, str):
            continue
        domain = domain.strip().lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
    return domains


def extract_metadata(filepath):
    try:
        import exifread
    except ImportError:
        log_trace("extract_metadata: exifread not installed.")
        return {}
    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f, details=False)
        gps = {}
        if "GPS GPSLatitude" in tags and "GPS GPSLongitude" in tags:
            try:
                lat = float(tags["GPS GPSLatitude"].values[0]) + \
                      float(tags["GPS GPSLatitude"].values[1]) / 60 + \
                      float(tags["GPS GPSLatitude"].values[2]) / 3600
                lon = float(tags["GPS GPSLongitude"].values[0]) + \
                      float(tags["GPS GPSLongitude"].values[1]) / 60 + \
                      float(tags["GPS GPSLongitude"].values[2]) / 3600
                gps["latitude"] = lat
                gps["longitude"] = lon
            except Exception as exc:
                log_trace(f"extract_metadata: GPS parse error: {exc}")
        return {
            "gps": gps,
            "camera": str(tags.get("Image Model", "")),
            "date_taken": str(tags.get("EXIF DateTimeOriginal", "")),
        }
    except Exception as exc:
        log_trace(f"extract_metadata: EXCEPTION {type(exc).__name__}: {exc}")
        return {}


def whois_domain(domain):
    try:
        res = _sp.run(["whois", domain], capture_output=True, text=True, timeout=20)
        if res.returncode != 0 or not res.stdout.strip():
            log_trace(f"whois_domain: rc={res.returncode} or empty stdout for "
                      f"{domain} — stderr={(res.stderr or '')[:200]}")
            return {}

        lines = res.stdout.splitlines()
        data = {}

        labels = {
            "registrar":                "registrar",
            "creation date":            "creation_date",
            "registry expiry date":     "expiry_date",
            "registrar registration expiration date": "expiry_date",
            "name server":              "name_servers",
            "domain status":            "domain_status",
            "registrant organization":  "registrant_org",
            "registrant country":       "registrant_country",
            "dnssec":                   "dnssec",
        }

        name_servers = []
        statuses = []

        for line in lines:
            line_lower = line.lower()
            for label, key in labels.items():
                if line_lower.startswith(label):
                    value = line.split(":", 1)[-1].strip()
                    if key == "name_servers":
                        if value and value not in name_servers:
                            name_servers.append(value)
                    elif key == "domain_status":
                        status_code = value.split()[0] if value else ""
                        if status_code and status_code not in statuses:
                            statuses.append(status_code)
                    else:
                        if key in data:
                            continue
                        data[key] = value

        if name_servers:
            data["name_servers"] = name_servers[:10]
        if statuses:
            data["domain_status"] = statuses

        if not data.get("creation_date"):
            for line in lines:
                if "creation date:" in line.lower():
                    data["creation_date"] = line.split(":", 1)[-1].strip()
                    break

        return data

    except Exception as exc:
        log_trace(f"whois_domain: EXCEPTION {type(exc).__name__}: {exc} "
                  f"for {domain}")
        return {}


def wayback_available(url):
    """
    Return the closest Wayback snapshot URL for *url*, or None.

    Uses ``params=`` so a URL containing ``&``, ``#``, or other reserved
    characters is percent-encoded by requests instead of silently
    corrupting the query string.
    """
    try:
        r = http_session.get(
            "https://archive.org/wayback/available",
            params={"url": url},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            snapshots = data.get("archived_snapshots", {})
            if snapshots and "closest" in snapshots:
                return snapshots["closest"].get("url")
        else:
            log_trace(f"wayback_available: HTTP {r.status_code} for {url[:80]}")
    except Exception as exc:
        log_trace(f"wayback_available: EXCEPTION {type(exc).__name__}: {exc} "
                  f"for {url[:80]}")
    return None


def crt_sh_subdomains(domain: str, timeout: int = 20) -> list[str]:
    """
    Return every subdomain that has ever appeared in a Certificate
    Transparency log for *domain*.
    """
    domain = (domain or "").strip().lower()
    if not domain or "." not in domain:
        return []

    if "://" in domain:
        domain = urlparse(domain).netloc or domain
    domain = domain.split("/")[0].split("?")[0]
    if not domain or "." not in domain:
        return []

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": "WhoCord-OSINT/1.1",
        "Accept":     "application/json",
    }

    max_bytes = 10 * 1024 * 1024

    for attempt in range(2):
        try:
            resp = http_session.get(
                url, headers=headers, timeout=timeout, stream=True,
            )
        except Exception as exc:
            log_trace(f"crt_sh: network error for {domain}: "
                      f"{type(exc).__name__}: {exc}")
            if attempt == 0:
                time.sleep(2)
                continue
            return []

        if resp.status_code in (502, 503, 504) and attempt == 0:
            log_trace(f"crt_sh: HTTP {resp.status_code} for {domain}, retrying")
            time.sleep(2)
            continue

        if resp.status_code != 200:
            log_trace(f"crt_sh: HTTP {resp.status_code} for {domain}")
            return []

        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    truncated = True
                    break
        except Exception as exc:
            log_trace(f"crt_sh: read error for {domain}: "
                      f"{type(exc).__name__}: {exc}")
            if attempt == 0:
                time.sleep(2)
                continue
            return []

        if truncated:
            log_trace(f"crt_sh: response truncated at {max_bytes} bytes for {domain}")

        body = b"".join(chunks)
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            log_trace(f"crt_sh: JSON parse error for {domain}: {exc}")
            if attempt == 0:
                time.sleep(2)
                continue
            return []

        if not isinstance(data, list):
            log_trace(f"crt_sh: expected JSON array, got {type(data).__name__}")
            return []

        subdomains: set[str] = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value", "")
            if not isinstance(name_value, str) or not name_value:
                continue
            for raw_name in name_value.split("\n"):
                name = raw_name.strip().lower()
                if not name:
                    continue
                if name.startswith("*."):
                    name = name[2:]
                if not name or name == domain:
                    continue
                if not name.endswith("." + domain):
                    continue
                if any(c.isspace() for c in name):
                    continue
                subdomains.add(name)

        return sorted(subdomains)

    return []


import re as _re
LOCATION_REGEX = _re.compile(r'(?:from|in|located\sin|based\sin)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)')


def infer_location(text):
    if not text:
        return None
    match = LOCATION_REGEX.search(text)
    return match.group(1) if match else None


def detect_language(text):
    try:
        from langdetect import detect_langs
    except ImportError:
        log_trace("detect_language: langdetect not installed.")
        return None
    try:
        langs = detect_langs(text)
        if langs:
            return langs[0].lang, langs[0].prob
    except Exception as exc:
        log_trace(f"detect_language: EXCEPTION {type(exc).__name__}: {exc}")
    return None


_NON_USERNAME_SEGMENTS = frozenset({
    "oembed", "lookup", "profile", "users", "user", "api", "signup",
    "sign-in", "signin", "signup", "register", "login", "auth", "oauth",
    "public", "static", "assets", "img", "images", "search", "query",
    "check", "validate", "available", "checkusername", "email_available",
})


def _is_plausible_username(segment: str) -> bool:
    if not segment or len(segment) < 3 or len(segment) > 40:
        return False
    if segment.lower() in _NON_USERNAME_SEGMENTS:
        return False
    return bool(re.fullmatch(r'[a-zA-Z0-9._\-]+', segment))


def socialscan_filter(urls):
    if not tool_available("socialscan"):
        log_trace("socialscan_filter: socialscan not on PATH — keeping all URLs.")
        return urls

    username = None
    for url in urls:
        pl, sl = classify_url(url)
        if pl and sl and _is_plausible_username(sl):
            username = sl
            break

    if not username:
        for url in urls:
            try:
                parsed = urlparse(url)
                if "/api/" in parsed.path.lower():
                    continue
                if parsed.netloc.lower().startswith(("api.", "public-api.")):
                    continue
                if any(kw in parsed.path.lower() for kw in
                       ("oembed", "/lookup", "/validate", "/checkusername",
                        "email_available", "/signup", "/wayback/available")):
                    continue
                path = parsed.path.strip('/').split('/')[-1]
                if _is_plausible_username(path):
                    username = path
                    break
            except Exception as exc:
                log_trace(
                    f"socialscan_filter: url parse failed for "
                    f"{url[:80]!r}: {type(exc).__name__}: {exc}"
                )
                continue

    if not username:
        log_trace("socialscan_filter: no plausible username extracted — "
                  "keeping all URLs.")
        return urls

    temp_dir = os.path.join(CACHE_DIR, "socialscan_tmp")
    os.makedirs(temp_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(temp_dir, 0o700)
    except OSError:
        pass
    outfile = os.path.join(temp_dir, f"scan_{username}.json")

    if getattr(sys, 'frozen', False):
        python_exe = utils._get_frozen_python()
        script = os.path.join(os.path.dirname(sys.executable), "socialscan")
        cmd = [python_exe, script, username, "--json", outfile]
    else:
        cmd = ["socialscan", username, "--json", outfile]
    if utils.DEBUG_MODE:
        utils.debug_subprocess(cmd, timeout=60)
        return urls

    res = _sp.run(cmd, capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        print(f"  socialscan exited rc={res.returncode} — keeping all URLs")
        log_trace(f"socialscan_filter: rc={res.returncode}, "
                  f"stderr={(res.stderr or '')[:200]}")
        return urls
    if not os.path.exists(outfile):
        print("  socialscan produced no output file — keeping all URLs")
        log_trace("socialscan_filter: no output file produced.")
        return urls

    try:
        with open(outfile, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        print("  socialscan produced malformed JSON — keeping all URLs")
        log_trace(f"socialscan_filter: JSON parse error: {exc}")
        try:
            os.unlink(outfile)
        except OSError:
            pass
        return urls
    os.unlink(outfile)

    available_platforms = set()
    unavailable_platforms = set()
    for query, results in data.items():
        if not isinstance(results, list):
            continue
        for entry in results:
            if not isinstance(entry, dict):
                continue
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
            filtered.append(url)
            continue
        domain = urlparse(url).netloc.lower().replace("www.", "")
        matching_platform = None
        for plat, plat_domain in platform_to_domain.items():
            if domain.endswith(plat_domain):
                matching_platform = plat
                break
        if matching_platform is None:
            filtered.append(url)
        elif matching_platform in available_platforms:
            filtered.append(url)
        elif matching_platform in unavailable_platforms:
            print(f"    Skipping {url} (socialscan says not available)")
        else:
            filtered.append(url)
    return filtered if filtered else urls