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
from .utils import resilient_task, tool_available, clean_username, CACHE_DIR, get_base_dir, log_trace

from . import config as _config_module


def _flag(name: str, default: bool = False) -> bool:
    return bool(getattr(_config_module, name, default))


from .scraping import is_likely_profile_url_v2


# ═══════════════════════════════════════════════════════════════════════════
# User Scanner (kaifcodec/user-scanner) — replaces sherlock, naminter,
# social_analyzer, and blackbird-username.
#
# Fixed: the tool frequently ignores `-o <file>` and prints JSON to stdout
# instead. This version reads whichever channel actually contains data,
# normalises every plausible JSON shape, and — critically — records the
# reason when nothing parseable came back, so the operator can tell the
# difference between "site not found" and "tool crashed on startup".
# ═══════════════════════════════════════════════════════════════════════════

_USER_SCANNER_NAMES = ("user-scanner", "user_scanner", "userscanner", "UserScanner")


def _user_scanner_binary() -> str | None:
    """Return the first matching user-scanner executable on PATH."""
    for name in _USER_SCANNER_NAMES:
        p = shutil.which(name)
        if p:
            return p
    return None


def _extract_json_blob(text: str):
    """
    Find and parse the first JSON object/array inside *text*.

    Tools like user-scanner often print banners or progress lines before
    the real payload, so we scan for the first balanced ``{...}`` or
    ``[...]`` block instead of assuming the whole stdout is JSON.
    Returns the parsed value or ``None``.
    """
    if not text:
        return None
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start < 0:
            continue
        depth  = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def _entry_url(entry: dict) -> str:
    """Return the first HTTP URL found under any of the known key names."""
    for k in ("url", "profile_url", "profile", "link", "href", "account_url"):
        v = entry.get(k)
        if isinstance(v, str) and v.startswith("http"):
            return v.strip()
    return ""


def _entry_is_negative(entry: dict) -> bool:
    """
    Return True only when the entry explicitly signals 'not found'.

    Many user-scanner builds omit the status field entirely when a profile
    is found, so we can't require status == "found".  We only reject
    entries that carry an unambiguous negative marker.
    """
    for k in ("status", "exists", "found", "registered", "available", "taken"):
        if k not in entry:
            continue
        v = entry[k]
        if isinstance(v, bool):
            return not v
        s = str(v).strip().lower()
        if s in ("false", "no", "0", "not found", "not_found",
                 "absent", "none", "unavailable", "free"):
            return True
    return False


def _site_from_url(url: str) -> str:
    """Best-effort short platform name from a URL."""
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc.lower()
        for prefix in ("www.", "api.", "public-api."):
            if netloc.startswith(prefix):
                netloc = netloc[len(prefix):]
        parts = netloc.split(".")
        return parts[-2] if len(parts) >= 2 else (netloc or "unknown")
    except Exception:
        return "unknown"


def _normalise_user_scanner(data) -> list[dict]:
    """
    Turn any plausible user-scanner output shape into the pipeline's
    expected list of ``{"site", "url", "category", "extra"}`` dicts.
    """
    raw_entries: list = []

    if isinstance(data, list):
        raw_entries = data
    elif isinstance(data, dict):
        for key in ("results", "data", "findings", "accounts",
                    "sites", "profiles", "matches"):
            v = data.get(key)
            if isinstance(v, list):
                raw_entries = v
                break
        if not raw_entries:
            for site_name, entry in data.items():
                if isinstance(entry, dict):
                    e = dict(entry)
                    e.setdefault("site_name", site_name)
                    raw_entries.append(e)
                elif isinstance(entry, list):
                    for sub in entry:
                        if isinstance(sub, dict):
                            s = dict(sub)
                            s.setdefault("site_name", site_name)
                            raw_entries.append(s)
                elif isinstance(entry, str) and entry.startswith("http"):
                    raw_entries.append({"site_name": site_name, "url": entry})
    elif isinstance(data, str):
        raw_entries = [{"url": ln.strip()} for ln in data.splitlines()
                       if ln.strip().startswith("http")]

    results: list[dict] = []
    for entry in raw_entries:
        if isinstance(entry, str):
            if entry.startswith("http"):
                results.append({
                    "site":     _site_from_url(entry),
                    "url":      entry.strip(),
                    "category": "",
                    "extra":    {},
                })
            continue

        if not isinstance(entry, dict):
            continue

        url = _entry_url(entry)
        if not url:
            continue
        if _entry_is_negative(entry):
            continue

        site = str(
            entry.get("site_name")
            or entry.get("site")
            or entry.get("platform")
            or entry.get("name")
            or _site_from_url(url)
        ).strip() or "unknown"

        skip = {"url", "profile_url", "profile", "link", "href", "account_url",
                "site", "site_name", "platform", "name",
                "status", "exists", "found", "registered", "available", "taken",
                "category", "type", "extra"}

        extra: dict = {}
        if isinstance(entry.get("extra"), dict):
            extra.update(entry["extra"])
        for k, v in entry.items():
            if k in skip:
                continue
            if isinstance(v, (str, int, float, bool)) and v not in ("", None):
                extra[k] = v

        results.append({
            "site":     site,
            "url":      url,
            "category": str(entry.get("category", "") or ""),
            "extra":    extra,
        })

    return results


@resilient_task(max_retries=1)
def run_user_scanner(target: str, mode: str = "username") -> list[dict]:
    """
    Run user-scanner against a username or email.

    Returns a list of dicts:
        {"site": str, "url": str, "category": str, "extra": dict}

    Failure modes are recorded via ``log_trace`` so the debug log
    distinguishes "no hits" from "tool crashed on startup" from "tool
    produced output we could not parse."
    """
    binary = _user_scanner_binary()
    if not binary:
        msg = (f"user-scanner: executable not found (looked for "
               f"{', '.join(_USER_SCANNER_NAMES)}). Skipping.")
        print(f"  {msg}")
        log_trace(msg)
        return []

    # Multiple flag conventions — different releases accept different
    # combinations. Stop at the first one that produces parsable output.
    flag = "-e" if mode == "email" else "-u"
    arg_variants = [
        [flag, target, "-f", "json", "-o", None],
        [flag, target, "--format", "json", "--output", None],
        [flag, target, "--json", None],
        [flag, target, "-j", None],
        [flag, target, "-f", "json"],
        [flag, target, "--format", "json"],
        [flag, target],
    ]

    parsed_data = None
    used_args   = None
    last_stdout = ""
    last_rc     = None
    last_err    = ""

    for arg_tpl in arg_variants:
        tmp = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8",
        )
        tmp.close()
        outfile = tmp.name

        args = []
        for a in arg_tpl:
            if a is None:
                args.append(outfile)
            else:
                args.append(a)

        try:
            result, stdout, stderr = utils.run_external_tool(
                binary, *args, timeout=600,
            )
            last_stdout = stdout or ""
            last_rc     = getattr(result, "returncode", None)
            last_err    = stderr or ""
        except Exception as exc:
            log_trace(f"user-scanner: attempt {' '.join(args[:2])} raised "
                      f"{type(exc).__name__}: {exc}")
            try:
                os.unlink(outfile)
            except OSError:
                pass
            continue

        # 1. Prefer the output file
        if os.path.isfile(outfile) and os.path.getsize(outfile) > 0:
            try:
                with open(outfile, "r", encoding="utf-8") as f:
                    parsed_data = json.load(f)
                used_args = args
                break
            except json.JSONDecodeError as exc:
                log_trace(f"user-scanner: output file not valid JSON: {exc}")

        # 2. Try JSON on stdout
        blob = _extract_json_blob(last_stdout)
        if blob is not None:
            parsed_data = blob
            used_args   = args
            break

        # 3. Last resort: URLs on stdout
        urls = re.findall(r'https?://[^\s"\'<>]+', last_stdout)
        if urls:
            parsed_data = [{"url": u} for u in urls]
            used_args   = args
            break

        try:
            os.unlink(outfile)
        except OSError:
            pass

    # ── Diagnostics ─────────────────────────────────────────────────────
    if parsed_data is None:
        snippet = (last_stdout or "").strip().replace("\n", " ⏎ ")[:300]
        err_snippet = (last_err or "").strip().replace("\n", " ⏎ ")[:200]
        detail = (
            "user-scanner returned no parsable output.\n"
            f"    binary      : {binary}\n"
            f"    mode        : {mode}\n"
            f"    last rc     : {last_rc}\n"
            f"    stdout size : {len(last_stdout)} chars\n"
            f"    stdout head : {snippet or '(empty)'}"
        )
        if err_snippet:
            detail += f"\n    stderr head : {err_snippet}"
        print(f"  {detail}")
        log_trace(detail)
        return []

    results = _normalise_user_scanner(parsed_data)

    if not results:
        try:
            sample = json.dumps(parsed_data, ensure_ascii=False)[:300]
        except Exception:
            sample = repr(parsed_data)[:300]
        detail = (
            "user-scanner: parsed JSON but found no HTTP URLs in it.\n"
            f"    args used : {' '.join(str(a) for a in (used_args or []))}\n"
            f"    data head : {sample}"
        )
        print(f"  {detail}")
        log_trace(detail)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# Legacy tools — kept only when explicitly still needed
# ═══════════════════════════════════════════════════════════════════════════

@resilient_task(max_retries=1)
def run_maigret(username):
    """Kept: broadest raw username coverage (~3000 sites)."""
    if not tool_available("maigret"):
        log_trace("maigret: not on PATH — skipping.")
        return []

    result, _stdout, stderr = utils.run_external_tool(
        "maigret", username,
        "--all-sites", "--json", "simple", "--timeout", "15",
        timeout=600,
    )
    rc = getattr(result, "returncode", None)
    if rc not in (0, None):
        log_trace(f"maigret: exited rc={rc} — stderr: {(stderr or '')[:200]}")

    reports_dir = os.path.join(os.path.dirname(get_base_dir()), "reports")
    if not os.path.isdir(reports_dir):
        log_trace(f"maigret: reports dir {reports_dir!r} missing — no output.")
        return []

    candidates = []
    for fn in os.listdir(reports_dir):
        if fn.startswith(f"report_{username}") and fn.endswith(".json"):
            candidates.append(os.path.join(reports_dir, fn))
    if not candidates:
        for fn in os.listdir(reports_dir):
            if username in fn and "simple" in fn and fn.endswith(".json"):
                candidates.append(os.path.join(reports_dir, fn))
    if not candidates:
        log_trace(f"maigret: no matching report_*.json for {username!r}.")
        return []

    latest = max(candidates, key=os.path.getmtime)
    try:
        with open(latest, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  Maigret JSON read error: {e}")
        log_trace(f"maigret: JSON read error on {latest}: {e}")
        return []

    results = []
    for site, info in data.items():
        if not isinstance(info, dict):
            continue
        status_block = info.get("status", {})
        raw_status = status_block.get("status", "")
        if str(raw_status).lower() in ("claimed", "available"):
            ids = status_block.get("ids", {})
            results.append({
                "site": site,
                "url": info.get("url_user", ""),
                "name": ids.get("fullname") or status_block.get("username", ""),
                "bio": ids.get("bio", ""),
                "location": ids.get("location", ""),
                "image": ids.get("image", ""),
                "full": info,
            })
    return results


def run_sociopath(seed_url, recursive=0):
    """Kept: URL spider, complementary to user-scanner."""
    if not _flag("ENABLE_SOCIOPATH"):
        return []

    if not tool_available("sociopath"):
        if not utils.install_package("sociopath"):
            print("  [X] sociopath could not be installed automatically.")
            log_trace("sociopath: not on PATH and pip install failed.")
            return []
        else:
            print("  sociopath installed successfully.")

    if not tool_available("sociopath"):
        log_trace("sociopath: still not on PATH after install — skipping.")
        return []

    cmd = ["sociopath", seed_url, "--json", "-r", str(recursive)]
    result, stdout, stderr = utils.debug_subprocess(cmd, timeout=60)
    rc = getattr(result, "returncode", None)
    if rc not in (0, None):
        log_trace(f"sociopath: rc={rc}, stderr={(stderr or '')[:200]}")
    if not stdout:
        log_trace(f"sociopath: empty stdout for {seed_url[:60]}")
        return []

    json_start = stdout.find('[')
    if json_start == -1:
        log_trace(f"sociopath: no JSON array found in stdout ({len(stdout)} chars).")
        return []
    json_str = stdout[json_start:]
    bracket_count = 0
    json_end = -1
    for i, ch in enumerate(json_str):
        if ch == '[':
            bracket_count += 1
        elif ch == ']':
            bracket_count -= 1
        if bracket_count == 0:
            json_end = i + 1
            break
    if json_end == -1:
        log_trace("sociopath: JSON array never closed in stdout.")
        return []
    json_str = json_str[:json_end]

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"  sociopath JSON error: {e}")
        log_trace(f"sociopath: JSON parse error: {e}")
        return []

    results = data if isinstance(data, list) else data.get("results", [])
    enriched = []
    for r in results:
        url = r.get("URL", "")
        if not url or not is_likely_profile_url_v2(url):
            continue
        enriched.append({
            "url": url,
            "display_name": r.get("DisplayName", ""),
            "email": r.get("Fields", {}).get("email", ""),
            "description": r.get("Bio", ""),
            "source_type": r.get("Platform", "website"),
            "PageTitle": r.get("PageTitle", ""),
        })
    return enriched


@resilient_task(max_retries=1)
def run_linkook(username):
    """Kept: deep URL discovery, complementary to user-scanner."""
    if not tool_available("linkook"):
        log_trace("linkook: not on PATH — skipping.")
        return []
    result, stdout, stderr = utils.run_external_tool("linkook", username, timeout=60)
    rc = getattr(result, "returncode", None)
    if rc not in (0, None):
        log_trace(f"linkook: rc={rc}, stderr={(stderr or '')[:200]}")
    if stdout is None:
        log_trace("linkook: no stdout captured.")
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
def run_blackbird(target, mode="username"):
    """
    Kept for email mode only — its JSON API endpoint detection is unique.
    Username mode is now handled by user-scanner.
    """
    if mode != "email":
        return []
    if not _flag("ENABLE_BLACKBIRD"):
        return []
    BLACKBIRD_DIR = _config_module.BLACKBIRD_DIR

    blackbird_py = os.path.join(BLACKBIRD_DIR, "blackbird.py")
    if not os.path.isfile(blackbird_py):
        print("  Blackbird not found – attempting to clone the repository …")
        try:
            import subprocess as _clone_sp
            _clone_sp.check_call(
                ["git", "clone", "https://github.com/p1ngul1n0/blackbird", BLACKBIRD_DIR],
                stdout=_clone_sp.DEVNULL, stderr=_clone_sp.DEVNULL,
            )
            print("  Blackbird cloned successfully.")
        except Exception as exc:
            print(f"  [!] Failed to clone Blackbird. Please manually run:")
            print(f"      git clone https://github.com/p1ngul1n0/blackbird {BLACKBIRD_DIR}")
            log_trace(f"blackbird: git clone failed: {exc}")
            return []
        if not os.path.isfile(blackbird_py):
            print(f"  [!] Cloned, but blackbird.py still not found at {blackbird_py}")
            log_trace("blackbird: blackbird.py missing after clone.")
            return []

    try:
        import dotenv  # noqa: F401
    except ImportError:
        print("  Installing python-dotenv for Blackbird …")
        _sp.check_call([sys.executable, "-m", "pip", "install", "python-dotenv"],
                       stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)

    wmn_data = os.path.join(BLACKBIRD_DIR, "data", "wmn-data.json")
    if not os.path.isfile(wmn_data):
        print("  Blackbird data file not found – downloading (one‑time, ~1 MB) …")
        try:
            import urllib.request
            os.makedirs(os.path.dirname(wmn_data), exist_ok=True)
            urllib.request.urlretrieve(
                "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
                wmn_data,
            )
            print("  Done – data file downloaded successfully.")
        except Exception as e:
            print(f"  Auto‑download failed: {e}")
            log_trace(f"blackbird: wmn-data download failed: {e}")
            return []

    t0 = time.time()
    python_exe = utils._get_frozen_python() if getattr(sys, 'frozen', False) else sys.executable
    args = ["--email", target]
    cmd = [python_exe, blackbird_py] + args + ["--json", "--no-update", "--no-nsfw", "--timeout", "15"]

    import sys as _sys_bb
    if getattr(_sys_bb, 'frozen', False):
        env = os.environ.copy()
        bundle_dir = os.path.dirname(_sys_bb.executable)
        env['PYTHONHOME'] = bundle_dir
        paths = []
        internal = os.path.join(bundle_dir, '_internal')
        if os.path.isdir(internal):
            paths.append(internal)
        ext = os.path.join(bundle_dir, 'ext_lib')
        if os.path.isdir(ext):
            paths.append(ext)
        if paths:
            existing = env.get('PYTHONPATH', '')
            env['PYTHONPATH'] = os.pathsep.join(paths) + (os.pathsep + existing if existing else '')
    else:
        env = None

    result, stdout, stderr = utils.debug_subprocess(cmd, timeout=600, cwd=BLACKBIRD_DIR, env=env)
    rc = getattr(result, "returncode", None)
    if rc not in (0, None):
        log_trace(f"blackbird: rc={rc}, stderr={(stderr or '')[:300]}")
    time.sleep(1)

    results_dir = os.path.join(BLACKBIRD_DIR, "results")
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
        log_trace("blackbird: no fresh *_blackbird.json produced.")
        return []

    try:
        with open(best_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  Blackbird JSON read error: {e}")
        log_trace(f"blackbird: JSON read error on {best_path}: {e}")
        return []

    results = []
    if isinstance(data, list):
        for entry in data:
            url = entry.get("url", "")
            if url and url.startswith("http"):
                results.append({
                    "site": entry.get("name", entry.get("site", "unknown")),
                    "url": url,
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
                                "url": url,
                            })
    return results