"""
discord_osint/utils/__init__.py
-------------------------------
Shared helpers: directory resolution, HTTP sessions with retry, subprocess
wrappers, dependency checks, and the resilient_task decorator.

Change log
----------
- ``debug_subprocess`` and ``run_external_tool`` now return
  ``(CompletedProcess, stdout, stderr)``. The CompletedProcess carries
  ``returncode``, which callers previously could not see (it was
  discarded before the tuple was built). This is what lets a caller
  distinguish "tool ran and produced no output" from "tool crashed on
  launch".
- ``resilient_task`` records every retry and the terminal failure to
  ``log_trace`` so a run with DEBUG on leaves a durable trail.
- ``_get_github_session`` bare-except fallback branches now log their
  decisions.
"""

import re
import time
import requests
import shutil
import functools
import os
import sys
import threading
import subprocess as _sp
import logging
import logging.handlers
from datetime import datetime
import sys as _sys
import os as _os


# ─────────────────────────────────────────────────────────────────────
# Directory resolution
# ─────────────────────────────────────────────────────────────────────

def get_base_dir():
    """Directory where the executable (or main script) lives."""
    if getattr(_sys, 'frozen', False):
        return _os.path.dirname(_sys.executable)
    else:
        return _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))


def get_data_dir():
    """Directory for bundled data files (blackbird, templates)."""
    if getattr(_sys, 'frozen', False):
        return _sys._MEIPASS
    else:
        return get_base_dir()


# Constants
MAX_SCRAPE_WORKERS = 5
REQUEST_DELAY = 2.0
CACHE_DIR = os.path.join(get_base_dir(), "investigation_cache")

DEBUG_MODE = False
_debug_logger = None


def init_debug_log(target_id):
    global _debug_logger
    os.makedirs(CACHE_DIR, exist_ok=True)
    log_dir = os.path.join(CACHE_DIR, "debug_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(
        log_dir,
        f"debug_{target_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    logger = logging.getLogger(f'whoCord.{target_id}')
    logger.setLevel(logging.DEBUG)
    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(ch)
    _debug_logger = logger
    _debug_logger.info("=== Debug log started for target %s ===", target_id)


def log_trace(msg: str) -> None:
    """
    Append *msg* to the active debug log file.

    No-op when DEBUG_MODE is off or no debug log has been initialised yet.
    Never raises — a debug-log failure must never crash a stage.

    Import this from any module that wants to record fine-grained
    decisions (URL classification, fetch results, skip reasons, etc.)
    to the debug file without touching stdout.
    """
    if _debug_logger is None:
        return
    try:
        _debug_logger.debug(msg)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────
# Subprocess wrappers
# ─────────────────────────────────────────────────────────────────────

def debug_subprocess(cmd, **kwargs):
    """
    Run *cmd* with optional debug capture.

    Always returns ``(CompletedProcess, stdout, stderr)``. The
    CompletedProcess exposes ``returncode`` so callers can distinguish
    a clean exit with no output from a crash.
    """
    def _filter_line(line):
        return re.sub(
            r'("Content"\s*:\s*)"(?:[^"\\]|\\.)*"',
            r'\1"<content truncated>"',
            line
        )

    if DEBUG_MODE and _debug_logger:
        _debug_logger.debug("Running: %s", ' '.join(cmd))
        timeout = kwargs.pop('timeout', None)
        kwargs['stdout'] = _sp.PIPE
        kwargs['stderr'] = _sp.STDOUT
        kwargs.pop('capture_output', None)
        kwargs.pop('text', None)
        proc = _sp.Popen(cmd, **kwargs)
        captured_lines = []

        def reader():
            for raw_line in iter(proc.stdout.readline, b''):
                line = raw_line.decode('utf-8', errors='replace')
                filtered = _filter_line(line)
                _debug_logger.debug(filtered.rstrip())
                captured_lines.append(line)
            proc.stdout.close()

        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()
        try:
            proc.wait(timeout=timeout)
        except _sp.TimeoutExpired:
            proc.kill()
            proc.wait()
            _debug_logger.warning("Command timed out after %ds", timeout)
        finally:
            reader_thread.join(timeout=5)

        stdout_text = ''.join(captured_lines)
        # In debug mode stdout and stderr are merged; report stderr as
        # empty so callers don't double-count.
        result = _sp.CompletedProcess(args=cmd, returncode=proc.returncode,
                                      stdout=stdout_text, stderr='')
        return result, stdout_text, ''

    # Non-debug path — keep stdout and stderr separate so the caller can
    # log the actual error text when returncode is non-zero.
    kwargs['capture_output'] = True
    kwargs['text'] = True
    result = _sp.run(cmd, **kwargs)
    return result, result.stdout, result.stderr


def _get_frozen_python():
    if getattr(_sys, 'frozen', False):
        candidate = os.path.join(os.path.dirname(_sys.executable), 'python3')
        if os.path.isfile(candidate):
            return candidate
        return _sys.executable
    return _sys.executable


def run_external_tool(tool_name, *args, timeout=None, cwd=None):
    """
    Run an external OSINT tool.

    Returns ``(CompletedProcess, stdout, stderr)``. The caller can read
    ``result.returncode`` to distinguish success-with-no-output from a
    crash.
    """
    if getattr(_sys, 'frozen', False):
        script = os.path.join(os.path.dirname(_sys.executable), tool_name)
        if not os.path.isfile(script):
            raise FileNotFoundError(f"Tool script '{tool_name}' not found")
        python_exe = _get_frozen_python()
        cmd = [python_exe, script] + list(args)
        env = os.environ.copy()
        bundle_dir = os.path.dirname(_sys.executable)
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
        kwargs = {'timeout': timeout, 'cwd': cwd, 'env': env}
        return debug_subprocess(cmd, **kwargs)
    else:
        cmd = [tool_name] + list(args)
        return debug_subprocess(cmd, timeout=timeout, cwd=cwd)


# ─────────────────────────────────────────────────────────────────────
# HTTP sessions
# ─────────────────────────────────────────────────────────────────────

def get_http_session(retries=3, backoff_factor=1):
    session = requests.Session()
    retry_strategy = requests.adapters.Retry(
        total=retries, backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"])
    adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


http_session = get_http_session()


def _get_ip_via_doh(host, dns="https://dns.google/resolve"):
    try:
        resp = requests.get(dns, params={"name": host, "type": "A"}, timeout=5)
        if resp.status_code == 200:
            for a in resp.json().get("Answer", []):
                if a.get("type") == 1:
                    return a["data"]
    except Exception as exc:
        log_trace(f"_get_ip_via_doh: {type(exc).__name__}: {exc}")
    return None


def _force_github_resolution(session, host, resolved_ip):
    class ForceIPHTTPAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs['assert_hostname'] = host
            super().init_poolmanager(*args, **kwargs)

        def cert_verify(self, conn, url, verify, cert):
            conn.assert_hostname = host
            return super().cert_verify(conn, url, verify, cert)

    adapter = ForceIPHTTPAdapter()
    session.mount(f"https://{host}/", adapter)
    orig = session.request

    def patched(method, url, **kw):
        if host in url:
            url = url.replace(f"https://{host}", f"https://{resolved_ip}")
        return orig(method, url, **kw)

    session.request = patched


def _get_github_session():
    sess = get_http_session()
    try:
        test = sess.get("https://api.github.com", timeout=5)
        if test.status_code == 200 and "current_user_url" in test.json():
            return sess
        log_trace(
            f"_get_github_session: api.github.com responded "
            f"HTTP {test.status_code} on probe — trying DoH fallback."
        )
    except Exception as exc:
        log_trace(
            f"_get_github_session: direct probe failed "
            f"({type(exc).__name__}: {exc}) — trying DoH fallback."
        )

    print("GitHub API unreachable normally – trying DoH...")
    new_ip = _get_ip_via_doh("api.github.com")
    if new_ip:
        print(f"Using IP {new_ip} for api.github.com")
        log_trace(f"_get_github_session: routing api.github.com via {new_ip}.")
        _force_github_resolution(sess, "api.github.com", new_ip)
    else:
        log_trace("_get_github_session: DoH returned no A record — leaving "
                  "session untouched.")
    return sess


github_session = _get_github_session()


# ─────────────────────────────────────────────────────────────────────
# resilient_task
# ─────────────────────────────────────────────────────────────────────

def resilient_task(max_retries=3, backoff_factor=1.5):
    """
    Retry decorator.

    On terminal failure returns ``None`` (the caller's contract). Every
    retry and the final exception are recorded via ``log_trace`` so a
    debug-log run shows *which* call failed and *why*.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    wait = backoff_factor ** attempt
                    msg = (f"    [!] {func.__name__} failed "
                           f"(attempt {attempt + 1}/{max_retries}), "
                           f"retrying in {wait:.1f}s...")
                    print(msg)
                    log_trace(f"resilient_task: {func.__name__} attempt "
                              f"{attempt + 1} raised {type(e).__name__}: {e}")
                    time.sleep(wait)
            msg = f"    [X] {func.__name__} permanently failed: {last_exc}"
            print(msg)
            log_trace(f"resilient_task: {func.__name__} exhausted retries — "
                      f"{type(last_exc).__name__}: {last_exc}")
            return None
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────
# Dependency checks
# ─────────────────────────────────────────────────────────────────────

def tool_available(name):
    return shutil.which(name) is not None


def clean_username(raw: str) -> str:
    raw = raw.strip()
    cleaned = re.sub(r'^\.+', '', raw)
    return cleaned if cleaned else raw


EXT_TOOLS = {
    "sherlock": "pip install sherlock-project",
    "maigret": "pip install maigret",
    "user-scanner": "pip install user-scanner",
    "holehe": "pip install holehe",
    "h8mail": "pip install h8mail",
    "gitfive": "pip install gitfive",
    "naminter": "pip install naminter",
    "socid_extractor": "pip install socid-extractor",
    "socialscan": "pip install socialscan",
    "linkook": "pip install linkook",
    "theHarvester": "pip install theharvester",
    "toutatis": "pip install toutatis",
    "sociopath": "Install manually – see README installation section",
    "sharetrace": "pip install sharetrace",
    "scylla": "Install manually – see README installation section",
    "phoneinfoga": "Install manually – download binary from GitHub releases",
    "whois": "apt-get install whois (or brew install whois)",
}


def check_dependencies():
    missing = []
    for tool, install_cmd in EXT_TOOLS.items():
        if not shutil.which(tool):
            missing.append(f"{tool}: {install_cmd}")
    if missing:
        print("Missing external tools:")
        for m in missing:
            print(f"  - {m}")
        print("Please install them before running investigations.\n")
    return missing


TOOL_PACKAGES = {
    "theHarvester": "theharvester",
    "toutatis": "toutatis",
    "user-scanner": "user-scanner",
    "sherlock": "sherlock-project",
    "maigret": "maigret",
    "holehe": "holehe",
    "h8mail": "h8mail",
    "gitfive": "gitfive",
    "naminter": "naminter",
    "socid_extractor": "socid-extractor",
    "socialscan": "socialscan",
    "linkook": "linkook",
    "sociopath": "external",
    "sharetrace": "sharetrace",
    "scylla": "external",
    "phoneinfoga": "external",
}


def check_tool_version(tool_name):
    if tool_name in TOOL_PACKAGES:
        pkg = TOOL_PACKAGES[tool_name]
        try:
            from importlib.metadata import version
            return version(pkg)
        except Exception:
            try:
                import pkg_resources
                return pkg_resources.get_distribution(pkg).version
            except Exception:
                return None
    else:
        return "external"


def upgrade_tools(interactive=True, log_callback=None):
    def log(msg):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)

    outdated = []
    for tool, pkg in TOOL_PACKAGES.items():
        if not tool_available(tool):
            continue
        current = check_tool_version(tool)
        if current and current != "external":
            outdated.append((tool, pkg, current))
        elif pkg == "external":
            outdated.append((tool, pkg, check_tool_version(tool)))

    if not outdated:
        log("All Pip tools appear to be up-to-date.")
        return

    pip_outdated = [(t, p, v) for t, p, v in outdated if p != "external"]
    external_outdated = [(t, p, v) for t, p, v in outdated if p == "external"]

    if external_outdated:
        log("\nThe following tools are installed but cannot be auto‑upgraded (install manually):")
        for tool, pkg, ver in external_outdated:
            log(f"  {tool} (manual install) – current version: {ver}")

    if pip_outdated:
        log("\nPip tools that can be upgraded:")
        for tool, pkg, ver in pip_outdated:
            log(f"  {tool} ({pkg}) v{ver}")

        if interactive:
            ans = input("\nUpgrade all pip tools? [y/N] ").strip().lower()
            if ans != 'y':
                return

        for tool, pkg, _ in pip_outdated:
            log(f"Upgrading {pkg}...")
            try:
                _sp.check_call(
                    [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
                    stdout=_sp.PIPE, stderr=_sp.STDOUT
                )
                log(f"  {pkg} upgraded successfully.")
            except _sp.CalledProcessError as e:
                log(f"  Upgrade failed for {pkg}: {e.output.decode()}")
    else:
        log("No pip‑based tools to upgrade.")


import subprocess as _install_sp
import sys as _install_sys


def install_package(package_name: str) -> bool:
    """
    Attempt to install *package_name* using pip.
    Returns True if installation succeeded, False otherwise.
    """
    try:
        _install_sp.check_call(
            [_install_sys.executable, "-m", "pip", "install", package_name],
            stdout=_install_sp.DEVNULL, stderr=_install_sp.DEVNULL
        )
        return True
    except Exception as exc:
        log_trace(f"install_package: {package_name} failed: "
                  f"{type(exc).__name__}: {exc}")
        return False