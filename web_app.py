"""
Flask web application – WhoCord Canvas.

Change log
----------
- Job finalization moved into the worker thread. Previously the SSE
  generator called ``mark_status`` / ``teardown`` / wrote
  ``investigation_finished`` — which meant a disconnected client could
  leave a job stuck in "running" forever, with no terminal audit entry
  and no retention eligibility. The worker now owns its own lifecycle.
- ``error_occurred`` is tracked inside ``_on_emit`` so an ``error``
  *event* (which does not raise) still results in a terminal
  ``status="error"``.
- Session cookie no longer carries the shared secret. The cookie value
  is a random per-boot session id looked up in a server-side map.
  Header/query tokens still compare against ``_SESSION_SECRET``.
- Read-access auditing: ``/api/investigations/<id>`` and
  ``/api/investigations/<id>/report`` write a ``case_viewed`` event.
  The cost route (polled every 3 s by the UI) is deliberately not
  audited.
- Chat LLM calls now write a ``third_party_contacted`` audit event and
  feed the job's cost accumulator.
- URL sanitization at the route boundary resolves the host and
  validates it against the SSRF blocklist, so a rejected URL fails
  with a clear 400 instead of deep inside a stage.
- ``MAX_LLM_SPEND_USD`` / ``MAX_ENRICHMENT_CREDITS`` are wired into
  every ``CostAccumulator`` created by this module.
- JSON array bodies now return 400 instead of raising AttributeError.
- Ad-hoc ``/run`` calls with no ``case_id`` land in the unassigned
  bucket instead of each getting its own generated case.
- Per-job disclosure view: ``/api/investigations/<id>/disclosures``.
- The legacy ``/report`` route now serves the most recently completed
  job's report from the registry rather than a module global.
- ``_origin_is_local`` parses the Origin header with ``urllib.parse``
  rather than prefix-matching.
"""

from __future__ import annotations

import atexit
import hmac
import json
import os
import queue
import re
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import (
    Flask, Response, jsonify, render_template,
    request, send_from_directory, stream_with_context,
)

from discord_osint import audit
from discord_osint.config import (
    JobConfig,
    reset_active_config,
    set_active_config,
)
from discord_osint.config_service import ConfigService, get_llm_endpoint
from discord_osint.costs import CostAccumulator
from discord_osint.pipeline.events import EventEmitter, to_sse_line
from discord_osint.utils import upgrade_tools, intel_target_key
from discord_osint.utils.sanitizers import (
    sanitize_email,
    sanitize_user_id,
    sanitize_username,
    sanitize_domain,
)
from discord_osint.utils.url_safety import (
    validate_url as _ssrf_validate_url,
    UnsafeURLError,
)

from web_services.batch import BatchRunner
from web_services.chat import active_chat_system_prompt, build_chat_context
from web_services.config_actions import ConfigActionDispatcher
from web_services.jobs import JobRegistry
from web_services.llm_models import fetch_models_for_provider
from web_services.retention import RetentionManager


# ---------------------------------------------------------------------------
# Constants and the shared concurrency budget
# ---------------------------------------------------------------------------

_MODULE_MODES = frozenset({"email", "domain", "phone", "image", "url", "probe"})
_ALL_MODES    = frozenset({"manual", "discord"}) | _MODULE_MODES

_PIVOT_CONFIRM_TIMEOUT = 45

_DEFAULT_PAGE_SIZE = 200
_MAX_PAGE_SIZE     = 1000

# Process-wide cap on concurrent investigations. Both /run and batch
# mode acquire from this semaphore, so the cap is the real ceiling
# regardless of which route started the job. Override with
# WHOCORD_MAX_CONCURRENT_JOBS in the environment.
_MAX_CONCURRENT_JOBS = max(
    1, int(os.environ.get("WHOCORD_MAX_CONCURRENT_JOBS", "4")),
)
_JOB_SEMAPHORE = threading.Semaphore(_MAX_CONCURRENT_JOBS)


# ---------------------------------------------------------------------------
# Module-level instances
# ---------------------------------------------------------------------------

app             = Flask(__name__)
config_service  = ConfigService()
job_registry    = JobRegistry()
config_actions  = ConfigActionDispatcher(config_service)
retention       = RetentionManager(job_registry, config_service)
batch_runner    = BatchRunner(
    job_registry,
    config_service,
    global_semaphore=_JOB_SEMAPHORE,
)


# ---------------------------------------------------------------------------
# Retention startup hook
# ---------------------------------------------------------------------------

_retention_started = False
_retention_lock    = threading.Lock()


def _start_retention_once() -> None:
    global _retention_started
    if _retention_started:
        return
    with _retention_lock:
        if _retention_started:
            return
        _retention_started = True
    retention.start_once()
    atexit.register(retention.stop)


# ---------------------------------------------------------------------------
# Session cookie + shared secret
# ---------------------------------------------------------------------------
#
# Two credentials now:
#
#   * The shared secret (``_SESSION_SECRET``) — used by scripts that
#     set ``X-WhoCord-Token`` or ``?token=``. Stored at
#     ``~/.whocord/session_secret``, mode 0600.
#
#   * A session id — a random per-boot token issued as an HttpOnly
#     cookie when the SPA or the legacy dashboard is served. Looked
#     up in ``_SESSIONS``. The cookie never carries the shared secret.
#
# The cookie mechanism exists so the browser never possesses the
# install-wide secret. Compromising a browser profile no longer leaks
# the secret used by every other client.

_SESSION_COOKIE_NAME = "whocord_session"

_SECRET_PATH = os.environ.get(
    "WHOCORD_SECRET_PATH",
    os.path.expanduser("~/.whocord/session_secret"),
)

_SESSIONS: dict[str, float] = {}
_SESSIONS_LOCK = threading.Lock()
_SESSION_TTL   = 24 * 3600  # 24 h


def _load_or_create_secret() -> str:
    """
    Read or create the shared secret.

    Permission handling
    -------------------
    If the secret file exists with group- or world-readable bits, fix
    the mode to 0600 and warn on stderr. Refusing to start would break
    every existing install whose secret was created under a permissive
    umask. Only refuse if the chmod itself fails.
    """
    env = os.environ.get("WHOCORD_SECRET")
    if env:
        return env.strip()

    if os.path.isfile(_SECRET_PATH):
        try:
            st = os.stat(_SECRET_PATH)
        except OSError as exc:
            raise RuntimeError(
                f"could not stat {_SECRET_PATH}: {exc}"
            ) from exc

        if st.st_mode & 0o077:
            print(
                f"[config] WARNING: {_SECRET_PATH} has mode "
                f"{oct(st.st_mode & 0o777)}; fixing to 0600",
                file=sys.stderr,
            )
            try:
                os.chmod(_SECRET_PATH, 0o600)
            except OSError as exc:
                raise RuntimeError(
                    f"refusing to use {_SECRET_PATH}: mode "
                    f"{oct(st.st_mode & 0o777)} and chmod failed: {exc}"
                ) from exc

        with open(_SECRET_PATH, encoding="utf-8") as f:
            return f.read().strip()

    parent = os.path.dirname(_SECRET_PATH) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass

    secret = secrets.token_urlsafe(32)
    with open(_SECRET_PATH, "w", encoding="utf-8") as f:
        f.write(secret)
    try:
        os.chmod(_SECRET_PATH, 0o600)
    except OSError:
        pass
    return secret


_SESSION_SECRET = _load_or_create_secret()


def _sweep_sessions() -> None:
    """Drop expired session entries. Called on every issue."""
    now = time.time()
    with _SESSIONS_LOCK:
        expired = [sid for sid, exp in _SESSIONS.items() if exp < now]
        for sid in expired:
            _SESSIONS.pop(sid, None)


def _issue_session() -> str:
    _sweep_sessions()
    sid = secrets.token_urlsafe(32)
    with _SESSIONS_LOCK:
        _SESSIONS[sid] = time.time() + _SESSION_TTL
    return sid


def _session_valid(sid: str) -> bool:
    if not sid:
        return False
    with _SESSIONS_LOCK:
        exp = _SESSIONS.get(sid)
        if exp is None:
            return False
        if exp < time.time():
            _SESSIONS.pop(sid, None)
            return False
    return True


def _attach_session_cookie(resp: Response) -> Response:
    """
    Set the session cookie on an HTML response.

    Reuses the caller's existing session id if it is still valid, so
    two tabs on the same browser share one session and a page reload
    does not orphan the previous id.

    Cookie attributes:
      * HttpOnly — invisible to JS.
      * SameSite=Lax — sent on top-level GET navigations; not sent on
        cross-site POST/PUT/DELETE, which is what CSRF actually needs.
      * Path=/ — the whole app.
      * No Secure flag: the tool ships bound to http://127.0.0.1.
        Add ``Secure`` here if you ever front it with TLS.
    """
    existing = request.cookies.get(_SESSION_COOKIE_NAME, "")
    sid = existing if _session_valid(existing) else _issue_session()

    resp.set_cookie(
        _SESSION_COOKIE_NAME,
        sid,
        httponly=True,
        samesite="Lax",
        path="/",
        max_age=_SESSION_TTL,
    )
    return resp


_PUBLIC_EXACT      = frozenset({"/", "/index.html", "/favicon.ico"})
_PUBLIC_PREFIXES   = ("/assets/", "/static/")

_PROTECTED_EXACT    = frozenset({
    "/run", "/config", "/get_config", "/stop", "/report",
    "/upgrade_tools", "/shutdown",
})
_PROTECTED_PREFIXES = ("/api/",)

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _origin_is_local(origin: str) -> bool:
    """
    Return True when *origin* is a loopback origin.

    Parsed with ``urlparse`` rather than prefix-matched, so
    ``http://127.0.0.1.evil.com`` cannot slip through a naive
    ``startswith("http://127.0.0.1:")``.
    """
    if not origin:
        return False
    try:
        p = urlparse(origin)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    return host in _LOOPBACK_HOSTS


def _is_protected(path: str) -> bool:
    if path in _PROTECTED_EXACT:
        return True
    return any(path.startswith(p) for p in _PROTECTED_PREFIXES)


@app.before_request
def _enforce_auth():
    _start_retention_once()

    if request.method == "OPTIONS":
        return None

    path = request.path

    if path in _PUBLIC_EXACT:
        return None
    if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return None
    if not _is_protected(path):
        return None

    origin = request.headers.get("Origin", "")
    if origin and not _origin_is_local(origin):
        return jsonify({"error": "cross-origin request rejected"}), 403

    sec_fetch_site = request.headers.get("Sec-Fetch-Site", "")
    if sec_fetch_site in ("cross-site", "same-site"):
        return jsonify({"error": "cross-site request rejected"}), 403

    if request.method in ("POST", "PUT", "DELETE", "PATCH") and sec_fetch_site:
        if sec_fetch_site not in ("same-origin", "none"):
            return jsonify({"error": "cross-site request rejected"}), 403

    # Header or query token → shared secret.
    header = request.headers.get("X-WhoCord-Token")
    if header:
        if not hmac.compare_digest(header, _SESSION_SECRET):
            return jsonify({"error": "unauthorized"}), 401
        return None

    query = request.args.get("token")
    if query:
        if not hmac.compare_digest(query, _SESSION_SECRET):
            return jsonify({"error": "unauthorized"}), 401
        return None

    # Otherwise, session cookie.
    sid = request.cookies.get(_SESSION_COOKIE_NAME, "")
    if not _session_valid(sid):
        return jsonify({"error": "unauthorized"}), 401

    return None


def _serves_legacy_template(path: str) -> bool:
    if _react_built():
        return False
    if path in ("/", "/index.html"):
        return True
    if path.startswith(("/api/", "/assets/", "/static/")):
        return False
    if path in _PROTECTED_EXACT:
        return False
    return True


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")

    if "Content-Security-Policy" in resp.headers:
        return resp

    if _serves_legacy_template(request.path):
        script_src = "script-src 'self' 'unsafe-inline'"
    else:
        script_src = "script-src 'self'"

    resp.headers.setdefault(
        "Content-Security-Policy",
        f"default-src 'self'; "
        f"{script_src}; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: https:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'self'",
    )
    return resp


# ---------------------------------------------------------------------------
# Thread-safe stdout capture
# ---------------------------------------------------------------------------

class _StdoutCapture:
    def __init__(self, event_queue: queue.Queue) -> None:
        self._q   = event_queue
        self._buf = ""

    def write(self, s: str) -> None:
        if not s:
            return
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self._q.put({"type": "log", "payload": {"line": line}})

    def flush(self) -> None:
        if self._buf:
            self._q.put({"type": "log", "payload": {"line": self._buf}})
            self._buf = ""

    def isatty(self) -> bool:
        return False


class _StdoutRouter:
    def __init__(self) -> None:
        self._local    = threading.local()
        self._original = sys.stdout

    def set_capture(self, capture: _StdoutCapture) -> None:
        self._local.capture = capture

    def clear_capture(self) -> None:
        self._local.capture = None

    def _capture(self) -> _StdoutCapture | None:
        return getattr(self._local, "capture", None)

    def write(self, s: str) -> None:
        cap = self._capture()
        if cap is not None:
            cap.write(s)
        else:
            self._original.write(s)

    def flush(self) -> None:
        cap = self._capture()
        if cap is not None:
            cap.flush()
        else:
            self._original.flush()

    def isatty(self) -> bool:
        return False


_STDOUT_ROUTER = _StdoutRouter()
sys.stdout = _STDOUT_ROUTER


# ---------------------------------------------------------------------------
# SPA serving
# ---------------------------------------------------------------------------

_FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "frontend", "dist")


def _react_built() -> bool:
    return os.path.isdir(_FRONTEND_DIST) and os.path.isfile(
        os.path.join(_FRONTEND_DIST, "index.html")
    )


def _serve_spa_index() -> Response:
    with open(os.path.join(_FRONTEND_DIST, "index.html"), encoding="utf-8") as f:
        html = f.read()
    return _attach_session_cookie(Response(html, mimetype="text/html"))


def _serve_legacy_index() -> Response:
    html = render_template("index.html", session_token="")
    return _attach_session_cookie(Response(html, mimetype="text/html"))


@app.route("/")
def index():
    if _react_built():
        return _serve_spa_index()
    return _serve_legacy_index()


@app.route("/assets/<path:filename>")
def react_assets(filename):
    return send_from_directory(os.path.join(_FRONTEND_DIST, "assets"), filename)


@app.route("/<path:path>")
def serve_react(path):
    skip = ("api/", "run", "config", "get_config", "stop", "report",
            "upgrade", "shutdown")
    if any(path.startswith(p) for p in skip):
        return jsonify({"error": "not found"}), 404
    candidate = os.path.join(_FRONTEND_DIST, path)
    if _react_built() and os.path.isfile(candidate):
        return send_from_directory(_FRONTEND_DIST, path)
    if _react_built():
        return _serve_spa_index()
    return _serve_legacy_index()


# ---------------------------------------------------------------------------
# Mode validation + per-module sanitisers
# ---------------------------------------------------------------------------

def validate_mode_extended(raw: str) -> str:
    mode = raw.strip().lower()
    if mode in _ALL_MODES:
        return mode
    raise ValueError(f"Invalid mode {raw!r}. Valid: {sorted(_ALL_MODES)}")


def _sanitize_phone(raw: str) -> str:
    return re.sub(r"[^\d\+\-\s\(\)]", "", raw.strip())[:20]


def _sanitize_url(raw: str) -> str:
    """
    Validate and normalise a URL supplied at the route boundary.

    Two-stage: format (scheme + host present) then SSRF (resolves the
    host and rejects private / loopback / link-local addresses). Doing
    this here means a bad URL fails with a clear 400 instead of deep
    inside a stage, and it means ``_sanitize_url`` cannot be used as
    an SSRF-primitive launcher.

    Note: this performs a DNS lookup. On a slow resolver, /run for a
    url-mode target will block for the resolver's timeout before the
    job is created. That is the correct tradeoff — the alternative is
    discovering the URL is unreachable two minutes into a job.
    """
    s = raw.strip()
    if not s:
        raise ValueError("URL is required")
    if not s.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    s = s[:2048]
    try:
        _ssrf_validate_url(s)
    except UnsafeURLError as exc:
        raise ValueError(f"URL rejected: {exc}")
    return s


def _sanitize_image_url(raw: str) -> str:
    return _sanitize_url(raw)


def _sanitize_probe(raw: str) -> str:
    return raw.strip()[:512]


def _sanitize_case_id(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    s = re.sub(r"[^A-Za-z0-9._\-]", "_", s)
    return s[:64]


def _parse_page_args() -> tuple[int, int]:
    try:
        limit = int(request.args.get("limit", str(_DEFAULT_PAGE_SIZE)))
    except (TypeError, ValueError):
        limit = _DEFAULT_PAGE_SIZE
    try:
        offset = int(request.args.get("offset", "0"))
    except (TypeError, ValueError):
        offset = 0
    limit  = max(1, min(limit, _MAX_PAGE_SIZE))
    offset = max(0, offset)
    return limit, offset


def _require_object_body() -> dict | tuple[Response, int]:
    """
    Return the request body as a dict, or a 400 response when it is
    not a JSON object.

    A JSON array is a valid JSON document; ``[1,2].get("mode")`` raises
    AttributeError and produces a 500 with a stack trace. This helper
    closes that path for every state-changing route.
    """
    body = request.get_json(silent=True)
    if body is None:
        return {}
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    return body


# ---------------------------------------------------------------------------
# Read-access audit
# ---------------------------------------------------------------------------
#
# The cost route is polled every 3 s by the UI while a job runs. A
# 10-minute investigation would write ~200 case_viewed entries on that
# route alone and bury every meaningful audit line. Intel and report
# reads are once-per-view and are audited directly.

def _audit_case_read(job: dict, route: str) -> None:
    if route == "cost":
        return
    try:
        audit.write_event(
            "case_viewed",
            job_id=job.get("id", ""),
            target=job.get("target", ""),
            case_id=job.get("case_id", ""),
            route=route,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Config endpoints
# ---------------------------------------------------------------------------

@app.route("/get_config")
def get_config():
    tokens = config_service.token_status()
    pivot_cfg = {
        "enabled":         bool(getattr(config_service, "ENABLE_PIVOTING",       False)),
        "pivot_email":     bool(getattr(config_service, "PIVOT_EMAIL",           True)),
        "pivot_username":  bool(getattr(config_service, "PIVOT_USERNAME",        True)),
        "max_depth":       int( getattr(config_service, "PIVOT_MAX_DEPTH",       3)),
        "max_seeds":       int( getattr(config_service, "PIVOT_MAX_SEEDS",       5)),
        "require_confirm": bool(getattr(config_service, "PIVOT_REQUIRE_CONFIRM", False)),
    }
    llm_cfg = {
        "provider":           config_service.llm_provider,
        "model":              config_service.llm_model,
        "temperature":        config_service.llm_temperature,
        "max_tokens":         config_service.llm_max_tokens,
        "system_prompt":      config_service.llm_system_prompt,
        "intel_budget":       config_service.llm_intel_budget,
        "intel_include_raw":  config_service.llm_intel_include_raw,
        "intel_exclude_meta": config_service.llm_intel_exclude_meta,
    }
    enrichment_cfg = {
        "max_identifiers": config_service.enrichment_max_identifiers,
        "phone_reveal":    config_service.enrichment_phone_reveal,
        "enabled": {
            "apollo": config_service.enable_apollo,
            "lusha":  config_service.enable_lusha,
        },
        "keys_stored": {
            "apollo": bool(config_service.apollo_api_key),
            "lusha":  bool(config_service.lusha_api_key),
        },
    }
    spend_cfg = {
        "max_llm_spend_usd":      float(getattr(config_service, "MAX_LLM_SPEND_USD", 0.0) or 0.0),
        "max_enrichment_credits": float(getattr(config_service, "MAX_ENRICHMENT_CREDITS", 0.0) or 0.0),
        "cost_per_1k_input":      float(getattr(config_service, "LLM_COST_PER_1K_INPUT", 0.0) or 0.0),
        "cost_per_1k_output":     float(getattr(config_service, "LLM_COST_PER_1K_OUTPUT", 0.0) or 0.0),
    }
    redaction_cfg = {
        "redacted_findings": list(getattr(config_service, "REDACTED_FINDINGS", []) or []),
    }
    return jsonify({
        "tokens": tokens,
        "tools":  config_service.tools_list(),
        "mode":   config_service.mode,
        "multi_guild_search": config_service.multi_guild_search,
        "debug":  config_service.debug,
        "output_format":  config_service.output_format,
        "retention_days": config_service.retention_days,
        "pivot":  pivot_cfg,
        "llm":    llm_cfg,
        "enrichment": enrichment_cfg,
        "spend":  spend_cfg,
        "redaction": redaction_cfg,
    })


@app.route("/config", methods=["POST"])
def config_endpoint():
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({"success": False, "error": "body must be a JSON object"}), 400
    response_body, status = config_actions.dispatch(body)
    if response_body.get("success"):
        audit.write_event(
            "config_changed",
            action=body.get("action"),
        )
    return jsonify(response_body), status


# ---------------------------------------------------------------------------
# LLM model discovery
# ---------------------------------------------------------------------------

@app.route("/api/llm/models", methods=["GET"])
def api_llm_models():
    return jsonify(fetch_models_for_provider(config_service))


@app.route("/api/groq/models", methods=["GET"])
def api_groq_models():
    return jsonify(fetch_models_for_provider(config_service))


# ---------------------------------------------------------------------------
# OpenAPI spec
# ---------------------------------------------------------------------------

@app.route("/api/openapi.yaml", methods=["GET"])
def api_openapi():
    path = os.path.join(os.path.dirname(__file__), "docs", "openapi.yaml")
    if not os.path.isfile(path):
        return "OpenAPI spec not found", 404
    with open(path, "r", encoding="utf-8") as f:
        return Response(f.read(), mimetype="application/yaml")


# ---------------------------------------------------------------------------
# Contact-enrichment provider test
# ---------------------------------------------------------------------------

@app.route("/api/enrichment/test/<provider>", methods=["POST"])
def enrichment_test(provider: str):
    provider = (provider or "").strip().lower()

    if provider == "apollo":
        key = config_service.apollo_api_key
        if not key:
            return jsonify({
                "ok": False, "balance": None,
                "error": "No Apollo API key stored.",
            }), 400
        try:
            from discord_osint.enrichment.apollo_client import ApolloClient
            client = ApolloClient(key)
            result = client.test_connection()
            return jsonify(result)
        except Exception as exc:
            return jsonify({
                "ok": False, "balance": None, "error": str(exc),
            }), 500

    if provider == "lusha":
        key = config_service.lusha_api_key
        if not key:
            return jsonify({
                "ok": False, "balance": None,
                "error": "No Lusha API key stored.",
            }), 400
        try:
            from discord_osint.enrichment.lusha_client import LushaClient
            client = LushaClient(key)
            result = client.test_connection()
            return jsonify(result)
        except Exception as exc:
            return jsonify({
                "ok": False, "balance": None, "error": str(exc),
            }), 500

    return jsonify({
        "ok": False, "balance": None,
        "error": f"Unknown provider: {provider}",
    }), 404


# ---------------------------------------------------------------------------
# /run
# ---------------------------------------------------------------------------

@app.route("/run", methods=["POST"])
def run():
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    raw_mode = str(body.get("mode", "manual"))

    try:
        mode = validate_mode_extended(raw_mode)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    job_id       = str(uuid.uuid4())
    target_label = "unknown"
    # The *untruncated* sanitised target. target_label is a display
    # string (prefixed for discord, cut to 60 chars for url/image/probe),
    # so it cannot be used to derive the artifact filename key.
    intel_seed   = ""

    # Ad-hoc runs land in the unassigned bucket. Operators who want
    # grouping set case_id explicitly; we no longer auto-generate a
    # unique case per run, which cluttered /api/cases.
    case_id = _sanitize_case_id(str(body.get("case_id", "")))

    job_overrides: dict = {}

    try:
        if mode == "discord":
            user_id  = sanitize_user_id(str(body.get("user_id", "")))
            guild_raw = body.get("guild_id", "")
            guild_id = sanitize_user_id(str(guild_raw)) if guild_raw else ""
            job_overrides["MODE"] = "discord"
            job_overrides["TARGET_USER_ID"] = int(user_id)
            if guild_id:
                job_overrides["TARGET_GUILD_ID"] = int(guild_id)
            job_overrides["MULTI_GUILD_SEARCH"] = bool(body.get("multi_guild", False))
            target_label = f"discord:{user_id}"
            intel_seed   = user_id

        elif mode == "manual":
            username_raw = body.get("username", "")
            email_raw    = body.get("email", "")
            username = sanitize_username(str(username_raw)) if username_raw else ""
            email    = sanitize_email(str(email_raw))       if email_raw    else ""

            if not username and email:
                mode                         = "email"
                target_label                 = email
                intel_seed                   = email
                job_overrides["MODE"]         = "email"
                job_overrides["MANUAL_EMAIL"] = email
            else:
                job_overrides["MODE"]            = "manual"
                job_overrides["MANUAL_USERNAME"] = username
                job_overrides["MANUAL_EMAIL"]    = email
                target_label                     = username or email
                # run_osint_pipeline keys manual mode on MANUAL_USERNAME;
                # it only falls through to the email module when the
                # username is empty.
                intel_seed                       = username or email

        elif mode == "email":
            email = sanitize_email(str(body.get("target", body.get("email", ""))))
            if not email:
                return jsonify({"error": "email target is required"}), 400
            job_overrides["MANUAL_EMAIL"] = email
            job_overrides["MODE"]         = "email"
            target_label                  = email
            intel_seed                    = email

        elif mode == "domain":
            domain = sanitize_domain(str(body.get("target", body.get("domain", ""))))
            if not domain:
                return jsonify({"error": "domain target is required"}), 400
            job_overrides["MANUAL_DOMAIN"] = domain
            job_overrides["MODE"]          = "domain"
            target_label                   = domain
            intel_seed                     = domain

        elif mode == "phone":
            phone = _sanitize_phone(str(body.get("target", body.get("phone", ""))))
            if not phone:
                return jsonify({"error": "phone target is required"}), 400
            job_overrides["MANUAL_PHONE"] = phone
            job_overrides["MODE"]         = "phone"
            target_label                  = phone
            intel_seed                    = phone

        elif mode == "image":
            img_url = _sanitize_image_url(
                str(body.get("target", body.get("image_url", "")))
            )
            job_overrides["MANUAL_IMAGE_URL"] = img_url
            job_overrides["MODE"]             = "image"
            target_label                      = img_url[:60]
            intel_seed                        = img_url

        elif mode == "url":
            url_val = _sanitize_url(str(body.get("target", body.get("url", ""))))
            job_overrides["MANUAL_URL"] = url_val
            job_overrides["MODE"]       = "url"
            target_label                = url_val[:60]
            intel_seed                  = url_val

        elif mode == "probe":
            probe = _sanitize_probe(str(body.get("target", body.get("probe", ""))))
            if not probe:
                return jsonify({"error": "probe target is required"}), 400
            job_overrides["PROBE_STRING"] = probe
            job_overrides["MODE"]         = "probe"
            target_label                  = probe[:60]
            intel_seed                    = probe

    except Exception as exc:
        return jsonify({"error": f"Validation error: {exc}"}), 400

    cancel_event = threading.Event()
    job_registry.create(
        job_id=job_id,
        target=target_label,
        mode=mode,
        cancel_event=cancel_event,
        case_id=case_id,
        target_key=intel_target_key(mode, intel_seed),
    )
    job_registry.create_pivot_slot(job_id)

    input_rate  = float(getattr(config_service, "LLM_COST_PER_1K_INPUT", 0) or 0)
    output_rate = float(getattr(config_service, "LLM_COST_PER_1K_OUTPUT", 0) or 0)
    max_usd     = float(getattr(config_service, "MAX_LLM_SPEND_USD", 0) or 0)
    max_credits = float(getattr(config_service, "MAX_ENRICHMENT_CREDITS", 0) or 0)
    cost_acc = CostAccumulator(
        input_rate=input_rate,
        output_rate=output_rate,
        max_usd=max_usd,
        max_credits=max_credits,
    )
    job_registry.register_cost_accumulator(job_id, cost_acc)

    audit.write_event(
        "investigation_started",
        job_id=job_id,
        mode=mode,
        target=target_label,
        case_id=case_id,
    )

    def generate():
        event_queue: queue.Queue = queue.Queue()
        error_occurred = False

        def _on_emit(et: str, payload: dict) -> None:
            nonlocal error_occurred
            if et == "error":
                error_occurred = True

            if et == "third_party_contacted":
                fields = {k: v for k, v in payload.items() if k != "job_id"}
                try:
                    cost_acc.record_llm_call(
                        service=str(fields.get("service", "")),
                        model=str(fields.get("model", "")),
                        bytes_sent=int(fields.get("bytes_sent", 0) or 0),
                        bytes_received=int(fields.get("bytes_received", 0) or 0),
                        ok=bool(fields.get("ok", True)),
                    )
                except Exception:
                    pass
                audit.write_event("third_party_contacted",
                                  job_id=job_id, **fields)
            elif et == "finding" and isinstance(payload, dict):
                if payload.get("type") == "enrichment_complete":
                    providers = payload.get("providers") or []
                    try:
                        total_credits = float(payload.get("credits_consumed", 0) or 0)
                        matched = int(payload.get("matched", 0) or 0)
                        n = max(1, len(providers))
                        for p in (providers or ["unknown"]):
                            cost_acc.record_enrichment(
                                provider=str(p),
                                credits=total_credits / n,
                                matched=matched,
                            )
                    except Exception:
                        pass
            elif et == "report_ready":
                fmt  = payload.get("format", "")
                path = payload.get("path", "")
                try:
                    if path and os.path.isfile(path):
                        if fmt in ("html", "markdown", "json"):
                            job_registry.record_report(job_id, path, fmt)
                        elif fmt == "manifest":
                            job_registry.record_manifest(job_id, path)
                        elif fmt == "intel":
                            job_registry.record_intel(job_id, path)
                except Exception:
                    pass
            elif et == "done":
                intel_path = payload.get("intel_path", "")
                try:
                    if intel_path:
                        job_registry.record_intel(job_id, intel_path)
                except Exception:
                    pass

            event_queue.put({"type": et, "payload": payload})

        capture = _StdoutCapture(event_queue)
        emitter = EventEmitter(callback=_on_emit, also_print=False)

        def _confirm_fn(seeds, depth, stage_emit):
            slot = job_registry.get_pivot_slot(job_id)
            if slot is None:
                return []

            slot["event"].clear()
            slot["pending_seeds"] = [{"value": s, "type": t} for s, t in seeds]
            slot["approved"]      = None
            stage_emit("pivot_confirm_request", {
                "job_id": job_id, "depth": depth,
                "seeds": slot["pending_seeds"],
                "timeout_seconds": _PIVOT_CONFIRM_TIMEOUT,
            })

            deadline  = time.monotonic() + _PIVOT_CONFIRM_TIMEOUT
            responded = False
            while time.monotonic() < deadline:
                if cancel_event.is_set():
                    stage_emit("pivot_confirm_timeout", {
                        "job_id": job_id, "depth": depth,
                        "reason": "cancelled",
                    })
                    return []
                if slot["event"].wait(timeout=0.5):
                    responded = True
                    break

            if not responded or slot["approved"] is None:
                # Fail closed: an unanswered prompt runs zero seeds.
                stage_emit("pivot_confirm_timeout", {
                    "job_id": job_id, "depth": depth,
                    "reason": "timeout",
                })
                return []

            approved_values = {e["value"] for e in slot["approved"]}
            return [(s, t) for s, t in seeds if s in approved_values]

        require_confirm = bool(getattr(config_service, "PIVOT_REQUIRE_CONFIRM", False))
        active_confirm_fn = _confirm_fn if require_confirm else None

        yield to_sse_line("job_start", {
            "job_id": job_id, "target": target_label, "mode": mode,
            "case_id": case_id,
        })

        def _run():
            nonlocal error_occurred

            acquired = False
            try:
                if not _JOB_SEMAPHORE.acquire(timeout=5):
                    error_occurred = True
                    event_queue.put({
                        "type": "error",
                        "payload": {
                            "message": (
                                f"server at capacity ({_MAX_CONCURRENT_JOBS} "
                                f"investigation(s) running); retry shortly or "
                                f"stop an existing job"
                            ),
                        },
                    })
                    return
                acquired = True

                _STDOUT_ROUTER.set_capture(capture)

                base = config_service.to_dict()
                base.update(job_overrides)
                job_config = JobConfig(base)
                job_config._cancel_event      = cancel_event
                job_config._phase3_emit       = emitter
                job_config._pivot_confirm_fn  = active_confirm_fn
                job_config._job_id            = job_id
                job_config._case_id           = case_id
                job_config._cost_accumulator  = cost_acc

                token = set_active_config(job_config)
                try:
                    if mode in _MODULE_MODES:
                        from discord_osint.pipeline import run_module_pipeline
                        run_module_pipeline(mode, job_config)
                    else:
                        from discord_osint.pipeline import run_osint_pipeline
                        run_osint_pipeline(job_config)
                except Exception as exc:
                    import traceback as _tb
                    _tb.print_exc()
                    error_occurred = True
                    event_queue.put({"type": "error",
                                     "payload": {"message": str(exc)}})
                finally:
                    _STDOUT_ROUTER.clear_capture()
                    reset_active_config(token)
            finally:
                if acquired:
                    _JOB_SEMAPHORE.release()

                if error_occurred:
                    final_status = "error"
                elif cancel_event.is_set():
                    final_status = "cancelled"
                else:
                    final_status = "done"

                try:
                    job_registry.mark_status(job_id, final_status)
                    audit.write_event(
                        "investigation_finished",
                        job_id=job_id,
                        status=final_status,
                    )
                except Exception:
                    pass
                finally:
                    try:
                        job_registry.teardown(job_id)
                    except Exception:
                        pass

                event_queue.put({"type": "__final__",
                                 "payload": {"status": final_status}})
                event_queue.put(None)

        worker = threading.Thread(target=_run, daemon=True)
        job_registry.register_worker(job_id, worker)
        worker.start()

        final_status = "done"
        while True:
            try:
                item = event_queue.get(timeout=60)
            except queue.Empty:
                yield to_sse_line("heartbeat", {
                    "ts": datetime.now(timezone.utc).isoformat(),
                })
                continue
            if item is None:
                break
            et, payload = item["type"], item["payload"]
            if et == "__final__":
                final_status = payload.get("status", "done")
                continue
            yield to_sse_line(et, payload)

        yield to_sse_line("stream_end", {
            "job_id":     job_id,
            "status":     final_status,
            "report_url": f"/api/investigations/{job_id}/report",
        })

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# /api/batch
# ---------------------------------------------------------------------------

@app.route("/api/batch", methods=["POST"])
def api_batch_start():
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    raw_targets = body.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        return jsonify({"error": "targets must be a non-empty list"}), 400

    if len(raw_targets) > 500:
        return jsonify({"error": "batch size capped at 500 targets"}), 400

    raw_mode = str(body.get("mode", "manual"))
    try:
        mode = validate_mode_extended(raw_mode)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if mode == "discord":
        return jsonify({
            "error": "batch mode does not support discord",
            "hint":  "run discord investigations one at a time via /run",
        }), 400

    case_id = _sanitize_case_id(str(body.get("case_id", "")))
    if not case_id:
        case_id = f"batch_{uuid.uuid4().hex[:12]}"

    max_workers = body.get("max_workers")
    try:
        max_workers = max(1, min(10, int(max_workers))) if max_workers is not None else 3
    except (TypeError, ValueError):
        max_workers = 3

    targets = [str(t) for t in raw_targets if isinstance(t, (str, int, float))]

    summary = batch_runner.start(
        targets=targets,
        mode=mode,
        case_id=case_id,
        max_workers=max_workers,
    )

    audit.write_event(
        "batch_started",
        batch_id=summary["batch_id"],
        case_id=case_id,
        mode=mode,
        targets_queued=summary["targets_queued"],
    )

    return jsonify(summary)


@app.route("/api/batch", methods=["GET"])
def api_batch_list():
    return jsonify(batch_runner.list_batches())


@app.route("/api/batch/<batch_id>", methods=["GET"])
def api_batch_detail(batch_id: str):
    batch = batch_runner.get_batch(batch_id)
    if not batch:
        return jsonify({"error": "batch not found"}), 404

    jobs = []
    for jid in batch.get("job_ids", []):
        job = job_registry.get(jid)
        if job:
            jobs.append({
                "job_id":      jid,
                "target":      job.get("target", ""),
                "status":      job.get("status", ""),
                "has_report":  bool(job.get("report_path") and os.path.isfile(job["report_path"])),
                "has_intel":   bool(job.get("intel_path")  and os.path.isfile(job["intel_path"])),
            })
        else:
            jobs.append({
                "job_id": jid, "target": "", "status": "unknown",
                "has_report": False, "has_intel": False,
            })

    return jsonify({
        "batch_id":  batch_id,
        "case_id":   batch.get("case_id", ""),
        "mode":      batch.get("mode", ""),
        "job_count": len(batch.get("job_ids", [])),
        "jobs":      jobs,
    })


# ---------------------------------------------------------------------------
# /stop
# ---------------------------------------------------------------------------

@app.route("/stop", methods=["POST"])
def stop():
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({"success": False, "error": "body must be a JSON object"}), 400

    job_id = (body.get("job_id") or "").strip() or None

    if job_id:
        job = job_registry.get(job_id)
        if not job:
            return jsonify({"success": False, "error": "job not found"}), 404
        if job.get("status") != "running":
            return jsonify({
                "success": False,
                "error": f"job is not running (status={job.get('status')})",
            }), 409
    else:
        running = job_registry.list_running()
        if not running:
            return jsonify({"success": False, "error": "no running investigation"}), 404
        running.sort(key=lambda j: j.get("started_at", ""), reverse=True)
        job_id = running[0]["id"]

    if not job_registry.signal_cancel(job_id):
        return jsonify({
            "success": False,
            "error": "cancel token missing for job",
        }), 500

    slot = job_registry.get_pivot_slot(job_id)
    if slot is not None:
        slot["event"].set()

    audit.write_event("investigation_stopped", job_id=job_id)

    return jsonify({"success": True, "job_id": job_id})


# ---------------------------------------------------------------------------
# AI Chat
# ---------------------------------------------------------------------------

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    base_url, api_key, extra_headers = get_llm_endpoint(config_service)

    if not api_key:
        provider_label = (
            "GROQ_API_KEY" if config_service.llm_provider == "groq"
            else "OPENROUTER_API_KEY" if config_service.llm_provider == "openrouter"
            else "OLLAMA"
        )
        return jsonify({"error": f"{provider_label} not configured"}), 503

    body = request.get_json(force=True, silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    message  = str(body.get("message", "")).strip()
    map_data = body.get("map", {}) or {}
    job_id   = (body.get("job_id") or map_data.get("jobId") or "").strip() or None

    if not message:
        return jsonify({"error": "message is required"}), 400

    intel_path = None
    if job_id:
        job = job_registry.get(job_id)
        if job:
            intel_path = job_registry.find_intel_path(job)

    # Enforce the spend cap *before* issuing the call. Every other LLM
    # call site checks CostAccumulator.exceeded() at a checkpoint
    # (pipeline/base.py, reporting.py, reporting_stage.py); this route
    # only ever recorded its spend afterwards, so once a run hit
    # MAX_LLM_SPEND_USD the operator could keep chatting against the
    # same job indefinitely and the cap silently stopped meaning
    # anything. Checking here keeps the overshoot bounded to one call,
    # which is the same guarantee the pipeline makes.
    if job_id:
        _acc = job_registry.get_cost_accumulator(job_id)
        if _acc is not None:
            try:
                _over, _reason = _acc.exceeded()
            except Exception:
                _over, _reason = False, ""
            if _over:
                audit.write_event(
                    "llm_call_blocked",
                    job_id=job_id,
                    channel="chat",
                    reason=_reason or "spend cap reached",
                )
                return jsonify({
                    "error":  "LLM spend cap reached for this investigation",
                    "reason": _reason or "spend cap reached",
                }), 402

    user_content = build_chat_context(
        message=message,
        map_data=map_data,
        job_id=job_id,
        intel_path=intel_path,
        config_service=config_service,
    )
    system_prompt = active_chat_system_prompt(config_service)
    model         = config_service.llm_model
    temperature   = config_service.llm_temperature
    max_tokens    = min(config_service.llm_max_tokens, 4096)

    chat_url = f"{base_url}/chat/completions"

    def generate():
        import requests as _req

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
            **extra_headers,
        }
        payload = {
            "model":       model,
            "temperature": temperature,
            "max_tokens":  max_tokens,
            "stream":      True,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_content},
            ],
        }

        try:
            bytes_sent = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        except Exception:
            bytes_sent = 0

        bytes_received = 0
        status_code    = 0
        ok             = False

        try:
            with _req.post(chat_url, headers=headers, json=payload,
                           stream=True, timeout=120) as resp:
                status_code = resp.status_code
                ok          = status_code == 200

                if status_code != 200:
                    err = resp.text[:300]
                    bytes_received = len(err.encode("utf-8"))
                    yield f"data: {json.dumps({'token': f'[LLM {status_code}: {err}]'})}\n\n"
                    return

                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue
                    line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
                    bytes_received += len(line.encode("utf-8"))
                    if not line.startswith("data:"):
                        continue
                    chunk = line[5:].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        delta = json.loads(chunk)
                        token = (
                            delta.get("choices", [{}])[0]
                            .get("delta", {})
                            .get("content", "")
                        )
                        if token:
                            yield f"data: {json.dumps({'token': token})}\n\n"
                    except (json.JSONDecodeError, IndexError, KeyError):
                        pass
        except Exception as exc:
            yield f"data: {json.dumps({'token': f'[Stream error: {exc}]'})}\n\n"
        finally:
            # Audit every chat call, including failures. The intel dump
            # was sent to the provider regardless of the outcome.
            try:
                audit.write_event(
                    "third_party_contacted",
                    service=config_service.llm_provider,
                    endpoint="chat/completions",
                    model=model,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                    status=status_code,
                    ok=ok,
                    channel="chat",
                    job_id=job_id or "",
                )
            except Exception:
                pass

            if job_id:
                acc = job_registry.get_cost_accumulator(job_id)
                if acc is not None:
                    try:
                        acc.record_llm_call(
                            service=config_service.llm_provider,
                            model=model,
                            bytes_sent=bytes_sent,
                            bytes_received=bytes_received,
                            ok=ok,
                        )
                    except Exception:
                        pass

            yield "data: [DONE]\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Pivot confirmation
# ---------------------------------------------------------------------------

@app.route("/api/pivot/confirm/<job_id>", methods=["POST"])
def pivot_confirm(job_id: str):
    data = request.get_json(force=True, silent=True)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "body must be a JSON object"}), 400

    approved = data.get("approved_seeds", [])
    if not isinstance(approved, list):
        return jsonify({"success": False, "error": "approved_seeds must be a list"}), 400

    if not job_registry.respond_to_pivot(job_id, approved):
        return jsonify({"success": False, "error": "no pending pivot"}), 404
    return jsonify({"success": True, "approved_count": len(approved)})


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

@app.route("/report")
def report_legacy():
    """
    Legacy route: serve the most recently completed job's report.

    Previously this read a module-global ``REPORT_HTML`` that the /run
    generator overwrote on every report_ready event. Under concurrency
    that served whichever job finished last rather than the one the
    caller wanted. The registry-based route below is the correct one;
    this is a compatibility alias.
    """
    jobs = [j for j in job_registry.list_all()
            if j.get("report_path") and os.path.isfile(j["report_path"])]
    if not jobs:
        return "No report available.", 404
    jobs.sort(key=lambda j: j.get("started_at", ""), reverse=True)
    path = jobs[0]["report_path"]
    fmt = jobs[0].get("report_format", "html")
    with open(path, encoding="utf-8") as f:
        body = f.read()
    content_type = {
        "html":     "text/html; charset=utf-8",
        "markdown": "text/markdown; charset=utf-8",
        "json":     "application/json",
    }.get(fmt, "text/plain")
    return body, 200, {"Content-Type": content_type}


def _serialise_job(j: dict, *, include_manifest: bool = True) -> dict:
    report_path = j.get("report_path") or j.get("report_html")
    row = {
        "id":         j["id"],
        "target":     j.get("target", ""),
        "mode":       j.get("mode", ""),
        "case_id":    j.get("case_id", ""),
        "started_at": j.get("started_at", ""),
        "status":     j.get("status", ""),
        "has_report": bool(report_path and os.path.isfile(report_path)),
        "has_intel":  bool(j.get("intel_path") and os.path.isfile(j["intel_path"])),
    }
    if include_manifest:
        row["has_manifest"] = bool(
            j.get("manifest_path") and os.path.isfile(j["manifest_path"])
        )
    return row


@app.route("/api/investigations", methods=["GET"])
def api_investigations():
    case_filter = request.args.get("case_id")
    limit, offset = _parse_page_args()

    jobs = job_registry.list_all(
        case_id=case_filter, limit=limit, offset=offset,
    )
    total = job_registry.count_all(case_id=case_filter)

    return jsonify({
        "jobs":   [_serialise_job(j) for j in jobs],
        "total":  total,
        "limit":  limit,
        "offset": offset,
    })


@app.route("/api/investigations/<job_id>", methods=["GET"])
def api_investigation_detail(job_id: str):
    job = job_registry.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    _audit_case_read(job, "intel")
    intel_path = job_registry.find_intel_path(job)
    if not intel_path:
        return jsonify({"error": "no intel snapshot found"}), 404
    with open(intel_path, encoding="utf-8") as f:
        return jsonify(json.load(f))


_REPORT_CSP = (
    "sandbox allow-scripts allow-popups; "
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; "
    "img-src data: https:; "
    "font-src data:; "
    "base-uri 'none'; "
    "form-action 'none';"
)


@app.route("/api/investigations/<job_id>/report", methods=["GET"])
def api_investigation_report(job_id: str):
    job = job_registry.get(job_id)
    if not job:
        return "Investigation not found", 404
    _audit_case_read(job, "report")

    path = job.get("report_path") or job.get("report_html")
    if not path or not os.path.isfile(path):
        return "Report not yet available", 404

    fmt = job.get("report_format", "html")

    # Optional per-request redaction. The ?redact= override re-renders
    # the HTML from the intel snapshot with the named finding types
    # stripped. Falls back to serving the on-disk report unchanged if
    # any step fails, so a bad redact param cannot break the report.
    redact_param = request.args.get("redact", "")
    if fmt == "html" and redact_param:
        try:
            from discord_osint.intelligence.html_report import (
                generate_html_report, _apply_redaction,
            )
            intel_path = job_registry.find_intel_path(job)
            if intel_path and os.path.isfile(intel_path):
                with open(intel_path, encoding="utf-8") as f:
                    intel = json.load(f)
                redacted = {t.strip() for t in redact_param.split(",") if t.strip()}
                body = generate_html_report(
                    intel, job.get("target", ""),
                    redacted_types=frozenset(redacted),
                )
                return body, 200, {
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": _REPORT_CSP,
                }
        except Exception:
            pass  # fall through to the on-disk report

    with open(path, encoding="utf-8") as f:
        body = f.read()

    content_type = {
        "html":     "text/html; charset=utf-8",
        "markdown": "text/markdown; charset=utf-8",
        "json":     "application/json",
    }.get(fmt, "text/plain")

    headers = {"Content-Type": content_type}
    if fmt == "html":
        headers["Content-Security-Policy"] = _REPORT_CSP
    return body, 200, headers


@app.route("/api/investigations/<job_id>/cost", methods=["GET"])
def api_investigation_cost(job_id: str):
    job = job_registry.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    # Deliberately not audited: the UI polls this every 3 s.
    snapshot = job_registry.get_cost_snapshot(job_id)
    if snapshot is None:
        return jsonify({
            "job_id": job_id,
            "available": False,
            "reason": "no cost accumulator for this job",
        })
    return jsonify({
        "job_id": job_id,
        "available": True,
        **snapshot,
    })


@app.route("/api/investigations/<job_id>/disclosures", methods=["GET"])
def api_investigation_disclosures(job_id: str):
    """
    Return every third-party disclosure recorded for this job.

    Answers the operational question "what did this run send to whom"
    from the audit log, grouped by service.
    """
    job = job_registry.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404

    _audit_case_read(job, "disclosures")

    entries = audit.read_for_job(job_id, limit=10000)
    relevant = [e for e in entries if e.get("event") == "third_party_contacted"]

    by_service: dict[str, dict] = {}
    for e in relevant:
        svc = e.get("service") or "unknown"
        slot = by_service.setdefault(svc, {
            "service": svc,
            "calls": 0,
            "ok_calls": 0,
            "failed_calls": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "endpoints": set(),
            "models": set(),
            "channels": set(),
        })
        slot["calls"] += 1
        if e.get("ok"):
            slot["ok_calls"] += 1
        else:
            slot["failed_calls"] += 1
        slot["bytes_sent"]     += int(e.get("bytes_sent", 0) or 0)
        slot["bytes_received"] += int(e.get("bytes_received", 0) or 0)
        if e.get("endpoint"):
            slot["endpoints"].add(str(e["endpoint"]))
        if e.get("model"):
            slot["models"].add(str(e["model"]))
        if e.get("channel"):
            slot["channels"].add(str(e["channel"]))

    services = []
    for slot in by_service.values():
        slot["endpoints"] = sorted(slot["endpoints"])
        slot["models"]    = sorted(slot["models"])
        slot["channels"]  = sorted(slot["channels"])
        services.append(slot)
    services.sort(key=lambda s: s["calls"], reverse=True)

    return jsonify({
        "job_id":       job_id,
        "target":       job.get("target", ""),
        "total_calls":  len(relevant),
        "services":     services,
    })


@app.route("/api/investigations/<job_id>", methods=["DELETE"])
def api_investigation_delete(job_id: str):
    job = job_registry.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    if job.get("status") == "running":
        return jsonify({
            "error": "job is running; stop it before deleting",
        }), 409

    audit.write_event(
        "investigation_deleted",
        job_id=job_id,
        target=job.get("target", ""),
        case_id=job.get("case_id", ""),
        reason="operator",
    )

    ok, files, err = job_registry.delete_job(job_id, secure=True)
    if not ok:
        return jsonify({"error": err}), 500

    return jsonify({
        "success": True,
        "job_id":  job_id,
        "files_removed": files,
    })


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@app.route("/api/cases", methods=["GET"])
def api_cases_list():
    return jsonify(job_registry.list_cases())


@app.route("/api/cases/<case_id>", methods=["GET"])
def api_cases_detail(case_id: str):
    limit, offset = _parse_page_args()

    jobs = job_registry.list_all(case_id=case_id, limit=limit, offset=offset)
    total = job_registry.count_all(case_id=case_id)

    if total == 0:
        return jsonify({"error": "case not found"}), 404

    all_jobs = job_registry.list_all(case_id=case_id)
    all_jobs.sort(key=lambda j: j.get("started_at", ""))

    return jsonify({
        "case": {
            "case_id":       case_id,
            "job_count":     total,
            "first_started": all_jobs[0].get("started_at", ""),
            "last_started":  all_jobs[-1].get("started_at", ""),
            "targets":       [j.get("target", "") for j in all_jobs],
        },
        "jobs":   [_serialise_job(j, include_manifest=False) for j in jobs],
        "total":  total,
        "limit":  limit,
        "offset": offset,
    })


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@app.route("/api/audit", methods=["GET"])
def api_audit_list():
    try:
        limit = int(request.args.get("limit", "100"))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 1000))
    entries = audit.read_recent(limit=limit)
    return jsonify({"count": len(entries), "entries": entries})


@app.route("/api/audit/verify", methods=["GET"])
def api_audit_verify():
    valid, bad = audit.verify_log()
    return jsonify({
        "status":         "ok" if not bad else "tampered",
        "valid_entries":  valid,
        "tampered_lines": bad,
        "total_lines":    valid + len(bad),
    })


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

@app.route("/api/retention/run", methods=["POST"])
def api_retention_run():
    summary = retention.run_pass()
    return jsonify(summary)


# ---------------------------------------------------------------------------
# Upgrade / shutdown
# ---------------------------------------------------------------------------

@app.route("/upgrade_tools", methods=["POST"])
def upgrade_route():
    def generate():
        q: queue.Queue = queue.Queue()
        def _cb(msg): q.put(msg)
        def _run():
            try:
                upgrade_tools(interactive=False, log_callback=_cb)
            except Exception as exc:
                q.put(f"Error: {exc}")
            q.put(None)
        threading.Thread(target=_run, daemon=True).start()
        while True:
            msg = q.get()
            if msg is None:
                yield to_sse_line("done", {"message": "Upgrade completed."})
                break
            yield to_sse_line("log", {"line": str(msg)})
    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/shutdown", methods=["POST"])
def shutdown():
    data = request.get_json(silent=True)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    if data.get("confirm") != "yes":
        return jsonify({
            "error": "confirmation required",
            "hint":  "POST with {\"confirm\": \"yes\"} to shut down",
        }), 400
    audit.write_event("shutdown_requested")
    retention.stop()
    try:
        batch_runner.shutdown(wait=False)
    except Exception:
        pass
    threading.Timer(0.5, os._exit, args=(0,)).start()
    return jsonify({"success": True, "message": "shutting down"})


if __name__ == "__main__":
    sys.path.insert(0, os.getcwd())
    # threaded=True is not optional. /run and /api/ai/chat are
    # long-lived SSE streams; with the default single-threaded dev
    # server, /stop cannot be served while a job is running. For
    # anything beyond a demo, run behind waitress instead:
    #   waitress-serve --threads=8 --listen=127.0.0.1:5000 web_app:app
    app.run(debug=False, host="127.0.0.1", port=5000, threaded=True)