"""
Flask web application – WhoCord Canvas.

Changes in this revision
------------------------
- LLM provider is now selectable: ``LLM_PROVIDER`` config key accepts
  ``"groq"`` (default) or ``"openrouter"``.
- ``/api/llm/models`` replaces ``/api/groq/models``.
- ``_build_chat_context()`` splits the intel budget between canvas and
  intel dumps.
- Contact-enrichment: two new token keys (APOLLO_API_KEY, LUSHA_API_KEY)
  flow through the existing ``set_token`` action; ``set_enrichment``
  persists the enrichment cap and phone-reveal toggle; the new
  ``/api/enrichment/test/<provider>`` endpoint validates a stored key
  without spending a credit.
"""

from __future__ import annotations

import glob
import json
import os
import queue
import re
import sys
import threading
import uuid
from datetime import datetime

from flask import (
    Flask, Response, jsonify, render_template,
    request, send_from_directory, stream_with_context,
)

from discord_osint.config_service import ConfigService, get_llm_endpoint
from discord_osint.pipeline.events import EventEmitter, to_sse_line
from discord_osint.utils import CACHE_DIR, upgrade_tools
from discord_osint.utils.sanitizers import (
    sanitize_email,
    sanitize_user_id,
    sanitize_username,
    sanitize_domain,
)

app            = Flask(__name__)
config_service = ConfigService()

_MODULE_MODES = frozenset({"email", "domain", "phone", "image", "url", "probe"})
_ALL_MODES    = frozenset({"manual", "discord"}) | _MODULE_MODES

_ENRICHMENT_TOKEN_KEYS = ("APOLLO_API_KEY", "LUSHA_API_KEY")


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
        if self._buf.strip():
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
# Job registry
# ---------------------------------------------------------------------------

_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()

_CANCEL_EVENTS: dict[str, threading.Event] = {}
_WORKER_THREADS: dict[str, threading.Thread] = {}

REPORT_HTML: str | None = None

_PIVOT_RESPONSES: dict[str, dict] = {}
_PIVOT_LOCK            = threading.Lock()
_PIVOT_CONFIRM_TIMEOUT = 45

_REPORT_FILE_RE = re.compile(r"^report_(.+)_(\d{8}_\d{6})\.html$")


def _scan_existing_jobs() -> None:
    html_files = sorted(
        glob.glob(os.path.join(CACHE_DIR, "report_*.html")),
        key=os.path.getmtime,
    )
    for html_path in html_files:
        base = os.path.basename(html_path)
        m = _REPORT_FILE_RE.match(base)
        if not m:
            continue
        target_id = m.group(1)
        ts_str    = m.group(2)
        job_id    = str(uuid.uuid5(uuid.NAMESPACE_URL, html_path))
        intel_files = sorted(
            glob.glob(os.path.join(CACHE_DIR, f"intel_{target_id}_*.json")),
            key=os.path.getmtime,
        )
        intel_path = intel_files[-1] if intel_files else None
        try:
            started_at = datetime.strptime(ts_str, "%Y%m%d_%H%M%S").isoformat()
        except ValueError:
            started_at = datetime.fromtimestamp(os.path.getmtime(html_path)).isoformat()
        with _JOBS_LOCK:
            _JOBS[job_id] = {
                "id": job_id, "target": target_id, "mode": "unknown",
                "started_at": started_at, "status": "done",
                "report_html": html_path, "intel_path": intel_path,
            }


_scan_existing_jobs()


# ---------------------------------------------------------------------------
# SPA serving
# ---------------------------------------------------------------------------

_FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "frontend", "dist")


def _react_built() -> bool:
    return os.path.isdir(_FRONTEND_DIST) and os.path.isfile(
        os.path.join(_FRONTEND_DIST, "index.html")
    )


@app.route("/")
def index():
    if _react_built():
        return send_from_directory(_FRONTEND_DIST, "index.html")
    return render_template("index.html")


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
        return send_from_directory(_FRONTEND_DIST, "index.html")
    return render_template("index.html")


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
    s = raw.strip()
    if not s.startswith("http"):
        raise ValueError("URL must start with http:// or https://")
    return s[:2048]


def _sanitize_image_url(raw: str) -> str:
    return _sanitize_url(raw)


def _sanitize_probe(raw: str) -> str:
    return raw.strip()[:512]


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
    return jsonify({
        "tokens": tokens,
        "tools":  config_service.tools_list(),
        "mode":   config_service.mode,
        "multi_guild_search": config_service.multi_guild_search,
        "debug":  config_service.debug,
        "pivot":  pivot_cfg,
        "llm":    llm_cfg,
        "enrichment": enrichment_cfg,
    })


def _apply_pivot_nested(pivot: dict) -> None:
    setattr(config_service, "ENABLE_PIVOTING",
            bool(pivot.get("enabled",        False)))
    setattr(config_service, "PIVOT_EMAIL",
            bool(pivot.get("pivot_email",     True)))
    setattr(config_service, "PIVOT_USERNAME",
            bool(pivot.get("pivot_username",  True)))
    setattr(config_service, "PIVOT_MAX_DEPTH",
            int( pivot.get("max_depth",       3)))
    setattr(config_service, "PIVOT_MAX_SEEDS",
            int( pivot.get("max_seeds",       5)))
    setattr(config_service, "PIVOT_REQUIRE_CONFIRM",
            bool(pivot.get("require_confirm", False)))


def _apply_pivot_flat(data: dict) -> None:
    nested = {
        "enabled":         data.get("ENABLE_PIVOTING",       False),
        "pivot_email":     data.get("PIVOT_EMAIL",           True),
        "pivot_username":  data.get("PIVOT_USERNAME",        True),
        "max_depth":       data.get("PIVOT_MAX_DEPTH",       3),
        "max_seeds":       data.get("PIVOT_MAX_SEEDS",       5),
        "require_confirm": data.get("PIVOT_REQUIRE_CONFIRM", False),
    }
    _apply_pivot_nested(nested)


@app.route("/config", methods=["POST"])
def config_endpoint():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "no data"})

    action = data.get("action")

    if action == "set_token":
        key = data.get("key")
        if key in ("DISCORD_TOKEN", "GITHUB_TOKEN", "GROQ_API_KEY",
                   "OPENROUTER_API_KEY", "INSTAGRAM_SESSION", "HIBP_API_KEY",
                   "APOLLO_API_KEY", "LUSHA_API_KEY"):
            config_service.set_sensitive(key, data.get("value", ""))
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "invalid key"})

    if action == "toggle_tool":
        config_service.set_tool(data.get("key"), bool(data.get("enable", True)))
        return jsonify({"success": True})

    if action == "set_mode":
        config_service.mode = data.get("mode", "manual")
        config_service.save()
        return jsonify({"success": True})

    if action == "set_multi_guild":
        config_service.multi_guild_search = bool(data.get("multi", False))
        config_service.save()
        return jsonify({"success": True})

    if action == "toggle_debug":
        config_service.debug = not config_service.debug
        config_service.save()
        return jsonify({"success": True, "debug": config_service.debug})

    if action == "set_pivot":
        _apply_pivot_nested(data.get("pivot", {}) or {})
        try:
            config_service.save()
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)})
        return jsonify({"success": True})

    if action == "set_pivot_config":
        _apply_pivot_flat(data)
        try:
            config_service.save()
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)})
        return jsonify({"success": True})

    if action == "set_enrichment":
        enr = data.get("enrichment", {}) or {}
        if "max_identifiers" in enr:
            try:
                config_service.enrichment_max_identifiers = int(enr["max_identifiers"])
            except (TypeError, ValueError):
                pass
        if "phone_reveal" in enr:
            config_service.enrichment_phone_reveal = bool(enr["phone_reveal"])
        try:
            config_service.save()
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)})
        return jsonify({"success": True})

    if action == "set_llm":
        llm = data.get("llm", {}) or {}
        if "provider" in llm:
            config_service.llm_provider = str(llm["provider"])
        if "model" in llm:
            config_service.llm_model = str(llm["model"]).strip()
        if "temperature" in llm:
            config_service.llm_temperature = float(llm["temperature"])
        if "max_tokens" in llm:
            config_service.llm_max_tokens = int(llm["max_tokens"])
        if "system_prompt" in llm:
            config_service.llm_system_prompt = str(llm["system_prompt"])
        if "intel_budget" in llm:
            config_service.llm_intel_budget = int(llm["intel_budget"])
        if "intel_include_raw" in llm:
            config_service.llm_intel_include_raw = bool(llm["intel_include_raw"])
        if "intel_exclude_meta" in llm:
            config_service.llm_intel_exclude_meta = bool(llm["intel_exclude_meta"])
        try:
            config_service.save()
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)})
        return jsonify({"success": True})

    return jsonify({"success": False, "error": "unknown action"})


# ---------------------------------------------------------------------------
# LLM model discovery
# ---------------------------------------------------------------------------

_GROQ_FALLBACK_MODELS = [
    {"id": "llama-3.1-8b-instant",                             "owned_by": "groq", "free": True},
    {"id": "llama-3.3-70b-versatile",                          "owned_by": "groq", "free": True},
    {"id": "meta-llama/llama-4-maverick-17b-128e-instruct",    "owned_by": "groq", "free": True},
    {"id": "meta-llama/llama-4-scout-17b-16e-instruct",        "owned_by": "groq", "free": True},
    {"id": "openai/gpt-oss-120b",                              "owned_by": "groq", "free": True},
    {"id": "openai/gpt-oss-20b",                               "owned_by": "groq", "free": True},
    {"id": "qwen/qwen3-32b",                                   "owned_by": "groq", "free": True},
    {"id": "moonshotai/kimi-k2-instruct",                      "owned_by": "groq", "free": True},
    {"id": "gemma2-9b-it",                                     "owned_by": "groq", "free": True},
    {"id": "groq/compound",                                    "owned_by": "groq", "free": True},
    {"id": "groq/compound-mini",                               "owned_by": "groq", "free": True},
]

_OPENROUTER_FALLBACK_MODELS = [
    {"id": "deepseek/deepseek-chat-v3.1:free",              "owned_by": "deepseek", "free": True},
    {"id": "deepseek/deepseek-r1:free",                     "owned_by": "deepseek", "free": True},
    {"id": "google/gemini-2.0-flash-exp:free",              "owned_by": "google",   "free": True},
    {"id": "qwen/qwen3-coder:free",                         "owned_by": "qwen",     "free": True},
    {"id": "meta-llama/llama-3.3-70b-instruct:free",        "owned_by": "meta",     "free": True},
    {"id": "mistralai/mistral-7b-instruct:free",            "owned_by": "mistral",  "free": True},
]

_OPENROUTER_CURATED_PAID = {
    "openai/gpt-4o-mini",
    "openai/gpt-4o",
    "anthropic/claude-3.5-sonnet",
    "google/gemini-2.0-flash-001",
    "deepseek/deepseek-chat",
}


def _fetch_models_for_provider() -> dict:
    import requests as _req

    provider = config_service.llm_provider

    if provider == "openrouter":
        key = config_service.openrouter_api_key or ""
        headers = {"Accept": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"

        try:
            resp = _req.get(
                "https://openrouter.ai/api/v1/models",
                headers=headers, timeout=12,
            )
            if resp.status_code != 200:
                return {
                    "models": _OPENROUTER_FALLBACK_MODELS,
                    "source": "fallback",
                    "reason": f"OpenRouter returned HTTP {resp.status_code}",
                }

            payload = resp.json()
            raw     = payload.get("data", []) or []

            models: list[dict] = []
            for m in raw:
                if not isinstance(m, dict):
                    continue
                mid = m.get("id", "")
                if not mid:
                    continue
                pricing = m.get("pricing") or {}
                is_free = (
                    mid.endswith(":free")
                    or (str(pricing.get("prompt", "")) in ("0", "0.0")
                        and str(pricing.get("completion", "")) in ("0", "0.0"))
                )
                if not is_free and mid not in _OPENROUTER_CURATED_PAID:
                    continue
                models.append({
                    "id":       mid,
                    "owned_by": mid.split("/")[0] if "/" in mid else "openrouter",
                    "free":     is_free,
                })

            models.sort(key=lambda m: (not m["free"], m["id"]))
            return {"models": models, "source": "live"}

        except Exception as exc:
            return {
                "models": _OPENROUTER_FALLBACK_MODELS,
                "source": "fallback",
                "reason": str(exc),
            }

    key = config_service.groq_api_key or ""
    if not key:
        return {
            "models": _GROQ_FALLBACK_MODELS,
            "source": "fallback",
            "reason": "GROQ_API_KEY not configured",
        }

    try:
        resp = _req.get(
            "https://api.groq.com/openai/v1/models",
            headers={
                "Authorization": f"Bearer {key}",
                "Accept":        "application/json",
            },
            timeout=10,
        )
        if resp.status_code != 200:
            return {
                "models": _GROQ_FALLBACK_MODELS,
                "source": "fallback",
                "reason": f"Groq returned HTTP {resp.status_code}",
            }

        payload = resp.json()
        raw     = payload.get("data", []) or []
        models = [
            {
                "id":       m.get("id", ""),
                "owned_by": m.get("owned_by", "groq"),
                "free":     True,
            }
            for m in raw
            if isinstance(m, dict) and m.get("id")
        ]
        models.sort(key=lambda m: m["id"])
        return {"models": models, "source": "live"}

    except Exception as exc:
        return {
            "models": _GROQ_FALLBACK_MODELS,
            "source": "fallback",
            "reason": str(exc),
        }


@app.route("/api/llm/models", methods=["GET"])
def api_llm_models():
    return jsonify(_fetch_models_for_provider())


@app.route("/api/groq/models", methods=["GET"])
def api_groq_models():
    return jsonify(_fetch_models_for_provider())


# ---------------------------------------------------------------------------
# Contact-enrichment provider test
# ---------------------------------------------------------------------------

@app.route("/api/enrichment/test/<provider>", methods=["POST"])
def enrichment_test(provider: str):
    """
    Validate that the stored key works and, when the provider exposes it,
    report the remaining credit balance. Never spends a credit — both
    providers offer a 0-cost account/profile endpoint.
    """
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
# /run – SSE investigation endpoint
# ---------------------------------------------------------------------------

@app.route("/run", methods=["GET"])
def run():
    global REPORT_HTML

    raw_mode = request.args.get("mode", "manual")
    try:
        mode = validate_mode_extended(raw_mode)
    except ValueError as exc:
        return str(exc), 400

    job_id       = str(uuid.uuid4())
    target_label = "unknown"

    try:
        if mode == "discord":
            user_id  = sanitize_user_id(request.args.get("user_id", ""))
            guild_id = (sanitize_user_id(request.args.get("guild_id", ""))
                        if request.args.get("guild_id") else "")
            config_service.mode            = "discord"
            config_service.target_user_id  = int(user_id)
            if guild_id:
                config_service.target_guild_id = int(guild_id)
            config_service.multi_guild_search = (request.args.get("multi_guild", "0") == "1")
            config_service.save()
            target_label = f"discord:{user_id}"

        elif mode == "manual":
            username = sanitize_username(request.args.get("username", "")) if request.args.get("username") else ""
            email    = sanitize_email(request.args.get("email", ""))       if request.args.get("email")    else ""
            config_service.mode            = "manual"
            config_service.manual_username = username
            config_service.manual_email    = email
            config_service.save()
            target_label = username or email

            if not username and email:
                mode         = "email"
                target_label = email

        elif mode == "email":
            raw_email = request.args.get("target", request.args.get("email", ""))
            email     = sanitize_email(raw_email)
            if not email:
                return "email target is required", 400
            config_service.MANUAL_EMAIL = email
            config_service.mode         = "email"
            target_label                = email

        elif mode == "domain":
            raw_domain = request.args.get("target", request.args.get("domain", ""))
            domain     = sanitize_domain(raw_domain)
            if not domain:
                return "domain target is required", 400
            config_service.MANUAL_DOMAIN = domain
            config_service.mode          = "domain"
            target_label                 = domain

        elif mode == "phone":
            raw_phone = request.args.get("target", request.args.get("phone", ""))
            phone     = _sanitize_phone(raw_phone)
            if not phone:
                return "phone target is required", 400
            config_service.MANUAL_PHONE = phone
            config_service.mode         = "phone"
            target_label                = phone

        elif mode == "image":
            raw_url = request.args.get("target", request.args.get("image_url", ""))
            img_url = _sanitize_image_url(raw_url)
            config_service.MANUAL_IMAGE_URL = img_url
            config_service.mode             = "image"
            target_label                    = img_url[:60]

        elif mode == "url":
            raw_url = request.args.get("target", request.args.get("url", ""))
            url_val = _sanitize_url(raw_url)
            config_service.MANUAL_URL = url_val
            config_service.mode       = "url"
            target_label              = url_val[:60]

        elif mode == "probe":
            raw_probe = request.args.get("target", request.args.get("probe", ""))
            probe     = _sanitize_probe(raw_probe)
            if not probe:
                return "probe target is required", 400
            config_service.PROBE_STRING = probe
            config_service.mode         = "probe"
            target_label                = probe[:60]

    except Exception as exc:
        return f"Validation error: {exc}", 400

    cancel_event = threading.Event()
    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "id": job_id, "target": target_label, "mode": mode,
            "started_at": datetime.utcnow().isoformat(), "status": "running",
            "report_html": None, "intel_path": None,
            "cancel_event": cancel_event,
        }
    _CANCEL_EVENTS[job_id] = cancel_event

    with _PIVOT_LOCK:
        _PIVOT_RESPONSES[job_id] = {
            "event": threading.Event(), "pending_seeds": [], "approved": None,
        }

    def generate():
        global REPORT_HTML
        event_queue: queue.Queue = queue.Queue()

        def _on_emit(et: str, payload: dict) -> None:
            event_queue.put({"type": et, "payload": payload})

        capture = _StdoutCapture(event_queue)
        emitter = EventEmitter(callback=_on_emit, also_print=False)

        def _confirm_fn(seeds, depth, stage_emit):
            with _PIVOT_LOCK:
                slot = _PIVOT_RESPONSES.get(job_id)
            if slot is None:
                return seeds
            slot["event"].clear()
            slot["pending_seeds"] = [{"value": s, "type": t} for s, t in seeds]
            slot["approved"]      = None
            stage_emit("pivot_confirm_request", {
                "job_id": job_id, "depth": depth,
                "seeds": slot["pending_seeds"],
                "timeout_seconds": _PIVOT_CONFIRM_TIMEOUT,
            })
            responded = slot["event"].wait(timeout=_PIVOT_CONFIRM_TIMEOUT)
            if not responded or slot["approved"] is None:
                stage_emit("pivot_confirm_timeout", {"job_id": job_id, "depth": depth})
                return seeds
            approved_values = {e["value"] for e in slot["approved"]}
            return [(s, t) for s, t in seeds if s in approved_values]

        require_confirm = bool(getattr(config_service, "PIVOT_REQUIRE_CONFIRM", False))
        active_confirm_fn = _confirm_fn if require_confirm else None

        config_service._phase3_emit      = emitter
        config_service._pivot_confirm_fn = active_confirm_fn
        config_service._cancel_event     = cancel_event

        yield to_sse_line("job_start", {
            "job_id": job_id, "target": target_label, "mode": mode,
        })

        def _run():
            _STDOUT_ROUTER.set_capture(capture)
            try:
                if mode in _MODULE_MODES:
                    from discord_osint.pipeline import run_module_pipeline
                    run_module_pipeline(mode, config_service)
                else:
                    from discord_osint.pipeline import run_osint_pipeline
                    run_osint_pipeline(config_service)
            except Exception as exc:
                import traceback as _tb
                _tb.print_exc()
                event_queue.put({"type": "error", "payload": {"message": str(exc)}})
            finally:
                _STDOUT_ROUTER.clear_capture()
                event_queue.put(None)

        worker = threading.Thread(target=_run, daemon=True)
        _WORKER_THREADS[job_id] = worker
        worker.start()

        error_occurred = False
        cancelled      = False

        while True:
            try:
                item = event_queue.get(timeout=60)
            except queue.Empty:
                yield to_sse_line("heartbeat", {
                    "ts": datetime.utcnow().isoformat(),
                })
                continue
            if item is None:
                break
            et, payload = item["type"], item["payload"]
            yield to_sse_line(et, payload)
            if et == "error":
                error_occurred = True
                break
            if et == "abort":
                cancelled = True
            if et == "report_ready" and payload.get("format") == "html":
                path = payload.get("path", "")
                if os.path.isfile(path):
                    with _JOBS_LOCK:
                        _JOBS[job_id]["report_html"] = path
                    REPORT_HTML = path
            if et == "done":
                with _JOBS_LOCK:
                    _JOBS[job_id]["intel_path"] = payload.get("intel_path", "")

        with _PIVOT_LOCK:
            _PIVOT_RESPONSES.pop(job_id, None)
        _CANCEL_EVENTS.pop(job_id, None)
        _WORKER_THREADS.pop(job_id, None)
        with _JOBS_LOCK:
            if error_occurred:
                _JOBS[job_id]["status"] = "error"
            elif cancelled:
                _JOBS[job_id]["status"] = "cancelled"
            else:
                _JOBS[job_id]["status"] = "done"

        final_status = "error" if error_occurred else ("cancelled" if cancelled else "done")
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
# /stop
# ---------------------------------------------------------------------------

@app.route("/stop", methods=["POST"])
def stop():
    data   = request.get_json(silent=True) or {}
    job_id = (data.get("job_id") or "").strip() or None

    with _JOBS_LOCK:
        if job_id:
            job = _JOBS.get(job_id)
            if not job:
                return jsonify({"success": False, "error": "job not found"}), 404
            if job.get("status") != "running":
                return jsonify({
                    "success": False,
                    "error": f"job is not running (status={job.get('status')})",
                }), 409
        else:
            running = [j for j in _JOBS.values() if j.get("status") == "running"]
            if not running:
                return jsonify({"success": False, "error": "no running investigation"}), 404
            running.sort(key=lambda j: j.get("started_at", ""), reverse=True)
            job    = running[0]
            job_id = job["id"]

    cancel_event = _CANCEL_EVENTS.get(job_id)
    if cancel_event is None:
        return jsonify({
            "success": False,
            "error": "cancel token missing for job",
        }), 500

    cancel_event.set()
    return jsonify({"success": True, "job_id": job_id})


# ---------------------------------------------------------------------------
# AI Chat endpoint
# ---------------------------------------------------------------------------

_CHAT_SYSTEM_DEFAULT = (
    "You are an elite OSINT analyst assistant embedded in the WhoCord "
    "investigation canvas. The user shares their current map and the "
    "complete investigation dump. Be concise, structured, and analytical. "
    "Use bullet points for multiple findings. Never invent data not "
    "present in the dump."
)


def _active_chat_system_prompt() -> str:
    custom = (config_service.llm_system_prompt or "").strip()
    return custom if custom else _CHAT_SYSTEM_DEFAULT


def _build_chat_context(message: str, map_data: dict, job_id: str | None) -> str:
    from discord_osint.intelligence.intel_dump import (
        build_canvas_dump, build_intel_dump,
    )

    node_count = int(map_data.get("node_count", 0) or 0)
    edge_count = int(map_data.get("edge_count", 0) or 0)
    nodes      = map_data.get("nodes", []) or []
    edges      = map_data.get("edges", []) or []

    total_budget  = config_service.llm_intel_budget
    canvas_budget = max(1_500, min(8_000, int(total_budget * 0.5)))
    intel_budget  = max(1_500, total_budget - canvas_budget)

    canvas = build_canvas_dump(
        nodes=nodes,
        edges=edges,
        status=str(map_data.get("status", "idle")),
        current_stage=map_data.get("currentStage"),
        target=str(map_data.get("target", "") or ""),
        mode=str(map_data.get("mode", "") or ""),
        job_id=job_id or map_data.get("jobId"),
        pivot_depth=int(map_data.get("pivotDepth", 0) or 0),
        pivots=map_data.get("pivots", []) or [],
        logs=map_data.get("logs", []) or [],
        findings=map_data.get("findings", []) or [],
        budget=canvas_budget,
    )

    intel_block = ""
    if job_id:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
        intel_path = job.get("intel_path") if job else None
        if intel_path and os.path.isfile(intel_path):
            try:
                with open(intel_path, encoding="utf-8") as f:
                    intel = json.load(f)
                intel_block = build_intel_dump(
                    intel,
                    budget=intel_budget,
                    include_raw=config_service.llm_intel_include_raw,
                    exclude_meta=config_service.llm_intel_exclude_meta,
                )
            except Exception as exc:
                print(f"  chat: could not load intel for {job_id}: {exc}")

    header = f"=== INVESTIGATION MAP ({node_count} nodes, {edge_count} edges) ==="

    sections = [header, "", canvas]
    if intel_block:
        sections.extend(["", intel_block])
    sections.extend(["", "=== USER QUESTION ===", message])
    return "\n".join(sections)


@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    base_url, api_key, extra_headers = get_llm_endpoint(config_service)

    if not api_key:
        provider_label = "GROQ_API_KEY" if config_service.llm_provider == "groq" else "OPENROUTER_API_KEY"
        return jsonify({"error": f"{provider_label} not configured"}), 503

    body     = request.get_json(force=True, silent=True) or {}
    message  = str(body.get("message", "")).strip()
    map_data = body.get("map", {}) or {}
    job_id   = (body.get("job_id") or map_data.get("jobId") or "").strip() or None

    if not message:
        return jsonify({"error": "message is required"}), 400

    user_content  = _build_chat_context(message, map_data, job_id)
    system_prompt = _active_chat_system_prompt()
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
            with _req.post(chat_url, headers=headers, json=payload,
                           stream=True, timeout=120) as resp:
                if resp.status_code != 200:
                    err = resp.text[:300]
                    yield f"data: {json.dumps({'token': f'[LLM {resp.status_code}: {err}]'})}\n\n"
                    yield "data: [DONE]\n\n"
                    return

                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue
                    line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
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
    data     = request.get_json(force=True, silent=True) or {}
    approved = data.get("approved_seeds", [])
    with _PIVOT_LOCK:
        slot = _PIVOT_RESPONSES.get(job_id)
    if not slot:
        return jsonify({"success": False, "error": "no pending pivot"}), 404
    slot["approved"] = approved
    slot["event"].set()
    return jsonify({"success": True, "approved_count": len(approved)})


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

@app.route("/report")
def report_legacy():
    global REPORT_HTML
    if REPORT_HTML and os.path.isfile(REPORT_HTML):
        with open(REPORT_HTML, encoding="utf-8") as f:
            return f.read()
    return "No report available.", 404


@app.route("/api/investigations", methods=["GET"])
def api_investigations():
    with _JOBS_LOCK:
        jobs = list(_JOBS.values())
    jobs.sort(key=lambda j: j.get("started_at", ""), reverse=True)
    return jsonify([
        {
            "id": j["id"], "target": j.get("target", ""), "mode": j.get("mode", ""),
            "started_at": j.get("started_at", ""), "status": j.get("status", ""),
            "has_report": bool(j.get("report_html") and os.path.isfile(j["report_html"])),
            "has_intel":  bool(j.get("intel_path")  and os.path.isfile(j["intel_path"])),
        }
        for j in jobs
    ])


@app.route("/api/investigations/<job_id>", methods=["GET"])
def api_investigation_detail(job_id: str):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    intel_path = job.get("intel_path")
    if not intel_path or not os.path.isfile(intel_path):
        target     = job.get("target", "")
        candidates = sorted(
            glob.glob(os.path.join(CACHE_DIR, f"intel_{target}_*.json")),
            key=os.path.getmtime, reverse=True,
        )
        intel_path = candidates[0] if candidates else None
    if not intel_path or not os.path.isfile(intel_path):
        return jsonify({"error": "no intel snapshot found"}), 404
    with open(intel_path, encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.route("/api/investigations/<job_id>/report", methods=["GET"])
def api_investigation_report(job_id: str):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job:
        return "Investigation not found", 404
    html_path = job.get("report_html")
    if not html_path or not os.path.isfile(html_path):
        return "Report not yet available", 404
    with open(html_path, encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}


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
    os._exit(0)


if __name__ == "__main__":
    sys.path.insert(0, os.getcwd())
    app.run(debug=False, host="127.0.0.1", port=5000)