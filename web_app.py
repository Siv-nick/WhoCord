"""
Flask web application – WhoCord Phase 4.

Phase 4 changes
---------------
1. ``validate_mode()`` now accepts the six new module modes:
   email | domain | phone | image | url | probe.
2. ``/run`` endpoint routes module-mode requests to
   ``run_module_pipeline(mode, config)`` instead of the legacy
   ``run_osint_pipeline(config)``.
3. ``sanitize_target()`` – a lightweight single-field sanitiser used
   for all Phase 4 module inputs (domain, phone, image URL, URL,
   probe string).  Each has a dedicated light-touch sanitiser.
4. All other endpoints and behaviour are unchanged from Phase 3.
"""

from __future__ import annotations

import glob
import json
import os
import queue
import sys
import threading
import uuid
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request, send_from_directory, stream_with_context

from discord_osint.config_service import ConfigService
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

# Modes that are handled as Phase 4 modules
_MODULE_MODES  = frozenset({"email", "domain", "phone", "image", "url", "probe"})
# All valid modes (legacy + Phase 4)
_ALL_MODES     = frozenset({"manual", "discord"}) | _MODULE_MODES


# ---------------------------------------------------------------------------
# Job registry + pivot confirmation slots (identical to Phase 3)
# ---------------------------------------------------------------------------

_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
REPORT_HTML: str | None = None

_PIVOT_RESPONSES: dict[str, dict] = {}
_PIVOT_LOCK       = threading.Lock()
_PIVOT_CONFIRM_TIMEOUT = 45


def _scan_existing_jobs() -> None:
    html_files = sorted(
        glob.glob(os.path.join(CACHE_DIR, "report_*.html")),
        key=os.path.getmtime,
    )
    for html_path in html_files:
        base  = os.path.basename(html_path)
        parts = base.replace(".html", "").split("_")
        if len(parts) < 3:
            continue
        target_id   = parts[1]
        ts_str      = "_".join(parts[2:])
        job_id      = str(uuid.uuid5(uuid.NAMESPACE_URL, html_path))
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
                "id":          job_id,
                "target":      target_id,
                "mode":        "unknown",
                "started_at":  started_at,
                "status":      "done",
                "report_html": html_path,
                "intel_path":  intel_path,
            }


_scan_existing_jobs()

# ---------------------------------------------------------------------------
# React SPA serving
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
    skip = ("api/", "run", "config", "get_config", "stop", "report", "upgrade", "shutdown")
    if any(path.startswith(p) for p in skip):
        return jsonify({"error": "not found"}), 404
    candidate = os.path.join(_FRONTEND_DIST, path)
    if _react_built() and os.path.isfile(candidate):
        return send_from_directory(_FRONTEND_DIST, path)
    if _react_built():
        return send_from_directory(_FRONTEND_DIST, "index.html")
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Mode validation (extended for Phase 4)
# ---------------------------------------------------------------------------

def validate_mode_extended(raw: str) -> str:
    """Accept both legacy and Phase 4 module modes."""
    mode = raw.strip().lower()
    if mode in _ALL_MODES:
        return mode
    raise ValueError(f"Invalid mode {raw!r}. Valid: {sorted(_ALL_MODES)}")


# ---------------------------------------------------------------------------
# Per-module input sanitisers
# ---------------------------------------------------------------------------

def _sanitize_phone(raw: str) -> str:
    """Keep digits, +, -, spaces, and parentheses only."""
    import re
    return re.sub(r"[^\d\+\-\s\(\)]", "", raw.strip())[:20]


def _sanitize_url(raw: str) -> str:
    """Strip whitespace; must start with http."""
    s = raw.strip()
    if not s.startswith("http"):
        raise ValueError("URL must start with http:// or https://")
    return s[:2048]


def _sanitize_image_url(raw: str) -> str:
    return _sanitize_url(raw)


def _sanitize_probe(raw: str) -> str:
    """Minimal strip; probe accepts almost anything."""
    return raw.strip()[:512]


# ---------------------------------------------------------------------------
# Config endpoints (unchanged + pivot)
# ---------------------------------------------------------------------------

@app.route("/get_config")
def get_config():
    tokens = {
        "DISCORD_TOKEN":     bool(config_service.discord_token),
        "GITHUB_TOKEN":      bool(config_service.github_token),
        "GROQ_API_KEY":      bool(config_service.groq_api_key),
        "INSTAGRAM_SESSION": bool(config_service.instagram_session),
    }
    pivot_cfg = {
        "enabled":         bool(getattr(config_service, "ENABLE_PIVOTING",       False)),
        "pivot_email":     bool(getattr(config_service, "PIVOT_EMAIL",           True)),
        "pivot_username":  bool(getattr(config_service, "PIVOT_USERNAME",        True)),
        "max_depth":       int( getattr(config_service, "PIVOT_MAX_DEPTH",       3)),
        "max_seeds":       int( getattr(config_service, "PIVOT_MAX_SEEDS",       5)),
        "require_confirm": bool(getattr(config_service, "PIVOT_REQUIRE_CONFIRM", False)),
    }
    return jsonify({
        "tokens":             tokens,
        "tools":              config_service.tools_list(),
        "mode":               config_service.mode,
        "multi_guild_search": config_service.multi_guild_search,
        "debug":              config_service.debug,
        "pivot":              pivot_cfg,
    })


@app.route("/config", methods=["POST"])
def config_endpoint():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "no data"})
    action = data.get("action")

    if action == "set_token":
        key = data.get("key")
        if key in ("DISCORD_TOKEN", "GITHUB_TOKEN", "GROQ_API_KEY", "INSTAGRAM_SESSION"):
            config_service.set_sensitive(key, data.get("value", ""))
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "invalid key"})

    elif action == "toggle_tool":
        config_service.set_tool(data.get("key"), bool(data.get("enable", True)))
        return jsonify({"success": True})

    elif action == "set_mode":
        config_service.mode = data.get("mode", "manual")
        config_service.save()
        return jsonify({"success": True})

    elif action == "set_multi_guild":
        config_service.multi_guild_search = bool(data.get("multi", False))
        config_service.save()
        return jsonify({"success": True})

    elif action == "toggle_debug":
        config_service.debug = not config_service.debug
        config_service.save()
        return jsonify({"success": True, "debug": config_service.debug})

    elif action == "set_pivot":
        pivot = data.get("pivot", {})
        setattr(config_service, "ENABLE_PIVOTING",       bool(pivot.get("enabled",         False)))
        setattr(config_service, "PIVOT_EMAIL",           bool(pivot.get("pivot_email",      True)))
        setattr(config_service, "PIVOT_USERNAME",        bool(pivot.get("pivot_username",   True)))
        setattr(config_service, "PIVOT_MAX_DEPTH",       int( pivot.get("max_depth",        3)))
        setattr(config_service, "PIVOT_MAX_SEEDS",       int( pivot.get("max_seeds",        5)))
        setattr(config_service, "PIVOT_REQUIRE_CONFIRM", bool(pivot.get("require_confirm",  False)))
        try:
            config_service.save()
        except Exception:
            pass
        return jsonify({"success": True})

    return jsonify({"success": False, "error": "unknown action"})


# ---------------------------------------------------------------------------
# /run – SSE investigation endpoint (Phase 4 extended)
# ---------------------------------------------------------------------------

@app.route("/run", methods=["GET"])
def run():
    global REPORT_HTML

    raw_mode = request.args.get("mode", "manual")
    try:
        mode = validate_mode_extended(raw_mode)
    except ValueError as exc:
        return str(exc), 400

    job_id = str(uuid.uuid4())
    target_label = "unknown"

    # ------------------------------------------------------------------ #
    # Parse + sanitise inputs per mode                                     #
    # ------------------------------------------------------------------ #
    try:
        if mode == "discord":
            user_id  = sanitize_user_id(request.args.get("user_id", ""))
            guild_id = (sanitize_user_id(request.args.get("guild_id", ""))
                        if request.args.get("guild_id") else "")
            config_service.mode           = "discord"
            config_service.target_user_id = int(user_id)
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

        elif mode == "email":
            raw_email = request.args.get("target", request.args.get("email", ""))
            email     = sanitize_email(raw_email)
            if not email:
                return "email target is required", 400
            setattr(config_service, "MANUAL_EMAIL", email)
            config_service.mode = "email"
            target_label = email

        elif mode == "domain":
            raw_domain = request.args.get("target", request.args.get("domain", ""))
            domain     = sanitize_domain(raw_domain)
            if not domain:
                return "domain target is required", 400
            object.__setattr__(config_service, "MANUAL_DOMAIN", domain)
            config_service.mode = "domain"
            target_label = domain

        elif mode == "phone":
            raw_phone = request.args.get("target", request.args.get("phone", ""))
            phone     = _sanitize_phone(raw_phone)
            if not phone:
                return "phone target is required", 400
            object.__setattr__(config_service, "MANUAL_PHONE", phone)
            config_service.mode = "phone"
            target_label = phone

        elif mode == "image":
            raw_url  = request.args.get("target", request.args.get("image_url", ""))
            img_url  = _sanitize_image_url(raw_url)
            object.__setattr__(config_service, "MANUAL_IMAGE_URL", img_url)
            config_service.mode = "image"
            target_label = img_url[:60]

        elif mode == "url":
            raw_url  = request.args.get("target", request.args.get("url", ""))
            url_val  = _sanitize_url(raw_url)
            object.__setattr__(config_service, "MANUAL_URL", url_val)
            config_service.mode = "url"
            target_label = url_val[:60]

        elif mode == "probe":
            raw_probe = request.args.get("target", request.args.get("probe", ""))
            probe     = _sanitize_probe(raw_probe)
            if not probe:
                return "probe target is required", 400
            object.__setattr__(config_service, "PROBE_STRING", probe)
            config_service.mode = "probe"
            target_label = probe[:60]

    except (ValueError, Exception) as exc:
        return f"Validation error: {exc}", 400

    # ------------------------------------------------------------------ #
    # Register job                                                         #
    # ------------------------------------------------------------------ #
    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "id":          job_id,
            "target":      target_label,
            "mode":        mode,
            "started_at":  datetime.utcnow().isoformat(),
            "status":      "running",
            "report_html": None,
            "intel_path":  None,
        }

    with _PIVOT_LOCK:
        _PIVOT_RESPONSES[job_id] = {
            "event":         threading.Event(),
            "pending_seeds": [],
            "approved":      None,
        }

    def generate():
        global REPORT_HTML
        event_queue: queue.Queue = queue.Queue()

        def _on_emit(et: str, payload: dict) -> None:
            event_queue.put({"type": et, "payload": payload})

        class _StdoutCapture:
            def __init__(self):   self._buf = ""
            def write(self, s):
                if not s: return
                self._buf += s
                while "\n" in self._buf:
                    line, self._buf = self._buf.split("\n", 1)
                    if line.strip():
                        event_queue.put({"type": "log", "payload": {"line": line}})
            def flush(self):
                if self._buf.strip():
                    event_queue.put({"type": "log", "payload": {"line": self._buf}})
                    self._buf = ""
            def isatty(self): return False

        old_stdout = sys.stdout
        sys.stdout = _StdoutCapture()
        emitter    = EventEmitter(callback=_on_emit, also_print=False)

        # Pivot confirm closure (identical to Phase 3)
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
                "seeds": slot["pending_seeds"], "timeout_seconds": _PIVOT_CONFIRM_TIMEOUT,
            })
            responded = slot["event"].wait(timeout=_PIVOT_CONFIRM_TIMEOUT)
            if not responded or slot["approved"] is None:
                stage_emit("pivot_confirm_timeout", {"job_id": job_id, "depth": depth})
                return seeds
            approved_values = {e["value"] for e in slot["approved"]}
            return [(s, t) for s, t in seeds if s in approved_values]

        require_confirm   = bool(getattr(config_service, "PIVOT_REQUIRE_CONFIRM", False))
        active_confirm_fn = _confirm_fn if require_confirm else None

        config_service._phase3_emit      = emitter
        config_service._pivot_confirm_fn = active_confirm_fn

        yield to_sse_line("job_start", {"job_id": job_id, "target": target_label, "mode": mode})

        def _run_pipeline():
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
                sys.stdout = old_stdout
                event_queue.put(None)

        thread = threading.Thread(target=_run_pipeline, daemon=True)
        thread.start()

        error_occurred = False
        while True:
            try:
                item = event_queue.get(timeout=60)
            except queue.Empty:
                yield to_sse_line("heartbeat", {"ts": datetime.utcnow().isoformat()})
                continue

            if item is None:
                break

            et      = item["type"]
            payload = item["payload"]
            yield to_sse_line(et, payload)

            if et == "error":
                error_occurred = True
                break

            if et == "report_ready" and payload.get("format") == "html":
                path = payload.get("path", "")
                if os.path.isfile(path):
                    with _JOBS_LOCK:
                        _JOBS[job_id]["report_html"] = path
                    REPORT_HTML = path

            if et == "done":
                with _JOBS_LOCK:
                    _JOBS[job_id]["intel_path"] = payload.get("intel_path", "")

        thread.join(timeout=5)

        with _PIVOT_LOCK:
            _PIVOT_RESPONSES.pop(job_id, None)

        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "error" if error_occurred else "done"

        yield to_sse_line("stream_end", {
            "job_id":     job_id,
            "status":     "error" if error_occurred else "done",
            "report_url": f"/api/investigations/{job_id}/report",
        })

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Pivot confirmation endpoint (unchanged from Phase 3)
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
# Legacy + REST endpoints (unchanged)
# ---------------------------------------------------------------------------

@app.route("/stop", methods=["POST"])
def stop():
    return jsonify({"success": False, "error": "Stop not yet implemented"})


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
            "id":         j["id"],
            "target":     j.get("target", ""),
            "mode":       j.get("mode",   ""),
            "started_at": j.get("started_at", ""),
            "status":     j.get("status", ""),
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
