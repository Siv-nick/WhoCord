import subprocess
import os
import glob
import json
import time
import shutil
from flask import Flask, render_template, request, jsonify, Response, stream_with_context, url_for
from werkzeug.utils import secure_filename

current_process = None
app = Flask(__name__)
CACHE_DIR = "./investigation_cache"
CONFIG_FILE = "config.json"
REPORT_HTML = None

# -------------------------------------------------------------------
# Config helpers – read/write config.json and keyring (same as config.py)
# -------------------------------------------------------------------
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE) as f:
        return json.load(f)

def save_config(data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_current_config():
    """Return token status, tool toggles, and mode using the real config object."""
    from discord_osint.config import config as app_config
    masked_cfg = {
        "DISCORD_TOKEN": bool(app_config.DISCORD_TOKEN),
        "GITHUB_TOKEN": bool(app_config.GITHUB_TOKEN),
        "GROQ_API_KEY": bool(app_config.GROQ_API_KEY),
        "INSTAGRAM_SESSION": bool(app_config.INSTAGRAM_SESSION),
    }

    from discord_osint.tools_config import TOOLS_LIST
    tools = []
    for key, desc in TOOLS_LIST:
        tools.append({"key": key, "desc": desc, "enabled": getattr(app_config, key, True)})
    return {
        "tokens": masked_cfg,
        "tools": tools,
        "mode": getattr(app_config, 'MODE', 'manual'),
        "multi_guild_search": getattr(app_config, 'MULTI_GUILD_SEARCH', False)
    }

def set_token(key, value):
    import keyring
    SENSITIVE_KEYS = {
        "DISCORD_TOKEN": "discord-osint/discord",
        "GITHUB_TOKEN": "discord-osint/github",
        "GROQ_API_KEY": "discord-osint/groq",
        "INSTAGRAM_SESSION": "discord-osint/instagram",
    }
    if key in SENSITIVE_KEYS:
        service = SENSITIVE_KEYS[key]
        if value:
            keyring.set_password(service, key, value)
        else:
            try:
                keyring.delete_password(service, key)
            except:
                pass

def toggle_tool(key, enable):
    cfg = load_config()
    cfg[key] = enable
    save_config(cfg)

# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/config", methods=["POST"])
def config():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "no data"})
    action = data.get("action")
    if action == "set_token":
        key = data.get("key")
        value = data.get("value", "")
        if key in ("DISCORD_TOKEN", "GITHUB_TOKEN", "GROQ_API_KEY", "INSTAGRAM_SESSION"):
            set_token(key, value)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "invalid key"})
    elif action == "toggle_tool":
        key = data.get("key")
        enable = data.get("enable", True)
        try:
            toggle_tool(key, enable)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
    elif action == "set_mode":
        mode = data.get("mode")
        if mode in ("discord", "manual"):
            cfg = load_config()
            cfg["MODE"] = mode
            save_config(cfg)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "invalid mode"})
    elif action == "set_multi_guild":
        multi = data.get("multi", False)
        cfg = load_config()
        cfg["MULTI_GUILD_SEARCH"] = multi
        save_config(cfg)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "unknown action"})

@app.route("/get_config")
def get_config():
    return jsonify(get_current_config())

@app.route("/run", methods=["GET"])
def run():
    target = request.args.get("username", "").strip()
    email = request.args.get("email", "").strip()
    mode = request.args.get("mode", "manual").strip()

    if mode == "discord":
        user_id = request.args.get("user_id", "").strip()
        guild_id = request.args.get("guild_id", "").strip()
        if not user_id:
            return "User ID required for Discord mode.", 400
        cmd = ["discord-osint", "--mode", "discord", "--target", user_id, "--output", "html", "--debug"]
        if guild_id:
            cmd.extend(["--guild", guild_id])
    else:
        cmd = ["discord-osint", "--mode", "manual", "--target", target, "--output", "html", "--debug"]

    # Set email on config directly so pipeline can use it
    from discord_osint.config import config as app_config
    if email:
        app_config.MANUAL_EMAIL = email
    else:
        app_config.MANUAL_EMAIL = ""

    env = os.environ.copy()
    # Still pass via env for legacy support (pipeline also uses config)
    if email:
        env["MANUAL_EMAIL"] = email
    env['PYTHONUNBUFFERED'] = '1'         # force unbuffered output

    def generate():
        global REPORT_HTML, current_process
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=env, bufsize=1, cwd=os.getcwd()
        )
        current_process = process
        for line in iter(process.stdout.readline, ''):
            yield f"data: {line}\n\n"
        process.stdout.close()
        process.wait()
        current_process = None

        html_files = sorted(
            glob.glob(os.path.join(CACHE_DIR, "report_*.html")),
            key=os.path.getmtime, reverse=True
        )
        if html_files:
            REPORT_HTML = html_files[0]
            yield "event: done\ndata: /report\n\n"
        else:
            yield "event: error\ndata: No report generated\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route("/report")
def report():
    global REPORT_HTML
    if REPORT_HTML and os.path.exists(REPORT_HTML):
        with open(REPORT_HTML) as f:
            return f.read()
    return "No report available.", 404

@app.route("/stop", methods=["POST"])
def stop():
    global current_process
    if current_process and current_process.poll() is None:
        current_process.kill()
        current_process.wait()
        current_process = None
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "No running investigation"})

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.getcwd())
    app.run(debug=False, host="127.0.0.1", port=5000)
