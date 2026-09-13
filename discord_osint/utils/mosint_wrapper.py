"""
discord_osint/utils/mosint_wrapper.py
---------------------------------------
Thin wrapper around the MOSINT (Go) reverse‑email tool.
Provides a Pythonic way to call MOSINT and check its output
against a target username.
"""

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict

from . import clean_username


def run_mosint(email: str) -> Dict[str, Any]:
    """
    Run MOSINT against *email* and return the parsed JSON output.
    Compatible with MOSINT v3.x (uses -o flag).
    Returns an empty dict on failure.
    """
    mosint_bin = shutil.which("mosint")
    if not mosint_bin:
        home = os.path.expanduser("~")
        mosint_bin = os.path.join(home, "go", "bin", "mosint")
    if not mosint_bin or not os.path.isfile(mosint_bin):
        print("  MOSINT: binary not found – skipping.")
        return {}

    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w+", delete=False, encoding="utf-8"
    ) as tmp:
        outfile = tmp.name

    try:
        proc = subprocess.run(
            [mosint_bin, email, "-s", "-o", outfile],
            capture_output=True, text=True, timeout=120,
        )
        if os.path.isfile(outfile) and os.path.getsize(outfile) > 0:
            with open(outfile, "r", encoding="utf-8") as f:
                return json.load(f)
        if proc.stdout.strip():
            try:
                return json.loads(proc.stdout)
            except Exception:
                pass
        return {}
    except Exception as exc:
        print(f"  MOSINT error: {exc}")
        return {}
    finally:
        if os.path.isfile(outfile):
            os.unlink(outfile)


def mosint_confirms_link(email: str, target_username: str) -> bool:
    """
    Return True if MOSINT's results contain the target username
    in any of its social account fields, aliases, or related usernames.
    """
    data = run_mosint(email)
    if not data:
        return False

    target_clean = clean_username(target_username).lower()
    if not target_clean:
        return False

    def _contains_match(value: Any) -> bool:
        if isinstance(value, str):
            return target_clean in value.lower()
        if isinstance(value, list):
            return any(_contains_match(v) for v in value)
        if isinstance(value, dict):
            return any(_contains_match(v) for v in value.values())
        return False

    return _contains_match(data)
