import re
import time
import subprocess as _sp
import os
import json
import dns.resolver
import smtplib
import socket
import hashlib
import sys
import shutil
from . import utils
from .utils import resilient_task, tool_available, http_session
from .scraping import is_valid_email, is_valid_personal_email
from .pipeline.base import EmitFn
from .pipeline.context import InvestigationContext
from .utils.mosint_wrapper import run_mosint

# ── Bug 3 fix: never bind tool flags at import time. ──────────────────
from . import config as _config_module


def _flag(name: str, default: bool = False) -> bool:
    """Read a config flag dynamically (Bug 3 fix)."""
    return bool(getattr(_config_module, name, default))


def generate_email_guesses(first, last, domains):
    guesses = []
    try:
        from permutations import email_permuter
        for d in domains:
            try:
                guesses.extend(email_permuter.all_email_permuter(first, last, d))
            except Exception:
                guesses.extend(fallback_patterns(first, last, d))
    except ImportError:
        for d in domains:
            guesses.extend(fallback_patterns(first, last, d))
    return list(set(guesses))


def fallback_patterns(first, last, domain):
    f, l = first.lower(), last.lower()
    return [
        f"{f}@{domain}", f"{l}@{domain}",
        f"{f}.{l}@{domain}", f"{f}{l}@{domain}", f"{f}_{l}@{domain}",
        f"{f[0]}.{l}@{domain}", f"{f}.{l[0]}@{domain}", f"{f[0]}{l}@{domain}",
        f"{l}{f}@{domain}", f"{l}.{f}@{domain}", f"{l}_{f}@{domain}",
        f"{f}-{l}@{domain}", f"{l}-{f}@{domain}",
        f"{f[0]}{l[0]}@{domain}", f"{f[0]}-{l}@{domain}", f"{f}-{l[0]}@{domain}",
    ]


def verify_email_smtp(email):
    if not _flag("SMTP_CHECK"):
        return True, None
    try:
        from validate_email import validate_email
    except ImportError:
        return False, "library missing"
    try:
        is_valid = validate_email(
            email, check_format=True, check_blacklist=True, check_dns=True,
            check_smtp=True, smtp_timeout=8, smtp_helo_host='my.host.name',
            smtp_from_address='check@example.org',
        )
        return is_valid, None
    except Exception as e:
        return False, str(e)[:80]


@resilient_task(max_retries=2)
def run_holehe(email):
    if not tool_available("holehe"):
        return []
    _, stdout, _ = utils.run_external_tool(
        "holehe", email, "--only-used", "--no-color", timeout=120,
    )
    if stdout is None:
        return []
    sites = []
    for line in stdout.splitlines():
        if line.startswith("[+]") and not line.startswith("[+] Email used"):
            site = line[4:].strip()
            if site:
                sites.append(site)
    return sites


@resilient_task(max_retries=1)
def run_h8mail(email):
    """
    Compact breach summary or ``None`` when nothing interesting.

    Change log
    ----------
    - "clean" results now return ``None`` instead of a dict carrying the
      full h8mail ASCII banner.  Those dicts were treated as breach
      records by the report generator and bloated intel size for zero
      signal.
    - Whitespace is compressed and the ANSI banner is stripped so the
      remaining text is small and human-readable.
    """
    if not tool_available("h8mail"):
        return None
    _, stdout, _ = utils.run_external_tool("h8mail", "-t", email, timeout=180)
    if stdout is None:
        return None

    # Strip ANSI colour codes then collapse whitespace so we don't keep
    # the ASCII art banner.
    clean = re.sub(r"\x1b\[[0-9;]*m", "", stdout)
    compact = re.sub(r"\s+", " ", clean).strip()

    if "Not Compromised" in compact:
        # Nothing to report.  Don't store the banner.
        return None

    # Try to pull the execution time out of the recap for context.
    m = re.search(r"Execution time\s*\(seconds\)\s*:\s*([\d.]+)", compact)
    elapsed = m.group(1) if m else ""

    # Trim to a short tail so the stored value stays small.
    summary = compact[-500:] if len(compact) > 500 else compact
    return {"status": "compromised", "summary": summary, "elapsed_s": elapsed}


def run_gosearch(query):
    if not tool_available("gosearch"):
        return []
    try:
        res = _sp.run(["gosearch", "-u", query], capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            return [l.strip() for l in res.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    return []


@resilient_task(max_retries=1)
def run_ghunt(gmail):
    """
    Run GHunt against a Gmail address.

    Change log
    ----------
    Skips cleanly when no GHunt session is configured instead of letting
    the tool raise a Python traceback into the console output.
    """
    import shutil, re, json as _json

    ghunt_bin = os.path.expanduser("~/.local/bin/ghunt")
    if not os.path.isfile(ghunt_bin):
        ghunt_bin = shutil.which("ghunt")
    if not ghunt_bin or not os.path.isfile(str(ghunt_bin)):
        print("  GHunt binary not found – skipping.")
        return None
    if not gmail.lower().endswith('@gmail.com'):
        print("  GHunt: not a Gmail address – skipping.")
        return None

    # Detect missing session *before* invoking ghunt, otherwise the tool
    # dumps a traceback.
    creds_dir = os.path.expanduser("~/.malfrats/ghunt")
    if not os.path.isdir(creds_dir) or not os.listdir(creds_dir):
        print("  GHunt: no session configured (run `ghunt login`) – skipping.")
        return None

    cmd = [str(ghunt_bin), "email", gmail]
    _, stdout, _ = utils.debug_subprocess(cmd, timeout=60)
    if not stdout:
        return None

    try:
        parsed = _json.loads(stdout)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    try:
        start = stdout.find('{')
        end = stdout.rfind('}')
        if start != -1 and end > start:
            parsed = _json.loads(stdout[start:end + 1])
            if isinstance(parsed, dict):
                return parsed
    except Exception:
        pass

    data = {}
    avatar_match = re.search(r'\[\+\] Custom profile picture[^\n]*\n=>\s*(\S+)', stdout)
    if avatar_match:
        data["profile_picture"] = avatar_match.group(1).strip()
    gaia_match = re.search(r'Gaia ID\s*:\s*(\S+)', stdout)
    if gaia_match:
        data["gaia_id"] = gaia_match.group(1).strip()
    edit_match = re.search(r'Last profile edit\s*:\s*([^\n]+)', stdout)
    if edit_match:
        data["last_profile_edit"] = edit_match.group(1).strip()
    user_types = re.findall(r'^\-\s*(GOOGLE_USER.*)$', stdout, re.MULTILINE)
    if user_types:
        data["user_types"] = [t.strip() for t in user_types]
    services_match = re.search(r'Activated Google services\s*:\s*(.*?)(?:\n\n|\Z)', stdout, re.DOTALL)
    if services_match:
        services_block = services_match.group(1)
        services = re.findall(r'^\-\s*(.*)$', services_block, re.MULTILINE)
        data["activated_services"] = [s.strip() for s in services]
    maps_start = stdout.find("🗺️ Maps")
    if maps_start != -1:
        next_section = stdout.find("🗓️", maps_start + 1)
        if next_section == -1:
            maps_text = stdout[maps_start:]
        else:
            maps_text = stdout[maps_start:next_section]
        rev_match = re.search(r'Reviews\s*:\s*(\d+)', maps_text)
        if rev_match:
            data["maps_reviews"] = rev_match.group(1)
        ans_match = re.search(r'Answers\s*:\s*(\d+)', maps_text)
        if ans_match:
            data["maps_answers"] = ans_match.group(1)
        prof_match = re.search(r'Profile page\s*:\s*(\S+)', maps_text)
        if prof_match:
            data["maps_profile"] = prof_match.group(1).strip()
        if "maps_reviews" not in data and "Reviews" in maps_text:
            for line in maps_text.splitlines():
                if "Reviews" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        data["maps_reviews"] = parts[1].strip()
                if "Answers" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        data["maps_answers"] = parts[1].strip()
                if "Profile page" in line:
                    parts = line.split(":", 1)
                    if len(parts) >= 2:
                        data["maps_profile"] = parts[1].strip()

    if not data:
        if utils.DEBUG_MODE:
            print("  GHunt: could not extract any data.")
        return None
    return data


def check_hibp(email):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        r = http_session.get(
            f"https://haveibeenpwned.com/api/v2/breachedaccount/{email}",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


def check_emailrep(email):
    try:
        r = http_session.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "Mozilla/5.0"}, timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "reputation": data.get("reputation"),
                "profiles": data.get("details", {}).get("profiles", []),
                "data_breaches": data.get("details", {}).get("data_breaches", []),
            }
    except Exception:
        pass
    return {}


def _strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def run_scylla(email):
    if not tool_available("scylla") or not _flag("ENABLE_SCYLLA"):
        return ""

    scylla_bin = shutil.which("scylla")
    if not scylla_bin:
        return ""

    try:
        with open(scylla_bin, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()

        if first_line.startswith('#!') and 'python' in first_line:
            cmd = [sys.executable, scylla_bin, "-l", email]
        else:
            cmd = [scylla_bin, "-l", email]

        _, stdout, _ = utils.debug_subprocess(cmd, timeout=60)
    except Exception as e:
        if utils.DEBUG_MODE:
            print(f"  scylla execution error: {e}")
        return ""

    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    stdout = ansi_escape.sub('', stdout)

    lines = stdout.splitlines()
    useful_lines = []
    started = False
    for line in lines:
        if not started:
            if ("[*] Searching" in line or "Traceback" in line or "TypeError" in line or "Error" in line or
                    line.strip().startswith("usage:") or line.strip().startswith("scylla.py:")):
                started = True
                useful_lines.append(line)
                continue
        else:
            useful_lines.append(line)

    clean = "\n".join(useful_lines).strip()
    if not clean:
        return "Scylla ran but produced no output."
    return clean[:500]


def check_mx_record(domain):
    """Return list of MX hostnames for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [str(r.exchange).rstrip('.') for r in answers]
    except Exception:
        return []


def verify_email_smtp_advanced(email):
    """Verify email existence using SMTP RCPT TO."""
    domain = email.split('@')[1]
    mx_records = check_mx_record(domain)
    if not mx_records:
        return {'valid': False, 'reason': 'No MX record'}

    mx_host = mx_records[0]
    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
            smtp.helo(socket.gethostname())
            smtp.mail('verify@example.com')
            code, message = smtp.rcpt(email)
            if code == 250:
                return {'valid': True, 'reason': ''}
            else:
                return {'valid': False, 'reason': f'SMTP: {code} {message.decode()}'}
    except Exception as e:
        return {'valid': None, 'reason': str(e)}


def gravatar_lookup(email):
    """Return Gravatar image URL if an account exists."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
    try:
        r = http_session.get(url)
        if r.status_code == 200 and 'image' in r.headers.get('Content-Type', ''):
            return url
    except Exception:
        pass
    return None


def enrich_email(
    ctx: InvestigationContext,
    email: str,
    emit: EmitFn = lambda *_: None,
) -> None:
    """
    Run the full email enrichment suite and store results.

    Email is normalised to lowercase at the top so intel keys stay
    consistent regardless of how the address was discovered.
    """
    email = email.strip().lower()       # <-- normalise once, up front
    if not email or "@" not in email:
        return

    cfg = ctx.config

    # --- Holehe ---
    if cfg.ENABLE_HOLEHE:
        sites = run_holehe(email) or []
        if sites:
            ctx.intel_core.add_intel(
                "breaches", f"holehe_{email}",
                {"used_on": sites}, source="holehe",
            )
            emit("finding", {"type": "holehe", "email": email, "sites": sites, "count": len(sites)})

    # --- h8mail ---
    if cfg.ENABLE_H8MAIL:
        h8 = run_h8mail(email)
        if h8:
            ctx.intel_core.add_intel("breaches", f"h8mail_{email}", h8, source="h8mail")
            emit("finding", {"type": "h8mail", "email": email, "result": h8})

    # --- HIBP ---
    if cfg.ENABLE_HIBP:
        hibp = check_hibp(email) or []
        if hibp:
            ctx.intel_core.add_intel("breaches", f"hibp_{email}", hibp, source="hibp")
            emit("finding", {"type": "hibp", "email": email, "breaches": len(hibp)})

    # --- EmailRep ---
    if cfg.ENABLE_EMAILREP:
        rep = check_emailrep(email) or {}
        if rep:
            ctx.intel_core.add_intel("emailrep", email, rep, source="emailrep")
            emit("finding", {"type": "emailrep", "email": email, "data": rep})

    # --- GHunt (Gmail only) ---
    if cfg.ENABLE_GHUNT and email.endswith("@gmail.com"):
        gh = run_ghunt(email)
        if gh:
            ctx.intel_core.add_intel("ghunt", email, gh, source="ghunt")
            emit("finding", {"type": "ghunt", "email": email})

            socid = {}
            if isinstance(gh, dict):
                avatar = gh.get("profile_picture") or gh.get("avatar") or ""
                if avatar:
                    socid["image"] = avatar
                socid["name"] = gh.get("name") or email
                for field, label in [("gaia_id", "Gaia ID"), ("last_profile_edit", "Last Profile Edit")]:
                    if gh.get(field):
                        socid[field] = str(gh[field])
                if gh.get("user_types") and isinstance(gh["user_types"], list):
                    socid["user_types"] = ", ".join(gh["user_types"])
                if gh.get("activated_services") and isinstance(gh["activated_services"], list):
                    socid["services"] = ", ".join(gh["activated_services"])
                for flat_key, display in [("maps_reviews", "reviews"), ("maps_answers", "answers"), ("maps_profile", "maps_profile")]:
                    if gh.get(flat_key):
                        socid[display] = str(gh[flat_key])
                ctx.intel_core.add_intel(
                    "social_profiles",
                    "google/ghunt/socid_raw",
                    json.dumps(socid),
                    source="ghunt",
                )

    # --- SMTP verification ---
    if getattr(cfg, "ENABLE_EMAIL_VERIFY", False):
        vrf = verify_email_smtp_advanced(email)
        if vrf:
            ctx.intel_core.add_intel("email_verification", f"verify_{email}", vrf, source="smtp_verify")

    # --- Gravatar ---
    grav_url = gravatar_lookup(email)
    if grav_url:
        ctx.intel_core.add_intel("social_profiles", f"gravatar_{email}", grav_url, source="gravatar")
        ctx.add_avatar(grav_url)
        emit("finding", {"type": "gravatar", "email": email, "url": grav_url})

    # --- Scylla ---
    if cfg.ENABLE_SCYLLA:
        scylla_data = run_scylla(email)
        if scylla_data:
            ctx.intel_core.add_intel("breaches", f"scylla_{email}", scylla_data, source="scylla")
            emit("finding", {"type": "scylla", "email": email})

    # --- Blackbird email search + API fetch ---
    if getattr(cfg, "ENABLE_BLACKBIRD", False):
        try:
            from .username_search import run_blackbird
            results = run_blackbird(email, mode="email") or []
            for r in results:
                url = r.get("url", "")
                if url and url.startswith("http"):
                    ctx.intel_core.add_intel(
                        "social_profiles",
                        f"blackbird_email_{url[:60]}",
                        url,
                        source="blackbird_email",
                    )
                    try:
                        import requests
                        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
                        if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                            data = resp.json()
                            key = f"blackbird_api_{url[:60]}/socid_raw"
                            ctx.intel_core.add_intel("social_profiles", key, json.dumps(data), source="blackbird_api")
                    except Exception:
                        pass
        except Exception:
            pass

    # --- MOSINT ---
    mosint_data = run_mosint(email)
    if mosint_data:
        ctx.intel_core.intel.setdefault("mosint", {})[email] = mosint_data
        if isinstance(mosint_data, dict):
            for acc in mosint_data.get("data", []):
                url = acc.get("url") or acc.get("profile_url")
                if url and url.startswith("http"):
                    ctx.intel_core.add_intel("social_profiles", f"mosint_{url[:60]}", url, source="mosint")

    # --- Feed any discovered URLs into all_urls for scraping ---
    discovered_urls = [e["url"] for e in ctx.discovery if e.get("url")]
    ctx.all_urls = list(set(ctx.all_urls) | set(discovered_urls))