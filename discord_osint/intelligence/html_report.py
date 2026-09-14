"""
discord_osint/intelligence/html_report.py
-------------------------------------------
Generates a fully self-contained, dark-themed HTML investigation report.

Change log
----------
Adds three new renderers for Apollo / Lusha contact-enrichment output:

* ``_render_enrichment_section``    — matched profile cards + spend bar
* ``_render_enrichment_rejections`` — collapsed audit block listing every
                                      identifier the trust filter rejected,
                                      with its one-line reason
* ``_render_enrichment_profile_card`` — one matched contact card

Both new sections are additive: when neither provider ran, neither
section renders and the report is byte-identical to the previous
version.

``_safe_href()`` and ``_safe_img_src()`` gate every ``href=`` and
``src=`` in the report, as before.
"""

from __future__ import annotations

import html as _html
import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# URL safety helpers
# ---------------------------------------------------------------------------

_ALLOWED_HREF_SCHEMES  = frozenset({"http", "https", "mailto"})
_ALLOWED_IMG_SCHEMES   = frozenset({"http", "https"})


def _has_dangerous_scheme(raw: str) -> bool:
    if not raw:
        return False
    s = re.sub(r"[\x00-\x20]+", "", raw).strip()
    if not s:
        return False
    for scheme in _ALLOWED_HREF_SCHEMES:
        if s.lower().startswith(scheme + ":"):
            return False
    if s.startswith("//") or s.startswith("/") or s.startswith("#") or s.startswith("?"):
        return False
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:", s))


def _safe_href(raw: str) -> str:
    if raw is None:
        return "#"
    raw = str(raw).strip()
    if not raw:
        return "#"

    if _has_dangerous_scheme(raw):
        return "#"

    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https"):
        if not parsed.netloc:
            return "#"

    return _e(raw)


def _safe_img_src(raw: str) -> str:
    if raw is None:
        return ""
    raw = str(raw).strip()
    if not raw:
        return ""

    stripped = re.sub(r"[\x00-\x20]+", "", raw).strip()
    parsed   = urlparse(stripped)
    if parsed.scheme.lower() not in _ALLOWED_IMG_SCHEMES:
        return ""
    if not parsed.netloc:
        return ""
    return _e(raw)


# ---------------------------------------------------------------------------
# Platform metadata
# ---------------------------------------------------------------------------

_PLATFORM_META: dict[str, tuple[str, str]] = {
    "google":     ("🔍", "Google"),
    "github":     ("🐙", "GitHub"),
    "twitter":    ("🐦", "Twitter / X"),
    "reddit":     ("🤖", "Reddit"),
    "instagram":  ("📸", "Instagram"),
    "linkedin":   ("💼", "LinkedIn"),
    "facebook":   ("📘", "Facebook"),
    "youtube":    ("▶️", "YouTube"),
    "tiktok":     ("🎵", "TikTok"),
    "twitch":     ("🎮", "Twitch"),
    "steam":      ("🎮", "Steam"),
    "spotify":    ("🎧", "Spotify"),
    "pinterest":  ("📌", "Pinterest"),
    "soundcloud": ("🎵", "SoundCloud"),
    "medium":     ("✍️", "Medium"),
    "dev":        ("💻", "Dev.to"),
    "gitlab":     ("🦊", "GitLab"),
    "bitbucket":  ("🪣", "Bitbucket"),
    "keybase":    ("🔑", "Keybase"),
    "telegram":   ("✈️", "Telegram"),
    "discord":    ("💬", "Discord"),
    "gravatar":   ("🌐", "Gravatar"),
    "patreon":    ("🎨", "Patreon"),
    "tumblr":     ("📝", "Tumblr"),
    "mastodon":   ("🐘", "Mastodon"),
    "hackernews": ("🔶", "Hacker News"),
    "producthunt":("🚀", "Product Hunt"),
    "snapchat":   ("👻", "Snapchat"),
    "whatsapp":   ("💬", "WhatsApp"),
    "viber":      ("📱", "Viber"),
    "line":       ("💚", "Line"),
}

_DEFAULT_PLATFORM_META = ("🌐", "Unknown Platform")


def _platform_icon(platform: str) -> str:
    return _PLATFORM_META.get(platform.lower(), _DEFAULT_PLATFORM_META)[0]


def _platform_label(platform: str) -> str:
    return _PLATFORM_META.get(platform.lower(), (_DEFAULT_PLATFORM_META[0], platform.title()))[1]


# ---------------------------------------------------------------------------
# Intel parsing helpers
# ---------------------------------------------------------------------------

def _unpack(entry: Any) -> tuple[str, str]:
    if isinstance(entry, dict):
        val = entry.get("value", "")
        src = entry.get("source", "")
        if not isinstance(val, str):
            val = json.dumps(val) if val else ""
    else:
        val = str(entry) if entry else ""
        src = ""
    return val.strip(), src.strip()


def _e(text: str) -> str:
    return _html.escape(str(text))


# ---------------------------------------------------------------------------
# Social profiles parser
# ---------------------------------------------------------------------------

def _parse_social_profiles(intel: dict) -> dict[str, dict]:
    profiles: dict[str, dict] = defaultdict(lambda: {
        "platform":  "",
        "usernames": [],
        "urls":      [],
        "bio":       "",
        "blog":      "",
        "location":  "",
        "email":     "",
        "followers": "",
        "created":   "",
        "extra":     {},
    })

    for key, entry in intel.get("social_profiles", {}).items():
        val, src = _unpack(entry)
        if not val:
            continue

        if key.startswith("blackbird_email_") or key.startswith("blackbird_api_"):
            if key.startswith("blackbird_email_"):
                url_part = key[len("blackbird_email_"):]
            else:
                url_part = key[len("blackbird_api_"):]
                if url_part.endswith("/socid_raw"):
                    url_part = url_part[:-len("/socid_raw")]

            domain = ""
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url_part)
                netloc = parsed.netloc.lower()
                for prefix in ("www.", "api.", "spclient.", "auth.", "callback.",
                               "signin.", "signup.", "public."):
                    if netloc.startswith(prefix):
                        netloc = netloc[len(prefix):]
                if "." in netloc:
                    parts_domain = netloc.split(".")
                    domain = parts_domain[-2] if len(parts_domain) >= 2 else netloc
                else:
                    domain = netloc
            except Exception:
                domain = "unknown"
            if not domain:
                domain = "unknown"

            p = profiles[domain]
            p["platform"] = domain

            if key.startswith("blackbird_email_") and val.startswith("http"):
                if val not in p["urls"]:
                    p["urls"].append(val)

            elif key.startswith("blackbird_api_"):
                try:
                    api_data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(api_data, dict):
                        for field, field_val in api_data.items():
                            if isinstance(field_val, (str, int, float, bool)):
                                label = field.replace("_", " ").title()
                                p["extra"][label] = str(field_val)
                except Exception:
                    pass

            continue

        if "/" in key:
            parts    = key.split("/")
            platform = parts[0].lower()
            username = parts[1] if len(parts) > 1 else ""
            field    = parts[2] if len(parts) > 2 else "url"

            if username:
                unique_key = f"{platform}_{username}"
            else:
                unique_key = platform

            p = profiles[unique_key]
            p["platform"] = platform
            p["username_slug"] = username

            if username and username not in p["usernames"]:
                p["usernames"].append(username)

            if field == "bio":
                p["bio"] = p["bio"] or val[:500]
            elif field == "blog":
                p["blog"] = p["blog"] or val
            elif field == "socid_raw":
                try:
                    socid = json.loads(val) if isinstance(val, str) else val
                    if isinstance(socid, dict):
                        for sk, sv in socid.items():
                            sv_str = str(sv).strip() if sv else ""
                            if not sv_str:
                                continue
                            if sk in ("fullname", "name"):
                                p["extra"].setdefault("Full Name", sv_str)
                            elif sk in ("location",):
                                p["location"] = p["location"] or sv_str
                            elif sk in ("email",):
                                p["email"] = p["email"] or sv_str
                            elif sk in ("followers", "followers_count"):
                                p["followers"] = sv_str
                            elif sk in ("created_at", "created", "join_date"):
                                p["created"] = p["created"] or sv_str
                            elif sk in ("image", "avatar"):
                                if sv_str.startswith("http") and not p.get("avatar"):
                                    p["avatar"] = sv_str
                            elif sk not in ("url", "id"):
                                p["extra"][sk.replace("_", " ").title()] = sv_str[:120]
                except Exception:
                    pass
            elif field == "url" or val.startswith("http"):
                if val not in p["urls"]:
                    p["urls"].append(val)
            else:
                p["extra"][field.replace("_", " ").title()] = val[:120]

        elif key.startswith("discord_connected_"):
            sub_platform = key.replace("discord_connected_", "").split("_")[0].lower()
            p            = profiles[sub_platform]
            p["platform"] = sub_platform
            if val and val not in p["usernames"]:
                p["usernames"].append(val)

        elif key.startswith("gravatar_"):
            p = profiles["gravatar"]
            p["platform"] = "gravatar"
            if val.startswith("http") and val not in p["urls"]:
                p["urls"].append(val)

        else:
            parts_key = key.split("_", 2)
            if len(parts_key) >= 2 and parts_key[0] in ("discovery", "linkook"):
                raw_platform = parts_key[1]
                raw_platform = raw_platform.split("?")[0].split("#")[0]
                platform = raw_platform.rstrip(".").lower()
            else:
                platform = key.split("_")[0].lower()

            p = profiles[platform]
            p["platform"] = platform
            if val.startswith("http"):
                if val not in p["urls"]:
                    p["urls"].append(val)
            else:
                if val not in p["usernames"]:
                    p["usernames"].append(val)

    avatar_map = intel.get("profile_avatars", {})
    if avatar_map:
        for unique_key, data in profiles.items():
            if data.get("avatar"):
                continue
            original_key = f"{data['platform']}/{data.get('username_slug', '')}" if data.get('username_slug') else data['platform']
            if original_key in avatar_map:
                data["avatar"] = _unpack(avatar_map[original_key])[0]
                continue
            for url in data.get("urls", []):
                if url in avatar_map:
                    data["avatar"] = _unpack(avatar_map[url])[0]
                    break

    return dict(profiles)


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
:root{
  --bg:#0a0a0a;--surface:#141414;--surface2:#1c1c1c;
  --border:#2a2a2a;--border2:#333;
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --indigo:#6366f1;--indigo-dark:#4f46e5;--indigo-bg:#1e1b4b;
  --emerald:#10b981;--emerald-bg:#064e3b;
  --amber:#f59e0b;--amber-bg:#451a03;
  --red:#ef4444;--red-bg:#450a0a;
  --green:#22c55e;--green-bg:#052e16;
  --radius:10px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);
  line-height:1.55;font-size:14px}
a{color:var(--indigo);text-decoration:none}
a:hover{text-decoration:underline}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#111}
::-webkit-scrollbar-thumb{background:#333;border-radius:3px}

.container{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}

.report-header{
  background:linear-gradient(135deg,#0f0c29,#1a1040,#0a0a0a);
  border-bottom:1px solid var(--border);padding:2.5rem 1.5rem 2rem;
  text-align:center;margin-bottom:2rem}
.report-header h1{font-size:2rem;font-weight:800;color:#fff;letter-spacing:-0.03em}
.report-header .target{font-size:1.1rem;color:var(--indigo);font-weight:600;margin:.3rem 0}
.report-header .meta{font-size:.8rem;color:var(--text3);margin-top:.5rem}
.risk-badge{display:inline-block;padding:.25rem .8rem;border-radius:20px;font-size:.75rem;
  font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin:.5rem .25rem}
.risk-high  {background:var(--red-bg);  color:var(--red)}
.risk-med   {background:var(--amber-bg);color:var(--amber)}
.risk-low   {background:var(--green-bg);color:var(--green)}
.risk-info  {background:var(--indigo-bg);color:#a5b4fc}

.section{margin-bottom:2.5rem}
.section-title{
  font-size:1rem;font-weight:700;color:#fff;text-transform:uppercase;
  letter-spacing:.08em;padding:.5rem 0;margin-bottom:1rem;
  border-bottom:2px solid var(--border2);display:flex;align-items:center;gap:.5rem}
.section-title .icon{font-size:1.1rem}

.cards-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem}

.platform-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;transition:border-color .2s}
.platform-card:hover{border-color:var(--border2)}
.platform-header{
  display:flex;align-items:center;gap:.75rem;
  padding:.85rem 1.1rem;cursor:pointer;
  background:var(--surface2);border-bottom:1px solid var(--border);
  overflow:hidden;}
.platform-header:hover{background:#222}
.platform-icon{font-size:1.4rem;line-height:1}
.platform-name{
  font-weight:700;font-size:.95rem;color:#fff;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.platform-username{
  font-size:.8rem;color:var(--indigo);font-family:monospace;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  max-width:20ch;}
.platform-arrow{color:var(--text3);font-size:.75rem;transition:transform .2s}
.platform-card.open .platform-arrow{transform:rotate(180deg)}
.platform-body{padding:1rem 1.1rem;display:none;border-top:1px solid var(--border)}
.platform-card.open .platform-body{display:block}

.data-row{display:flex;gap:.6rem;padding:.3rem 0;font-size:.83rem;
  border-bottom:1px solid #1f1f1f}
.data-row:last-child{border-bottom:none}
.data-label{color:var(--text3);flex-shrink:0;min-width:90px;font-size:.77rem;
  text-transform:uppercase;letter-spacing:.04em;padding-top:1px}
.data-value{color:var(--text2);word-break:break-all;flex:1}
.data-value a{color:var(--indigo)}
.bio-text{font-size:.82rem;color:var(--text2);line-height:1.6;
  background:#111;border-radius:6px;padding:.6rem .8rem;margin-top:.4rem;
  border-left:3px solid var(--indigo)}

.identity-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.75rem}
.identity-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:.85rem 1rem}
.identity-card .label{font-size:.72rem;color:var(--text3);text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:.3rem}
.identity-card .value{font-size:.95rem;color:#fff;font-weight:600}
.identity-card .source{font-size:.7rem;color:var(--text3);margin-top:.2rem}
.confidence-bar{height:4px;background:#222;border-radius:2px;margin-top:.4rem;overflow:hidden}
.confidence-fill{height:100%;border-radius:2px;
  background:linear-gradient(90deg,var(--indigo),var(--emerald))}

.email-card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:1rem 1.1rem;margin-bottom:.75rem}
.email-address{font-family:monospace;font-size:.95rem;color:var(--indigo);font-weight:600}
.breach-list{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.6rem}
.breach-tag{background:var(--red-bg);color:var(--red);font-size:.72rem;font-weight:600;
  padding:.15rem .5rem;border-radius:4px}
.site-tag{background:#1a2035;color:#7aa2f7;font-size:.72rem;
  padding:.15rem .5rem;border-radius:4px}

.corr-item{display:flex;align-items:flex-start;gap:.75rem;
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:.7rem 1rem;margin-bottom:.5rem}
.corr-badge{flex-shrink:0;padding:.15rem .5rem;border-radius:4px;
  font-size:.7rem;font-weight:700;text-transform:uppercase}
.conf-high{background:#3d2b1f;color:#fb923c}
.conf-med {background:#2a2d1a;color:#bef264}
.conf-low {background:#1c2530;color:#7dd3fc}
.corr-desc{color:var(--text2);font-size:.83rem;line-height:1.5}

.narrative-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.85rem;
  margin-bottom:1.2rem}
.narrative-card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:1rem 1.1rem}
.narrative-card h4{font-size:.8rem;color:#a5b4fc;text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:.5rem}
.narrative-card p{color:var(--text2);font-size:.85rem;line-height:1.6}
.critical-list{list-style:none;padding:0}
.critical-list li{padding:.3rem 0;color:var(--text2);font-size:.85rem;
  border-bottom:1px solid var(--border);display:flex;gap:.5rem;align-items:flex-start}
.critical-list li::before{content:"🎯";font-size:.8rem;flex-shrink:0;margin-top:1px}

.pivot-card{background:var(--surface);border:1px solid #1a3d25;
  border-radius:var(--radius);margin-bottom:.75rem;overflow:hidden}
.pivot-header{
  display:flex;align-items:center;gap:.75rem;padding:.8rem 1.1rem;
  background:#0f2018;cursor:pointer;border-bottom:1px solid #1a3d25}
.pivot-header:hover{background:#142a1e}
.pivot-seed{font-family:monospace;font-size:.9rem;color:var(--green);font-weight:600}
.pivot-depth-badge{background:var(--green-bg);color:var(--green);font-size:.7rem;
  font-weight:700;padding:.15rem .45rem;border-radius:4px}
.pivot-body{padding:1rem 1.1rem;display:none;border-top:1px solid #1a3d25}
.pivot-card.open .pivot-body{display:block}

.tech-card{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:1rem 1.1rem;margin-bottom:.75rem}
.tech-card h4{font-size:.8rem;color:var(--text3);text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:.6rem}
.mono{font-family:monospace;font-size:.82rem;color:var(--text2);
  background:#111;padding:.5rem .75rem;border-radius:6px;word-break:break-all}

.stats-bar{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:1.5rem}
.stat-pill{background:var(--surface);border:1px solid var(--border);
  border-radius:20px;padding:.3rem .9rem;font-size:.8rem;color:var(--text2)}
.stat-pill strong{color:#fff}

.empty{color:var(--text3);font-style:italic;font-size:.85rem;padding:.5rem 0}

.report-footer{text-align:center;padding:2rem 0;color:var(--text3);font-size:.78rem;
  border-top:1px solid var(--border);margin-top:3rem}

/* Enrichment */
.enr-provider-tag{display:inline-block;padding:.1rem .45rem;border-radius:4px;
  font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
  background:var(--indigo-bg);color:#c7d2fe;margin-left:.4rem}
.enr-err{color:var(--red);font-size:.78rem}
"""

_JS = """
document.querySelectorAll('.platform-header').forEach(h => {
  h.addEventListener('click', () => {
    const card = h.closest('.platform-card');
    if (card.querySelector('.platform-body')) {
      card.classList.toggle('open');
    }
  });
});
document.querySelectorAll('.pivot-header').forEach(h => {
  h.addEventListener('click', () => {
    const card = h.closest('.pivot-card');
    card.classList.toggle('open');
  });
});
document.querySelectorAll('.platform-card[data-has-detail]').forEach(c => {
  c.classList.add('open');
});
"""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_stat_pill(label: str, value: Any) -> str:
    return f'<div class="stat-pill">{_e(label)}: <strong>{_e(str(value))}</strong></div>'


def _render_identity_section(intel: dict) -> str:
    clues   = intel.get("identity_clues", {})
    discord = intel.get("discord", {})
    scores  = intel.get("confidence_scores", [])

    rows: list[str] = []

    names: list[tuple[str, str]] = []
    for key, entry in clues.items():
        val, src = _unpack(entry)
        if key.startswith("name_") and val:
            names.append((val, src))

    disc_user_entry = discord.get("username")
    if disc_user_entry:
        disc_user, _ = _unpack(disc_user_entry)
        if disc_user:
            rows.append(
                f'<div class="identity-card">'
                f'<div class="label">Discord Handle</div>'
                f'<div class="value">💬 {_e(disc_user)}</div>'
                f'</div>'
            )

    acc_created_entry = discord.get("account_created")
    if acc_created_entry:
        acc_val, _ = _unpack(acc_created_entry)
        if acc_val:
            rows.append(
                f'<div class="identity-card">'
                f'<div class="label">Account Created</div>'
                f'<div class="value">{_e(str(acc_val))}</div>'
                f'</div>'
            )

    for name_val, name_src in names[:6]:
        rows.append(
            f'<div class="identity-card">'
            f'<div class="label">Name Clue</div>'
            f'<div class="value">👤 {_e(name_val)}</div>'
            f'<div class="source">via {_e(name_src)}</div>'
            f'</div>'
        )

    loc_entry = clues.get("inferred_location")
    if loc_entry:
        loc_val, _ = _unpack(loc_entry)
        if loc_val:
            rows.append(
                f'<div class="identity-card">'
                f'<div class="label">Location</div>'
                f'<div class="value">📍 {_e(loc_val)}</div>'
                f'</div>'
            )

    lang_entry = clues.get("language")
    if lang_entry:
        lang_val, _ = _unpack(lang_entry)
        if lang_val:
            rows.append(
                f'<div class="identity-card">'
                f'<div class="label">Language</div>'
                f'<div class="value">🗣 {_e(str(lang_val))}</div>'
                f'</div>'
            )

    if scores and isinstance(scores, list):
        top = scores[0] if isinstance(scores[0], dict) else {}
        top_name  = top.get("name", "")
        top_score = top.get("score", 0)
        if top_name:
            pct = int(float(top_score) * 100) if float(top_score) <= 1 else int(top_score)
            rows.append(
                f'<div class="identity-card">'
                f'<div class="label">Identity Confidence</div>'
                f'<div class="value">{_e(top_name)}</div>'
                f'<div class="confidence-bar">'
                f'<div class="confidence-fill" style="width:{pct}%"></div>'
                f'</div>'
                f'<div class="source">{pct}% confidence</div>'
                f'</div>'
            )

    if not rows:
        return '<div class="empty">No identity clues collected.</div>'

    return f'<div class="identity-grid">{"".join(rows)}</div>'


def _render_persona_section(intel: dict) -> str:
    persona_entry = intel.get("persona_summary", {}).get("persona")
    if not persona_entry:
        return ""

    persona_text, _ = _unpack(persona_entry)
    if not persona_text:
        return ""

    return f"""
    <div class="section">
      <div class="section-title"><span class="icon">🧑</span>Persona Summary (AI)</div>
      <div class="narrative-card" style="max-width:100%;">
        <p>{_e(persona_text)}</p>
      </div>
    </div>"""


def _render_platform_card(platform: str, data: dict) -> str:
    icon     = _platform_icon(platform)
    label    = _platform_label(platform)
    usernames = data.get("usernames", [])
    urls      = data.get("urls", [])
    bio       = data.get("bio", "")
    blog      = data.get("blog", "")
    location  = data.get("location", "")
    email     = data.get("email", "")
    followers = data.get("followers", "")
    created   = data.get("created", "")
    extra     = data.get("extra", {})

    primary_username = usernames[0] if usernames else (
        urls[0].split("/")[-1] if urls else ""
    )

    has_detail = bool(bio or location or email or followers or created
                      or extra or len(usernames) > 1 or len(urls) > 0)

    rows: list[str] = []

    if usernames:
        handles = " · ".join(_e(u) for u in usernames[:5])
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">Handle</span>'
            f'<span class="data-value">{handles}</span>'
            f'</div>'
        )

    if urls:
        links = " ".join(
            f'<a href="{_safe_href(u)}" target="_blank" '
            f'rel="noopener noreferrer">{_e(u[:60])}{"…" if len(u) > 60 else ""}</a>'
            for u in urls[:3]
        )
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">Profile URL</span>'
            f'<span class="data-value">{links}</span>'
            f'</div>'
        )

    if created:
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">Created</span>'
            f'<span class="data-value">📅 {_e(created)}</span>'
            f'</div>'
        )

    if location:
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">Location</span>'
            f'<span class="data-value">📍 {_e(location)}</span>'
            f'</div>'
        )

    if email:
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">Email</span>'
            f'<span class="data-value">✉️ {_e(email)}</span>'
            f'</div>'
        )

    if followers:
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">Followers</span>'
            f'<span class="data-value">👥 {_e(followers)}</span>'
            f'</div>'
        )

    if blog:
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">Blog/Link</span>'
            f'<span class="data-value">'
            f'<a href="{_safe_href(blog)}" target="_blank" '
            f'rel="noopener noreferrer">{_e(blog[:60])}</a>'
            f'</span>'
            f'</div>'
        )

    for k, v in list(extra.items())[:8]:
        rows.append(
            f'<div class="data-row">'
            f'<span class="data-label">{_e(k[:18])}</span>'
            f'<span class="data-value">{_e(v[:120])}</span>'
            f'</div>'
        )

    avatar = data.get("avatar", "")
    avatar_html = ""
    safe_avatar = _safe_img_src(avatar) if avatar else ""
    if safe_avatar:
        avatar_html = (
            f'<div style="text-align:center;margin-bottom:.8rem">'
            f'<img src="{safe_avatar}" alt="Profile avatar" '
            f'style="max-width:120px;max-height:120px;border-radius:50%;'
            f'border:2px solid var(--border2);display:inline-block"'
            f' onerror="this.style.display=\'none\'">'
            f'</div>'
        )

    bio_html = ""
    if bio:
        bio_html = f'<div class="bio-text">{_e(bio)}</div>'

    body_html = (
        f'<div class="platform-body">'
        f'{avatar_html}'
        f'{"".join(rows)}'
        f'{bio_html}'
        f'</div>'
    )

    has_detail_attr = 'data-has-detail="1"' if has_detail else ""
    return (
        f'<div class="platform-card" {has_detail_attr}>'
        f'<div class="platform-header">'
        f'<span class="platform-icon">{icon}</span>'
        f'<span class="platform-name">{_e(label)}</span>'
        f'<span class="platform-username">{_e(primary_username)}</span>'
        f'<span class="platform-arrow">▼</span>'
        f'</div>'
        f'{body_html}'
        f'</div>'
    )


def _render_profiles_section(intel: dict) -> str:
    profiles = _parse_social_profiles(intel)
    if not profiles:
        return '<div class="empty">No social profiles found.</div>'
    cards = [_render_platform_card(plat, data) for plat, data in sorted(profiles.items())]
    return f'<div class="cards-grid">{"".join(cards)}</div>'


def _render_email_section(intel: dict) -> str:
    emails_intel   = intel.get("emails", {})
    breaches_intel = intel.get("breaches", {})

    if not emails_intel:
        return '<div class="empty">No emails collected.</div>'

    parts: list[str] = []
    for _key, entry in emails_intel.items():
        email_val, src = _unpack(entry)
        if not email_val or "@" not in email_val:
            continue

        email_lower = email_val.lower()
        holehe_sites: list[str] = []
        hibp_sites:   list[str] = []

        for bk, bv in breaches_intel.items():
            bv_raw, _ = _unpack(bv)
            if not bv_raw:
                continue

            if email_lower in bk.lower():
                if "holehe_" in bk:
                    try:
                        data = json.loads(bv_raw) if isinstance(bv_raw, str) else bv_raw
                        if isinstance(data, dict):
                            holehe_sites.extend(data.get("used_on", [])[:10])
                    except Exception:
                        pass
                elif "hibp_" in bk:
                    try:
                        data = json.loads(bv_raw) if isinstance(bv_raw, str) else bv_raw
                        if isinstance(data, list):
                            hibp_sites.extend(
                                b.get("Name", str(b))[:30]
                                for b in data[:10] if isinstance(b, dict)
                            )
                    except Exception:
                        pass

        breach_html = ""
        if hibp_sites:
            tags = "".join(f'<span class="breach-tag">{_e(s)}</span>' for s in hibp_sites[:8])
            breach_html += f'<div style="margin-top:.5rem">' \
                           f'<span style="font-size:.72rem;color:#ef4444;font-weight:700;margin-right:.3rem">HIBP:</span>' \
                           f'{tags}</div>'
        if holehe_sites:
            tags = "".join(f'<span class="site-tag">{_e(s)}</span>' for s in holehe_sites[:10])
            breach_html += f'<div style="margin-top:.35rem">' \
                           f'<span style="font-size:.72rem;color:#7aa2f7;font-weight:700;margin-right:.3rem">Registered on:</span>' \
                           f'{tags}</div>'

        total_breaches = len(hibp_sites) + len(holehe_sites)
        badge_html = f'<span class="risk-badge risk-high">{total_breaches} breach{"es" if total_breaches!=1 else ""}</span>' \
                     if total_breaches > 0 else '<span class="risk-badge risk-info">no breaches found</span>'

        mosint_text = ""
        mosint_data = intel.get("mosint", {}).get(email_lower)
        if mosint_data:
            flags = []
            for site in ("spotify", "twitter", "instagram"):
                if mosint_data.get(f"{site}_exists"):
                    flags.append(f"{site.title()} ✓")
            if flags:
                mosint_text = (
                    f'<div style="margin-top:0.35rem">'
                    f'<span style="font-size:.72rem;color:#a5b4fc;font-weight:700;margin-right:.3rem">MOSINT:</span>'
                    + " ".join(f'<span class="site-tag">{f}</span>' for f in flags)
                    + f'</div>'
                )

        parts.append(
            f'<div class="email-card">'
            f'<div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap">'
            f'<span class="email-address">✉️ {_e(email_val)}</span>'
            f'{badge_html}'
            f'<span style="font-size:.72rem;color:var(--text3)">via {_e(src)}</span>'
            f'</div>'
            f'{breach_html}'
            f'{mosint_text}'
            f'</div>'
        )

    return "".join(parts) if parts else '<div class="empty">No emails collected.</div>'


def _render_intelligence_section(intel: dict) -> str:
    report = intel.get("intelligence_report", {})
    if not report:
        return '<div class="empty">Intelligence engine did not run or produced no output.</div>'

    narrative     = report.get("narrative", {})
    correlations  = report.get("correlations", [])
    entity_counts = report.get("entity_counts", {})
    g_summary     = report.get("graph_summary", {})

    parts: list[str] = []

    if entity_counts:
        pills = "".join(
            _render_stat_pill(k, v)
            for k, v in entity_counts.items()
        )
        pills += _render_stat_pill("Graph nodes", g_summary.get("total_nodes", 0))
        pills += _render_stat_pill("Graph edges", g_summary.get("total_edges", 0))
        parts.append(f'<div class="stats-bar">{pills}</div>')

    if narrative:
        _card_defs = [
            ("executive_summary",   "📋 Executive Summary"),
            ("identity_assessment", "🪪 Identity Assessment"),
            ("digital_footprint",   "🌐 Digital Footprint"),
            ("risk_indicators",     "⚠️ Risk Indicators"),
        ]
        cards_html: list[str] = []
        for key, title in _card_defs:
            val = narrative.get(key, "")
            if val:
                cards_html.append(
                    f'<div class="narrative-card">'
                    f'<h4>{title}</h4>'
                    f'<p>{_e(str(val))}</p>'
                    f'</div>'
                )
        if cards_html:
            parts.append(f'<div class="narrative-grid">{"".join(cards_html)}</div>')

        critical = narrative.get("critical_points", [])
        if critical:
            items = "".join(f'<li>{_e(str(pt))}</li>' for pt in critical)
            parts.append(
                f'<div class="narrative-card" style="margin-bottom:1rem">'
                f'<h4>🎯 Critical Points</h4>'
                f'<ul class="critical-list">{items}</ul>'
                f'</div>'
            )

    if correlations:
        parts.append('<h4 style="font-size:.85rem;color:#94a3b8;margin:.75rem 0 .4rem">Correlations</h4>')
        for c in correlations:
            conf  = c.get("confidence", 0.0)
            ctype = c.get("type", "")
            desc  = c.get("description", "")
            cls   = "conf-high" if conf >= 0.75 else "conf-med" if conf >= 0.50 else "conf-low"
            parts.append(
                f'<div class="corr-item">'
                f'<span class="corr-badge {cls}">{_e(ctype)}</span>'
                f'<span class="corr-desc">{_e(desc)} <em style="color:#6366f1">({conf:.0%})</em></span>'
                f'</div>'
            )

    return "".join(parts) if parts else '<div class="empty">No intelligence data.</div>'


def _render_pivot_section(intel: dict) -> str:
    pivot_reports = intel.get("pivot_reports", [])
    if not pivot_reports:
        return ""

    parts: list[str] = []
    for pr in pivot_reports:
        seed      = pr.get("seed", "")
        seed_type = pr.get("seed_type", "")
        depth     = pr.get("depth", "?")
        report    = pr.get("report", {})
        ec        = report.get("entity_counts", {})
        corrs     = report.get("correlations", [])
        narrative = report.get("narrative", {})
        total_e   = sum(ec.values())
        icon      = "✉️" if seed_type == "email" else "👤"
        exec_sum  = narrative.get("executive_summary", "")

        body_parts: list[str] = []
        if exec_sum:
            body_parts.append(
                f'<div class="narrative-card" style="margin-bottom:.75rem">'
                f'<h4>Executive Summary</h4><p>{_e(exec_sum)}</p>'
                f'</div>'
            )
        if ec:
            pills = "".join(_render_stat_pill(k, v) for k, v in ec.items())
            body_parts.append(f'<div class="stats-bar">{pills}</div>')
        if corrs:
            for c in corrs[:5]:
                conf  = c.get("confidence", 0.0)
                ctype = c.get("type", "")
                desc  = c.get("description", "")
                cls   = "conf-high" if conf >= 0.75 else "conf-med" if conf >= 0.50 else "conf-low"
                body_parts.append(
                    f'<div class="corr-item">'
                    f'<span class="corr-badge {cls}">{_e(ctype)}</span>'
                    f'<span class="corr-desc">{_e(desc[:120])}</span>'
                    f'</div>'
                )

        parts.append(
            f'<div class="pivot-card">'
            f'<div class="pivot-header">'
            f'<span style="font-size:1rem">{icon}</span>'
            f'<span class="pivot-seed">{_e(seed)}</span>'
            f'<span class="pivot-depth-badge">depth {depth}</span>'
            f'<span style="color:#4ade80;font-size:.75rem;margin-left:auto">'
            f'{total_e} entities · {len(corrs)} correlations</span>'
            f'<span style="color:#4a5568;font-size:.7rem;margin-left:.5rem">▼</span>'
            f'</div>'
            f'<div class="pivot-body">{"".join(body_parts)}</div>'
            f'</div>'
        )

    return "".join(parts)


def _render_technical_section(intel: dict) -> str:
    parts: list[str] = []

    dns = intel.get("dns", {})
    if dns:
        for domain_key, entry in list(dns.items())[:5]:
            if domain_key.endswith("_ip") or domain_key.endswith("_geo"):
                continue
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(data, dict):
                        rows = []
                        for rtype, records in data.items():
                            rows.append(f'<div class="data-row"><span class="data-label">{rtype}</span><span class="data-value">{", ".join(records[:5])}</span></div>')
                        parts.append(
                            f'<div class="tech-card">'
                            f'<h4>📡 DNS · {_e(domain_key)}</h4>'
                            f'{"".join(rows)}'
                            f'</div>'
                        )
                except Exception:
                    pass

    ssl_info = intel.get("ssl", {})
    if ssl_info:
        for domain_key, entry in list(ssl_info.items())[:5]:
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(data, dict):
                        rows = []
                        for k, v in data.items():
                            rows.append(f'<div class="data-row"><span class="data-label">{k.replace("_", " ").title()}</span><span class="data-value">{_e(str(v))}</span></div>')
                        parts.append(
                            f'<div class="tech-card">'
                            f'<h4>🔒 SSL Certificate · {_e(domain_key)}</h4>'
                            f'{"".join(rows)}'
                            f'</div>'
                        )
                except Exception:
                    pass

    for key, entry in intel.get("dns", {}).items():
        if key.endswith("_geo"):
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(data, dict):
                        rows = []
                        for k, v in data.items():
                            rows.append(f'<div class="data-row"><span class="data-label">{k.replace("_", " ").title()}</span><span class="data-value">{_e(str(v))}</span></div>')
                        parts.append(
                            f'<div class="tech-card">'
                            f'<h4>📍 IP Geolocation</h4>'
                            f'{"".join(rows)}'
                            f'</div>'
                        )
                except Exception:
                    pass

    subdomains = intel.get("subdomains", {})
    if subdomains:
        for domain_key, entry in subdomains.items():
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(data, list):
                        tags = "".join(f'<span class="site-tag">{_e(s)}</span>' for s in data[:30])
                        parts.append(
                            f'<div class="tech-card">'
                            f'<h4>🌐 Subdomains · {_e(domain_key)}</h4>'
                            f'<div style="display:flex;flex-wrap:wrap;gap:.3rem">{tags}</div>'
                            f'</div>'
                        )
                except Exception:
                    pass

    harvester_emails = intel.get("harvester_emails", {})
    if harvester_emails:
        for domain_key, entry in harvester_emails.items():
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    emails = data.get("emails", [])
                    if emails:
                        email_list = "".join(f'<span class="site-tag">{_e(e)}</span>' for e in emails[:15])
                        parts.append(
                            f'<div class="tech-card">'
                            f'<h4>📧 theHarvester Emails · {_e(domain_key)}</h4>'
                            f'<div style="display:flex;flex-wrap:wrap;gap:.3rem">{email_list}</div>'
                            f'</div>'
                        )
                except Exception:
                    pass

    harvester_hosts = intel.get("harvester_hosts", {})
    if harvester_hosts:
        for domain_key, entry in harvester_hosts.items():
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    hosts = data.get("hosts", [])
                    if hosts:
                        host_list = "".join(f'<span class="site-tag">{_e(h)}</span>' for h in hosts[:15])
                        parts.append(
                            f'<div class="tech-card">'
                            f'<h4>🌐 theHarvester Hosts · {_e(domain_key)}</h4>'
                            f'<div style="display:flex;flex-wrap:wrap;gap:.3rem">{host_list}</div>'
                            f'</div>'
                        )
                except Exception:
                    pass

    whois = intel.get("whois", {})
    if whois:
        for domain, entry in list(whois.items())[:5]:
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(data, dict):
                        rows = []
                        for field, label in [
                            ("registrar", "Registrar"),
                            ("creation_date", "Creation Date"),
                            ("expiry_date", "Expiry Date"),
                            ("registrant_org", "Registrant Organization"),
                            ("registrant_country", "Registrant Country"),
                            ("dnssec", "DNSSEC"),
                        ]:
                            if data.get(field):
                                rows.append(f'<div class="data-row"><span class="data-label">{label}</span><span class="data-value">{_e(str(data[field]))}</span></div>')
                        if data.get("name_servers") and isinstance(data["name_servers"], list):
                            ns = ", ".join(data["name_servers"][:8])
                            rows.append(f'<div class="data-row"><span class="data-label">Name Servers</span><span class="data-value">{_e(ns)}</span></div>')
                        if data.get("domain_status") and isinstance(data["domain_status"], list):
                            statuses = ", ".join(data["domain_status"][:5])
                            rows.append(f'<div class="data-row"><span class="data-label">Domain Status</span><span class="data-value">{_e(statuses)}</span></div>')

                        if rows:
                            parts.append(
                                f'<div class="tech-card">'
                                f'<h4>WHOIS · {_e(domain)}</h4>'
                                f'{"".join(rows)}'
                                f'</div>'
                            )
                        else:
                            parts.append(
                                f'<div class="tech-card">'
                                f'<h4>WHOIS · {_e(domain)}</h4>'
                                f'<div class="mono">{_e(str(val)[:500])}</div>'
                                f'</div>'
                            )
                except Exception:
                    parts.append(
                        f'<div class="tech-card">'
                        f'<h4>WHOIS · {_e(domain)}</h4>'
                        f'<div class="mono">{_e(str(val)[:500])}</div>'
                        f'</div>'
                    )

    phone = intel.get("phone", {})
    if phone:
        rows = []
        def _get_phone_val(field: str) -> str:
            entry = phone.get(field)
            if entry and isinstance(entry, dict):
                return _unpack(entry)[0]
            return ""

        number = _get_phone_val("number")
        if number:
            rows.append(f'<div class="data-row"><span class="data-label">Number</span><span class="data-value">{_e(number)}</span></div>')
        e164 = _get_phone_val("e164")
        if e164:
            rows.append(f'<div class="data-row"><span class="data-label">E.164</span><span class="data-value">{_e(e164)}</span></div>')
        is_valid = _get_phone_val("is_valid")
        if is_valid:
            rows.append(f'<div class="data-row"><span class="data-label">Valid</span><span class="data-value">{_e(is_valid)}</span></div>')
        num_type = _get_phone_val("number_type")
        if num_type:
            rows.append(f'<div class="data-row"><span class="data-label">Type</span><span class="data-value">{_e(num_type)}</span></div>')
        country = _get_phone_val("country")
        if country:
            rows.append(f'<div class="data-row"><span class="data-label">Country</span><span class="data-value">{_e(country)}</span></div>')
        carrier = _get_phone_val("carrier")
        if carrier:
            rows.append(f'<div class="data-row"><span class="data-label">Carrier (phonenumbers)</span><span class="data-value">{_e(carrier)}</span></div>')

        carrier_lookup = phone.get("carrier_lookup")
        if carrier_lookup and isinstance(carrier_lookup, dict):
            val, _ = _unpack(carrier_lookup)
            if val:
                try:
                    if isinstance(val, str):
                        data = json.loads(val)
                    else:
                        data = val
                    if isinstance(data, dict):
                        if data.get("carrier"):
                            rows.append(f'<div class="data-row"><span class="data-label">Carrier (API)</span><span class="data-value">{_e(data["carrier"])}</span></div>')
                        if data.get("country_name"):
                            rows.append(f'<div class="data-row"><span class="data-label">Country (API)</span><span class="data-value">{_e(data["country_name"])}</span></div>')
                        if data.get("line_type"):
                            rows.append(f'<div class="data-row"><span class="data-label">Line Type</span><span class="data-value">{_e(data["line_type"])}</span></div>')
                except Exception:
                    pass

        if rows:
            parts.append(
                f'<div class="tech-card">'
                f'<h4>📞 Phone Investigation</h4>'
                f'{"".join(rows)}'
                f'</div>'
            )

    url_intel = intel.get("url_intel", {})
    if url_intel:
        rows = []
        http_meta = url_intel.get("http_meta")
        if http_meta and isinstance(http_meta, dict):
            val, _ = _unpack(http_meta)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(data, dict):
                        if data.get("status_code"):
                            rows.append(f'<div class="data-row"><span class="data-label">HTTP Status</span><span class="data-value">{_e(str(data["status_code"]))}</span></div>')
                        if data.get("final_url"):
                            rows.append(
                                f'<div class="data-row">'
                                f'<span class="data-label">Final URL</span>'
                                f'<span class="data-value">'
                                f'<a href="{_safe_href(data["final_url"])}" '
                                f'target="_blank" rel="noopener noreferrer">'
                                f'{_e(data["final_url"])}</a>'
                                f'</span></div>'
                            )
                        if data.get("redirect_chain") and isinstance(data["redirect_chain"], list):
                            chain = " → ".join(data["redirect_chain"][:5])
                            rows.append(f'<div class="data-row"><span class="data-label">Redirects</span><span class="data-value">{_e(chain)}</span></div>')
                        extra_headers = []
                        if data.get("server"):
                            extra_headers.append(f"Server: {data['server']}")
                        if data.get("x_powered_by"):
                            extra_headers.append(f"X-Powered-By: {data['x_powered_by']}")
                        if data.get("last_modified"):
                            extra_headers.append(f"Last-Modified: {data['last_modified']}")
                        if data.get("strict_transport"):
                            extra_headers.append(f"HSTS: {data['strict_transport']}")
                        if extra_headers:
                            rows.append(f'<div class="data-row"><span class="data-label">Extra Headers</span><span class="data-value">{_e(" · ".join(extra_headers))}</span></div>')
                        if data.get("content_type"):
                            rows.append(f'<div class="data-row"><span class="data-label">Content Type</span><span class="data-value">{_e(data["content_type"])}</span></div>')
                except Exception:
                    pass

        page_meta = url_intel.get("page_meta")
        has_metadata = False
        if page_meta and isinstance(page_meta, dict):
            val, _ = _unpack(page_meta)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    if isinstance(data, dict):
                        if data.get("title"):
                            rows.append(f'<div class="data-row"><span class="data-label">Title</span><span class="data-value">{_e(data["title"][:200])}</span></div>')
                            has_metadata = True
                        if data.get("description"):
                            rows.append(f'<div class="data-row"><span class="data-label">Description</span><span class="data-value">{_e(data["description"][:200])}</span></div>')
                            has_metadata = True
                        og = data.get("og")
                        if og and isinstance(og, dict):
                            if og.get("og:image"):
                                rows.append(
                                    f'<div class="data-row">'
                                    f'<span class="data-label">OG Image</span>'
                                    f'<span class="data-value">'
                                    f'<a href="{_safe_href(og["og:image"])}" '
                                    f'target="_blank" rel="noopener noreferrer">Preview</a>'
                                    f'</span></div>'
                                )
                                has_metadata = True
                except Exception:
                    pass

        http_status = None
        if http_meta and isinstance(http_meta, dict):
            val, _ = _unpack(http_meta)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    http_status = data.get("status_code")
                except Exception:
                    pass
        if not has_metadata and http_status and http_status != 200:
            rows.append(f'<div class="data-row"><span class="data-label">Note</span><span class="data-value">Page returned status {http_status} – no metadata could be extracted.</span></div>')
        elif not has_metadata:
            rows.append(f'<div class="data-row"><span class="data-label">Note</span><span class="data-value">No page metadata (title/description) found.</span></div>')

        domain = url_intel.get("domain")
        if domain and isinstance(domain, dict):
            val, _ = _unpack(domain)
            if val:
                rows.append(f'<div class="data-row"><span class="data-label">Domain</span><span class="data-value">{_e(val)}</span></div>')

        interesting_links = url_intel.get("interesting_links")
        if interesting_links and isinstance(interesting_links, dict):
            val, _ = _unpack(interesting_links)
            if val:
                try:
                    links = json.loads(val) if isinstance(val, str) else val
                    if isinstance(links, list) and links:
                        link_tags = "".join(
                            f'<span class="site-tag">'
                            f'<a href="{_safe_href(link)}" target="_blank" '
                            f'rel="noopener noreferrer">{_e(link[:60])}</a>'
                            f'</span>'
                            for link in links[:10]
                        )
                        rows.append(f'<div class="data-row"><span class="data-label">Interesting Links</span><span class="data-value">{link_tags}</span></div>')
                except Exception:
                    pass

        emails = intel.get("emails", {})
        if emails:
            email_tags = []
            for key, entry in list(emails.items())[:5]:
                email_val, _ = _unpack(entry)
                if email_val:
                    email_tags.append(f'<span class="site-tag">{_e(email_val)}</span>')
            if email_tags:
                rows.append(f'<div class="data-row"><span class="data-label">Emails Found</span><span class="data-value">{"".join(email_tags)}</span></div>')

        if rows:
            parts.append(
                f'<div class="tech-card">'
                f'<h4>🌐 URL Analysis</h4>'
                f'{"".join(rows)}'
                f'</div>'
            )

    wayback = intel.get("wayback", {})
    if wayback:
        rows = []
        for url, entry in list(wayback.items())[:5]:
            val, _ = _unpack(entry)
            if val:
                rows.append(
                    f'<div class="data-row">'
                    f'<span class="data-label">URL</span>'
                    f'<span class="data-value">'
                    f'<a href="{_safe_href(str(val))}" target="_blank" '
                    f'rel="noopener noreferrer">{_e(url[:60])}</a>'
                    f'</span>'
                    f'</div>'
                )
        if rows:
            parts.append(
                f'<div class="tech-card">'
                f'<h4>⏮ Wayback Machine Snapshots</h4>'
                f'{"".join(rows)}'
                f'</div>'
            )

    media = intel.get("media", {})
    if media:
        gps_rows = []
        for key, entry in media.items():
            if "exif_gps" in key:
                val, _ = _unpack(entry)
                if val:
                    gps_rows.append(
                        f'<div class="data-row">'
                        f'<span class="data-label">GPS</span>'
                        f'<span class="data-value">📍 {_e(str(val))}</span>'
                        f'</div>'
                    )
        if gps_rows:
            parts.append(
                f'<div class="tech-card">'
                f'<h4>📷 EXIF Data</h4>'
                f'{"".join(gps_rows)}'
                f'</div>'
            )

    ghunt = intel.get("ghunt", {})
    if ghunt:
        for email_key, entry in list(ghunt.items())[:3]:
            val, _ = _unpack(entry)
            if val:
                try:
                    data = json.loads(val) if isinstance(val, str) else val
                    data_str = json.dumps(data, indent=2)[:600] if isinstance(data, dict) else str(val)[:400]
                except Exception:
                    data_str = str(val)[:400]
                parts.append(
                    f'<div class="tech-card">'
                    f'<h4>🔍 GHunt · {_e(email_key)}</h4>'
                    f'<div class="mono">{_e(data_str)}</div>'
                    f'</div>'
                )

    return "".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Contact-enrichment section renderers
# ---------------------------------------------------------------------------

def _render_enrichment_profile_card(provider: str, person: dict) -> str:
    """Render one enriched contact (Apollo or Lusha) as a card."""
    if not isinstance(person, dict):
        return ""

    name_parts = [
        person.get("first_name") or person.get("firstName") or "",
        person.get("last_name")  or person.get("lastName")  or "",
    ]
    full_name = " ".join(p for p in name_parts if p).strip() or \
                person.get("name") or "Unknown"

    title    = person.get("title") or person.get("jobTitle") or ""
    city     = person.get("city") or ""
    state    = person.get("state") or ""
    country  = person.get("country") or ""
    location = ", ".join(str(x) for x in (city, state, country) if x)

    linkedin = person.get("linkedin_url") or person.get("linkedinUrl") or ""

    org = person.get("organization") or {}
    company = ""
    if isinstance(org, dict):
        company = org.get("name") or ""
    company = company or person.get("companyName") or person.get("company") or ""

    emails: list[str] = []
    for key in ("email", "emailAddress", "emails", "emailAddresses"):
        val = person.get(key)
        if isinstance(val, str) and "@" in val:
            emails.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and "@" in item:
                    emails.append(item)
                elif isinstance(item, dict):
                    e = item.get("emailAddress") or item.get("email")
                    if isinstance(e, str) and "@" in e:
                        emails.append(e)

    phones: list[str] = []
    for key in ("phone", "phoneNumber", "phones", "phoneNumbers"):
        val = person.get(key)
        if isinstance(val, str) and val.strip():
            phones.append(val.strip())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    phones.append(item.strip())
                elif isinstance(item, dict):
                    p = item.get("phoneNumber") or item.get("number")
                    if isinstance(p, str) and p.strip():
                        phones.append(p.strip())

    rows: list[str] = []
    if title:
        rows.append(f'<div class="data-row"><span class="data-label">Title</span><span class="data-value">{_e(title)}</span></div>')
    if company:
        rows.append(f'<div class="data-row"><span class="data-label">Company</span><span class="data-value">{_e(company)}</span></div>')
    if location:
        rows.append(f'<div class="data-row"><span class="data-label">Location</span><span class="data-value">📍 {_e(location)}</span></div>')
    if linkedin:
        rows.append(
            f'<div class="data-row"><span class="data-label">LinkedIn</span>'
            f'<span class="data-value"><a href="{_safe_href(linkedin)}" '
            f'target="_blank" rel="noopener noreferrer">'
            f'{_e(linkedin[:80])}</a></span></div>'
        )
    for email in dict.fromkeys(emails):
        rows.append(f'<div class="data-row"><span class="data-label">Email</span><span class="data-value">✉️ {_e(email)}</span></div>')
    for phone in dict.fromkeys(phones):
        rows.append(f'<div class="data-row"><span class="data-label">Phone</span><span class="data-value">📞 {_e(phone)}</span></div>')

    if not rows:
        return ""

    icon = "🅰️" if provider == "apollo" else "🅻"
    return (
        f'<div class="platform-card" data-has-detail="1">'
        f'<div class="platform-header" style="cursor:default">'
        f'<span class="platform-icon">{icon}</span>'
        f'<span class="platform-name">{_e(full_name[:60])}</span>'
        f'<span class="platform-username">{_e(title[:30])}</span>'
        f'</div>'
        f'<div class="platform-body">{"".join(rows)}</div>'
        f'</div>'
    )


def _render_enrichment_section(intel: dict) -> str:
    """
    Matched Apollo / Lusha profiles, plus the spend summary.

    Returns "" when the enrichment stage did not run.
    """
    profiles = intel.get("enrichment_profiles") or {}
    spend    = intel.get("enrichment_spend") or {}
    if not profiles and not spend:
        return ""

    parts: list[str] = []

    # Spend summary pills.
    if spend:
        pills: list[str] = []
        for provider, info in spend.items():
            if not isinstance(info, dict):
                continue
            matched = info.get("matched", 0)
            credits = info.get("credits", 0.0)
            pills.append(_render_stat_pill(f"{provider.title()} matched", matched))
            try:
                pills.append(_render_stat_pill(
                    f"{provider.title()} credits", f"{float(credits):g}",
                ))
            except (TypeError, ValueError):
                pass
            err = info.get("error")
            if err:
                pills.append(
                    f'<div class="stat-pill"><span class="enr-err">'
                    f'{_e(provider.title())}: {_e(str(err)[:80])}'
                    f'</span></div>'
                )
        if pills:
            parts.append(f'<div class="stats-bar">{"".join(pills)}</div>')

    # Per-provider profile cards.
    for provider, people in profiles.items():
        if not people:
            continue
        cards = [
            _render_enrichment_profile_card(provider, p)
            for p in people if isinstance(p, dict)
        ]
        cards = [c for c in cards if c]
        if not cards:
            continue
        parts.append(
            f'<h4 style="font-size:.85rem;color:#94a3b8;margin:.75rem 0 .4rem">'
            f'{_e(provider.title())} matches ({len(cards)})'
            f'<span class="enr-provider-tag">{_e(provider)}</span>'
            f'</h4>'
        )
        parts.append(f'<div class="cards-grid">{"".join(cards)}</div>')

    return "".join(parts) if parts else ""


def _render_enrichment_rejections(intel: dict) -> str:
    """
    Collapsed audit block listing every identifier the trust filter
    rejected, per provider, with its one-line reason.
    """
    decisions = intel.get("enrichment_decisions") or {}
    if not decisions:
        return ""

    rows: list[str] = []
    total_rejected = 0

    for provider, entries in decisions.items():
        if not isinstance(entries, list):
            continue
        rejected = [e for e in entries if isinstance(e, dict) and not e.get("accepted")]
        if not rejected:
            continue
        total_rejected += len(rejected)

        inner: list[str] = []
        for entry in rejected:
            kind   = _e(str(entry.get("kind", "")))
            value  = _e(str(entry.get("value", ""))[:120])
            reason = _e(str(entry.get("reason", "")))
            inner.append(
                f'<div class="data-row">'
                f'<span class="data-label">{kind}</span>'
                f'<span class="data-value">'
                f'<code style="color:#a5b4fc">{value}</code>'
                f'<span style="color:var(--text3);margin-left:.5rem">— {reason}</span>'
                f'</span></div>'
            )

        rows.append(
            f'<details style="margin-bottom:.75rem">'
            f'<summary style="cursor:pointer;color:var(--text2);font-size:.85rem">'
            f'{_e(provider)}: {len(rejected)} identifier(s) rejected by the trust filter'
            f'</summary>'
            f'<div style="margin-top:.5rem">{"".join(inner)}</div>'
            f'</details>'
        )

    if not rows:
        return ""

    return f"""
    <div class="section">
      <div class="section-title"><span class="icon">🚫</span>Rejected Identifiers ({total_rejected})</div>
      <p style="font-size:.8rem;color:var(--text3);margin-bottom:.75rem">
        These identifiers were evaluated but not submitted to the enabled
        provider(s). Each carries the reason the trust filter rejected it.
      </p>
      {"".join(rows)}
    </div>"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_html_report(intel_core: Any, target_id: Any) -> str:
    """
    Generate a complete, self-contained dark-themed HTML report.
    """
    intel = intel_core.intel if hasattr(intel_core, "intel") else intel_core

    target_name = str(target_id)
    disc_user   = intel.get("discord", {}).get("username")
    if disc_user:
        val, _ = _unpack(disc_user)
        if val:
            target_name = val

    email_count   = len(intel.get("emails", {}))
    profile_count = len(_parse_social_profiles(intel))
    breach_count  = len(intel.get("breaches", {}))
    pivot_count   = len(intel.get("pivot_reports", []))
    has_intel     = bool(intel.get("intelligence_report"))
    has_enrich    = bool(intel.get("enrichment_profiles") or intel.get("enrichment_spend"))
    generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    if breach_count > 5 or email_count > 3:
        risk_label, risk_class = "High", "risk-high"
    elif breach_count > 0 or profile_count > 5:
        risk_label, risk_class = "Medium", "risk-med"
    elif profile_count > 0 or email_count > 0:
        risk_label, risk_class = "Low", "risk-low"
    else:
        risk_label, risk_class = "Minimal", "risk-info"

    pivot_html    = _render_pivot_section(intel)
    pivot_section = ""
    if pivot_html:
        pivot_section = f"""
        <div class="section">
          <div class="section-title"><span class="icon">🔄</span>Pivot Sub-Investigations ({pivot_count})</div>
          {pivot_html}
        </div>"""

    tech_html    = _render_technical_section(intel)
    tech_section = ""
    if tech_html:
        tech_section = f"""
        <div class="section">
          <div class="section-title"><span class="icon">🔧</span>Technical Data</div>
          {tech_html}
        </div>"""

    enrichment_html    = _render_enrichment_section(intel)
    enrichment_section = ""
    if enrichment_html:
        enrichment_section = f"""
        <div class="section">
          <div class="section-title"><span class="icon">🛰</span>Contact Enrichment</div>
          {enrichment_html}
        </div>"""

    rejection_html = _render_enrichment_rejections(intel)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WhoCord Report – {_e(target_name)}</title>
  <style>{_CSS}</style>
</head>
<body>

  <div class="report-header">
    <h1>WhoCord Intelligence Report</h1>
    <div class="target">🎯 {_e(target_name)}</div>
    <div>
      <span class="risk-badge {risk_class}">{risk_label} Risk</span>
      {f'<span class="risk-badge risk-info">🧠 Intelligence</span>' if has_intel else ""}
      {f'<span class="risk-badge risk-info">🛰 Enriched</span>' if has_enrich else ""}
      {f'<span class="risk-badge risk-info">🔄 {pivot_count} Pivot{"s" if pivot_count!=1 else ""}</span>' if pivot_count else ""}
    </div>
    <div class="meta">Generated {generated_at} · WhoCord v1.1</div>
  </div>

  <div class="container">

    <div class="stats-bar">
      {_render_stat_pill("Emails", email_count)}
      {_render_stat_pill("Platforms", profile_count)}
      {_render_stat_pill("Breach records", breach_count)}
      {_render_stat_pill("Pivot branches", pivot_count)}
    </div>

    <div class="section">
      <div class="section-title"><span class="icon">👤</span>Identity</div>
      {_render_identity_section(intel)}
      {_render_persona_section(intel)}
    </div>

    <div class="section">
      <div class="section-title"><span class="icon">🔗</span>Social Profiles ({profile_count})</div>
      {_render_profiles_section(intel)}
    </div>

    <div class="section">
      <div class="section-title"><span class="icon">✉️</span>Email Intelligence ({email_count})</div>
      {_render_email_section(intel)}
    </div>

    <div class="section">
      <div class="section-title"><span class="icon">🧠</span>Intelligence Analysis</div>
      {_render_intelligence_section(intel)}
    </div>

    {enrichment_section}
    {rejection_html}
    {pivot_section}
    {tech_section}

    <div class="report-footer">
      WhoCord v1.1 · {_e(target_name)} · {generated_at}
    </div>

  </div>

  <script>{_JS}</script>
</body>
</html>"""