import json
import re
import os
import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from .scraping import looks_like_real_name_v2, is_valid_email
from .utils import CACHE_DIR

# -------------------------------------------------------------------
#  Identity confidence scoring (unchanged)
# -------------------------------------------------------------------
def calculate_identity_confidence(intel):
    dev_domains = {"github.com","gitlab.com","dev.to","hackerrank.com","hashnode.com","keybase.io","npmjs.com"}
    prof_domains = {"about.me","linkedin.com","patreon.com","buymeacoffee.com","ko-fi.com"}
    name_map = {}
    for key, entry in intel.get("identity_clues",{}).items():
        if not key.startswith("name_"): continue
        raw = entry.get("value","")
        if not looks_like_real_name_v2(raw): continue
        domain = key.split("/")[0].replace("name_github","github.com").replace("name_generic_https://","")
        if domain not in name_map: name_map[domain] = {}
        if raw not in name_map[domain]: name_map[domain][raw] = 0
        name_map[domain][raw] += 1

    candidates = {}
    for domain, names in name_map.items():
        for name, cnt in names.items():
            if name not in candidates: candidates[name] = {"count":0,"platforms":set(),"dev":0,"prof":0,"email_match":False}
            candidates[name]["count"] += cnt
            candidates[name]["platforms"].add(domain)
            if domain in dev_domains: candidates[name]["dev"] += 1
            if domain in prof_domains: candidates[name]["prof"] += 1

    emails = intel.get("emails",{})
    for name, data in candidates.items():
        parts = name.lower().split()
        for email_key, email_entry in emails.items():
            local = email_entry["value"].split("@")[0].lower()
            if any(p in local for p in parts):
                data["email_match"] = True
                break

    scored = []
    for name, data in candidates.items():
        score = 0
        score += data["count"] * 10
        score += len(data["platforms"]) * 15
        score += data["dev"] * 20
        score += data["prof"] * 10
        if data["email_match"]: score += 25
        if len(name.split()) < 2: score -= 15
        if not data["dev"] and not data["prof"]: score -= 10
        score = max(0, min(100, score))
        scored.append({"name":name, "score":score, "platforms":len(data["platforms"]),
                       "breakdown":{"count":data["count"],"dev":data["dev"],"prof":data["prof"],"email_match":data["email_match"]}})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:5]

def run_name_analysis(name_list):
    res = {"name_origins":{}, "similarity_matrix":{}}
    if not name_list: return res
    try:
        from nametrace import NameTracer
        nt = NameTracer()
        preds = nt.predict(name_list, batch_size=len(name_list))
        for name,pred in zip(name_list, preds):
            res["name_origins"][name] = {"is_human":pred.get("is_human",False),"gender":pred.get("gender","unknown"),"subregion":pred.get("subregion","unknown")}
    except Exception as e: print(f"  NameTrace error: {e}")
    try:
        from rapidfuzz import fuzz
        for i,a in enumerate(name_list):
            for j,b in enumerate(name_list):
                if i>=j: continue
                score = fuzz.ratio(a.lower(), b.lower()) / 100.0
                if score>0.50: res["similarity_matrix"][f"{a} ↔ {b}"] = round(score,3)
    except Exception as e: print(f"  RapidFuzz error: {e}")
    return res

# -------------------------------------------------------------------
#  AI report generation (fully guarded)
# -------------------------------------------------------------------
def generate_ai_report(core, groq_api_key):
    """Generate an AI summary using Groq's Llama 3.3 model."""
    if not groq_api_key:
        print("  AI report skipped – no Groq API key set.")
        return None

    # Grab the intel dict safely
    if hasattr(core, 'intel'):
        intel = core.intel
    elif isinstance(core, dict):
        intel = core
    else:
        print(f"  AI report error: unexpected core type {type(core)}")
        return None

    try:
        from openai import OpenAI
        client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=groq_api_key)

        # Defensive: confidence_scores might be a dict due to corrupted cache
        top_list = intel.get("confidence_scores", [])
        if isinstance(top_list, dict):
            # Convert dict to list of items (unlikely, but handle gracefully)
            top_list = [v for v in top_list.values() if isinstance(v, dict)]
        top_candidates = top_list[:3] if isinstance(top_list, list) else []

        email_list = []
        for key, entry in intel.get("emails", {}).items():
            if entry.get("source") != "email_guesser":
                email_list.append({"email": entry["value"], "source": entry["source"]})
        breach_status = {}
        for key, entry in intel.get("breaches", {}).items():
            breach_status[key] = "compromised" if "Not Compromised" not in str(entry["value"]) else "clean"
        profiles = [v["value"] for k, v in intel.get("social_profiles", {}).items() if v.get("value", "").startswith("http")][:15]

        summary = {
            "discord_username": intel.get("discord", {}).get("username", {}).get("value", "?"),
            "top_identities": [{"name": c["name"], "score": c["score"]} for c in top_candidates],
            "emails": email_list[:10],
            "breach_status": breach_status,
            "profile_urls": profiles
        }

        prompt = f"""You are an OSINT analyst. Based on the following data, produce a concise JSON report with exactly these keys:

- executive_summary: a brief overview of the investigation
- identity_assessment: evaluation of the subject's identity (pseudonymity, possible real name)
- digital_footprint: summary of platforms, categories, and online presence
- risk_indicators: identified risks (breaches, exposed info, password reuse, etc.)
- relationship_analysis: connections between data points (e.g., same username across platforms, email used for Spotify/Adobe/etc., possible linking of Discord to real identity)
- critical_points: a list of the most important findings that require immediate attention (array of strings)

Data: {json.dumps(summary, indent=2)}"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=5500,
            temperature=0.25
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw, flags=re.MULTILINE)
        try:
            return json.loads(raw)
        except:
            return {"executive_summary": raw, "identity_assessment": "", "digital_footprint": "", "risk_indicators": "", "next_steps": ""}
    except Exception as e:
        import traceback
        print(f"  AI report error: {e}")
        traceback.print_exc()
        return None

def format_ai_report_markdown(report_dict):
    md = []
    def add_section(title, content):
        md.append(f"## {title}")
        md.append(str(content))
        md.append("")
    add_section("Executive Summary", report_dict.get("executive_summary",""))
    add_section("Identity Assessment", report_dict.get("identity_assessment",""))
    add_section("Digital Footprint", report_dict.get("digital_footprint",""))
    add_section("Risk Indicators", report_dict.get("risk_indicators",""))
    return "\n".join(md)

# -------------------------------------------------------------------
#  HTML report generation
# -------------------------------------------------------------------
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

def _format_breach_data(raw_breaches):
    """
    Convert the messy breach dict into a list of
    { 'source': ..., 'summary': ..., 'details': ... }
    that the template can display cleanly.
    """
    cleaned = []
    for key, entry in raw_breaches.items():
        source = entry.get("source", "unknown")
        value = entry.get("value", {})
        if isinstance(value, dict):
            # holehe / emailrep etc.
            if "used_on" in value:
                sites = ", ".join(value["used_on"])
                summary = f"Used on: {sites}"
            elif "status" in value:
                status = value.get("status", "unknown")
                summary = f"Status: {status}"
                if "raw" in value:
                    # h8mail – we only show the status, not the raw log
                    pass
            else:
                summary = json.dumps(value, indent=2)
        else:
            summary = str(value)[:500]
        cleaned.append({
            "source": source,
            "summary": summary,
            "details": value if isinstance(value, dict) else {"raw": str(value)[:500]}
        })
    return cleaned

def _load_blackbird_results(intel):
    """
    Recursively load all Blackbird JSON files from
    investigation_cache/blackbird_output and the Blackbird installation directory.
    """
    results = []
    seen_files = set()

    # List of directories to search
    dirs_to_search = []

    # 1) The cache output folder
    bb_cache_dir = os.path.join(CACHE_DIR, "blackbird_output")
    if os.path.isdir(bb_cache_dir):
        dirs_to_search.append(bb_cache_dir)

    # 2) The Blackbird installation directory (as fallback)
    from .config import BLACKBIRD_DIR
    if os.path.isdir(BLACKBIRD_DIR) and os.path.abspath(BLACKBIRD_DIR) not in [os.path.abspath(d) for d in dirs_to_search]:
        dirs_to_search.append(BLACKBIRD_DIR)

    # Walk each directory recursively
    for search_dir in dirs_to_search:
        for root, dirs, files in os.walk(search_dir):
            for fname in sorted(files):
                if fname.endswith("_blackbird.json") and fname not in seen_files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r") as f:
                            data = json.load(f)
                        results.append({"filename": fname, "entries": data})
                        seen_files.add(fname)
                    except:
                        pass
    return results

def generate_html_report(intel_core, target_id):
    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR)

    template_path = os.path.join(TEMPLATE_DIR, "report.html")
    _create_default_template(template_path)

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template("report.html")

    intel = intel_core.intel

    # --- Discord info (only show what exists) ---
    discord_info = intel.get("discord", {})
    # Build a clean dict for the template, leaving out empty values
    discord_clean = {
        "username": discord_info.get("username", {}).get("value", None),
        "account_created": discord_info.get("account_created", {}).get("value", None),
        "bio": discord_info.get("bio", {}).get("value", None),
        "avatar_cdn": discord_info.get("avatar_cdn", {}).get("value", None),
    }

    # --- Social profiles (unchanged but we keep the nice site names) ---
    social_profiles = []
    for k, v in intel.get("social_profiles", {}).items():
        val = v.get("value", "")
        if val and val.startswith("http"):
            # Clean platform name
            raw = k.replace("discovery_", "", 1)
            http_pos = raw.find("http")
            if http_pos > 0:
                site = raw[:http_pos].strip("_").replace("_", " ")
            else:
                site = raw.replace("_", " ")
            if not site:
                site = "Unknown"
            social_profiles.append({"site": site, "url": val})

    # --- Enrichment (socid data from scraped profiles) ---
    enrichment = []
    for k, v in intel.get("social_profiles", {}).items():
        if "/socid_raw" in k:
            try:
                data = json.loads(v.get("value", "{}"))
                clean = {}
                for field in ["fullname", "bio", "image", "twitchtracker_channel_id", "twitchtracker_username", "twitchtracker_created_at"]:
                    if field in data:
                        clean[field] = data[field]
                if clean:
                    enrichment.append({"source": k.replace("_https://", "https://"), "data": clean})
            except:
                pass
    emails = [{"email": v.get("value", ""), "source": v.get("source", "")}
              for k, v in intel.get("emails", {}).items()]

    # --- Breach intelligence – reformat for readability ---
    raw_breaches = intel.get("breaches", {})
    clean_breaches = _format_breach_data(raw_breaches)

    identity_clues = intel.get("identity_clues", {})
    whois = intel.get("whois", {})
    media = intel.get("media", {})
    name_analysis = intel.get("name_analysis", {})
    confidence_scores = intel.get("confidence_scores", [])
    timeline = intel.get("timeline", [])
    wayback_clean = {}
    for url, data in intel.get("wayback", {}).items():
        if isinstance(data, dict) and "value" in data:
            wayback_clean[url] = data["value"]

    # --- Blackbird data (load from cache) ---
    blackbird_data = _load_blackbird_results(intel)

    html = template.render(
        target_id=target_id,
        timestamp=datetime.datetime.now().isoformat(),
        discord_info=discord_clean,
        social_profiles=social_profiles,
        emails=emails,
        breaches=clean_breaches,
        identity_clues=identity_clues,
        whois=whois,
        media=media,
        name_analysis=name_analysis,
        confidence_scores=confidence_scores,
        timeline=timeline,
        wayback=wayback_clean,
        blackbird=blackbird_data,
        enrichment=enrichment,
    )
    return html

def _create_default_template(path):
    """Comprehensive dark‑themed report template – WhoCord v1.0.2"""
    template_content = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report – {{ target_id }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #0a0a0a; color: #e0e0e0;
    padding: 2rem;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  .header { display: flex; align-items: center; gap: 1rem; margin-bottom: 2rem; }
  .header img { height: 50px; }
  .header h1 { color: #ffffff; margin: 0; font-size: 2rem; }
  .meta { color: #999; font-size: 0.9rem; margin-bottom: 2rem; }
  section {
    background: #1a1a1a; border-radius: 12px;
    padding: 1.5rem; margin-bottom: 1.5rem;
    border: 1px solid #2a2a2a;
  }
  h2 { color: #ffffff; margin-bottom: 1rem; font-size: 1.4rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #2a2a2a; }
  th { color: #aaa; font-weight: 600; }
  a { color: #999; text-decoration: none; }
  a:hover { color: #fff; text-decoration: underline; }
  .badge {
    display: inline-block; padding: 0.2rem 0.6rem;
    border-radius: 4px; font-size: 0.8rem; margin-right: 0.5rem;
  }
  .badge.success { background: #00c896; color: #000; }
  .badge.warning { background: #ffb347; color: #000; }
  .badge.danger { background: #ff4d6a; color: #fff; }
  ul { list-style: none; padding-left: 0; }
  li { margin-bottom: 0.5rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; }
  .card { background: #121212; border-radius: 8px; padding: 1rem; border: 1px solid #2a2a2a; overflow-wrap: break-word; word-break: break-all; }
  .card h3 { margin-bottom: 0.5rem; color: #ffffff; }
  .footer { text-align: center; margin-top: 2rem; color: #555; }
  .timeline-item { margin-bottom: 0.5rem; padding-left: 1rem; border-left: 2px solid #555; }
  pre { white-space: pre-wrap; font-size: 0.8rem; background: #0e0e0e; padding: 0.5rem; border-radius: 4px; }
  details summary { cursor: pointer; color: #aaa; margin-top: 0.5rem; }
  details pre { margin-top: 0.5rem; background: #0e0e0e; padding: 0.5rem; border-radius: 4px; }
  img.avatar-thumb { max-width: 64px; max-height: 64px; border-radius: 4px; margin-top: 4px; display: block; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <img src="/static/images/logo.png" alt="WhoCord" style="height:50px;">
    <h1>OSINT Investigation Report</h1>
  </div>
  <div class="meta">
    <strong>Target ID:</strong> {{ target_id }}<br>
    <strong>Generated:</strong> {{ timestamp }}
  </div>

  <!-- all sections remain exactly the same as before -->
  {% if discord_info and (discord_info.username or discord_info.account_created or discord_info.bio or discord_info.avatar_cdn) %}
  <section>
    <h2>📱 Discord Identity</h2>
    <table>
      {% if discord_info.username %}<tr><th>Username</th><td>{{ discord_info.username }}</td></tr>{% endif %}
      {% if discord_info.account_created %}<tr><th>Account Created</th><td>{{ discord_info.account_created }}</td></tr>{% endif %}
      {% if discord_info.bio %}<tr><th>Bio</th><td>{{ discord_info.bio }}</td></tr>{% endif %}
      {% if discord_info.avatar_cdn %}<tr><th>Avatar</th><td><a href="{{ discord_info.avatar_cdn }}" target="_blank">View</a></td></tr>{% endif %}
    </table>
  </section>
  {% endif %}

  {% if social_profiles %}
  <section>
    <h2>🌐 Discovered Social Profiles</h2>
    <div class="grid">
      {% for p in social_profiles %}
      <div class="card">
        <h3>{{ p.site }}</h3>
        <a href="{{ p.url }}" target="_blank">{{ p.url }}</a>
      </div>
      {% endfor %}
    </div>
  </section>
  {% endif %}

  {% if emails %}
  <section>
    <h2>✉️ Emails</h2>
    <table>
      <tr><th>Email</th><th>Source</th></tr>
      {% for e in emails %}
      <tr>
        <td>{{ e.email }}</td>
        <td>{{ e.source }}</td>
      </tr>
      {% endfor %}
    </table>
  </section>
  {% endif %}

  {% if breaches %}
  <section>
    <h2>🔓 Breach Intelligence</h2>
    {% for breach in breaches %}
    <div class="card" style="margin-bottom:0.5em;">
      <strong>{{ breach.source | title }}</strong>
      <p>{{ breach.summary }}</p>
      {% if breach.details %}
      <details style="margin-top:0.3em;">
        <summary>Show raw details</summary>
        <pre>{{ breach.details | tojson(indent=2) }}</pre>
      </details>
      {% endif %}
    </div>
    {% endfor %}
  </section>
  {% endif %}

  {% if enrichment %}
  <section>
    <h2>🧪 Enriched Profile Data</h2>
    {% for item in enrichment %}
    <div class="card" style="margin-bottom:0.5em;">
      <h3>{{ item.source[:60] }}…</h3>
      <ul>
        {% for key, val in item.data.items() %}
        <li><strong>{{ key }}:</strong> {{ val }}</li>
        {% endfor %}
      </ul>
    </div>
    {% endfor %}
  </section>
  {% endif %}

  {% if identity_clues %}
  <section>
    <h2>🧩 Identity Clues</h2>
    <table>
      <tr><th>Clue</th><th>Value</th></tr>
      {% for key, val in identity_clues.items() %}
      <tr>
        <td>{{ key }}</td>
        <td>{{ val.get('value', '') }}</td>
      </tr>
      {% endfor %}
    </table>
  </section>
  {% endif %}

  {% if whois %}
  <section>
    <h2>🌍 WHOIS Information</h2>
    {% for domain, info in whois.items() %}
    <div class="card" style="margin-bottom:1em;">
      <h3>{{ domain }}</h3>
      <ul>
        <li><strong>Registrant:</strong> {{ info.get('registrant_name', '') }}</li>
        <li><strong>Email:</strong> {{ info.get('registrant_email', '') }}</li>
        <li><strong>Creation Date:</strong> {{ info.get('creation_date', '') }}</li>
      </ul>
    </div>
    {% endfor %}
  </section>
  {% endif %}

  {% if media %}
  <section>
    <h2>📸 Media / EXIF</h2>
    {% for key, val in media.items() %}
    <div class="card" style="margin-bottom:1em;">
      <strong>{{ key }}</strong> : {{ val }}
    </div>
    {% endfor %}
  </section>
  {% endif %}

  {% if name_analysis %}
  <section>
    <h2>🔬 Name Analysis</h2>
    <table>
      <tr><th>Name</th><th>Origin</th><th>Gender</th><th>Subregion</th></tr>
      {% for name, details in name_analysis.get('name_origins', {}).items() %}
      <tr>
        <td>{{ name }}</td>
        <td>{{ details.is_human }}</td>
        <td>{{ details.gender }}</td>
        <td>{{ details.subregion }}</td>
      </tr>
      {% endfor %}
    </table>
    {% if name_analysis.get('similarity_matrix') %}
    <h3 style="margin-top:1em;">Name Similarities</h3>
    <ul>
      {% for pair, score in name_analysis.similarity_matrix.items() %}
      <li>{{ pair }} → {{ score }}</li>
      {% endfor %}
    </ul>
    {% endif %}
  </section>
  {% endif %}

  {% if confidence_scores %}
  <section>
    <h2>🏆 Identity Confidence Scores</h2>
    {% for c in confidence_scores %}
    <div class="card" style="margin-bottom:0.5em;">
      <strong>{{ c.name }}</strong> – score: {{ c.score }}
      <br>Platforms: {{ c.platforms }}
      <br>Breakdown: {{ c.breakdown }}
    </div>
    {% endfor %}
  </section>
  {% endif %}

  {% if wayback %}
  <section>
    <h2>🕰️ Wayback Machine Snapshots</h2>
    <ul>
      {% for url, snap in wayback.items() %}
      <li><a href="{{ snap }}">{{ url }}</a></li>
      {% endfor %}
    </ul>
  </section>
  {% endif %}

  {% if blackbird %}
  <section>
    <h2>🐦 Blackbird Search Results</h2>
    {% for file in blackbird %}
    <div class="card" style="margin-bottom:1em;">
      <h3>{{ file.filename }}</h3>
      {% if file.entries %}
        <ul>
        {% for entry in file.entries %}
          <li>
            <strong>{{ entry.get("name", "?") }}</strong> – 
            <a href="{{ entry.get('url', '#') }}" target="_blank">{{ entry.get("url", '') }}</a>
            {% if entry.get("metadata") %}
              {% for meta in entry.metadata %}
                {% if meta.type == 'Image' and meta.value %}
                  <img src="{{ meta.value }}" alt="avatar" class="avatar-thumb">
                {% endif %}
              {% endfor %}
            {% endif %}
          </li>
        {% endfor %}
        </ul>
      {% else %}
        <p>No entries found.</p>
      {% endif %}
    </div>
    {% endfor %}
  </section>
  {% endif %}

  {% if timeline %}
  <section>
    <h2>⏱️ Investigation Timeline</h2>
    <ul>
      {% for event in timeline %}
      <li class="timeline-item">{{ event }}</li>
      {% endfor %}
    </ul>
  </section>
  {% endif %}

  <div class="footer">🔎 Generated by WhoCord v1.0.2 – Universal OSINT Pipeline</div>
</div>
</body>
</html>"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(template_content)
