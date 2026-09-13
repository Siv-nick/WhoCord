"""
discord_osint/reporting.py
--------------------------
Report helpers: identity confidence scoring, name analysis, AI persona
summaries, AI structured reports, and markdown formatting.

Note: the HTML report generator lives in
``discord_osint/intelligence/html_report.py``.  This file only holds the
non-HTML reporting utilities that the pipeline stages still call directly.
"""

import json
import re
import os
import datetime

from .scraping import looks_like_real_name_v2, is_valid_email
from .utils import CACHE_DIR


# -------------------------------------------------------------------
#  Identity confidence scoring
# -------------------------------------------------------------------
def calculate_identity_confidence(intel):
    dev_domains  = {"github.com", "gitlab.com", "dev.to", "hackerrank.com",
                    "hashnode.com", "keybase.io", "npmjs.com"}
    prof_domains = {"about.me", "linkedin.com", "patreon.com",
                    "buymeacoffee.com", "ko-fi.com"}

    name_map = {}
    for key, entry in intel.get("identity_clues", {}).items():
        if not key.startswith("name_"):
            continue
        raw = entry.get("value", "")
        if not looks_like_real_name_v2(raw):
            continue
        domain = (key.split("/")[0]
                  .replace("name_github", "github.com")
                  .replace("name_generic_https://", ""))
        if domain not in name_map:
            name_map[domain] = {}
        if raw not in name_map[domain]:
            name_map[domain][raw] = 0
        name_map[domain][raw] += 1

    candidates = {}
    for domain, names in name_map.items():
        for name, cnt in names.items():
            if name not in candidates:
                candidates[name] = {
                    "count": 0, "platforms": set(),
                    "dev": 0, "prof": 0, "email_match": False,
                }
            candidates[name]["count"] += cnt
            candidates[name]["platforms"].add(domain)
            if domain in dev_domains:
                candidates[name]["dev"] += 1
            if domain in prof_domains:
                candidates[name]["prof"] += 1

    emails = intel.get("emails", {})
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
        if data["email_match"]:
            score += 25
        if len(name.split()) < 2:
            score -= 15
        if not data["dev"] and not data["prof"]:
            score -= 10
        score = max(0, min(100, score))
        scored.append({
            "name": name,
            "score": score,
            "platforms": len(data["platforms"]),
            "breakdown": {
                "count": data["count"],
                "dev": data["dev"],
                "prof": data["prof"],
                "email_match": data["email_match"],
            },
        })
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:5]


# -------------------------------------------------------------------
#  Name analysis (NameTrace + RapidFuzz)
# -------------------------------------------------------------------
def run_name_analysis(name_list):
    res = {"name_origins": {}, "similarity_matrix": {}}
    if not name_list:
        return res

    try:
        from nametrace import NameTracer
        nt = NameTracer()
        preds = nt.predict(name_list, batch_size=len(name_list))
        for name, pred in zip(name_list, preds):
            res["name_origins"][name] = {
                "is_human":  pred.get("is_human", False),
                "gender":    pred.get("gender", "unknown"),
                "subregion": pred.get("subregion", "unknown"),
            }
    except Exception as e:
        print(f"  NameTrace error: {e}")

    try:
        from rapidfuzz import fuzz
        for i, a in enumerate(name_list):
            for j, b in enumerate(name_list):
                if i >= j:
                    continue
                score = fuzz.ratio(a.lower(), b.lower()) / 100.0
                if score > 0.50:
                    res["similarity_matrix"][f"{a} ↔ {b}"] = round(score, 3)
    except Exception as e:
        print(f"  RapidFuzz error: {e}")

    return res


# -------------------------------------------------------------------
#  AI Persona Summary — gathers intel from every available source
# -------------------------------------------------------------------
def generate_persona_summary(intel, groq_api_key):
    """
    Ask the LLM to summarise the subject's persona based on every piece
    of intel we've collected (emails, breaches, bios, names, location,
    phone, WHOIS, URL metadata, GHunt, pivots).
    """
    if not groq_api_key:
        return None

    try:
        from openai import OpenAI
        client = OpenAI(base_url="https://api.groq.com/openai/v1",
                        api_key=groq_api_key)

        # ── 1. Emails + breach context ──────────────────────────────────
        emails   = intel.get("emails", {})
        breaches = intel.get("breaches", {})
        email_lines = []
        for key, entry in emails.items():
            email_val = entry.get("value", "") if isinstance(entry, dict) else ""
            if not email_val or "@" not in email_val:
                continue
            sites = []
            for bk, bv in breaches.items():
                if email_val in bk:
                    bval = bv.get("value", {}) if isinstance(bv, dict) else bv
                    if isinstance(bval, dict) and bval.get("used_on"):
                        sites.extend(bval["used_on"])
            if sites:
                email_lines.append(
                    f"Email {email_val} registered on: {', '.join(set(sites[:5]))}"
                )
            else:
                email_lines.append(f"Email {email_val} (no registrations found)")

        # ── 2. Bios ─────────────────────────────────────────────────────
        bios = []
        for k, v in intel.get("social_profiles", {}).items():
            if "bio" in k.lower() or "desc" in k.lower():
                val = v.get("value", "") if isinstance(v, dict) else ""
                if val:
                    bios.append(val[:500])
        for k, v in intel.get("social_profiles", {}).items():
            if "socid_raw" in k:
                try:
                    socid_data = json.loads(v.get("value", "{}"))
                    if isinstance(socid_data, dict) and socid_data.get("bio"):
                        bios.append(socid_data["bio"][:500])
                except Exception:
                    pass

        # ── 3. Identity clues ───────────────────────────────────────────
        identity = intel.get("identity_clues", {})
        names    = [v.get("value", "") for k, v in identity.items()
                    if k.startswith("name_") and v.get("value")]
        location = ""
        lang     = ""
        for k, v in identity.items():
            if k == "inferred_location":
                location = v.get("value", "")
            if k == "language":
                lang = v.get("value", "")

        # ── 4. Phone ────────────────────────────────────────────────────
        phone = intel.get("phone", {})
        phone_str = ""
        if phone:
            num     = phone.get("number", {})
            num_val = num.get("value", "") if isinstance(num, dict) else ""
            carr    = phone.get("carrier", {})
            carr_val = carr.get("value", "") if isinstance(carr, dict) else ""
            if num_val:
                phone_str = f"Phone number: {num_val} (carrier: {carr_val})"

        # ── 5. Domain WHOIS ─────────────────────────────────────────────
        whois = intel.get("whois", {})
        whois_str = ""
        for domain, data in whois.items():
            if isinstance(data, dict):
                reg = data.get("registrant_org", "") or data.get("registrant_name", "")
                whois_str = (
                    f"Domain {domain} registered to {reg}"
                    if reg else f"Domain {domain} (no public registrant)"
                )

        # ── 6. URL page metadata ────────────────────────────────────────
        url_intel = intel.get("url_intel", {})
        url_title = ""
        url_desc  = ""
        if url_intel:
            page_meta = url_intel.get("page_meta", {})
            if isinstance(page_meta, dict):
                val = page_meta.get("value", {}) if "value" in page_meta else page_meta
                if isinstance(val, dict):
                    url_title = val.get("title", "")
                    url_desc  = val.get("description", "")

        # ── 7. GHunt ────────────────────────────────────────────────────
        ghunt      = intel.get("ghunt", {})
        ghunt_str  = ""
        for email, data in ghunt.items():
            if isinstance(data, dict):
                services = data.get("activated_services", [])
                if services:
                    ghunt_str = f"Google account with services: {', '.join(services)}"
                break

        # ── 8. Pivot sub-reports ────────────────────────────────────────
        pivot_count = len(intel.get("pivot_reports", []))

        # ── Build prompt ────────────────────────────────────────────────
        prompt_parts = [
            "You are an experienced OSINT investigator. Based on the following "
            "collected data, write a single concise paragraph describing the "
            "person's online persona, interests, profession, and any notable "
            "characteristics. Use clear, factual language.",
            "",
            "=== DATA ===",
        ]
        if email_lines:
            prompt_parts.append("Emails and registrations:\n" + "\n".join(email_lines))
        if bios:
            prompt_parts.append("Profile biographies:\n" + "\n---\n".join(bios[:15]))
        if names:
            prompt_parts.append(f"Possible names: {', '.join(names[:5])}")
        if location:
            prompt_parts.append(f"Inferred location: {location}")
        if lang:
            prompt_parts.append(f"Language: {lang}")
        if phone_str:
            prompt_parts.append(phone_str)
        if whois_str:
            prompt_parts.append(whois_str)
        if url_title or url_desc:
            prompt_parts.append(
                f"Page title: {url_title[:200]}\nPage description: {url_desc[:300]}"
            )
        if ghunt_str:
            prompt_parts.append(ghunt_str)
        if pivot_count:
            prompt_parts.append(f"Number of pivot sub-investigations: {pivot_count}")

        if not any([email_lines, bios, names, location, lang,
                    phone_str, whois_str, url_title, ghunt_str]):
            return "Insufficient data to form a persona."

        prompt = "\n".join(prompt_parts)

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4000,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"  Persona summary error: {e}")
        return None


# -------------------------------------------------------------------
#  AI structured report (JSON) — unchanged
# -------------------------------------------------------------------
def generate_ai_report(core, groq_api_key):
    """Generate an AI summary using Groq's Llama 3.3 model."""
    if not groq_api_key:
        print("  AI report skipped – no Groq API key set.")
        return None

    if hasattr(core, "intel"):
        intel = core.intel
    elif isinstance(core, dict):
        intel = core
    else:
        print(f"  AI report error: unexpected core type {type(core)}")
        return None

    try:
        from openai import OpenAI
        client = OpenAI(base_url="https://api.groq.com/openai/v1",
                        api_key=groq_api_key)

        top_list = intel.get("confidence_scores", [])
        if isinstance(top_list, dict):
            top_list = [v for v in top_list.values() if isinstance(v, dict)]
        top_candidates = top_list[:3] if isinstance(top_list, list) else []

        email_list = []
        for key, entry in intel.get("emails", {}).items():
            if entry.get("source") != "email_guesser":
                email_list.append({"email": entry["value"], "source": entry["source"]})

        breach_status = {}
        for key, entry in intel.get("breaches", {}).items():
            breach_status[key] = (
                "compromised"
                if "Not Compromised" not in str(entry["value"])
                else "clean"
            )

        profiles = [
            v["value"] for k, v in intel.get("social_profiles", {}).items()
            if v.get("value", "").startswith("http")
        ][:15]

        summary = {
            "discord_username": intel.get("discord", {}).get("username", {}).get("value", "?"),
            "top_identities":   [{"name": c["name"], "score": c["score"]} for c in top_candidates],
            "emails":           email_list[:10],
            "breach_status":    breach_status,
            "profile_urls":     profiles,
        }

        prompt = f"""You are an OSINT analyst. Based on the following data, produce a concise JSON report with exactly these keys:

- executive_summary: a brief overview of the investigation
- identity_assessment: evaluation of the subject's identity (pseudonymity, possible real name)
- digital_footprint: summary of platforms, categories, and online presence
- risk_indicators: identified risks (breaches, exposed info, password reuse, etc.)
- relationship_analysis: connections between data points
- critical_points: a list of the most important findings (array of strings)

Data: {json.dumps(summary, indent=2)}"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=5500,
            temperature=0.25,
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.MULTILINE)
        try:
            return json.loads(raw)
        except Exception:
            return {
                "executive_summary":  raw,
                "identity_assessment": "",
                "digital_footprint":  "",
                "risk_indicators":    "",
                "next_steps":         "",
            }
    except Exception as e:
        import traceback
        print(f"  AI report error: {e}")
        traceback.print_exc()
        return None


# -------------------------------------------------------------------
#  Markdown formatter for the AI report
# -------------------------------------------------------------------
def format_ai_report_markdown(report_dict):
    md = []

    def add_section(title, content):
        md.append(f"## {title}")
        md.append(str(content))
        md.append("")

    add_section("Executive Summary",   report_dict.get("executive_summary", ""))
    add_section("Identity Assessment", report_dict.get("identity_assessment", ""))
    add_section("Digital Footprint",   report_dict.get("digital_footprint", ""))
    add_section("Risk Indicators",     report_dict.get("risk_indicators", ""))
    return "\n".join(md)