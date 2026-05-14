"""
discord_osint/intelligence/narrative.py
-----------------------------------------
Generate a structured AI intelligence narrative by sending a rich context
prompt to Groq's LLM API.

The prompt feeds in:
  - Entity counts and top-confidence entities
  - Correlations found by the detectors
  - Breach summary from intel
  - Knowledge-graph statistics

The LLM is asked to respond with a **strict JSON object** whose keys map
directly to the five narrative sections stored in
``intel["intelligence_report"]["narrative"]``.

Failure handling
----------------
Any failure (network error, parse error, API quota) returns an empty dict
and prints a warning.  The stage continues without a narrative rather than
raising so that an LLM outage never kills a completed investigation.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from .entities import BaseEntity
from .correlations import Correlation


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GROQ_API_URL  = "https://api.groq.com/openai/v1/chat/completions"
_LLM_MODEL     = "llama-3.3-70b-versatile"
_MAX_TOKENS    = 6000
_TEMPERATURE   = 0.25    # low temperature → deterministic, structured output

_NARRATIVE_KEYS = (
    "executive_summary",
    "identity_assessment",
    "digital_footprint",
    "risk_indicators",
    "critical_points",
)

_SYSTEM_PROMPT = (
    "You are an elite OSINT intelligence analyst. "
    "You receive structured investigation data and produce concise, professional reports. "
    "You ALWAYS respond with ONLY valid JSON. "
    "No markdown fences, no explanatory text, no preamble – pure JSON."
)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _fmt_entities(entities: list[BaseEntity], limit: int = 15) -> str:
    """Return a formatted block of the top-confidence entities."""
    top = sorted(entities, key=lambda e: e.confidence, reverse=True)[:limit]
    lines = []
    for e in top:
        lines.append(
            f"  [{e.entity_type:18s}] {e.value!r:50s}  "
            f"conf={e.confidence:.2f}  src={e.source}"
        )
    return "\n".join(lines) if lines else "  (none)"


def _fmt_correlations(correlations: list[Correlation], limit: int = 10) -> str:
    """Return a formatted block of the top correlations."""
    if not correlations:
        return "  None detected."
    lines = []
    for c in correlations[:limit]:
        lines.append(
            f"  [{c.correlation_type:25s}]  conf={c.confidence:.2f}  "
            f"{c.description[:100]}"
        )
    return "\n".join(lines)


def _fmt_breaches(intel: dict[str, Any]) -> str:
    """Summarise breach data from the intel dict."""
    breaches = intel.get("breaches", {})
    if not breaches:
        return "No breach data found."

    sites: list[str] = []
    hibp_count = 0
    for key, entry in breaches.items():
        val = entry.get("value", entry) if isinstance(entry, dict) else entry
        if "hibp_" in key and isinstance(val, list):
            hibp_count += len(val)
            sites.extend(
                b.get("Name", str(b))[:30] for b in val[:3]
                if isinstance(b, dict)
            )
        elif "holehe_" in key and isinstance(val, dict):
            sites.extend(val.get("used_on", [])[:4])

    site_str = ", ".join(sites[:10]) if sites else "details unavailable"
    return (
        f"{len(breaches)} breach record(s) found. "
        f"HIBP breach count: {hibp_count}. "
        f"Relevant sites / services: {site_str}."
    )


def _build_prompt(
    graph_summary: dict,
    correlations: list[Correlation],
    entities: list[BaseEntity],
    intel: dict[str, Any],
) -> str:
    """Assemble the full LLM user prompt with all collected intelligence."""

    # ------------------------------------------------------------------ #
    # 1. Emails + breaches
    # ------------------------------------------------------------------ #
    emails = intel.get("emails", {})
    email_list = []
    for key, entry in emails.items():
        val = entry.get("value", "") if isinstance(entry, dict) else str(entry)
        if not val or "@" not in val:
            continue
        src = entry.get("source", "") if isinstance(entry, dict) else ""
        email_list.append({"email": val, "source": src})

    # Breach data per email
    breaches = intel.get("breaches", {})
    email_breach_map: dict[str, list[str]] = {}
    for bk, bv in breaches.items():
        bval = bv.get("value", {}) if isinstance(bv, dict) else bv
        if isinstance(bval, dict) and "used_on" in bval:   # Holehe
            for email in email_list:
                if email["email"] in bk:
                    email_breach_map.setdefault(email["email"], []).extend(bval["used_on"])
        elif "hibp_" in bk:
            # HIBP: list of breach dicts
            if isinstance(bval, list):
                for breach in bval[:5]:
                    name = breach.get("Name", "")
                    if name:
                        email_breach_map.setdefault(email["email"], []).append(f"HIBP:{name}")
        elif "h8mail_" in bk:
            status = bval.get("status", "") if isinstance(bval, dict) else ""
            if status:
                email_breach_map.setdefault(email["email"], []).append(f"h8mail:{status}")

    email_str = "\n".join(
        f"- {e['email']} (source: {e['source']})"
        + (f" → breaches: {', '.join(email_breach_map.get(e['email'], []))}" if email_breach_map.get(e['email']) else "")
        for e in email_list[:20]
    ) or "None"

    # ------------------------------------------------------------------ #
    # 2. Social profiles
    # ------------------------------------------------------------------ #
    profiles = intel.get("social_profiles", {})
    profile_list = []
    for key, entry in profiles.items():
        val = entry.get("value", "") if isinstance(entry, dict) else ""
        if not val or not val.startswith("http"):
            continue
        platform = key.split("/")[0] if "/" in key else key.split("_")[0]
        profile_list.append({"platform": platform, "url": val})
    profile_str = "\n".join(
        f"- {p['platform']}: {p['url']}" for p in profile_list[:30]
    ) or "None"

    # Bios, locations, emails from social profiles (enrichment)
    bio_str = ""
    loc_str = ""
    for key, entry in profiles.items():
        if key.endswith("/bio"):
            val = entry.get("value", "") if isinstance(entry, dict) else ""
            if val:
                bio_str += f"\n- {key.split('/')[0]}: {val[:200]}"
        if key.endswith("/location"):
            val = entry.get("value", "") if isinstance(entry, dict) else ""
            if val:
                loc_str += f"\n- {key.split('/')[0]}: {val}"

    # ------------------------------------------------------------------ #
    # 3. Identity clues
    # ------------------------------------------------------------------ #
    identity = intel.get("identity_clues", {})
    identity_str = "\n".join(
        f"- {k}: {v.get('value', '')[:100]}" for k, v in identity.items() if v.get('value')
    ) or "None"

    # ------------------------------------------------------------------ #
    # 4. Technical data (domain, WHOIS, DNS, SSL, IP, subdomains, theHarvester)
    # ------------------------------------------------------------------ #
    whois = intel.get("whois", {})
    whois_str = json.dumps(whois, indent=2)[:1000] if whois else "None"

    dns = intel.get("dns", {})
    dns_str = json.dumps(dns, indent=2)[:1000] if dns else "None"

    ssl = intel.get("ssl", {})
    ssl_str = json.dumps(ssl, indent=2)[:500] if ssl else "None"

    subdomains = intel.get("subdomains", {})
    sub_str = ""
    for domain, sublist in subdomains.items():
        if isinstance(sublist, dict) and "value" in sublist:
            sublist = sublist["value"]
        if isinstance(sublist, list):
            sub_str += f"\n- {domain}: {', '.join(sublist[:20])}"

    harvester_emails = intel.get("harvester_emails", {})
    harv_emails = []
    for domain, entry in harvester_emails.items():
        val = entry.get("value", {}) if isinstance(entry, dict) else entry
        if isinstance(val, dict):
            harv_emails.extend(val.get("emails", []))
    harv_email_str = ", ".join(harv_emails[:20]) or "None"

    # ------------------------------------------------------------------ #
    # 5. URL analysis
    # ------------------------------------------------------------------ #
    url_intel = intel.get("url_intel", {})
    page_title = ""
    page_desc = ""
    interesting_links = []
    if url_intel:
        page_meta = url_intel.get("page_meta", {})
        if isinstance(page_meta, dict):
            val = page_meta.get("value", {}) if "value" in page_meta else page_meta
            if isinstance(val, dict):
                page_title = val.get("title", "")
                page_desc = val.get("description", "")
        interesting = url_intel.get("interesting_links", {})
        if isinstance(interesting, dict):
            links = interesting.get("value", []) if "value" in interesting else interesting
            if isinstance(links, list):
                interesting_links = links[:20]

    url_str = f"Title: {page_title[:200]}\nDescription: {page_desc[:300]}\nInteresting links: {', '.join(interesting_links)}" if url_intel else "None"

    # ------------------------------------------------------------------ #
    # 6. Phone investigation
    # ------------------------------------------------------------------ #
    phone = intel.get("phone", {})
    phone_str = ""
    if phone:
        number = phone.get("number", {})
        num_val = number.get("value", "") if isinstance(number, dict) else ""
        valid = phone.get("is_valid", {})
        valid_val = valid.get("value", "") if isinstance(valid, dict) else ""
        country = phone.get("country", {})
        country_val = country.get("value", "") if isinstance(country, dict) else ""
        carrier = phone.get("carrier", {})
        carrier_val = carrier.get("value", "") if isinstance(carrier, dict) else ""
        phone_str = f"Number: {num_val}, Valid: {valid_val}, Country: {country_val}, Carrier: {carrier_val}"

    # ------------------------------------------------------------------ #
    # 7. GHunt (Google account)
    # ------------------------------------------------------------------ #
    ghunt = intel.get("ghunt", {})
    ghunt_str = json.dumps(ghunt, indent=2)[:800] if ghunt else "None"

    # ------------------------------------------------------------------ #
    # 8. Pivot sub‑reports
    # ------------------------------------------------------------------ #
    pivot_reports = intel.get("pivot_reports", [])
    pivot_str = ""
    if pivot_reports:
        for pr in pivot_reports[:3]:
            seed = pr.get("seed", "")
            seed_type = pr.get("seed_type", "")
            total_e = sum(pr.get("report", {}).get("entity_counts", {}).values())
            pivot_str += f"\n- {seed_type}:{seed} → {total_e} entities"

    # ------------------------------------------------------------------ #
    # 9. Build final prompt
    # ------------------------------------------------------------------ #
    prompt_parts = [
        "=== COMPLETE OSINT INVESTIGATION DATA ===",
        "",
        f"TARGET: {intel.get('target', {}).get('value', 'unknown')}",
        "",
        "=== EMAILS & BREACHES ===",
        email_str,
        "",
        "=== SOCIAL PROFILES (URLs) ===",
        profile_str,
        "",
        "=== SOCIAL PROFILE BIOS ===",
        bio_str[:1500] or "None",
        "",
        "=== IDENTITY CLUES ===",
        identity_str,
        "",
        "=== TECHNICAL DATA ===",
        f"WHOIS: {whois_str}",
        f"DNS: {dns_str}",
        f"SSL: {ssl_str}",
        f"Subdomains: {sub_str[:500]}",
        f"theHarvester emails: {harv_email_str}",
        "",
        "=== URL ANALYSIS ===",
        url_str,
        "",
        "=== PHONE INVESTIGATION ===",
        phone_str or "None",
        "",
        "=== GHUNT GOOGLE DATA ===",
        ghunt_str,
        "",
        "=== PIVOT SUB‑REPORTS ===",
        pivot_str or "None",
        "",
        "=== KNOWLEDGE GRAPH ===",
        f"Nodes: {graph_summary.get('total_nodes', 0)}, Edges: {graph_summary.get('total_edges', 0)}",
        f"Node types: {json.dumps(graph_summary.get('node_counts_by_type', {}))}",
        "",
        "=== CORRELATIONS ===",
        _fmt_correlations(correlations),
        "",
        "=== REQUIRED OUTPUT ===",
        "",
        "Respond with ONLY this JSON object – no other text:",
        "{",
        '  "executive_summary":  "<2-3 sentence overview of who this target is>",',
        '  "identity_assessment": "<how confident are we this is one real person, and why>",',
        '  "digital_footprint":  "<description of their online presence, platforms, activity>",',
        '  "risk_indicators":    "<OPSEC failures, leaked PII, suspicious patterns, or none>",',
        '  "critical_points":    ["<finding 1>", "<finding 2>", "...up to 6 key points>"]',
        "}",
    ]
    return "\n".join(prompt_parts)

# ---------------------------------------------------------------------------
# JSON parsing helpers
# ---------------------------------------------------------------------------

def _strip_fences(text: str) -> str:
    """Remove markdown code fences that some models add despite instructions."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _extract_json(text: str) -> str:
    """
    Attempt to extract a JSON object from *text* even when it has some
    preamble or trailing text.
    """
    start = text.find("{")
    end   = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_narrative(
    graph_summary: dict,
    correlations: list[Correlation],
    entities: list[BaseEntity],
    intel: dict[str, Any],
    groq_api_key: str,
) -> dict:
    """
    Call the Groq LLM and return a parsed narrative dict.

    Returns an empty dict on any failure so the pipeline can continue.

    Parameters
    ----------
    graph_summary:
        Output of :func:`~discord_osint.intelligence.graph.graph_summary`.
    correlations:
        Output of :func:`~discord_osint.intelligence.correlations.run_all_detectors`.
    entities:
        Flat entity list from the extractor.
    intel:
        Raw ``InvestigationCore.intel`` dict.
    groq_api_key:
        Groq API key string.

    Returns
    -------
    dict
        Keys: ``executive_summary``, ``identity_assessment``,
        ``digital_footprint``, ``risk_indicators``, ``critical_points``.
        Empty dict on failure.
    """
    if not groq_api_key:
        return {}

    prompt = _build_prompt(graph_summary, correlations, entities, intel)

    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model":       _LLM_MODEL,
        "temperature": _TEMPERATURE,
        "max_tokens":  _MAX_TOKENS,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
    }

    try:
        resp = requests.post(_GROQ_API_URL, headers=headers, json=payload, timeout=45)
    except requests.RequestException as exc:
        print(f"  [!] Narrative – network error: {exc}")
        return {}

    if resp.status_code != 200:
        print(f"  [!] Narrative – Groq API {resp.status_code}: {resp.text[:200]}")
        return {}

    try:
        raw = resp.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        print(f"  [!] Narrative – unexpected API response shape: {exc}")
        return {}

    # Parse JSON – try progressively looser approaches
    clean = _strip_fences(raw)
    for attempt in (clean, _extract_json(clean)):
        try:
            parsed = json.loads(attempt)
            break
        except json.JSONDecodeError:
            continue
    else:
        print(f"  [!] Narrative – failed to parse LLM JSON response.")
        return {}

    # Normalise: ensure all expected keys are present
    result: dict = {}
    for key in _NARRATIVE_KEYS:
        val = parsed.get(key, "")
        # critical_points must be a list
        if key == "critical_points" and not isinstance(val, list):
            val = [str(val)] if val else []
        result[key] = val

    return result
