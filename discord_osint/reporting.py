"""
discord_osint/reporting.py
--------------------------
Report helpers: identity confidence scoring, name analysis, AI persona
summaries, AI structured reports, and markdown formatting.

LLM provider resolution
-----------------------
Every LLM call routes through ``config_service.get_llm_endpoint()``,
which returns the base URL, API key, and extra headers for whichever
provider (``LLM_PROVIDER``) is active. Switching from Groq to
OpenRouter is a single config-key change with no code edits required.
"""

import json
import re
import os
import datetime

from .scraping import looks_like_real_name_v2, is_valid_email
from .utils import CACHE_DIR
from .config_service import get_llm_endpoint


# ---------------------------------------------------------------------------
# LLM settings helper
# ---------------------------------------------------------------------------

def _llm_settings() -> tuple[str, float, int, str, int, bool, bool]:
    try:
        from .config import config as _cfg
    except Exception:
        return ("llama3-8b-8192", 0.25, 4096, "", 60000, True, True)

    def _f(v, d):
        try:
            return float(v)
        except (TypeError, ValueError):
            return d

    def _i(v, d):
        try:
            return int(v)
        except (TypeError, ValueError):
            return d

    def _b(v, d):
        if v is None:
            return d
        if isinstance(v, str):
            return v.strip().lower() in ("1", "true", "yes", "on")
        return bool(v)

    model  = getattr(_cfg, "LLM_MODEL", "llama3-8b-8192") or "llama3-8b-8192"
    temp   = _f(getattr(_cfg, "LLM_TEMPERATURE", 0.25), 0.25)
    tokens = _i(getattr(_cfg, "LLM_MAX_TOKENS", 4096), 4096)
    prompt = getattr(_cfg, "LLM_SYSTEM_PROMPT", "") or ""
    budget = _i(getattr(_cfg, "LLM_INTEL_BUDGET", 60000), 60000)
    raw    = _b(getattr(_cfg, "LLM_INTEL_INCLUDE_RAW", True), True)
    meta   = _b(getattr(_cfg, "LLM_INTEL_EXCLUDE_META", True), True)
    return model, temp, tokens, prompt, budget, raw, meta


def _build_system_prompt(base_prompt: str) -> str:
    """
    Combine a caller-supplied (or default) base prompt with the
    untrusted-data contract. The contract is always appended, so a
    custom prompt cannot reopen the injection surface.
    """
    from .intelligence.intel_dump import UNTRUSTED_DATA_RULES

    base = (base_prompt or "").strip()
    if base:
        return base + "\n\n" + UNTRUSTED_DATA_RULES
    return UNTRUSTED_DATA_RULES


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
#  AI Persona Summary
# -------------------------------------------------------------------
def generate_persona_summary(intel, groq_api_key=None):
    """
    Ask the LLM to summarise the subject's persona using the FULL intel
    dump rather than just bios and emails.

    The *groq_api_key* argument is accepted for backwards compatibility
    but ignored — the active provider and its key are read from the
    config via ``get_llm_endpoint()``.
    """
    base_url, api_key, extra_headers = get_llm_endpoint()
    if not api_key:
        return None

    try:
        from openai import OpenAI
        from .intelligence.intel_dump import build_intel_dump

        client = OpenAI(
            base_url=base_url,
            api_key=api_key,
            default_headers=extra_headers or None,
        )

        model, temp, tokens, custom_prompt, budget, include_raw, exclude_meta = \
            _llm_settings()

        dump = build_intel_dump(
            intel,
            budget=budget,
            include_raw=include_raw,
            exclude_meta=exclude_meta,
        )
        if not dump.strip():
            return "Insufficient data to form a persona."

        user_prompt = (
            "You are an experienced OSINT investigator.  Using the "
            "complete investigation dump below, write a single concise "
            "paragraph (4-6 sentences) describing the subject's online "
            "persona, interests, profession, and any notable "
            "characteristics.  Use clear, factual language.  Cite the "
            "section name when a finding is important.\n\n"
            + dump
        )

        system_prompt = _build_system_prompt(
            custom_prompt
            or "You are an experienced OSINT investigator. "
               "Respond with plain prose, no markdown fences."
        )

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens=min(tokens, 4000),
            temperature=temp,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"  Persona summary error: {e}")
        return None


# -------------------------------------------------------------------
#  AI structured report (JSON)
# -------------------------------------------------------------------
def generate_ai_report(core, groq_api_key=None):
    """
    Generate a structured JSON report using the FULL intel dump.

    The *groq_api_key* argument is accepted for backwards compatibility
    but ignored — the active provider and its key are read from the
    config via ``get_llm_endpoint()``.
    """
    base_url, api_key, extra_headers = get_llm_endpoint()
    if not api_key:
        print("  AI report skipped – no API key set for the active provider.")
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
        from .intelligence.intel_dump import build_intel_dump

        client = OpenAI(
            base_url=base_url,
            api_key=api_key,
            default_headers=extra_headers or None,
        )

        model, temp, tokens, custom_prompt, budget, include_raw, exclude_meta = \
            _llm_settings()

        dump = build_intel_dump(
            intel,
            budget=budget,
            include_raw=include_raw,
            exclude_meta=exclude_meta,
        )

        user_prompt = (
            "You are an OSINT analyst.  Using the complete investigation "
            "dump below, produce a concise JSON report with exactly these "
            "keys:\n\n"
            "- executive_summary: a brief overview of the investigation\n"
            "- identity_assessment: evaluation of the subject's identity "
            "(pseudonymity, possible real name)\n"
            "- digital_footprint: summary of platforms, categories, and "
            "online presence\n"
            "- risk_indicators: identified risks (breaches, exposed info, "
            "password reuse, etc.)\n"
            "- relationship_analysis: connections between data points\n"
            "- critical_points: a list of the most important findings "
            "(array of strings)\n\n"
            + dump
        )

        system_prompt = _build_system_prompt(
            custom_prompt
            or "You are an OSINT analyst. Respond ONLY with valid JSON, "
               "no markdown fences, no preamble."
        )

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens=min(tokens, 5500),
            temperature=temp,
        )
        raw = response.choices[0].message.content.strip()
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.MULTILINE)

        try:
            parsed = json.loads(cleaned)
            if not isinstance(parsed, dict):
                raise ValueError("expected a JSON object at the top level")
            return parsed
        except Exception as parse_exc:
            print(f"  AI report parse error: {parse_exc}")
            return {
                "executive_summary":  (
                    "[AI report could not be parsed as JSON. "
                    "See debug logs for the raw response.]"
                ),
                "identity_assessment": "",
                "digital_footprint":  "",
                "risk_indicators":    "",
                "critical_points":    [],
                "_parse_error":       str(parse_exc),
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