"""
discord_osint/pipeline/stages/analysis.py
------------------------------------------
AnalysisStage – WHOIS lookups, Wayback Machine, GitFive, name
analysis, location/language inference, and identity confidence scoring.

This stage runs after scraping so it can work with the full set of
collected intel.

Reads from ctx
--------------
ctx.intel_core.intel   – all gathered data
ctx.all_urls           – to find GitHub usernames and blog domains

Writes to ctx
-------------
ctx.intel_core         – WHOIS, wayback, gitfive emails/names,
                          name analysis, location, language,
                          confidence_scores
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...discord_api import classify_url
from ...scraping import (
    looks_like_real_name_v2, is_valid_personal_email, is_likely_github_user
)
from ...extras import whois_domain, wayback_available, infer_location, detect_language
from ...scraping import run_gitfive
from ...reporting import calculate_identity_confidence, run_name_analysis
from ...utils import tool_available, install_package

class AnalysisStage(Stage):
    name = "analysis"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        cfg = ctx.config
        intel = ctx.intel_core.intel

        # ------------------------------------------------------------------ #
        # 1. WHOIS on blog domains                                            #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_WHOIS:
            print("\n-- WHOIS on blog domains --")
            emit("progress", {"message": "WHOIS lookups"})
            blogs: list[str] = []
            for k, v in intel.get("social_profiles", {}).items():
                if "blog" in k and v.get("value", "").startswith("http"):
                    blogs.append(v["value"])
            for blog_url in set(blogs):
                try:
                    domain = urlparse(blog_url).netloc
                    if domain:
                        w = whois_domain(domain)
                        if w:
                            ctx.intel_core.add_intel(
                                "whois", domain, w, source="whois"
                            )
                            emit("finding", {"type": "whois", "domain": domain, "data": w})
                except Exception as exc:
                    print(f"  WHOIS error for {blog_url}: {exc}")

        # ------------------------------------------------------------------ #
        # 2. Wayback Machine                                                  #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_WAYBACK:
            print("\n-- Wayback Machine --")
            emit("progress", {"message": "Wayback Machine checks"})
            for url in ctx.all_urls:
                snap = wayback_available(url)
                if snap:
                    ctx.intel_core.add_intel(
                        "wayback", url, snap, source="wayback"
                    )
                    emit("finding", {"type": "wayback", "url": url, "snapshot": snap})

        # ------------------------------------------------------------------ #
        # 3. GitFive on GitHub usernames                                      #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_GITFIVE:
            print("\n-- GitFive on GitHub usernames --")
            emit("progress", {"message": "GitFive GitHub analysis"})
            github_slugs: set[str] = set()
            for url in ctx.all_urls:
                pl, sl = classify_url(url)
                if pl == "github" and sl and is_likely_github_user(sl):
                    github_slugs.add(sl)

            # Auto‑install gitfive if missing
            if not tool_available("gitfive"):
                print("  gitfive not found – attempting to install via pip …")
                if install_package("gitfive"):
                    print("  gitfive installed successfully.")
                else:
                    print("  [X] Could not install gitfive. Please run: pip install gitfive")
            for slug in github_slugs:
                print(f"  GitFive on {slug}...")
                gf = run_gitfive(slug) or {}
                for email_entry in gf.get("emails", []):
                    email = email_entry.get("email", "")
                    if is_valid_personal_email(email):
                        ctx.intel_core.add_intel(
                            "emails", f"gitfive_{email}",
                            email, source="gitfive",
                        )
                        emit("finding", {"type": "email", "value": email, "source": "gitfive"})
                name = gf.get("name", "")
                if name and looks_like_real_name_v2(name):
                    ctx.intel_core.add_intel(
                        "identity_clues", f"name_gitfive_{slug}",
                        name, source="gitfive",
                    )

        # ------------------------------------------------------------------ #
        # 4. Name analysis (NameTrace + RapidFuzz)                           #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_NAME_ANALYSIS:
            print("\n-- Name analysis --")
            emit("progress", {"message": "Name analysis"})
            name_set: set[str] = set()
            for k, v in intel.get("identity_clues", {}).items():
                if k.startswith("name_") and v.get("value"):
                    name_set.add(v["value"])
            if name_set:
                analysis = run_name_analysis(list(name_set))
                ctx.intel_core.intel["name_analysis"] = analysis
                for name, origin in analysis.get("name_origins", {}).items():
                    ctx.intel_core.add_intel(
                        "name_analysis", f"origin_{name}",
                        origin, source="nametrace",
                    )
                similarity = analysis.get("similarity_matrix", {})
                if similarity:
                    emit("finding", {"type": "name_similarity", "data": similarity})

        # ------------------------------------------------------------------ #
        # 5. Location & language detection                                    #
        # ------------------------------------------------------------------ #
        all_text = ""
        for k, v in intel.get("social_profiles", {}).items():
            if "bio" in k or "desc" in k:
                all_text += v.get("value", "") + " "

        if all_text.strip():
            if cfg.ENABLE_LOCATION:
                print("\n-- Location inference --")
                loc = infer_location(all_text)
                if loc:
                    ctx.intel_core.add_intel(
                        "identity_clues", "inferred_location",
                        loc, source="location_inference",
                    )
                    emit("finding", {"type": "location", "value": loc})
                    print(f"  Inferred location: {loc}")

            if cfg.ENABLE_LANGDETECT:
                print("\n-- Language detection --")
                lang = detect_language(all_text)
                if lang:
                    ctx.intel_core.add_intel(
                        "identity_clues", "language",
                        lang, source="langdetect",
                    )
                    emit("finding", {"type": "language", "value": str(lang)})
                    print(f"  Detected language: {lang}")

        # ------------------------------------------------------------------ #
        # 6. Confidence scoring (always runs)                                 #
        # ------------------------------------------------------------------ #
        print("\n-- Identity confidence scoring --")
        scores = calculate_identity_confidence(intel)
        ctx.intel_core.intel["confidence_scores"] = scores
        if scores:
            top = scores[0]
            print(f"  Top identity candidate: {top.get('name')} "
                  f"(score {top.get('score')})")
            emit("finding", {"type": "confidence_scores", "data": scores})
