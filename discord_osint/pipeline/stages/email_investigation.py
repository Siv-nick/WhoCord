"""
discord_osint/pipeline/stages/email_investigation.py
------------------------------------------------------
EmailInvestigationStage – Phase 4 standalone email investigation module.

This is the dedicated entry-point stage when mode="email".  Unlike the
legacy EmailIntelStage (which enriches emails discovered mid-pipeline),
this stage:

  1. Registers the target email as a first-class intel seed.
  2. Runs every email-intelligence tool available (same wrappers as
     EmailIntelStage).
  3. Runs Blackbird email search to find linked social profiles and
     populates ctx.discovery / ctx.all_urls so a follow-on ScrapingStage
     can enrich those profiles.

Reads from ctx
--------------
ctx.manual_email  – the target email address

Writes to ctx
-------------
ctx.intel_core    – breaches, holehe sites, hibp, emailrep, ghunt,
                    gravatar, smtp verification, blackbird profiles
ctx.discovery     – social profiles found via Blackbird
ctx.avatar_urls   – Gravatar avatar URL if found
"""

from __future__ import annotations
import json
from ...utils.mosint_wrapper import run_mosint
from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...scraping import is_valid_email
from ...email_intel import (
    run_holehe,
    run_h8mail,
    run_ghunt,
    run_scylla,
    check_hibp,
    check_emailrep,
    verify_email_smtp_advanced,
    gravatar_lookup,
)

_MAX_EMAILS = 5


class EmailInvestigationStage(Stage):
    """
    Standalone email investigation.
    Runs all email-intelligence tools against ctx.manual_email.
    """

    name = "email_investigation"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        email = ctx.manual_email.strip().lower()

        if not email:
            print("  [EmailInvestigation] No email supplied – skipping.")
            return

        if not is_valid_email(email):
            print(f"  [EmailInvestigation] Invalid email {email!r} – skipping.")
            return

        print(f"\n{'=' * 60}")
        print(f"== Email Investigation: {email}")
        print(f"{'=' * 60}")
        emit("progress", {"message": f"Email investigation: {email}"})

        # Seed the email into intel so downstream stages see it
        ctx.intel_core.add_intel("emails", email, email, source="manual_input")

        cfg = ctx.config

        # ------------------------------------------------------------------ #
        # Holehe – site registrations                                         #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_HOLEHE:
            print("\n-- Holehe (site registrations) --")
            emit("progress", {"message": "Holehe: checking site registrations", "tool": "holehe"})
            try:
                sites = run_holehe(email) or []
                if sites:
                    ctx.intel_core.add_intel(
                        "breaches", f"holehe_{email}",
                        {"used_on": sites}, source="holehe",
                    )
                    emit("finding", {"type": "holehe", "email": email, "sites": sites, "count": len(sites)})
                    print(f"  Holehe: {email} registered on {len(sites)} site(s): {', '.join(sites[:5])}")
                else:
                    print("  Holehe: no registrations found.")
            except Exception as exc:
                print(f"  Holehe error: {exc}")

        # ------------------------------------------------------------------ #
        # h8mail – breach check                                               #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_H8MAIL:
            print("\n-- h8mail (breach check) --")
            emit("progress", {"message": "h8mail: breach check", "tool": "h8mail"})
            try:
                h8 = run_h8mail(email)
                if h8:
                    ctx.intel_core.add_intel("breaches", f"h8mail_{email}", h8, source="h8mail")
                    emit("finding", {"type": "h8mail", "email": email, "result": h8})
                    print(f"  h8mail: breach data found.")
                else:
                    print("  h8mail: no breach data.")
            except Exception as exc:
                print(f"  h8mail error: {exc}")

        # ------------------------------------------------------------------ #
        # HaveIBeenPwned                                                       #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_HIBP:
            print("\n-- HIBP (HaveIBeenPwned) --")
            emit("progress", {"message": "Checking HaveIBeenPwned", "tool": "hibp"})
            try:
                hibp = check_hibp(email) or []
                if hibp:
                    ctx.intel_core.add_intel("breaches", f"hibp_{email}", hibp, source="hibp")
                    emit("finding", {"type": "hibp", "email": email, "breaches": len(hibp)})
                    print(f"  HIBP: {len(hibp)} breach(es) found.")
                else:
                    print("  HIBP: no breaches.")
            except Exception as exc:
                print(f"  HIBP error: {exc}")

        # ------------------------------------------------------------------ #
        # EmailRep                                                             #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_EMAILREP:
            print("\n-- EmailRep --")
            emit("progress", {"message": "EmailRep reputation check", "tool": "emailrep"})
            try:
                rep = check_emailrep(email) or {}
                if rep:
                    ctx.intel_core.add_intel("emailrep", email, rep, source="emailrep")
                    emit("finding", {"type": "emailrep", "email": email, "data": rep})
                    print(f"  EmailRep: data retrieved.")
            except Exception as exc:
                print(f"  EmailRep error: {exc}")

        # ------------------------------------------------------------------ #
        # GHunt (Gmail only)                                                  #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_GHUNT and email.endswith("@gmail.com"):
            print("\n-- GHunt (Gmail) --")
            emit("progress", {"message": "GHunt: Google account lookup", "tool": "ghunt"})
            try:
                gh = run_ghunt(email)
                if gh:
                    ctx.intel_core.add_intel("ghunt", email, gh, source="ghunt")
                    emit("finding", {"type": "ghunt", "email": email})
                    print(f"  GHunt: data retrieved.")

                    # Build a socid‑like dict so the HTML parser can render a card
                    socid = {}
                    if isinstance(gh, dict):
                        avatar = gh.get("profile_picture") or gh.get("avatar") or ""
                        if avatar:
                            socid["image"] = avatar
                        socid["name"] = gh.get("name") or email

                        # Basic fields
                        for field, label in [
                            ("gaia_id", "Gaia ID"),
                            ("last_profile_edit", "Last Profile Edit"),
                        ]:
                            if gh.get(field):
                                socid[field] = str(gh[field])

                        # User types
                        if gh.get("user_types") and isinstance(gh["user_types"], list):
                            socid["user_types"] = ", ".join(gh["user_types"])

                        # Services
                        if gh.get("activated_services") and isinstance(gh["activated_services"], list):
                            socid["services"] = ", ".join(gh["activated_services"])

                        # ─── MAPS DATA – flat keys only, no nesting checks ───
                        # These keys come directly from run_ghunt().
                        for flat_key, display_key in [
                            ("maps_reviews", "reviews"),
                            ("maps_answers", "answers"),
                            ("maps_profile", "maps_profile"),
                        ]:
                            val = gh.get(flat_key)
                            if val:
                                # Use the display key (not "maps_*") for clean HTML rows
                                socid[display_key] = str(val)
                                print(f"    [GHUNT DEBUG] Added {display_key} = {val}")   # ← temporary debug

                        # Ensure profile page URL is clickable
                        if gh.get("maps_profile") and "maps_profile" not in socid:
                            socid["maps_profile"] = str(gh["maps_profile"])

                        # Store as a social profile (socid_raw format)
                        ctx.intel_core.add_intel(
                            "social_profiles",
                            "google/ghunt/socid_raw",
                            json.dumps(socid),
                            source="ghunt",
                        )
                        print(f"    [GHUNT DEBUG] socid keys stored: {list(socid.keys())}")   # ← temporary debug
            except Exception as exc:
                print(f"  GHunt error: {exc}")

        # ------------------------------------------------------------------ #
        # SMTP verification                                                   #
        # ------------------------------------------------------------------ #
        if getattr(cfg, "ENABLE_EMAIL_VERIFY", False):
            print("\n-- SMTP Verification --")
            emit("progress", {"message": "SMTP: verifying deliverability"})
            try:
                vrf = verify_email_smtp_advanced(email)
                if vrf:
                    ctx.intel_core.add_intel(
                        "email_verification", f"verify_{email}", vrf, source="smtp_verify"
                    )
                    print(f"  SMTP: {vrf}")
            except Exception as exc:
                print(f"  SMTP verification error: {exc}")

        # ------------------------------------------------------------------ #
        # Gravatar                                                             #
        # ------------------------------------------------------------------ #
        print("\n-- Gravatar --")
        emit("progress", {"message": "Gravatar lookup"})
        try:
            grav_url = gravatar_lookup(email)
            if grav_url:
                ctx.intel_core.add_intel(
                    "social_profiles", f"gravatar_{email}", grav_url, source="gravatar"
                )
                ctx.add_avatar(grav_url)
                emit("finding", {"type": "gravatar", "email": email, "url": grav_url})
                print(f"  Gravatar: {grav_url}")
        except Exception as exc:
            print(f"  Gravatar error: {exc}")

        # ------------------------------------------------------------------ #
        # Scylla                                                               #
        # ------------------------------------------------------------------ #
        if cfg.ENABLE_SCYLLA:
            print("\n-- Scylla breach DB --")
            emit("progress", {"message": "Scylla: breach database", "tool": "scylla"})
            try:
                scylla_data = run_scylla(email)
                if scylla_data:
                    ctx.intel_core.add_intel(
                        "breaches", f"scylla_{email}", scylla_data, source="scylla"
                    )
                    emit("finding", {"type": "scylla", "email": email})
                    print(f"  Scylla: data found.")
            except Exception as exc:
                print(f"  Scylla error: {exc}")

        # ------------------------------------------------------------------ #
        # Blackbird – email → social profiles                                 #
        # ------------------------------------------------------------------ #
        self._run_blackbird_email(ctx, email, emit)

        # ------------------------------------------------------------------ #
        # MOSINT – reverse email lookup for social accounts                   #
        # ------------------------------------------------------------------ #
        print("\n-- MOSINT (reverse email lookup) --")
        emit("progress", {"message": "MOSINT: reverse email lookup", "tool": "mosint"})
        try:
            mosint_data = run_mosint(email)
            if mosint_data:
                # MOSINT can return a list or a dict; normalise to a list
                if isinstance(mosint_data, list):
                    accounts = mosint_data
                elif isinstance(mosint_data, dict):
                    accounts = mosint_data.get("data", [])
                    if not accounts:
                        accounts = mosint_data.get("results", [])
                else:
                    accounts = []

                found = 0
                for acc in accounts:
                    if not isinstance(acc, dict):
                        continue
                    url = acc.get("url") or acc.get("profile_url")
                    username = acc.get("username") or acc.get("account")
                    if url and url.startswith("http"):
                        ctx.intel_core.add_intel(
                            "social_profiles",
                            f"mosint_{url[:60]}",
                            url,
                            source="mosint",
                        )
                        found += 1
                    elif username:
                        # Minimal fallback – still register the finding
                        ctx.intel_core.add_intel(
                            "social_profiles",
                            f"mosint_username_{username}",
                            username,
                            source="mosint",
                        )

                if found:
                    emit("finding", {"type": "mosint_profiles", "count": found})
                    print(f"  MOSINT: {found} profile URL(s) found.")
                else:
                    print("  MOSINT: no profile URLs found.")
            else:
                print("  MOSINT: no output.")
            if isinstance(mosint_data, dict):
                ctx.intel_core.intel.setdefault("mosint", {})[email.lower()] = mosint_data
        except Exception as exc:
            print(f"  MOSINT error: {exc}")

        # Feed ALL discovered URLs into all_urls so ScrapingStage can enrich them
        discovered_urls = [e["url"] for e in ctx.discovery if e.get("url")]
        ctx.all_urls = list(set(ctx.all_urls) | set(discovered_urls))

        print(f"\n== Email investigation complete: {email} ==")

    # ------------------------------------------------------------------ #
    # Blackbird email search                                               #
    # ------------------------------------------------------------------ #

    def _run_blackbird_email(
        self,
        ctx: InvestigationContext,
        email: str,
        emit: EmitFn,
    ) -> None:
        """
        Run Blackbird in email mode, fetch each API endpoint's JSON response
        (if available), and store enriched data directly in intel.
        """
        try:
            from ...username_search import run_blackbird
        except ImportError:
            return

        cfg = ctx.config
        if not getattr(cfg, "ENABLE_BLACKBIRD", False):
            return

        print("\n-- Blackbird (email search) --")
        emit("progress", {"message": "Blackbird: email search", "tool": "blackbird"})
        try:
            results = run_blackbird(email, mode="email") or []
            found = 0
            for r in results:
                url = r.get("url", "")
                site = r.get("site", "blackbird")
                if url and url.startswith("http"):
                    # Store the URL as a social profile
                    ctx.intel_core.add_intel(
                        "social_profiles",
                        f"blackbird_email_{url[:60]}",
                        url,
                        source="blackbird_email",
                    )
                    # Try to fetch the endpoint and store the JSON as socid_raw
                    self._fetch_and_store_api_data(ctx, url)
                    found += 1
            print(f"  Blackbird: {found} profile URL(s) found.")
            if found:
                emit("finding", {
                    "type":   "social_profiles_found",
                    "source": "blackbird_email",
                    "count":  found,
                })
        except Exception as exc:
            print(f"  Blackbird email error: {exc}")

    def _fetch_and_store_api_data(self, ctx: InvestigationContext, url: str) -> None:
        import requests, json as _json
        headers = {"User-Agent": "Mozilla/5.0"}
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", "").lower():
                data = r.json()
                key = f"blackbird_api_{url[:60]}/socid_raw"
                ctx.intel_core.add_intel("social_profiles", key, _json.dumps(data), source="blackbird_api")
                print(f"    Stored API data for {url[:60]}")
            else:
                print(f"    API fetch failed for {url[:60]}: status {r.status_code}, content-type {r.headers.get('Content-Type')}")
        except Exception as e:
            print(f"    API fetch error for {url[:60]}: {e}")
        except Exception:
            pass
