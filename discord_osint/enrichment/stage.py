"""
discord_osint/enrichment/stage.py
---------------------------------
EnrichmentStage — the opt-in contact-enrichment phase.

Runs at the end of the main pipeline, after every collection stage has
had a chance to deposit emails, phones, and LinkedIn URLs into the
investigation's intel dict.

Flow
----
1. Collect every email, phone, and LinkedIn URL the investigation has.
2. Build the corroboration context (names, domains, locations).
3. Evaluate each identifier against each enabled provider through the
   shared trust filter.
4. Record both accepted and rejected decisions in
   ``intel["enrichment_decisions"]`` so the report can show the audit.
5. Cap the accepted set per provider (``ENRICHMENT_MAX_IDENTIFIERS``),
   sort by score, check the provider's credit balance, and submit.
6. Parse the response, fold newly-discovered emails / phones / names /
   profile URLs back into the standard intel buckets so the pivot engine
   can chase them, and store the full enriched profiles under
   ``intel["enrichment_profiles"]["<provider>"]``.

Failure behaviour
-----------------
Enrichment is a nice-to-have. Every provider call is wrapped so a
network failure, auth rejection, rate limit, or plan restriction skips
that provider cleanly and lets the investigation continue. The stage
never raises.
"""

from __future__ import annotations

from typing import Any

from ..pipeline.base import Stage, EmitFn
from ..pipeline.context import InvestigationContext
from .trust_filter import (
    FilterDecision,
    Identifier,
    collect_context,
    evaluate_many,
)
from .apollo_client import (
    ApolloClient,
    ApolloAuthError,
    ApolloCreditError,
)
from .lusha_client import (
    LushaClient,
    LushaAuthError,
    LushaCreditError,
    LushaPlanError,
)

try:
    from ..utils import log_trace
except Exception:  # pragma: no cover
    def log_trace(msg: str) -> None:
        pass


_DEFAULT_CAP = 25


class EnrichmentStage(Stage):
    """Opt-in Apollo / Lusha contact enrichment."""

    name = "enrichment"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        cfg = ctx.config

        providers: list[str] = []
        if bool(getattr(cfg, "ENABLE_APOLLO", False)) and \
                (getattr(cfg, "APOLLO_API_KEY", "") or "").strip():
            providers.append("apollo")
        if bool(getattr(cfg, "ENABLE_LUSHA", False)) and \
                (getattr(cfg, "LUSHA_API_KEY", "") or "").strip():
            providers.append("lusha")

        if not providers:
            log_trace("enrichment: no provider enabled or configured — skipping.")
            return

        print("\n" + "=" * 60)
        print(f"== Contact Enrichment ({', '.join(providers)})")
        print("=" * 60)
        emit("progress", {
            "message": f"Contact enrichment: {', '.join(providers)}",
        })

        # ------------------------------------------------------------------ #
        # 1. Collect identifiers                                              #
        # ------------------------------------------------------------------ #
        identifiers = self._collect_identifiers(ctx)
        if not identifiers:
            print("  No identifiers to evaluate — skipping enrichment.")
            log_trace("enrichment: no identifiers collected.")
            return

        print(f"  Collected {len(identifiers)} identifier(s) from the investigation.")

        # ------------------------------------------------------------------ #
        # 2. Corroboration context                                            #
        # ------------------------------------------------------------------ #
        context = collect_context(ctx.intel_core.intel)
        for ident in identifiers:
            ident.context = context

        # ------------------------------------------------------------------ #
        # 3. Evaluate per provider                                            #
        # ------------------------------------------------------------------ #
        cap = int(getattr(cfg, "ENRICHMENT_MAX_IDENTIFIERS", _DEFAULT_CAP))
        cap = max(1, cap)

        decisions_by_provider: dict[str, list[FilterDecision]] = {}
        for provider in providers:
            decisions = evaluate_many(identifiers, provider)  # type: ignore[arg-type]
            decisions_by_provider[provider] = decisions

            accepted = [d for d in decisions if d.accepted]
            rejected = [d for d in decisions if not d.accepted]
            print(
                f"  Trust filter [{provider}]: "
                f"{len(accepted)} accepted / {len(rejected)} rejected "
                f"of {len(decisions)}."
            )
            for d in rejected[:5]:
                print(f"    ✗ {d.identifier.kind}: {d.identifier.value[:50]} — {d.reason}")

        # Persist the full decision list for the report.
        ctx.intel_core.intel["enrichment_decisions"] = {
            provider: [d.to_dict() for d in decisions]
            for provider, decisions in decisions_by_provider.items()
        }

        # ------------------------------------------------------------------ #
        # 4. Submit per provider                                              #
        # ------------------------------------------------------------------ #
        spend_summary: dict[str, dict] = {}

        for provider in providers:
            decisions = decisions_by_provider[provider]
            accepted = [d for d in decisions if d.accepted]
            accepted.sort(key=lambda d: d.score, reverse=True)
            accepted = accepted[:cap]

            if not accepted:
                print(f"  [{provider}] Nothing accepted by the filter — no spend.")
                spend_summary[provider] = {
                    "submitted": 0, "matched": 0,
                    "credits": 0.0, "error": None,
                }
                continue

            print(
                f"  [{provider}] Submitting {len(accepted)} identifier(s) "
                f"(cap={cap})…"
            )
            emit("progress", {
                "message": f"{provider}: submitting {len(accepted)} identifier(s)",
                "tool": provider,
            })

            try:
                summary = self._submit(ctx, provider, accepted, cfg, emit)
                spend_summary[provider] = summary
            except (ApolloAuthError, LushaAuthError) as exc:
                print(f"  [!] {provider}: auth rejected — {exc}")
                spend_summary[provider] = {
                    "submitted": len(accepted), "matched": 0,
                    "credits": 0.0, "error": str(exc),
                }
            except (ApolloCreditError, LushaCreditError) as exc:
                print(f"  [!] {provider}: credits exhausted — {exc}")
                spend_summary[provider] = {
                    "submitted": len(accepted), "matched": 0,
                    "credits": 0.0, "error": str(exc),
                }
            except LushaPlanError as exc:
                print(f"  [!] {provider}: plan restriction — {exc}")
                spend_summary[provider] = {
                    "submitted": len(accepted), "matched": 0,
                    "credits": 0.0, "error": str(exc),
                }
            except Exception as exc:  # noqa: BLE001
                # Enrichment must never abort the run.
                print(f"  [!] {provider}: unexpected error — {exc}")
                log_trace(
                    f"enrichment: {provider} raised "
                    f"{type(exc).__name__}: {exc}"
                )
                spend_summary[provider] = {
                    "submitted": len(accepted), "matched": 0,
                    "credits": 0.0, "error": str(exc),
                }

        ctx.intel_core.intel["enrichment_spend"] = spend_summary

        # ------------------------------------------------------------------ #
        # 5. Summary                                                          #
        # ------------------------------------------------------------------ #
        total_credits = sum(s.get("credits", 0.0) for s in spend_summary.values())
        total_matched = sum(s.get("matched", 0) for s in spend_summary.values())
        print(
            f"\n  Enrichment complete — "
            f"{total_matched} profile(s) matched, "
            f"{total_credits:g} credit(s) consumed."
        )
        emit("finding", {
            "type":            "enrichment_complete",
            "providers":       list(spend_summary.keys()),
            "matched":         total_matched,
            "credits_consumed": total_credits,
        })

    # ------------------------------------------------------------------ #
    # Identifier collection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _collect_identifiers(ctx: InvestigationContext) -> list[Identifier]:
        """
        Walk every intel bucket that can contain an email, phone, or
        LinkedIn URL and return a de-duplicated list of Identifiers.
        """
        intel = ctx.intel_core.intel
        seen: set[tuple[str, str]] = set()
        out: list[Identifier] = []

        def _add(kind: str, value: str, source: str) -> None:
            if not value:
                return
            key = (kind, value.strip().lower())
            if key in seen:
                return
            seen.add(key)
            out.append(Identifier(kind=kind, value=value.strip(), source=source))  # type: ignore[arg-type]

        # Emails — the canonical bucket plus a couple of one-off stores.
        for _key, entry in (intel.get("emails") or {}).items():
            val, src = _unpack(entry)
            if val and "@" in val:
                _add("email", val, src or "unknown")

        for _key, entry in (intel.get("harvester_emails") or {}).items():
            val = entry.get("value") if isinstance(entry, dict) else entry
            if isinstance(val, dict):
                for email in val.get("emails", []):
                    if isinstance(email, str) and "@" in email:
                        _add("email", email, "theharvester")

        # Phones — from the phone module's intel bucket.
        phone_block = intel.get("phone") or {}
        for key, entry in phone_block.items():
            if key not in ("number", "e164", "raw_input"):
                continue
            val, src = _unpack(entry)
            if val:
                _add("phone", val, src or "phone_metadata")

        # LinkedIn URLs — from social_profiles, any key that mentions
        # linkedin, and any value that is a linkedin.com/in/ URL.
        for key, entry in (intel.get("social_profiles") or {}).items():
            val, src = _unpack(entry)
            if not val:
                continue
            if "linkedin" in key.lower() or "linkedin.com/in/" in val.lower():
                if "linkedin.com/in/" in val.lower():
                    _add("linkedin", val, src or "social_profiles")

        for _key, entry in (intel.get("discovered_urls") or {}).items():
            val, src = _unpack(entry)
            if isinstance(val, str) and "linkedin.com/in/" in val.lower():
                _add("linkedin", val, src or "discovery")

        return out

    # ------------------------------------------------------------------ #
    # Submission
    # ------------------------------------------------------------------ #

    def _submit(
        self,
        ctx: InvestigationContext,
        provider: str,
        accepted: list[FilterDecision],
        cfg: Any,
        emit: EmitFn,
    ) -> dict:
        identifiers = [d.identifier for d in accepted]

        if provider == "apollo":
            client = ApolloClient(getattr(cfg, "APOLLO_API_KEY", ""))

            # Credit-safety pre-check.
            balance = client.get_credit_balance()
            if balance is not None:
                lead = balance.get("lead")
                if lead is not None and lead <= 0:
                    print(
                        "  [!] Apollo: reported lead-credit balance is 0 — "
                        "skipping submission."
                    )
                    log_trace("enrichment: apollo lead credit balance is 0.")
                    return {
                        "submitted": len(identifiers), "matched": 0,
                        "credits": 0.0,
                        "error": "lead credit balance is 0",
                        "balance": balance,
                    }
                ctx.intel_core.intel.setdefault("enrichment_balance", {})["apollo"] = balance

            result = client.enrich(identifiers)
            self._fold_apollo(ctx, result, emit)
            return {
                "submitted": len(identifiers),
                "matched":   result.matched_count,
                "credits":   result.credits_consumed,
                "error":     None,
            }

        if provider == "lusha":
            client = LushaClient(getattr(cfg, "LUSHA_API_KEY", ""))

            balance = client.get_credit_balance()
            if balance is not None:
                if balance <= 0:
                    print(
                        "  [!] Lusha: reported credit balance is 0 — "
                        "skipping submission."
                    )
                    log_trace("enrichment: lusha credit balance is 0.")
                    return {
                        "submitted": len(identifiers), "matched": 0,
                        "credits": 0.0,
                        "error": "credit balance is 0",
                        "balance": 0,
                    }
                ctx.intel_core.intel.setdefault("enrichment_balance", {})["lusha"] = balance

            reveal_phones = bool(
                getattr(cfg, "ENABLE_ENRICHMENT_PHONE_REVEAL", False)
            )
            result = client.enrich(identifiers, reveal_phones=reveal_phones)
            self._fold_lusha(ctx, result, emit)
            return {
                "submitted": len(identifiers),
                "matched":   result.matched_count,
                "credits":   result.credits_consumed,
                "error":     None,
            }

        return {"submitted": 0, "matched": 0, "credits": 0.0, "error": "unknown provider"}

    # ------------------------------------------------------------------ #
    # Folding results back into the investigation
    # ------------------------------------------------------------------ #

    @staticmethod
    def _fold_apollo(
        ctx: InvestigationContext,
        result: Any,
        emit: EmitFn,
    ) -> None:
        """
        Store Apollo matches under ``enrichment_profiles.apollo`` and
        fold the newly-discovered emails / LinkedIn URLs / names into the
        standard intel buckets so the pivot engine can chase them.
        """
        intel = ctx.intel_core.intel
        intel.setdefault("enrichment_profiles", {})["apollo"] = result.matches

        for person in result.matches:
            if not isinstance(person, dict):
                continue

            email = person.get("email")
            if isinstance(email, str) and "@" in email:
                ctx.intel_core.add_intel(
                    "emails", f"apollo_{email}", email, source="apollo"
                )
                emit("finding", {"type": "email", "value": email, "source": "apollo"})

            linkedin = person.get("linkedin_url")
            if isinstance(linkedin, str) and "linkedin.com/in/" in linkedin:
                ctx.intel_core.add_intel(
                    "social_profiles",
                    f"apollo_linkedin_{linkedin[:60]}",
                    linkedin,
                    source="apollo",
                )

            name = person.get("name")
            if isinstance(name, str) and name.strip():
                ctx.intel_core.add_intel(
                    "identity_clues",
                    f"name_apollo_{name[:40]}",
                    name.strip(),
                    source="apollo",
                )

            # Organisation domain can seed a pivot on the company.
            org = person.get("organization") or {}
            if isinstance(org, dict):
                domain = org.get("primary_domain")
                if isinstance(domain, str) and "." in domain:
                    ctx.intel_core.add_intel(
                        "social_profiles",
                        f"apollo_org_{domain}",
                        f"https://{domain}",
                        source="apollo",
                    )

    @staticmethod
    def _fold_lusha(
        ctx: InvestigationContext,
        result: Any,
        emit: EmitFn,
    ) -> None:
        intel = ctx.intel_core.intel
        intel.setdefault("enrichment_profiles", {})["lusha"] = result.contacts

        for contact in result.contacts:
            if not isinstance(contact, dict):
                continue

            # Email may be a string or a list of {emailAddress: ...} dicts.
            emails = _lusha_emails(contact)
            for email in emails:
                if "@" in email:
                    ctx.intel_core.add_intel(
                        "emails", f"lusha_{email}", email, source="lusha"
                    )
                    emit("finding", {"type": "email", "value": email, "source": "lusha"})

            phones = _lusha_phones(contact)
            for phone in phones:
                ctx.intel_core.add_intel(
                    "phone", f"lusha_{phone}", phone, source="lusha"
                )

            linkedin = contact.get("linkedinUrl") or contact.get("linkedin_url")
            if isinstance(linkedin, str) and "linkedin.com/in/" in linkedin:
                ctx.intel_core.add_intel(
                    "social_profiles",
                    f"lusha_linkedin_{linkedin[:60]}",
                    linkedin,
                    source="lusha",
                )

            name_parts = [
                contact.get("firstName") or contact.get("first_name") or "",
                contact.get("lastName")  or contact.get("last_name")  or "",
            ]
            full_name = " ".join(p for p in name_parts if p).strip()
            if full_name:
                ctx.intel_core.add_intel(
                    "identity_clues",
                    f"name_lusha_{full_name[:40]}",
                    full_name,
                    source="lusha",
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unpack(entry: Any) -> tuple[str, str]:
    """Return ``(value_str, source_str)`` from an intel dict entry."""
    if isinstance(entry, dict):
        val = entry.get("value", "")
        src = entry.get("source", "") or ""
        if not isinstance(val, str):
            val = str(val) if val is not None else ""
        return val.strip(), str(src).strip()
    if entry is None:
        return "", ""
    return str(entry).strip(), ""


def _lusha_emails(contact: dict) -> list[str]:
    """Extract email strings from a Lusha contact object."""
    out: list[str] = []
    for key in ("email", "emailAddress", "emailAddresses", "emails"):
        val = contact.get(key)
        if isinstance(val, str) and "@" in val:
            out.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and "@" in item:
                    out.append(item)
                elif isinstance(item, dict):
                    for sub in ("emailAddress", "email", "address"):
                        e = item.get(sub)
                        if isinstance(e, str) and "@" in e:
                            out.append(e)
    return list(dict.fromkeys(out))


def _lusha_phones(contact: dict) -> list[str]:
    """Extract phone strings from a Lusha contact object."""
    out: list[str] = []
    for key in ("phone", "phoneNumber", "phoneNumbers", "phones"):
        val = contact.get(key)
        if isinstance(val, str) and val.strip():
            out.append(val.strip())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    out.append(item.strip())
                elif isinstance(item, dict):
                    for sub in ("phoneNumber", "number", "internationalNumber"):
                        p = item.get(sub)
                        if isinstance(p, str) and p.strip():
                            out.append(p.strip())
    return list(dict.fromkeys(out))