"""
discord_osint/enrichment/trust_filter.py
----------------------------------------
Shared identifier trust filter for paid contact-enrichment providers.

Every identifier the investigation discovers is evaluated here before it
is allowed to consume a credit at Apollo or Lusha. The filter answers a
single question per identifier: "is this plausibly a real,
professionally-active person's contact detail, and did it come from a
source worth trusting?"

Design
------
The decision is rule-based, not purely score-based, so every rejection
carries a concrete one-line reason the analyst can audit. A numeric
score is also computed and stored alongside the decision; it is used for
ordering the batch and for the audit trail, not as the sole gate.

Three evidence families are weighed:

  1. **Source trust** — a manually-typed email is trusted; one pulled
     from a generic page scraper is not. Sources are bucketed into
     HIGH / MEDIUM / LOW / REJECT tiers.
  2. **Corroboration** — does the identifier agree with anything else
     we already know about the target? Name tokens in the local part,
     a company-domain match, an institutional domain.
  3. **Shape** — does the identifier look like a real one? Throwaway
     domains, role accounts, synthetic-looking local parts, fictional
     phone ranges, and unmatchable line types are rejected outright.

Provider input capability
-------------------------
Neither Apollo nor Lusha accepts a phone number as an *input* identifier
— both only reveal phones as a data point on a person already matched by
email, LinkedIn URL, or name+company. The filter therefore evaluates
phones on their own merits (shape, line type, fictional ranges) and then
rejects them for these providers with a reason that names the
limitation, so the audit log records the decision rather than silently
dropping them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Literal
from urllib.parse import urlparse

try:
    import phonenumbers
    _PHONENUMBERS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PHONENUMBERS_AVAILABLE = False

try:
    from ..utils import log_trace
except Exception:  # pragma: no cover
    def log_trace(msg: str) -> None:
        pass


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

IdentifierKind = Literal["email", "phone", "linkedin"]
ProviderName   = Literal["apollo", "lusha"]


@dataclass
class Identifier:
    """One candidate identifier discovered during the investigation."""

    kind:    IdentifierKind
    value:   str
    source:  str
    context: dict = field(default_factory=dict)
    """Extra facts about the target used for corroboration:
       ``names``     – list of known name strings
       ``domains``   – list of known company / personal domains
       ``locations`` – list of known location strings
    """


@dataclass
class FilterDecision:
    """The filter's verdict on one identifier."""

    identifier: Identifier
    accepted:   bool
    reason:     str
    score:      float = 0.0

    def to_dict(self) -> dict:
        return {
            "kind":     self.identifier.kind,
            "value":    self.identifier.value,
            "source":   self.identifier.source,
            "accepted": self.accepted,
            "reason":   self.reason,
            "score":    round(self.score, 3),
        }


# ---------------------------------------------------------------------------
# Source trust tiers
# ---------------------------------------------------------------------------

_HIGH_TRUST_SOURCES = frozenset({
    "manual_input",
    "discord_api",
    "discord_enrich",
    "snowflake",
    "phone_metadata",
    "phonenumbers_lib",
    "carrier_api",
})

_MEDIUM_TRUST_SOURCES = frozenset({
    "gitfive",
    "scrape_github",
    "smtp_verify",
    "ghunt",
    "hibp",
    "h8mail",
    "holehe",
    "emailrep",
    "discord_bio",
    "user-scanner",
    "maigret",
    "naminter",
    "theharvester",
    "sharetrace",
    "mosint",
})

_LOW_TRUST_SOURCES = frozenset({
    "scrape_twitter",
    "scrape_reddit",
    "gravatar",
    "socid-extractor",
    "wayback",
    "whois",
    "location_inference",
    "langdetect",
})

_REJECT_SOURCES = frozenset({
    "generic_scrape",
    "url_page_scrape",
    "discovery",
    "api_fetch",
    "blackbird_email",
    "blackbird_api",
})


def _source_tier(source: str) -> str:
    """
    Bucket a source string into HIGH / MEDIUM / LOW / REJECT.

    Unrecognised sources default to LOW so the filter errs on the side of
    not spending a credit.
    """
    if not source:
        return "LOW"
    src = source.lower()
    if src in _HIGH_TRUST_SOURCES:
        return "HIGH"
    if src in _MEDIUM_TRUST_SOURCES:
        return "MEDIUM"
    if src in _LOW_TRUST_SOURCES:
        return "LOW"
    if src in _REJECT_SOURCES:
        return "REJECT"
    # Prefix matching for scrape_* / discovery_* etc.
    for prefix in ("scrape_", "discovery_", "generic_", "blackbird_"):
        if src.startswith(prefix):
            return "LOW" if prefix == "scrape_" else "REJECT"
    return "LOW"


_SOURCE_TIER_SCORE = {
    "HIGH":   0.80,
    "MEDIUM": 0.55,
    "LOW":    0.30,
    "REJECT": 0.00,
}


# ---------------------------------------------------------------------------
# Shape rules — email
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

_THROWAWAY_DOMAINS = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwaway.email", "yopmail.com", "sharklasers.com",
    "trashmail.com", "maildrop.cc", "getnada.com", "dispostable.com",
    "fakeinbox.com", "temp-mail.org", "tempail.com", "mohmal.com",
    "mailnesia.com", "mailcatch.com", "spamgourmet.com", "trashmail.de",
    "yopmail.fr", "jetable.org", "throwam.com", "mailsac.com",
    "inboxbear.com", "discard.email", "mailnull.com", "spam4.me",
    "grr.la", "guerrillamail.info", "guerrillamail.biz",
    "guerrillamail.de", "guerrillamail.net", "guerrillamail.org",
    "spam.la", "throwawaymail.com",
})

_ROLE_ACCOUNTS = frozenset({
    "noreply", "no-reply", "donotreply", "do-not-reply", "donotrespond",
    "support", "info", "admin", "administrator", "webmaster",
    "postmaster", "mailer-daemon", "help", "helpdesk", "sales",
    "contact", "hello", "team", "billing", "jobs", "careers",
    "hr", "press", "legal", "privacy", "abuse", "security",
    "marketing", "newsletter", "notifications", "alerts",
    "feedback", "enquiries", "enquiry", "inquiries", "inquiry",
    "office", "accounts", "accounting", "payments", "service",
    "customerservice", "customer.service", "cs", "it", "devops",
})

_ESCAPE_PREFIX_RE = re.compile(r"^u00[0-9a-f]{2}", re.IGNORECASE)
_HEX_LOCAL_RE     = re.compile(r"^[a-f0-9]{16,}$", re.IGNORECASE)


def _check_email_shape(value: str) -> tuple[bool, str]:
    """
    Return ``(ok, reason)`` for an email's shape.

    ``ok=False`` means the address is structurally not worth a credit.
    """
    local, _, domain = value.partition("@")
    domain = domain.lower()
    local_lower = local.lower()

    if not _EMAIL_RE.match(value):
        return False, "not a valid email address"

    if _ESCAPE_PREFIX_RE.match(local):
        return False, "HTML-escape artefact in local part"

    if domain in _THROWAWAY_DOMAINS:
        return False, f"throwaway domain ({domain})"

    if local_lower in _ROLE_ACCOUNTS:
        return False, f"role account ({local_lower}@)"

    # Strip plus-tags and dots before role-account re-check.
    base = local_lower.split("+", 1)[0].replace(".", "").replace("_", "").replace("-", "")
    if base in _ROLE_ACCOUNTS:
        return False, f"role account ({local_lower}@)"

    if _HEX_LOCAL_RE.match(local):
        return False, "synthetic-looking local part (long hex)"

    if "test" in local_lower and domain in ("example.com", "example.org", "test.com"):
        return False, "placeholder test address"

    return True, ""


# ---------------------------------------------------------------------------
# Shape rules — phone
# ---------------------------------------------------------------------------

_FICTIONAL_US_RE = re.compile(r"^\+?1?[\s\-\.\(]?555[\s\-\.\)]?\d{4}$")


def _check_phone_shape(value: str) -> tuple[bool, str]:
    """
    Return ``(ok, reason)`` for a phone number's shape.

    Uses ``phonenumbers`` when available. When the library is missing we
    fall back to a conservative digit-count check rather than accepting
    anything.
    """
    if not value:
        return False, "empty phone value"

    # Fictional US 555 range is explicitly not a real number.
    digits_only = re.sub(r"[^\d+]", "", value)
    if _FICTIONAL_US_RE.match(digits_only.lstrip("+")):
        return False, "fictional 555 range"

    # All-same-digit numbers (e.g. +11111111111) are synthetic.
    bare = re.sub(r"\D", "", digits_only)
    if bare and len(set(bare)) == 1:
        return False, "all-same-digit number (synthetic)"

    if not _PHONENUMBERS_AVAILABLE:
        if len(bare) < 7 or len(bare) > 15:
            return False, "digit count out of E.164 range"
        return True, ""

    try:
        parsed = phonenumbers.parse(value, None)
    except Exception as exc:
        return False, f"unparseable phone ({type(exc).__name__})"

    if not phonenumbers.is_possible_number(parsed):
        return False, "not a possible number"

    if not phonenumbers.is_valid_number(parsed):
        return False, "not a valid number"

    try:
        ntype = phonenumbers.number_type(parsed)
    except Exception:
        ntype = -1

    # Reject line types that cannot belong to a professionally-active
    # person we would want to enrich.
    bad_types = set()
    for name in ("PREMIUM_RATE", "SHARED_COST", "PAGER", "VOICEMAIL",
                 "UNKNOWN"):
        const = getattr(phonenumbers.PhoneNumberType, name, None)
        if const is not None:
            bad_types.add(const)
    if ntype in bad_types:
        return False, f"unmatchable line type ({ntype})"

    return True, ""


# ---------------------------------------------------------------------------
# Shape rules — LinkedIn
# ---------------------------------------------------------------------------

_LINKEDIN_RE = re.compile(
    r"^https?://([a-z]{2,3}\.)?linkedin\.com/in/([A-Za-z0-9\-_%\.]+)/?",
    re.IGNORECASE,
)

_LINKEDIN_NON_PROFILE_SLUGS = frozenset({
    "company", "school", "jobs", "feed", "search", "help",
    "login", "signup", "settings", "pulse", "learning",
})


def _check_linkedin_shape(value: str) -> tuple[bool, str]:
    if not value:
        return False, "empty LinkedIn value"
    m = _LINKEDIN_RE.match(value.strip())
    if not m:
        return False, "not a LinkedIn /in/ profile URL"
    slug = m.group(2).lower()
    if slug in _LINKEDIN_NON_PROFILE_SLUGS:
        return False, f"non-profile LinkedIn path ({slug})"
    if len(slug) < 3 or len(slug) > 100:
        return False, "LinkedIn slug length out of range"
    return True, ""


_SHAPE_CHECKERS = {
    "email":    _check_email_shape,
    "phone":    _check_phone_shape,
    "linkedin": _check_linkedin_shape,
}


# ---------------------------------------------------------------------------
# Corroboration
# ---------------------------------------------------------------------------

def _normalise_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _corroboration_signals(identifier: Identifier) -> list[str]:
    """
    Return a list of positive corroboration signals (empty when none).
    """
    signals: list[str] = []
    ctx = identifier.context or {}
    names   = [n for n in (ctx.get("names") or []) if isinstance(n, str) and n.strip()]
    domains = [d for d in (ctx.get("domains") or []) if isinstance(d, str) and d.strip()]
    locations = [l for l in (ctx.get("locations") or []) if isinstance(l, str) and l.strip()]

    if identifier.kind == "email":
        local, _, domain = identifier.value.lower().partition("@")
        local_clean = _normalise_token(local)
        domain_clean = domain.lower().lstrip("www.")

        for name in names:
            tokens = [_normalise_token(t) for t in name.split() if len(t) >= 3]
            if any(t and t in local_clean for t in tokens):
                signals.append(f"name token matches local part ({name!r})")
                break

        for d in domains:
            d_clean = d.lower().lstrip("www.").split(":")[0]
            if d_clean and domain_clean.endswith(d_clean):
                signals.append(f"domain matches known company ({d!r})")
                break

        if domain_clean.endswith((".edu", ".gov", ".ac.uk", ".ac.")):
            signals.append("institutional domain")

    elif identifier.kind == "linkedin":
        for name in names:
            if name.lower() in identifier.value.lower():
                signals.append(f"name appears in LinkedIn URL ({name!r})")
                break

    elif identifier.kind == "phone":
        if locations:
            for loc in locations:
                token = _normalise_token(loc.split(",")[0])
                if token and token in identifier.value.lower():
                    signals.append(f"location match ({loc!r})")
                    break

    return signals


# ---------------------------------------------------------------------------
# Provider input capability
# ---------------------------------------------------------------------------

_PROVIDER_INPUT_KINDS: dict[str, frozenset[str]] = {
    # Neither provider accepts a phone as an *input* identifier. Both only
    # reveal phones as a data point on a person matched by email, LinkedIn
    # URL, or name+company.
    "apollo": frozenset({"email", "linkedin"}),
    "lusha":  frozenset({"email", "linkedin"}),
}

_PROVIDER_PHONE_REASON = (
    "phone is reveal-only for {provider}; not accepted as an input identifier"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate(
    identifier: Identifier,
    provider: ProviderName,
    *,
    accept_threshold: float = 0.50,
) -> FilterDecision:
    """
    Evaluate one identifier for one provider and return a decision.

    The order of checks is deliberate: hard shape rejections come first so
    the audit log always records the most specific reason.
    """
    tier  = _source_tier(identifier.source)
    score = _SOURCE_TIER_SCORE[tier]

    # 1. Source is junk — reject before looking at shape.
    if tier == "REJECT":
        return FilterDecision(
            identifier=identifier,
            accepted=False,
            reason=f"untrusted source ({identifier.source})",
            score=0.0,
        )

    # 2. Provider input capability.
    allowed = _PROVIDER_INPUT_KINDS.get(provider, frozenset())
    if identifier.kind not in allowed:
        return FilterDecision(
            identifier=identifier,
            accepted=False,
            reason=_PROVIDER_PHONE_REASON.format(provider=provider),
            score=score,
        )

    # 3. Shape.
    checker = _SHAPE_CHECKERS.get(identifier.kind)
    if checker is None:
        return FilterDecision(
            identifier=identifier,
            accepted=False,
            reason=f"unsupported identifier kind ({identifier.kind})",
            score=score,
        )
    ok, reason = checker(identifier.value)
    if not ok:
        return FilterDecision(
            identifier=identifier,
            accepted=False,
            reason=reason,
            score=0.0,
        )

    # 4. Corroboration.
    signals = _corroboration_signals(identifier)
    if signals:
        score += 0.15 * min(len(signals), 2)
    score = min(score, 1.0)

    # 5. Threshold.
    if score < accept_threshold:
        detail = "no corroborating signal" if not signals else "; ".join(signals)
        return FilterDecision(
            identifier=identifier,
            accepted=False,
            reason=f"weak evidence ({tier.lower()} source; {detail})",
            score=score,
        )

    reason = "; ".join(signals) if signals else f"{tier.lower()}-trust source"
    return FilterDecision(
        identifier=identifier,
        accepted=True,
        reason=reason,
        score=score,
    )


def evaluate_many(
    identifiers: Iterable[Identifier],
    provider: ProviderName,
    *,
    accept_threshold: float = 0.50,
) -> list[FilterDecision]:
    return [
        evaluate(i, provider, accept_threshold=accept_threshold)
        for i in identifiers
    ]


def collect_context(intel: dict) -> dict:
    """
    Build the corroboration context (names / domains / locations) from the
    investigation's intel dict.

    This is what feeds ``Identifier.context`` — it is deliberately
    permissive in what it picks up, because more context means better
    corroboration, and the shape rules are what actually gate the spend.
    """
    names: list[str] = []
    domains: list[str] = []
    locations: list[str] = []

    for key, entry in (intel.get("identity_clues") or {}).items():
        val = entry.get("value") if isinstance(entry, dict) else entry
        if not isinstance(val, str) or not val.strip():
            continue
        if key.startswith("name_"):
            names.append(val.strip())
        elif key == "inferred_location":
            locations.append(val.strip())

    for _key, entry in (intel.get("social_profiles") or {}).items():
        val = entry.get("value") if isinstance(entry, dict) else entry
        if not isinstance(val, str):
            continue
        if val.startswith("http"):
            try:
                host = urlparse(val).netloc.lower()
                if host and "linkedin.com" not in host and "twitter.com" not in host:
                    domains.append(host.lstrip("www."))
            except Exception:
                pass

    for domain_key in (intel.get("whois") or {}):
        if isinstance(domain_key, str) and "." in domain_key:
            domains.append(domain_key.lower())

    def _uniq(seq):
        seen = set()
        out = []
        for x in seq:
            k = x.lower()
            if k and k not in seen:
                seen.add(k)
                out.append(x)
        return out

    return {
        "names":     _uniq(names),
        "domains":   _uniq(domains),
        "locations": _uniq(locations),
    }