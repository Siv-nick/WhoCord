"""
discord_osint/enrichment/lusha_client.py
----------------------------------------
Lusha V3 contact-enrichment client.

Endpoint facts (as of the current docs):

* ``POST /v3/contacts/search-and-enrich`` — search by identifier and
  reveal full contact data in one call. Up to **100** contacts per
  request.
* Auth header is ``api_key: Bearer <key>``.
* Accepted input identifiers: ``id`` (Lusha contact ID), ``linkedinUrl``,
  ``email``, ``firstName`` + ``lastName`` + ``companyName`` or
  ``companyDomain``. **Phones are not an input.**
* Credit cost: 1 credit per result returned; bulk requests cost 1 credit
  per 1–25 results. **A request that returns no results still costs a
  minimum of 1 credit** — this is the single most important difference
  from Apollo.
* Credit balance: ``GET /v3/account/usage`` (5 req/min) returns
  ``credits.total``, ``credits.used``, ``credits.remaining``.

Because Lusha charges a minimum of 1 credit even for a zero-result
batch, this client splits a batch into individual requests only when the
caller explicitly asks for it. By default it submits all survivors in a
single call so the per-batch minimum is paid once.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

try:
    from ..utils import log_trace
except Exception:  # pragma: no cover
    def log_trace(msg: str) -> None:
        pass


_BASE_URL        = "https://api.lusha.com"
_SEARCH_ENRICH   = f"{_BASE_URL}/v3/contacts/search-and-enrich"
_ACCOUNT_USAGE   = f"{_BASE_URL}/v3/account/usage"
_BATCH_MAX       = 100
_DEFAULT_TIMEOUT = 30


@dataclass
class LushaEnrichmentResult:
    contacts:         list[dict]
    credits_consumed: float
    raw_response:     dict

    @property
    def matched_count(self) -> int:
        return len(self.contacts)


class LushaClient:
    """Thin wrapper around the Lusha V3 enrichment + account endpoints."""

    def __init__(self, api_key: str, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.api_key = (api_key or "").strip()
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _headers(self) -> dict:
        return {
            "api_key":      f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }

    # ------------------------------------------------------------------ #
    # Enrichment
    # ------------------------------------------------------------------ #

    def enrich(
        self,
        identifiers: list[Any],
        *,
        reveal_phones: bool = False,
    ) -> LushaEnrichmentResult:
        """
        Submit *identifiers* in a single batched call (up to 100).

        ``reveal_phones`` costs 5 extra credits per contact, so it
        defaults to off. Emails are always revealed at 1 credit each.
        """
        if not identifiers:
            return LushaEnrichmentResult([], 0.0, {})

        contacts: list[dict] = []
        for idx, ident in enumerate(identifiers):
            entry = self._identifier_to_contact(ident, idx)
            if entry is not None:
                contacts.append(entry)

        if not contacts:
            return LushaEnrichmentResult([], 0.0, {})

        # Lusha accepts up to 100 contacts per call. Anything beyond that
        # is split into additional calls — each of which pays its own
        # minimum-credit cost.
        all_contacts: list[dict] = []
        total_credits = 0.0
        last_raw: dict = {}

        for i in range(0, len(contacts), _BATCH_MAX):
            chunk = contacts[i:i + _BATCH_MAX]
            body = {
                "contacts": chunk,
                "metadata": {
                    "revealEmails": True,
                    "revealPhones": bool(reveal_phones),
                },
            }

            try:
                resp = requests.post(
                    _SEARCH_ENRICH,
                    headers=self._headers(),
                    json=body,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                log_trace(f"lusha: network error on search-and-enrich: {exc}")
                print(f"  [!] Lusha: network error ({exc}) — skipping batch.")
                continue

            if resp.status_code == 401:
                log_trace("lusha: 401 — API key rejected.")
                print("  [!] Lusha: API key rejected (401) — stopping enrichment.")
                raise LushaAuthError("Lusha API key rejected")

            if resp.status_code == 402:
                log_trace("lusha: 402 — insufficient credits.")
                print("  [!] Lusha: insufficient credits (402) — stopping enrichment.")
                raise LushaCreditError("Lusha credit balance exhausted")

            if resp.status_code == 403:
                log_trace(
                    "lusha: 403 — plan restriction (revealEmails/revealPhones "
                    "require the Unified Credits plan)."
                )
                print("  [!] Lusha: plan does not permit the requested reveal.")
                raise LushaPlanError("Lusha plan does not permit reveal")

            if resp.status_code == 429:
                log_trace("lusha: 429 rate limited.")
                print("  [!] Lusha: rate limited — skipping batch.")
                continue

            if resp.status_code not in (200, 201, 207):
                log_trace(
                    f"lusha: unexpected HTTP {resp.status_code} — "
                    f"{resp.text[:200]}"
                )
                print(f"  [!] Lusha: HTTP {resp.status_code} — skipping batch.")
                continue

            try:
                data = resp.json()
            except Exception as exc:
                log_trace(f"lusha: JSON parse error: {exc}")
                continue

            last_raw = data

            # V3 search-and-enrich returns {"contacts": {...}, "companies": {...}}
            # keyed by client reference id. Older shapes returned a list.
            if isinstance(data, dict):
                contact_block = data.get("contacts")
                if isinstance(contact_block, dict):
                    all_contacts.extend(contact_block.values())
                elif isinstance(contact_block, list):
                    all_contacts.extend(contact_block)

            try:
                total_credits += float(data.get("creditsUsed") or 0)
            except (TypeError, ValueError):
                pass

        # A zero-result batch still consumes the minimum 1 credit — record
        # it so the report is honest about the spend.
        if not all_contacts and identifiers:
            total_credits = max(total_credits, 1.0)
            log_trace(
                f"lusha: batch returned 0 results — minimum 1 credit consumed."
            )

        return LushaEnrichmentResult(
            contacts=all_contacts,
            credits_consumed=total_credits,
            raw_response=last_raw,
        )

    @staticmethod
    def _identifier_to_contact(ident: Any, idx: int) -> dict | None:
        """Map a trust-filter Identifier onto a Lusha ``contacts[]`` entry."""
        kind  = getattr(ident, "kind", "")
        value = (getattr(ident, "value", "") or "").strip()
        if not value:
            return None

        entry: dict = {"clientReferenceId": f"whocord-{idx}"}

        if kind == "email":
            entry["email"] = value
        elif kind == "linkedin":
            entry["linkedinUrl"] = value
        else:
            log_trace(f"lusha: dropping unsupported identifier kind={kind!r}")
            return None

        return entry

    # ------------------------------------------------------------------ #
    # Credit balance / connection test
    # ------------------------------------------------------------------ #

    def get_credit_balance(self) -> int | None:
        """
        Return the remaining credit balance, or ``None`` when unknown.

        Uses ``GET /v3/account/usage``. The endpoint is rate-limited to
        5 requests per minute, so callers should cache the result.
        """
        try:
            resp = requests.get(
                _ACCOUNT_USAGE,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            log_trace(f"lusha: balance network error: {exc}")
            return None

        if resp.status_code != 200:
            log_trace(
                f"lusha: balance HTTP {resp.status_code} — {resp.text[:160]}"
            )
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        credits = data.get("credits") or {}
        remaining = credits.get("remaining")
        try:
            return int(remaining)
        except (TypeError, ValueError):
            return None

    def test_connection(self) -> dict:
        """
        Return ``{"ok": bool, "balance": int|None, "error": str|None}``.

        Uses the 0-credit account-usage endpoint.
        """
        try:
            resp = requests.get(
                _ACCOUNT_USAGE,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"ok": False, "balance": None, "error": f"network error: {exc}"}

        if resp.status_code == 401:
            return {"ok": False, "balance": None, "error": "API key rejected (401)"}
        if resp.status_code == 403:
            return {"ok": False, "balance": None, "error": "account inactive (403)"}
        if resp.status_code == 429:
            return {
                "ok": False,
                "balance": None,
                "error": "rate limited on /account/usage (5 req/min) — retry shortly",
            }
        if resp.status_code != 200:
            return {
                "ok": False,
                "balance": None,
                "error": f"HTTP {resp.status_code}: {resp.text[:120]}",
            }

        try:
            data = resp.json()
        except Exception as exc:
            return {"ok": False, "balance": None, "error": f"invalid JSON: {exc}"}

        credits = data.get("credits") or {}
        try:
            remaining = int(credits.get("remaining"))
        except (TypeError, ValueError):
            remaining = None

        return {"ok": True, "balance": remaining, "error": None}


class LushaAuthError(RuntimeError):
    """Raised when Lusha rejects the API key."""


class LushaCreditError(RuntimeError):
    """Raised when Lusha reports insufficient credits."""


class LushaPlanError(RuntimeError):
    """Raised when the Lusha plan does not permit the requested reveal."""