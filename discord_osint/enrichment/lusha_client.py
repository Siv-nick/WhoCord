"""
discord_osint/enrichment/lusha_client.py
----------------------------------------
Lusha V3 contact-enrichment client.

Change log
----------
- Phase 5: requests calls route through the shared ``http_session``.
  The Retry adapter handles transient 429s from Lusha's 5 req/min
  account-usage limit and the search-and-enrich endpoint's per-minute
  budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..utils import http_session

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
        if not identifiers:
            return LushaEnrichmentResult([], 0.0, {})

        contacts: list[dict] = []
        for idx, ident in enumerate(identifiers):
            entry = self._identifier_to_contact(ident, idx)
            if entry is not None:
                contacts.append(entry)

        if not contacts:
            return LushaEnrichmentResult([], 0.0, {})

        all_contacts:  list[dict] = []
        total_credits: float      = 0.0
        last_raw:      dict       = {}

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
                resp = http_session.post(
                    _SEARCH_ENRICH,
                    headers=self._headers(),
                    json=body,
                    timeout=self.timeout,
                )
            except Exception as exc:
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
                log_trace("lusha: 429 rate limited after retries.")
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

        if not all_contacts and identifiers:
            total_credits = max(total_credits, 1.0)
            log_trace("lusha: batch returned 0 results — minimum 1 credit consumed.")

        return LushaEnrichmentResult(
            contacts=all_contacts,
            credits_consumed=total_credits,
            raw_response=last_raw,
        )

    @staticmethod
    def _identifier_to_contact(ident: Any, idx: int) -> dict | None:
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
        try:
            resp = http_session.get(
                _ACCOUNT_USAGE,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except Exception as exc:
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
        try:
            resp = http_session.get(
                _ACCOUNT_USAGE,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except Exception as exc:
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