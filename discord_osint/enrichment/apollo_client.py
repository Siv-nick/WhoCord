"""
discord_osint/enrichment/apollo_client.py
-----------------------------------------
Apollo.io people-enrichment client.

Endpoint facts (as of the current docs):

* ``POST /api/v1/people/bulk_match`` enriches up to **10** people per call.
* Auth header is ``x-api-key: <key>``.
* Accepted input identifiers: ``email``, ``linkedin_url``, ``name`` +
  ``domain`` / ``organization_name``, ``id`` (Apollo person ID),
  ``hashed_email``. **Phones are not an input** — they can only be
  *revealed* on a person already matched.
* Credit cost: 1–9 credits per person, **charged only when
  credit-consuming data is found**. A miss costs 0 credits.
* ``reveal_phone_number=true`` requires a webhook and delivers phone
  numbers asynchronously, so this client leaves it off and relies on
  whatever phones are already attached to the matched profile.

Response shape (standard, non-waterfall)::

    {
      "status": "success",
      "total_requested_enrichments": N,
      "unique_enriched_records":    M,
      "missing_records":            K,
      "credits_consumed":           <decimal>,
      "matches": [ { person object }, ... ]
    }

A 200 response with ``missing_records == N`` and an empty ``matches``
array is a clean "nobody matched" — not an error.
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


_BASE_URL      = "https://api.apollo.io/api/v1"
_BULK_MATCH    = f"{_BASE_URL}/people/bulk_match"
_PROFILE_URL   = f"{_BASE_URL}/users/api_profile"
_BULK_MAX      = 10
_DEFAULT_TIMEOUT = 30


@dataclass
class ApolloEnrichmentResult:
    matches:          list[dict]
    missing_records:  int
    credits_consumed: float
    raw_response:     dict

    @property
    def matched_count(self) -> int:
        return len(self.matches)


class ApolloClient:
    """Thin wrapper around the Apollo enrichment + credit endpoints."""

    def __init__(self, api_key: str, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.api_key = (api_key or "").strip()
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _headers(self) -> dict:
        return {
            "x-api-key":    self.api_key,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
            "Accept":       "application/json",
        }

    # ------------------------------------------------------------------ #
    # Enrichment
    # ------------------------------------------------------------------ #

    def enrich(self, identifiers: list[Any]) -> ApolloEnrichmentResult:
        """
        Submit *identifiers* (trust-filter survivors) in batches of
        ``_BULK_MAX``. Returns a merged result.

        Each identifier must expose ``.kind`` and ``.value``. Phones are
        already filtered out upstream — if one slips through it is
        dropped here with a debug-log line rather than rejected by the
        API.
        """
        if not identifiers:
            return ApolloEnrichmentResult([], 0, 0.0, {})

        all_matches: list[dict] = []
        total_missing   = 0
        total_credits   = 0.0
        last_raw: dict  = {}

        for i in range(0, len(identifiers), _BULK_MAX):
            chunk = identifiers[i:i + _BULK_MAX]
            details = []
            for ident in chunk:
                detail = self._identifier_to_detail(ident)
                if detail is not None:
                    details.append(detail)

            if not details:
                continue

            body = {
                "details": details,
                # Work emails are returned by default; personal-email
                # reveal is off to keep credit usage predictable.
                "reveal_personal_emails": False,
                # Phone reveal requires a webhook — deliberately off.
                "reveal_phone_number": False,
            }

            try:
                resp = requests.post(
                    _BULK_MATCH,
                    headers=self._headers(),
                    json=body,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                log_trace(f"apollo: network error on bulk_match: {exc}")
                print(f"  [!] Apollo: network error ({exc}) — skipping batch.")
                continue

            if resp.status_code == 401:
                log_trace("apollo: 401 — API key rejected.")
                print("  [!] Apollo: API key rejected (401) — stopping enrichment.")
                raise ApolloAuthError("Apollo API key rejected")

            if resp.status_code == 402:
                log_trace("apollo: 402 — no credits remaining.")
                print("  [!] Apollo: no credits remaining (402) — stopping enrichment.")
                raise ApolloCreditError("Apollo credit balance exhausted")

            if resp.status_code == 429:
                retry = resp.headers.get("Retry-After", "?")
                log_trace(f"apollo: 429 rate limited (Retry-After={retry}).")
                print(f"  [!] Apollo: rate limited — skipping batch.")
                continue

            if resp.status_code != 200:
                log_trace(
                    f"apollo: unexpected HTTP {resp.status_code} — "
                    f"{resp.text[:200]}"
                )
                print(f"  [!] Apollo: HTTP {resp.status_code} — skipping batch.")
                continue

            try:
                data = resp.json()
            except Exception as exc:
                log_trace(f"apollo: JSON parse error: {exc}")
                continue

            last_raw = data
            all_matches.extend(data.get("matches") or [])
            total_missing += int(data.get("missing_records") or 0)
            try:
                total_credits += float(data.get("credits_consumed") or 0)
            except (TypeError, ValueError):
                pass

        return ApolloEnrichmentResult(
            matches=all_matches,
            missing_records=total_missing,
            credits_consumed=total_credits,
            raw_response=last_raw,
        )

    @staticmethod
    def _identifier_to_detail(ident: Any) -> dict | None:
        """Map a trust-filter Identifier onto an Apollo ``details[]`` entry."""
        kind  = getattr(ident, "kind", "")
        value = (getattr(ident, "value", "") or "").strip()
        if not value:
            return None
        if kind == "email":
            return {"email": value}
        if kind == "linkedin":
            return {"linkedin_url": value}
        # Phones are not an Apollo input — drop with a trace.
        log_trace(f"apollo: dropping unsupported identifier kind={kind!r}")
        return None

    # ------------------------------------------------------------------ #
    # Credit balance / connection test
    # ------------------------------------------------------------------ #

    def get_credit_balance(self) -> dict | None:
        """
        Return ``{"lead": int|None, "direct_dial": int|None, ...}`` or
        ``None`` when the check could not be performed.

        Uses ``GET /users/api_profile?include_credit_usage=true``. A
        ``None`` return means "unknown", not "zero" — callers must treat
        it as "proceed, but watch for 402".
        """
        try:
            resp = requests.get(
                _PROFILE_URL,
                headers=self._headers(),
                params={"include_credit_usage": "true"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            log_trace(f"apollo: credit-balance network error: {exc}")
            return None

        if resp.status_code != 200:
            log_trace(
                f"apollo: credit-balance HTTP {resp.status_code} — "
                f"{resp.text[:160]}"
            )
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        def _left(key: str) -> int | None:
            block = data.get(key)
            if not isinstance(block, dict):
                return None
            left = block.get("left_over")
            try:
                return int(left)
            except (TypeError, ValueError):
                return None

        return {
            "lead":        _left("lead_credit"),
            "direct_dial": _left("direct_dial_credit"),
            "export":      _left("export_credit"),
            "ai":          _left("ai_credit"),
            "power_up":    _left("power_up_credit"),
        }

    def test_connection(self) -> dict:
        """
        Return ``{"ok": bool, "balance": dict|None, "error": str|None}``.

        Uses the 0-credit profile endpoint so the test never spends.
        """
        try:
            resp = requests.get(
                _PROFILE_URL,
                headers=self._headers(),
                params={"include_credit_usage": "true"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"ok": False, "balance": None, "error": f"network error: {exc}"}

        if resp.status_code == 401:
            return {"ok": False, "balance": None, "error": "API key rejected (401)"}
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

        def _left(key: str) -> int | None:
            block = data.get(key)
            if not isinstance(block, dict):
                return None
            try:
                return int(block.get("left_over"))
            except (TypeError, ValueError):
                return None

        balance = {
            "lead":        _left("lead_credit"),
            "direct_dial": _left("direct_dial_credit"),
            "export":      _left("export_credit"),
        }
        return {"ok": True, "balance": balance, "error": None}


class ApolloAuthError(RuntimeError):
    """Raised when Apollo rejects the API key."""


class ApolloCreditError(RuntimeError):
    """Raised when Apollo reports a zero credit balance."""