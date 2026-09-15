"""
discord_osint/cord_cat.py
-------------------------
CordCat (cord.cat) Discord OSINT client.

CordCat resolves a Discord snowflake into four sources in one call:

* Discord profile metadata (username, display name, avatar, public
  badges, exact account creation time derived from the snowflake).
* Breach exposure cross-referenced against 500M+ entries, with the
  exposed field names, plus GeoIP and ASN when the breach data
  includes an IP.
* FiveM / GTA records (77M+ entries).
* EU DSA statements — sanctions listed under the Digital Services Act.

Plus a derived bot / risk score with the reasons behind it.

API
---
Base URL:  https://api.cord.cat
Auth:      X-API-Key: cc_...   (or Authorization: Bearer cc_...)
Endpoint:  GET /api/v2/query/:discord_id

Free tier: 60 requests/hour, 1 request/second. The server caches
results for ~10 minutes, so repeated lookups of the same snowflake
within that window are free.

Client behaviour
----------------
The client is deliberately defensive about response shape. CordCat's
documented field names vary slightly across their marketing examples
and the docs page (``userInfo`` vs ``user_info``, ``fivem`` vs
``fiveM``, ``statements`` vs ``dsa_statements``). Every field the
client reads is looked up under multiple plausible keys, with a
sensible empty default when none match. Nothing raises on unexpected
shape.

Cache
-----
In-memory, keyed by discord_id, TTL matching the server's 10-minute
window. Cleared on process restart. The cache is process-local, so a
worker thread and the main thread see the same entries — the shared
``_cache_lock`` guards all access.

Rate limiting
-------------
Two limits, both from the free tier:

* 1 request / second
* 60 requests / hour

The per-second limit is enforced with a blocking sleep. The per-hour
limit raises ``CordCatRateLimitError`` so the caller can decide
whether to abandon the investigation or queue the lookup for later.
In practice the 60/hour cap is only reachable during a pivot loop
that discovers many Discord IDs in one run, which does not happen in
normal use.

Trust and disclosure
--------------------
Every lookup sends the target's Discord snowflake to ``cord.cat``.
That is a third-party disclosure and appears in
``docs/data-handling.md`` §2.4. The operator must have
``ENABLE_CORD_CAT`` on and a stored ``CORD_CAT_API_KEY`` for any
lookup to happen.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

from .utils import http_session, log_trace


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BASE_URL = "https://api.cord.cat"
_QUERY_PATH = "/api/v2/query"
_DEFAULT_TIMEOUT = 15

_CACHE_TTL_SECONDS = 10 * 60
_RATE_LIMIT_PER_HOUR = 60
_RATE_LIMIT_PER_SECOND = 1.0


class CordCatRateLimitError(RuntimeError):
    """Raised when the client-side hourly rate limit is hit."""


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class CordCatResult:
    """
    The parsed response of one cord.cat lookup.

    ``ok`` is True when the lookup succeeded (which includes the
    "snowflake not found" case — that returns empty sections, not
    an error). ``error`` is populated when the lookup failed —
    network error, auth rejection, rate limit, unexpected response.
    """
    discord_id: str
    ok: bool
    user_info:  dict = field(default_factory=dict)
    breach:     dict = field(default_factory=dict)
    fivem:      dict = field(default_factory=dict)
    statements: list = field(default_factory=list)
    score:      dict = field(default_factory=dict)
    meta:       dict = field(default_factory=dict)
    error:      str = ""
    fetched_at: float = 0.0

    def to_dict(self) -> dict:
        """Serialise for storage in ``intel_core``."""
        return {
            "discord_id": self.discord_id,
            "user_info":  self.user_info,
            "breach":     self.breach,
            "fivem":      self.fivem,
            "statements": self.statements,
            "score":      self.score,
            "meta":       self.meta,
            "fetched_at": self.fetched_at,
        }

    @property
    def has_breach(self) -> bool:
        if not self.breach:
            return False
        if self.breach.get("found") is True:
            return True
        try:
            return int(self.breach.get("count") or 0) > 0
        except (TypeError, ValueError):
            return bool(self.breach.get("datasets") or self.breach.get("records"))

    @property
    def has_fivem(self) -> bool:
        if not self.fivem:
            return False
        if self.fivem.get("found") is True:
            return True
        records = self.fivem.get("records") or self.fivem.get("entries") or []
        return bool(records)

    @property
    def has_statements(self) -> bool:
        return bool(self.statements)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

_cache: dict[str, tuple[float, CordCatResult]] = {}
_cache_lock = threading.Lock()


def clear_cache() -> None:
    """Empty the lookup cache. For tests."""
    with _cache_lock:
        _cache.clear()


def _cache_get(discord_id: str) -> Optional[CordCatResult]:
    with _cache_lock:
        entry = _cache.get(discord_id)
        if entry is None:
            return None
        ts, result = entry
        if time.time() - ts >= _CACHE_TTL_SECONDS:
            _cache.pop(discord_id, None)
            return None
        return result


def _cache_put(result: CordCatResult) -> None:
    with _cache_lock:
        _cache[result.discord_id] = (time.time(), result)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

_rate_lock = threading.Lock()
_last_call_ts = 0.0
_recent_calls: list[float] = []


def _wait_for_rate_limit() -> None:
    """
    Block until the per-second limit allows a call, then record the
    call. Raises ``CordCatRateLimitError`` if the per-hour cap is
    already exhausted.
    """
    global _last_call_ts

    with _rate_lock:
        now = time.monotonic()

        # Prune calls older than an hour.
        cutoff = now - 3600
        _recent_calls[:] = [t for t in _recent_calls if t > cutoff]

        if len(_recent_calls) >= _RATE_LIMIT_PER_HOUR:
            raise CordCatRateLimitError(
                f"cord.cat free tier limit reached "
                f"({_RATE_LIMIT_PER_HOUR} requests/hour)"
            )

        elapsed = now - _last_call_ts
        if elapsed < _RATE_LIMIT_PER_SECOND:
            time.sleep(_RATE_LIMIT_PER_SECOND - elapsed)

        _last_call_ts = time.monotonic()
        _recent_calls.append(_last_call_ts)


def _reset_rate_limit() -> None:
    """Clear rate-limit state. For tests."""
    global _last_call_ts
    with _rate_lock:
        _last_call_ts = 0.0
        _recent_calls.clear()


# ---------------------------------------------------------------------------
# Response field extraction
# ---------------------------------------------------------------------------

def _first_present(d: Any, *keys: str, default: Any = None) -> Any:
    """
    Return the value of the first key present in *d*, or *default*.

    Used because cord.cat uses camelCase in one place and snake_case in
    another for the same field. Both spellings are accepted so a schema
    change on their side does not silently drop data.
    """
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _parse_response(discord_id: str, data: dict, now: float) -> CordCatResult:
    """
    Turn a raw cord.cat response into a CordCatResult.

    Any section that is present but not a dict/list of the expected
    type is dropped with a log_trace line rather than raising.
    """
    user_info  = _first_present(data, "userInfo", "user_info", "user", default={})
    breach     = _first_present(data, "breach", "breaches", "breachData", default={})
    fivem      = _first_present(data, "fivem", "fiveM", "five_m", "fiveMRecords", default={})
    statements = _first_present(
        data, "statements", "dsa_statements", "dsaStatements", default=[],
    )
    score      = _first_present(data, "score", "risk", "riskScore", default={})
    meta       = _first_present(data, "meta", "metadata", default={})

    if not isinstance(user_info, dict):
        log_trace(f"cord_cat: user_info is {type(user_info).__name__}, dropping")
        user_info = {}
    if not isinstance(breach, dict):
        log_trace(f"cord_cat: breach is {type(breach).__name__}, dropping")
        breach = {}
    if not isinstance(fivem, dict):
        log_trace(f"cord_cat: fivem is {type(fivem).__name__}, dropping")
        fivem = {}
    if not isinstance(statements, list):
        log_trace(f"cord_cat: statements is {type(statements).__name__}, wrapping")
        statements = [statements] if statements else []
    if not isinstance(score, dict):
        log_trace(f"cord_cat: score is {type(score).__name__}, dropping")
        score = {}
    if not isinstance(meta, dict):
        meta = {}

    return CordCatResult(
        discord_id=discord_id,
        ok=True,
        user_info=user_info,
        breach=breach,
        fivem=fivem,
        statements=statements,
        score=score,
        meta=meta,
        fetched_at=now,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup(
    discord_id: str,
    *,
    api_key: str,
    timeout: int = _DEFAULT_TIMEOUT,
) -> CordCatResult:
    """
    Look up a Discord snowflake via cord.cat.

    Returns a ``CordCatResult``. ``ok`` is True on a successful call —
    including a 404, which cord.cat returns when the ID has no data
    and which the pipeline treats as "no enrichment, nothing to
    report".

    ``ok`` is False on: no API key, network failure, auth rejection,
    rate-limit response from the server, or a response body that is
    not a JSON object. The ``error`` field carries a short reason.

    Raises ``CordCatRateLimitError`` when the client-side hourly cap
    has already been hit. Callers may catch this and skip further
    lookups rather than treating it as a per-lookup failure.
    """
    discord_id = str(discord_id or "").strip()
    if not discord_id:
        return CordCatResult(discord_id="", ok=False, error="empty discord_id")

    if not api_key:
        return CordCatResult(
            discord_id=discord_id, ok=False, error="no API key configured",
        )

    cached = _cache_get(discord_id)
    if cached is not None:
        log_trace(f"cord_cat: cache hit for {discord_id}")
        return cached

    _wait_for_rate_limit()

    url = f"{_BASE_URL}{_QUERY_PATH}/{quote(discord_id, safe='')}"
    headers = {
        "X-API-Key":    api_key,
        "Accept":       "application/json",
        "User-Agent":   "WhoCord-OSINT/1.1",
    }

    try:
        resp = http_session.get(url, headers=headers, timeout=timeout)
    except Exception as exc:
        msg = f"network error: {type(exc).__name__}: {exc}"
        log_trace(f"cord_cat: {msg} for {discord_id}")
        return CordCatResult(discord_id=discord_id, ok=False, error=msg)

    if resp.status_code == 404:
        # Documented behaviour: no data for this ID. Not an error.
        result = CordCatResult(discord_id=discord_id, ok=True, fetched_at=time.time())
        _cache_put(result)
        return result

    if resp.status_code == 401:
        return CordCatResult(
            discord_id=discord_id, ok=False, error="API key rejected (401)",
        )

    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After", "?")
        msg = f"rate limited (Retry-After={retry_after})"
        log_trace(f"cord_cat: {msg} for {discord_id}")
        return CordCatResult(discord_id=discord_id, ok=False, error=msg)

    if resp.status_code != 200:
        return CordCatResult(
            discord_id=discord_id,
            ok=False,
            error=f"HTTP {resp.status_code}: {resp.text[:200]}",
        )

    try:
        data = resp.json()
    except Exception as exc:
        return CordCatResult(
            discord_id=discord_id, ok=False, error=f"invalid JSON: {exc}",
        )

    if not isinstance(data, dict):
        return CordCatResult(
            discord_id=discord_id,
            ok=False,
            error=f"response root is {type(data).__name__}, expected object",
        )

    result = _parse_response(discord_id, data, time.time())
    _cache_put(result)
    return result


def emit_findings(result: CordCatResult, emit) -> None:
    """
    Emit structured findings from a CordCat result.

    Called by the Discord pipeline stage. The ``emit`` callable has the
    signature ``(event_type: str, payload: dict) -> None``.

    Only emits for sections that have data. A result with an empty
    breach and no fivem records and no statements produces no finding
    events beyond the user-info one — the caller decides whether to
    surface the raw intel entry separately.
    """
    if not result.ok:
        return

    # Discord profile enrichment (always present when the ID resolves)
    if result.user_info:
        username = (
            _first_present(result.user_info, "username", "name", default="")
        )
        if username:
            emit("finding", {
                "type":             "cordcat_user",
                "discord_id":       result.discord_id,
                "username":         username,
                "display_name":     _first_present(
                    result.user_info, "display_name", "global_name",
                    "displayName", default="",
                ),
                "avatar":           _first_present(
                    result.user_info, "avatar", "avatar_url", default="",
                ),
                "account_created":  _first_present(
                    result.user_info, "created_at", "createdAt",
                    "creation_date", default="",
                ),
                "badges":           _first_present(
                    result.user_info, "badges", "public_flags_badges",
                    default=[],
                ),
                "source":           "cord_cat",
            })

    # Breach exposure
    if result.has_breach:
        emit("finding", {
            "type":            "cordcat_breach",
            "discord_id":      result.discord_id,
            "count":           _first_present(
                result.breach, "count", "breach_count", "total",
                default=0,
            ),
            "datasets":        _first_present(
                result.breach, "datasets", "sources", "breaches",
                default=[],
            ),
            "exposed_fields":  _first_present(
                result.breach, "exposed_fields", "fields", "exposed",
                default=[],
            ),
            "geo":             _first_present(
                result.breach, "geo", "geolocation", "geoip",
                default={},
            ),
            "asn":             _first_present(
                result.breach, "asn", "network", default={},
            ),
            "source":          "cord_cat",
        })

    # FiveM / GTA records
    if result.has_fivem:
        records = (
            _first_present(result.fivem, "records", "entries", default=[])
            or []
        )
        emit("finding", {
            "type":       "cordcat_fivem",
            "discord_id": result.discord_id,
            "count":      len(records) if isinstance(records, list) else 0,
            "records":    (records[:10] if isinstance(records, list) else []),
            "source":     "cord_cat",
        })

    # EU DSA statements
    for stmt in (result.statements or [])[:5]:
        if not isinstance(stmt, dict):
            continue
        emit("finding", {
            "type":       "cordcat_dsa_statement",
            "discord_id": result.discord_id,
            "facts":      _first_present(stmt, "facts", "statement", default=""),
            "scope":      _first_present(stmt, "scope", "territory", default=""),
            "grounds":    _first_present(stmt, "grounds", "legal_basis", "basis", default=""),
            "source":     "cord_cat",
        })

    # Bot / risk score
    if result.score:
        emit("finding", {
            "type":       "cordcat_score",
            "discord_id": result.discord_id,
            "value":      _first_present(
                result.score, "value", "score", "risk", default=0,
            ),
            "reasons":    _first_present(
                result.score, "reasons", "signals", default=[],
            ),
            "source":     "cord_cat",
        })