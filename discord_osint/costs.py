
"""
discord_osint/costs.py
----------------------
Running cost accumulator for a single investigation.

Uses the ``third_party_contacted`` events emitted by every LLM call
site (narrative, persona summary, structured report, chat) plus the
``enrichment_complete`` findings from Apollo / Lusha.

Token estimation
----------------
The LLM providers return token counts in the API response, but the
client code does not currently extract them. This module estimates
tokens from the byte counts recorded on the audit event:

    estimated_tokens = bytes / 4

Roughly right for English text. The resulting cost is an *estimate*,
not a bill.

Pricing
-------
Two config keys:

    LLM_COST_PER_1K_INPUT    default 0.0
    LLM_COST_PER_1K_OUTPUT   default 0.0

Zero means "do not track" — the accumulator stores byte counts and
event counts but reports a cost of 0.

Spend caps
----------
Two additional config keys:

    MAX_LLM_SPEND_USD         default 0.0 (= no cap)
    MAX_ENRICHMENT_CREDITS    default 0.0 (= no cap)

When a cap is set and reached, ``exceeded()`` returns True and the
pipeline aborts at the next checkpoint. The check runs inside each
LLM call site *and* between pipeline stages, so a single expensive
call cannot overshoot the cap by more than one call's worth.

Enrichment credits
------------------
Apollo and Lusha return credit counts directly. The accumulator reads
``enrichment_spend`` from intel and reports credits as-is. It does not
attempt to convert credits to dollars.

Thread safety
-------------
One accumulator per job, mutated only from the worker thread and read
from the SSE generator thread. A single lock guards all reads and
writes.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


# Rough token-to-byte ratio. English text is close to 4 bytes/token;
# code and JSON are closer to 3. The constant is a compromise.
_BYTES_PER_TOKEN = 4.0


@dataclass
class CostSummary:
    """Aggregated cost and event counts for one investigation."""

    llm_calls:          int = 0
    llm_bytes_in:       int = 0
    llm_bytes_out:      int = 0
    llm_est_tokens_in:  int = 0
    llm_est_tokens_out: int = 0
    llm_cost_usd:       float = 0.0

    enrichment_calls:   int = 0
    enrichment_credits: float = 0.0

    breakdown: list[dict] = field(default_factory=list)
    """One entry per recorded event, oldest first."""

    def to_dict(self) -> dict:
        return {
            "llm_calls":          self.llm_calls,
            "llm_bytes_in":       self.llm_bytes_in,
            "llm_bytes_out":      self.llm_bytes_out,
            "llm_est_tokens_in":  self.llm_est_tokens_in,
            "llm_est_tokens_out": self.llm_est_tokens_out,
            "llm_cost_usd":       round(self.llm_cost_usd, 6),
            "enrichment_calls":   self.enrichment_calls,
            "enrichment_credits": round(self.enrichment_credits, 3),
            "breakdown":          self.breakdown[-50:],
        }


def _non_negative_int(value: Any) -> int:
    """
    Coerce *value* to a non-negative int, defaulting to 0.

    Byte counts arrive from emitted events, which cross a thread and a
    JSON boundary before they get here. Anything that is not a sane
    count is treated as zero rather than propagating into the totals.
    """
    try:
        n = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


class CostAccumulator:
    """Per-job cost accumulator. Thread-safe."""

    def __init__(
        self,
        *,
        input_rate: float = 0.0,
        output_rate: float = 0.0,
        max_usd: float = 0.0,
        max_credits: float = 0.0,
    ) -> None:
        """
        Parameters
        ----------
        input_rate:
            USD per 1,000 input tokens. Zero disables cost tracking.
        output_rate:
            USD per 1,000 output tokens. Zero disables cost tracking.
        max_usd:
            Hard ceiling on accumulated LLM cost. Zero means no cap.
            When the ceiling is reached, ``exceeded()`` returns True
            and the pipeline aborts at the next checkpoint.
        max_credits:
            Hard ceiling on accumulated enrichment credits. Zero means
            no cap.
        """
        self._input_rate  = max(0.0, float(input_rate))
        self._output_rate = max(0.0, float(output_rate))
        self._max_usd     = max(0.0, float(max_usd))
        self._max_credits = max(0.0, float(max_credits))

        self._summary = CostSummary()
        self._lock    = threading.Lock()
        self._exceeded = False
        self._reason   = ""

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #

    def record_llm_call(
        self,
        *,
        service: str = "",
        model: str = "",
        bytes_sent: int = 0,
        bytes_received: int = 0,
        ok: bool = True,
    ) -> None:
        """
        Record one LLM call. The byte counts come straight from the
        ``third_party_contacted`` audit event.
        """
        # Clamp once, here, and use the clamped values everywhere
        # below. The token estimates were already clamped but the raw
        # byte counters were not, so a negative or non-numeric
        # bytes_sent (a malformed third_party_contacted payload) drove
        # llm_bytes_in negative while the token count stayed at zero —
        # an internally inconsistent summary that then fed the spend
        # cap check.
        sent_b = _non_negative_int(bytes_sent)
        recv_b = _non_negative_int(bytes_received)

        tokens_in  = sent_b / _BYTES_PER_TOKEN
        tokens_out = recv_b / _BYTES_PER_TOKEN

        cost = 0.0
        if self._input_rate > 0:
            cost += (tokens_in / 1000.0) * self._input_rate
        if self._output_rate > 0:
            cost += (tokens_out / 1000.0) * self._output_rate

        entry = {
            "kind":         "llm",
            "service":      service,
            "model":        model,
            "bytes_in":     sent_b,
            "bytes_out":    recv_b,
            "est_tokens_in":  int(tokens_in),
            "est_tokens_out": int(tokens_out),
            "cost_usd":     round(cost, 6),
            "ok":           bool(ok),
        }

        with self._lock:
            self._summary.llm_calls          += 1
            self._summary.llm_bytes_in       += sent_b
            self._summary.llm_bytes_out      += recv_b
            self._summary.llm_est_tokens_in  += int(tokens_in)
            self._summary.llm_est_tokens_out += int(tokens_out)
            self._summary.llm_cost_usd       += cost
            self._summary.breakdown.append(entry)
            self._check_caps_locked()

    def record_enrichment(
        self,
        *,
        provider: str = "",
        credits: float = 0.0,
        matched: int = 0,
    ) -> None:
        """Record one enrichment submission."""
        try:
            credits_f = float(credits or 0.0)
        except (TypeError, ValueError):
            credits_f = 0.0

        entry = {
            "kind":     "enrichment",
            "provider": provider,
            "credits":  round(credits_f, 3),
            "matched":  int(matched or 0),
        }

        with self._lock:
            self._summary.enrichment_calls   += 1
            self._summary.enrichment_credits += credits_f
            self._summary.breakdown.append(entry)
            self._check_caps_locked()

    # ------------------------------------------------------------------ #
    # Cap enforcement
    # ------------------------------------------------------------------ #

    def _check_caps_locked(self) -> None:
        """
        Update the exceeded flag based on the current totals.

        Called at the end of every record_* method while the lock is
        held. Once set, the flag is sticky — costs never decrease, so
        a cap that has been exceeded stays exceeded.
        """
        if self._exceeded:
            return

        if self._max_usd > 0 and self._summary.llm_cost_usd >= self._max_usd:
            self._exceeded = True
            self._reason = (
                f"LLM spend cap reached "
                f"(${self._summary.llm_cost_usd:.4f} >= ${self._max_usd:.2f})"
            )
            return

        if (self._max_credits > 0
                and self._summary.enrichment_credits >= self._max_credits):
            self._exceeded = True
            self._reason = (
                f"enrichment credit cap reached "
                f"({self._summary.enrichment_credits:g} >= "
                f"{self._max_credits:g})"
            )

    def exceeded(self) -> tuple[bool, str]:
        """
        Return ``(exceeded, reason)``. Callers use this at checkpoints
        — inside LLM call sites and between pipeline stages — to abort
        cleanly rather than continue spending.
        """
        with self._lock:
            return self._exceeded, self._reason

    # ------------------------------------------------------------------ #
    # Reading
    # ------------------------------------------------------------------ #

    def snapshot(self) -> dict:
        """Return a serialisable copy of the current summary."""
        with self._lock:
            data = self._summary.to_dict()
            data["cap_exceeded"] = self._exceeded
            data["cap_reason"]   = self._reason
            data["max_usd"]      = self._max_usd
            data["max_credits"]  = self._max_credits
            return data

    def reset(self) -> None:
        with self._lock:
            self._summary  = CostSummary()
            self._exceeded = False
            self._reason   = ""
