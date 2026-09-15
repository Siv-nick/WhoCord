"""
discord_osint/intelligence/activity.py
--------------------------------------
Infer a target's likely timezone, active hours, and posting cadence
from the timestamps already present in the investigation intel.

This is pure analysis — no new data sources, no network calls. It runs
against timestamps the investigation has already collected: Discord
message timestamps, GitHub commit dates, WHOIS creation dates, EXIF
dates, and any other date-bearing findings.

Method
------
1. Collect every parseable timestamp into a list of ``datetime``
   objects (naive or aware; aware values are normalised to UTC).
2. Drop timestamps that look like infrastructure records rather than
   human activity: WHOIS and certificate dates, DNS records. These
   are machine-generated and cluster at business hours in the *server's*
   timezone, which is not the target's.
3. For each candidate UTC offset from -12:00 to +14:00 in 30-minute
   steps, compute a 24-bin histogram of the target's local hours.
4. Score the histogram by "circadian fit": activity should concentrate
   between roughly 08:00 and 23:00 local, with a trough between 02:00
   and 06:00. The offset with the highest fit is the inferred offset.
5. Derive ``active_hours`` (the contiguous window containing the middle
   80% of activity) and a 3-level posting cadence (sparse / steady /
   heavy) from the number of timestamps and their spread.

Confidence
----------
The result includes a ``confidence`` of "low" / "medium" / "high" based
on how many timestamps were available and how much better the best
offset scored than the runner-up. Fewer than 5 timestamps is always
"low" regardless of the score. A margin under 5% between best and
second-best is capped at "medium".

Known limitations
-----------------
* A target who works night shifts will be inferred as being in a
  different timezone than they actually are. The result is a signal,
  not a fact.
* Timestamps in intel are frequently local-time strings without a
  timezone. If the source did not declare UTC, the inferred offset
  absorbs both the target's real offset and any local-time drift.
* Some tools emit timestamps in their own timezone. GitHub's API
  returns UTC; theHarvester's output is naive; EXIF can be either.
  Mixed sources degrade the signal.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Candidate offsets in minutes, from -12:00 to +14:00 in 30-min steps.
_CANDIDATE_OFFSETS_MIN: tuple[int, ...] = tuple(range(-720, 840 + 1, 30))

# Sources whose timestamps are infrastructure events, not human activity.
# Excluded from the circadian analysis because they cluster at business
# hours in the server's timezone, not the target's.
_INFRA_SOURCES: frozenset[str] = frozenset({
    "whois",
    "dns_lookup",
    "ssl_module",
    "socket",
    "ipapi",
    "crtsh",
    "crt_sh",
})

# Keys whose values should not be scanned for timestamps.
_INFRA_KEYS: frozenset[str] = frozenset({
    "account_created",     # derived from the snowflake, not a real event
    "creation_date",
    "expiry_date",
    "not_before",
    "not_after",
    "started_at",
})


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class ActivityResult:
    """The inferred activity profile of a target."""

    inferred_utc_offset_min: Optional[int] = None
    inferred_utc_offset_str: str = ""
    inferred_timezone_hint: str = ""
    active_hours: str = ""
    posting_cadence: str = ""
    sample_size: int = 0
    confidence: str = "low"
    candidates: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "inferred_utc_offset_min": self.inferred_utc_offset_min,
            "inferred_utc_offset_str": self.inferred_utc_offset_str,
            "inferred_timezone_hint":  self.inferred_timezone_hint,
            "active_hours":            self.active_hours,
            "posting_cadence":         self.posting_cadence,
            "sample_size":             self.sample_size,
            "confidence":              self.confidence,
            "candidates":              self.candidates[:5],
        }

    @property
    def has_signal(self) -> bool:
        """True when at least a rough inference is available."""
        return self.inferred_utc_offset_min is not None and self.sample_size >= 3


# ---------------------------------------------------------------------------
# Timestamp collection
# ---------------------------------------------------------------------------

_ISO_LIKE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)"
)


def _parse_timestamp(value: str) -> Optional[datetime]:
    """
    Parse the common ISO-8601-ish variants that appear in the intel dict.

    Returns a timezone-aware UTC datetime on success, ``None`` on any
    parse failure. Aware inputs are converted to UTC; naive inputs are
    assumed to be UTC already (this is the wrong assumption for some
    tools, noted in the module docstring).
    """
    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    # Replace Z with +00:00 so datetime.fromisoformat handles it
    # uniformly on Python < 3.11.
    normalised = s.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(normalised)
    except (ValueError, TypeError):
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _collect_timestamps(intel: dict) -> list[datetime]:
    """
    Walk the intel dict and return every parseable human-activity
    timestamp.

    Rules
    -----
    * Skip the entries whose source is in ``_INFRA_SOURCES``.
    * Skip the entries whose key is in ``_INFRA_KEYS``.
    * Skip values that are not strings or do not contain a
      ``YYYY-MM-DD`` prefix.
    * Cap at 2000 timestamps to keep the offset scan fast.
    """
    out: list[datetime] = []
    seen: set[str] = set()

    def _scan(entry: Any, source_hint: str = "") -> None:
        if len(out) >= 2000:
            return
        if isinstance(entry, dict):
            src = (entry.get("source") or source_hint or "").lower()
            if src in _INFRA_SOURCES:
                return
            for k, v in entry.items():
                if k in _INFRA_KEYS:
                    continue
                _scan(v, source_hint=src)
        elif isinstance(entry, list):
            for item in entry:
                _scan(item, source_hint=source_hint)
        elif isinstance(entry, str):
            m = _ISO_LIKE.search(entry)
            if not m:
                return
            s = m.group(1)
            if s in seen:
                return
            seen.add(s)
            dt = _parse_timestamp(s)
            if dt is not None:
                out.append(dt)

    for key, entry in intel.items():
        if key in _INFRA_KEYS:
            continue
        _scan(entry)

    return out


# ---------------------------------------------------------------------------
# Circadian scoring
# ---------------------------------------------------------------------------

def _histogram_for_offset(
    timestamps: Iterable[datetime], offset_min: int,
) -> list[int]:
    """Return a 24-bin histogram of the local hours for *timestamps*."""
    hist = [0] * 24
    delta = timedelta(minutes=offset_min)
    for dt in timestamps:
        local = dt + delta
        hist[local.hour] += 1
    return hist


def _circadian_score(hist: list[int]) -> float:
    """
    Score a histogram by how "human" the distribution looks.

    Human activity concentrates between 08:00 and 23:00 local with a
    trough between 02:00 and 06:00. The score is the fraction of total
    activity that falls in the waking window, minus a small penalty for
    activity in the sleeping window.

    Returns a value in roughly [-0.5, 1.0]. Higher is better.
    """
    total = sum(hist)
    if total == 0:
        return 0.0

    waking = sum(hist[h] for h in range(8, 24))
    sleeping = sum(hist[h] for h in (0, 1, 2, 3, 4, 5, 6, 7))

    fraction_waking = waking / total
    fraction_sleeping = sleeping / total

    return fraction_waking - 0.35 * fraction_sleeping


def _active_hours(hist: list[int]) -> str:
    """
    Return the contiguous window containing the middle 80% of activity
    in a friendly "HH:00–HH:00" format.

    Falls back to the full 24-hour range when the distribution is too
    flat for a meaningful window.
    """
    total = sum(hist)
    if total == 0:
        return ""

    # Find the middle 80%.
    target_lo = total * 0.10
    target_hi = total * 0.90

    cumulative = 0
    start_hour = 0
    end_hour = 23
    for h in range(24):
        cumulative += hist[h]
        if cumulative >= target_lo and start_hour == 0 and h != 0:
            start_hour = h
            break

    cumulative = 0
    for h in range(23, -1, -1):
        cumulative += hist[h]
        if cumulative >= (total - target_hi) and end_hour == 23:
            end_hour = h
            break

    if start_hour <= end_hour:
        return f"{start_hour:02d}:00–{end_hour:02d}:00"
    # Wrap-around window (unusual but possible for night-shift targets).
    return f"{start_hour:02d}:00–{end_hour:02d}:00"


def _cadence(span_days: float, count: int) -> str:
    """Classify posting cadence from the sample size and time span."""
    if count < 3:
        return ""
    if span_days <= 0:
        return "sparse"
    per_day = count / span_days
    if per_day >= 5:
        return "heavy"
    if per_day >= 0.5:
        return "steady"
    return "sparse"


def _offset_to_string(offset_min: int) -> str:
    sign = "+" if offset_min >= 0 else "-"
    mins = abs(offset_min)
    hh = mins // 60
    mm = mins % 60
    return f"UTC{sign}{hh:02d}:{mm:02d}"


# Coarse region labels for the most common whole-hour offsets. These
# are hints, not ground truth — a UTC+1 offset could be Berlin, Lagos,
# or Algiers. The label is only shown when the inferred offset is a
# whole hour and matches a well-known bucket.
_HOUR_HINTS: dict[int, str] = {
    -10: "Hawaii",
    -8:  "US Pacific",
    -7:  "US Mountain",
    -6:  "US Central",
    -5:  "US Eastern",
    -4:  "Atlantic / Eastern South America",
    -3:  "Brazil / Argentina",
    0:   "UK / Portugal / West Africa",
    1:   "Central Europe / West Africa",
    2:   "Eastern Europe / Egypt / South Africa",
    3:   "Moscow / East Africa",
    4:   "Gulf / Azerbaijan",
    5:   "Pakistan / Central Asia",
    5.5: "India / Sri Lanka",
    7:   "Thailand / Vietnam / Indonesia",
    8:   "China / Singapore / Perth",
    9:   "Japan / Korea",
    10:  "Eastern Australia",
    12:  "New Zealand",
}


def _hint_for_offset(offset_min: int) -> str:
    if offset_min % 60 != 0 and offset_min != 330:
        return ""
    hours = offset_min / 60
    return _HOUR_HINTS.get(hours, "") or _HOUR_HINTS.get(offset_min / 60, "")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def infer_activity_profile(intel: dict) -> ActivityResult:
    """
    Return the inferred activity profile of a target from *intel*.

    The result is a signal, not a fact — see the module docstring for
    the caveats. The caller decides how to surface it.
    """
    timestamps = _collect_timestamps(intel)
    result = ActivityResult(sample_size=len(timestamps))

    if len(timestamps) < 3:
        return result

    # Score every candidate offset.
    scored: list[tuple[int, float, list[int]]] = []
    for off in _CANDIDATE_OFFSETS_MIN:
        hist = _histogram_for_offset(timestamps, off)
        score = _circadian_score(hist)
        scored.append((off, score, hist))

    scored.sort(key=lambda t: t[1], reverse=True)
    best_offset, best_score, best_hist = scored[0]
    second_score = scored[1][1] if len(scored) > 1 else 0.0
    margin = best_score - second_score

    result.inferred_utc_offset_min = best_offset
    result.inferred_utc_offset_str = _offset_to_string(best_offset)
    result.inferred_timezone_hint = _hint_for_offset(best_offset)
    result.active_hours = _active_hours(best_hist)

    # Cadence from the span between earliest and latest timestamp.
    earliest = min(timestamps)
    latest = max(timestamps)
    span_days = max((latest - earliest).total_seconds() / 86400.0, 0.5)
    result.posting_cadence = _cadence(span_days, len(timestamps))

    # Confidence.
    if len(timestamps) < 5:
        confidence = "low"
    elif margin >= 0.10 and len(timestamps) >= 20:
        confidence = "high"
    elif margin >= 0.05 or len(timestamps) >= 20:
        confidence = "medium"
    else:
        confidence = "low"
    result.confidence = confidence

    # Top five candidates for the report / debug view.
    result.candidates = [
        {
            "offset_min": off,
            "offset_str": _offset_to_string(off),
            "score":      round(score, 3),
        }
        for off, score, _ in scored[:5]
    ]

    return result