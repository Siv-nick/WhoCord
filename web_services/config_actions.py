"""
web_services/config_actions.py
------------------------------
Dispatcher for the /config POST endpoint.

Change log
----------
- Numeric coercion is now safe. ``int("not-a-number")`` previously
  raised and bubbled up as ``{"success": false, "error": "..."}``
  — acceptable — but ``int(None)`` and ``int([1,2])`` raised
  TypeError with an unhelpful message. The handlers now use
  ``_safe_int`` / ``_safe_float`` which fall back to the current
  value on any parse failure.
- Added ``set_spend`` for ``MAX_LLM_SPEND_USD`` and
  ``MAX_ENRICHMENT_CREDITS``.
- Added ``set_redaction`` for ``REDACTED_FINDINGS``.
"""

from __future__ import annotations

from typing import Any, Callable


_ALLOWED_TOKEN_KEYS = frozenset({
    "DISCORD_TOKEN",
    "GITHUB_TOKEN",
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "INSTAGRAM_SESSION",
    "HIBP_API_KEY",
    "APOLLO_API_KEY",
    "LUSHA_API_KEY",
    "CORD_CAT_API_KEY",
    "TINEYE_API_KEY",
})

_ALLOWED_OUTPUT_FORMATS = frozenset({"html", "markdown", "json"})


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


class ConfigActionDispatcher:
    def __init__(self, config_service: Any) -> None:
        self._cs = config_service

    def dispatch(self, data: dict) -> tuple[dict, int]:
        if not isinstance(data, dict) or not data:
            return {"success": False, "error": "no data"}, 200

        action = data.get("action")
        handler = self._HANDLERS.get(action)
        if handler is None:
            return {"success": False, "error": "unknown action"}, 200

        try:
            return handler(self, data), 200
        except Exception as exc:
            return {"success": False, "error": str(exc)}, 200

    # ------------------------------------------------------------------ #
    # Handlers
    # ------------------------------------------------------------------ #

    def _handle_set_token(self, data: dict) -> dict:
        key = data.get("key")
        if key not in _ALLOWED_TOKEN_KEYS:
            return {"success": False, "error": "invalid key"}
        self._cs.set_sensitive(key, data.get("value", ""))
        return {"success": True}

    def _handle_toggle_tool(self, data: dict) -> dict:
        self._cs.set_tool(data.get("key"), _safe_bool(data.get("enable"), True))
        return {"success": True}

    def _handle_set_mode(self, data: dict) -> dict:
        self._cs.mode = str(data.get("mode", "manual"))
        self._cs.save()
        return {"success": True}

    def _handle_set_multi_guild(self, data: dict) -> dict:
        self._cs.multi_guild_search = _safe_bool(data.get("multi"), False)
        self._cs.save()
        return {"success": True}

    def _handle_toggle_debug(self, data: dict) -> dict:
        self._cs.debug = not self._cs.debug
        self._cs.save()
        return {"success": True, "debug": self._cs.debug}

    def _handle_set_output_format(self, data: dict) -> dict:
        fmt = str(data.get("format", "html")).strip().lower()
        if fmt not in _ALLOWED_OUTPUT_FORMATS:
            return {
                "success": False,
                "error": f"format must be one of {sorted(_ALLOWED_OUTPUT_FORMATS)}",
            }
        self._cs.output_format = fmt
        self._cs.save()
        return {"success": True, "output_format": fmt}

    def _handle_set_pivot(self, data: dict) -> dict:
        self._apply_pivot_nested(data.get("pivot", {}) or {})
        self._cs.save()
        return {"success": True}

    def _handle_set_pivot_config(self, data: dict) -> dict:
        self._apply_pivot_flat(data)
        self._cs.save()
        return {"success": True}

    def _handle_set_enrichment(self, data: dict) -> dict:
        enr = data.get("enrichment", {}) or {}
        if "max_identifiers" in enr:
            try:
                self._cs.enrichment_max_identifiers = int(enr["max_identifiers"])
            except (TypeError, ValueError):
                pass
        if "phone_reveal" in enr:
            self._cs.enrichment_phone_reveal = _safe_bool(enr["phone_reveal"], False)
        self._cs.save()
        return {"success": True}

    def _handle_set_llm(self, data: dict) -> dict:
        llm = data.get("llm", {}) or {}
        if "provider" in llm:
            self._cs.llm_provider = str(llm["provider"])
        if "model" in llm:
            self._cs.llm_model = str(llm["model"]).strip()
        if "temperature" in llm:
            self._cs.llm_temperature = _safe_float(
                llm["temperature"], self._cs.llm_temperature,
            )
        if "max_tokens" in llm:
            self._cs.llm_max_tokens = _safe_int(
                llm["max_tokens"], self._cs.llm_max_tokens,
            )
        if "system_prompt" in llm:
            self._cs.llm_system_prompt = str(llm["system_prompt"])
        if "intel_budget" in llm:
            self._cs.llm_intel_budget = _safe_int(
                llm["intel_budget"], self._cs.llm_intel_budget,
            )
        if "intel_include_raw" in llm:
            self._cs.llm_intel_include_raw = _safe_bool(
                llm["intel_include_raw"], True,
            )
        if "intel_exclude_meta" in llm:
            self._cs.llm_intel_exclude_meta = _safe_bool(
                llm["intel_exclude_meta"], True,
            )
        self._cs.save()
        return {"success": True}

    def _handle_set_spend(self, data: dict) -> dict:
        """
        Update spend-cap settings.

        Both values are hard ceilings for a single investigation. 0.0
        disables the cap. ``CostAccumulator.exceeded()`` reads them at
        each checkpoint.
        """
        spend = data.get("spend", {}) or {}
        if "max_llm_spend_usd" in spend:
            v = _safe_float(spend["max_llm_spend_usd"], -1.0)
            if v >= 0:
                setattr(self._cs, "MAX_LLM_SPEND_USD", v)
        if "max_enrichment_credits" in spend:
            v = _safe_float(spend["max_enrichment_credits"], -1.0)
            if v >= 0:
                setattr(self._cs, "MAX_ENRICHMENT_CREDITS", v)
        self._cs.save()
        return {"success": True}

    def _handle_set_redaction(self, data: dict) -> dict:
        """
        Update the list of finding types stripped from the HTML report
        before it is written. Empty list means no redaction.
        """
        redaction = data.get("redaction", {}) or {}
        raw = redaction.get("redacted_findings", None)
        if raw is None:
            return {"success": True}
        if not isinstance(raw, list):
            return {"success": False, "error": "redacted_findings must be a list"}

        cleaned: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                continue
            s = item.strip()
            if s and s not in cleaned:
                cleaned.append(s)

        setattr(self._cs, "REDACTED_FINDINGS", cleaned)
        self._cs.save()
        return {"success": True, "redacted_findings": cleaned}

    # ------------------------------------------------------------------ #
    # Pivot helpers
    # ------------------------------------------------------------------ #

    def _apply_pivot_nested(self, pivot: dict) -> None:
        setattr(self._cs, "ENABLE_PIVOTING",
                _safe_bool(pivot.get("enabled"), False))
        setattr(self._cs, "PIVOT_EMAIL",
                _safe_bool(pivot.get("pivot_email"), True))
        setattr(self._cs, "PIVOT_USERNAME",
                _safe_bool(pivot.get("pivot_username"), True))
        setattr(self._cs, "PIVOT_MAX_DEPTH",
                _safe_int(pivot.get("max_depth"), 3))
        setattr(self._cs, "PIVOT_MAX_SEEDS",
                _safe_int(pivot.get("max_seeds"), 5))
        setattr(self._cs, "PIVOT_REQUIRE_CONFIRM",
                _safe_bool(pivot.get("require_confirm"), False))

    def _apply_pivot_flat(self, data: dict) -> None:
        nested = {
            "enabled":         data.get("ENABLE_PIVOTING",       False),
            "pivot_email":     data.get("PIVOT_EMAIL",           True),
            "pivot_username":  data.get("PIVOT_USERNAME",        True),
            "max_depth":       data.get("PIVOT_MAX_DEPTH",       3),
            "max_seeds":       data.get("PIVOT_MAX_SEEDS",       5),
            "require_confirm": data.get("PIVOT_REQUIRE_CONFIRM", False),
        }
        self._apply_pivot_nested(nested)

    _HANDLERS: dict[str, Callable] = {
        "set_token":         _handle_set_token,
        "toggle_tool":       _handle_toggle_tool,
        "set_mode":          _handle_set_mode,
        "set_multi_guild":   _handle_set_multi_guild,
        "toggle_debug":      _handle_toggle_debug,
        "set_output_format": _handle_set_output_format,
        "set_pivot":         _handle_set_pivot,
        "set_pivot_config":  _handle_set_pivot_config,
        "set_enrichment":    _handle_set_enrichment,
        "set_llm":           _handle_set_llm,
        "set_spend":         _handle_set_spend,
        "set_redaction":     _handle_set_redaction,
    }