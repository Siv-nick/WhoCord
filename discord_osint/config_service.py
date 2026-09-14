"""
discord_osint/config_service.py
-------------------------------
ConfigService – a stable, typed facade over the existing Config class.

The __setattr__ override dispatches through property setters when a
class-level descriptor exists, so `config_service.mode = "manual"` and
`config_service.llm_model = "..."` both persist correctly.

LLM provider selection
----------------------
``get_llm_endpoint()`` returns ``(base_url, api_key, extra_headers)``
for whichever OpenAI-compatible backend is active. Currently supported:

  • ``"groq"``       → https://api.groq.com/openai/v1
  • ``"openrouter"`` → https://openrouter.ai/api/v1

Every LLM call site (narrative generation, persona summary, structured
report, chat) routes through this helper so switching providers is a
one-key config change.

Contact enrichment
------------------
``apollo_api_key`` / ``lusha_api_key`` and the associated enable flags
are exposed here so the enrichment stage, the config UI, and the
"Test connection" endpoints all read and write through the same facade.
"""

from __future__ import annotations

from typing import Any

from .config import Config, DEFAULT_CONFIG, SENSITIVE_KEYS
from .errors import ConfigurationError


# ---------------------------------------------------------------------------
# LLM endpoint resolution
# ---------------------------------------------------------------------------

_GROQ_BASE_URL       = "https://api.groq.com/openai/v1"
_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

_OPENROUTER_HEADERS = {
    "HTTP-Referer":      "https://github.com/sivnick/whocord",
    "X-OpenRouter-Title": "WhoCord",
}


def get_llm_endpoint(cfg: Any = None) -> tuple[str, str, dict]:
    """
    Return ``(base_url, api_key, extra_headers)`` for the active provider.
    """
    if cfg is None:
        from .config import config as _singleton
        cfg = _singleton

    provider = (getattr(cfg, "LLM_PROVIDER", "groq") or "groq").strip().lower()

    if provider == "openrouter":
        key = getattr(cfg, "OPENROUTER_API_KEY", "") or ""
        return _OPENROUTER_BASE_URL, key, dict(_OPENROUTER_HEADERS)

    key = getattr(cfg, "GROQ_API_KEY", "") or ""
    return _GROQ_BASE_URL, key, {}


class ConfigService:
    """Typed wrapper around the existing Config dataclass."""

    def __init__(self, config: Config | None = None) -> None:
        if config is None:
            from .config import config as _singleton
            config = _singleton
        object.__setattr__(self, "_cfg", config)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _g(self, key: str) -> Any:
        return self._cfg.get(key, DEFAULT_CONFIG.get(key))

    def _s(self, key: str, value: Any) -> None:
        setattr(self._cfg, key, value)

    # ------------------------------------------------------------------ #
    # Sensitive / token properties
    # ------------------------------------------------------------------ #

    @property
    def discord_token(self) -> str:
        return self._cfg.DISCORD_TOKEN

    @discord_token.setter
    def discord_token(self, v: str) -> None:
        self._cfg.DISCORD_TOKEN = v

    @property
    def github_token(self) -> str:
        return self._cfg.GITHUB_TOKEN

    @github_token.setter
    def github_token(self, v: str) -> None:
        self._cfg.GITHUB_TOKEN = v

    @property
    def groq_api_key(self) -> str:
        return self._cfg.GROQ_API_KEY

    @groq_api_key.setter
    def groq_api_key(self, v: str) -> None:
        self._cfg.GROQ_API_KEY = v

    @property
    def openrouter_api_key(self) -> str:
        return getattr(self._cfg, "OPENROUTER_API_KEY", "") or ""

    @openrouter_api_key.setter
    def openrouter_api_key(self, v: str) -> None:
        self._cfg.OPENROUTER_API_KEY = v

    @property
    def instagram_session(self) -> str:
        return self._cfg.INSTAGRAM_SESSION

    @instagram_session.setter
    def instagram_session(self, v: str) -> None:
        self._cfg.INSTAGRAM_SESSION = v

    # ── Contact-enrichment provider keys ─────────────────────────────

    @property
    def apollo_api_key(self) -> str:
        return getattr(self._cfg, "APOLLO_API_KEY", "") or ""

    @apollo_api_key.setter
    def apollo_api_key(self, v: str) -> None:
        self._cfg.APOLLO_API_KEY = v

    @property
    def lusha_api_key(self) -> str:
        return getattr(self._cfg, "LUSHA_API_KEY", "") or ""

    @lusha_api_key.setter
    def lusha_api_key(self, v: str) -> None:
        self._cfg.LUSHA_API_KEY = v

    # ------------------------------------------------------------------ #
    # Mode / target properties
    # ------------------------------------------------------------------ #

    @property
    def mode(self) -> str:
        return self._cfg.MODE

    @mode.setter
    def mode(self, v: str) -> None:
        self._cfg.MODE = v

    @property
    def target_user_id(self) -> Any:
        return self._cfg.TARGET_USER_ID

    @target_user_id.setter
    def target_user_id(self, v: Any) -> None:
        self._cfg.TARGET_USER_ID = v

    @property
    def target_guild_id(self) -> Any:
        return self._cfg.TARGET_GUILD_ID

    @target_guild_id.setter
    def target_guild_id(self, v: Any) -> None:
        self._cfg.TARGET_GUILD_ID = v

    @property
    def manual_username(self) -> str:
        return self._cfg.MANUAL_USERNAME

    @manual_username.setter
    def manual_username(self, v: str) -> None:
        self._cfg.MANUAL_USERNAME = v

    @property
    def manual_email(self) -> str:
        return self._cfg.MANUAL_EMAIL

    @manual_email.setter
    def manual_email(self, v: str) -> None:
        self._cfg.MANUAL_EMAIL = v

    @property
    def multi_guild_search(self) -> bool:
        return bool(self._cfg.MULTI_GUILD_SEARCH)

    @multi_guild_search.setter
    def multi_guild_search(self, v: bool) -> None:
        self._cfg.MULTI_GUILD_SEARCH = v

    @property
    def extra_targets(self) -> list:
        return self._cfg.EXTRA_TARGETS or []

    @extra_targets.setter
    def extra_targets(self, v: list) -> None:
        self._cfg.EXTRA_TARGETS = v

    @property
    def output_format(self) -> str:
        return getattr(self._cfg, "OUTPUT_FORMAT", "html")

    @output_format.setter
    def output_format(self, v: str) -> None:
        self._cfg.OUTPUT_FORMAT = v

    @property
    def debug(self) -> bool:
        return bool(getattr(self._cfg, "DEBUG", False))

    @debug.setter
    def debug(self, v: bool) -> None:
        self._cfg.DEBUG = v

    @property
    def blackbird_dir(self) -> str:
        return self._cfg.BLACKBIRD_DIR

    # ------------------------------------------------------------------ #
    # Contact-enrichment configuration
    # ------------------------------------------------------------------ #

    @property
    def enable_apollo(self) -> bool:
        return bool(getattr(self._cfg, "ENABLE_APOLLO", False))

    @enable_apollo.setter
    def enable_apollo(self, v: bool) -> None:
        self._cfg.ENABLE_APOLLO = bool(v)

    @property
    def enable_lusha(self) -> bool:
        return bool(getattr(self._cfg, "ENABLE_LUSHA", False))

    @enable_lusha.setter
    def enable_lusha(self, v: bool) -> None:
        self._cfg.ENABLE_LUSHA = bool(v)

    @property
    def enrichment_max_identifiers(self) -> int:
        try:
            return max(1, int(getattr(self._cfg, "ENRICHMENT_MAX_IDENTIFIERS", 25)))
        except (TypeError, ValueError):
            return 25

    @enrichment_max_identifiers.setter
    def enrichment_max_identifiers(self, v: int) -> None:
        try:
            self._cfg.ENRICHMENT_MAX_IDENTIFIERS = max(1, int(v))
        except (TypeError, ValueError):
            self._cfg.ENRICHMENT_MAX_IDENTIFIERS = 25

    @property
    def enrichment_phone_reveal(self) -> bool:
        return bool(getattr(self._cfg, "ENABLE_ENRICHMENT_PHONE_REVEAL", False))

    @enrichment_phone_reveal.setter
    def enrichment_phone_reveal(self, v: bool) -> None:
        self._cfg.ENABLE_ENRICHMENT_PHONE_REVEAL = bool(v)

    # ------------------------------------------------------------------ #
    # LLM configuration (Groq / OpenRouter)
    # ------------------------------------------------------------------ #

    @property
    def llm_provider(self) -> str:
        v = (getattr(self._cfg, "LLM_PROVIDER", "groq") or "groq").strip().lower()
        return v if v in ("groq", "openrouter") else "groq"

    @llm_provider.setter
    def llm_provider(self, v: str) -> None:
        v = (v or "groq").strip().lower()
        self._cfg.LLM_PROVIDER = v if v in ("groq", "openrouter") else "groq"

    def llm_endpoint(self) -> tuple[str, str, dict]:
        return get_llm_endpoint(self._cfg)

    @property
    def llm_model(self) -> str:
        return getattr(self._cfg, "LLM_MODEL", "llama3-8b-8192") or "llama3-8b-8192"

    @llm_model.setter
    def llm_model(self, v: str) -> None:
        self._cfg.LLM_MODEL = str(v) if v else "llama3-8b-8192"

    @property
    def llm_temperature(self) -> float:
        try:
            return float(getattr(self._cfg, "LLM_TEMPERATURE", 0.25))
        except (TypeError, ValueError):
            return 0.25

    @llm_temperature.setter
    def llm_temperature(self, v: float) -> None:
        try:
            self._cfg.LLM_TEMPERATURE = float(v)
        except (TypeError, ValueError):
            self._cfg.LLM_TEMPERATURE = 0.25

    @property
    def llm_max_tokens(self) -> int:
        try:
            return int(getattr(self._cfg, "LLM_MAX_TOKENS", 4096))
        except (TypeError, ValueError):
            return 4096

    @llm_max_tokens.setter
    def llm_max_tokens(self, v: int) -> None:
        try:
            self._cfg.LLM_MAX_TOKENS = int(v)
        except (TypeError, ValueError):
            self._cfg.LLM_MAX_TOKENS = 4096

    @property
    def llm_system_prompt(self) -> str:
        return getattr(self._cfg, "LLM_SYSTEM_PROMPT", "") or ""

    @llm_system_prompt.setter
    def llm_system_prompt(self, v: str) -> None:
        self._cfg.LLM_SYSTEM_PROMPT = (v or "").strip()

    @property
    def llm_intel_budget(self) -> int:
        try:
            return int(getattr(self._cfg, "LLM_INTEL_BUDGET", 60000))
        except (TypeError, ValueError):
            return 60000

    @llm_intel_budget.setter
    def llm_intel_budget(self, v: int) -> None:
        try:
            self._cfg.LLM_INTEL_BUDGET = max(5000, int(v))
        except (TypeError, ValueError):
            self._cfg.LLM_INTEL_BUDGET = 60000

    @property
    def llm_intel_include_raw(self) -> bool:
        return bool(getattr(self._cfg, "LLM_INTEL_INCLUDE_RAW", True))

    @llm_intel_include_raw.setter
    def llm_intel_include_raw(self, v: bool) -> None:
        self._cfg.LLM_INTEL_INCLUDE_RAW = bool(v)

    @property
    def llm_intel_exclude_meta(self) -> bool:
        return bool(getattr(self._cfg, "LLM_INTEL_EXCLUDE_META", True))

    @llm_intel_exclude_meta.setter
    def llm_intel_exclude_meta(self, v: bool) -> None:
        self._cfg.LLM_INTEL_EXCLUDE_META = bool(v)

    # ------------------------------------------------------------------ #
    # Tool enable/disable
    # ------------------------------------------------------------------ #

    def is_enabled(self, tool_key: str) -> bool:
        return bool(self._cfg.get(tool_key, False))

    def set_tool(self, tool_key: str, enabled: bool) -> None:
        self._s(tool_key, bool(enabled))
        self._cfg.save()

    # ------------------------------------------------------------------ #
    # Sensitive key management
    # ------------------------------------------------------------------ #

    def set_sensitive(self, key: str, value: str) -> None:
        if key not in SENSITIVE_KEYS:
            raise ConfigurationError(f"{key!r} is not a recognised sensitive key")
        setattr(self._cfg, key, value)
        self._cfg.save()

    def token_status(self) -> dict[str, bool]:
        return {
            "DISCORD_TOKEN":      bool(self._cfg.DISCORD_TOKEN),
            "GITHUB_TOKEN":       bool(self._cfg.GITHUB_TOKEN),
            "GROQ_API_KEY":       bool(self._cfg.GROQ_API_KEY),
            "OPENROUTER_API_KEY": bool(self.openrouter_api_key),
            "INSTAGRAM_SESSION":  bool(self._cfg.INSTAGRAM_SESSION),
            "HIBP_API_KEY":       bool(getattr(self._cfg, "HIBP_API_KEY", "")),
            "APOLLO_API_KEY":     bool(self.apollo_api_key),
            "LUSHA_API_KEY":      bool(self.lusha_api_key),
        }

    def tools_list(self) -> list[dict]:
        from .tools_config import TOOLS_LIST
        return [
            {"key": key, "desc": desc, "enabled": self.is_enabled(key)}
            for key, desc in TOOLS_LIST
        ]

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def save(self) -> None:
        self._cfg.save()

    def get(self, key: str, default: Any = None) -> Any:
        return self._cfg.get(key, default)

    def to_dict(self) -> dict:
        return self._cfg.to_dict()

    # ------------------------------------------------------------------ #
    # Attribute protocol
    # ------------------------------------------------------------------ #

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return getattr(object.__getattribute__(self, "_cfg"), name)
        except AttributeError:
            raise AttributeError(f"ConfigService has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return

        descriptor = getattr(type(self), name, None)
        if isinstance(descriptor, property) and descriptor.fset is not None:
            object.__setattr__(self, name, value)
            return

        setattr(object.__getattribute__(self, "_cfg"), name, value)

    @property
    def raw(self) -> Config:
        return object.__getattribute__(self, "_cfg")