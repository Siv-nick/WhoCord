"""
discord_osint/config_service.py
-------------------------------
ConfigService – a stable, typed facade over the existing Config class.
"""

from __future__ import annotations

from typing import Any

from .config import Config, DEFAULT_CONFIG, SENSITIVE_KEYS
from .errors import ConfigurationError


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
    def instagram_session(self) -> str:
        return self._cfg.INSTAGRAM_SESSION

    @instagram_session.setter
    def instagram_session(self, v: str) -> None:
        self._cfg.INSTAGRAM_SESSION = v

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
            "DISCORD_TOKEN": bool(self._cfg.DISCORD_TOKEN),
            "GITHUB_TOKEN": bool(self._cfg.GITHUB_TOKEN),
            "GROQ_API_KEY": bool(self._cfg.GROQ_API_KEY),
            "INSTAGRAM_SESSION": bool(self._cfg.INSTAGRAM_SESSION),
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
        # All user-facing config keys go through the underlying Config,
        # which now persists them to _data (Bug 4 fix).
        setattr(object.__getattribute__(self, "_cfg"), name, value)

    @property
    def raw(self) -> Config:
        return object.__getattribute__(self, "_cfg")