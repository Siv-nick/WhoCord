import contextvars
import json
import os
import sys

import keyring

from .errors import ConfigurationError
from .utils import get_base_dir, get_data_dir

CONFIG_FILE = os.path.join(get_base_dir(), "config.json")

DEFAULT_CONFIG = {
    "DISCORD_TOKEN":          "",
    "GITHUB_TOKEN":           "",
    "GROQ_API_KEY":           "",
    "OPENROUTER_API_KEY":     "",
    "INSTAGRAM_SESSION":      "",
    "HIBP_API_KEY":           "",
    # ── Contact-enrichment providers (opt-in) ─────────────────────────
    "APOLLO_API_KEY":         "",
    "LUSHA_API_KEY":          "",
    "ENABLE_APOLLO":          False,
    "ENABLE_LUSHA":           False,
    "ENRICHMENT_MAX_IDENTIFIERS": 25,
    "ENABLE_ENRICHMENT_PHONE_REVEAL": False,
    # ── CordCat (opt-in) ──────────────────────────────────────────────
    "CORD_CAT_API_KEY":       "",
    "ENABLE_CORD_CAT":        False,
    # ── TinEye (opt-in; paid API tier) ────────────────────────────────
    "TINEYE_API_KEY":         "",
    "ENABLE_TINEYE":          False,
    "MULTI_GUILD_SEARCH":     False,
    "SKIP_GITHUB":            False,
    "ENABLE_USER_SCANNER":    True,
    "ENABLE_MAIGRET":         True,
    "ENABLE_LINKOOK":         True,
    "ENABLE_SOCIALSCAN":      True,
    "ENABLE_SOCIOPATH":       False,
    "ENABLE_BLACKBIRD":       True,
    "ENABLE_WMN":             True,
    "ENABLE_HOLEHE":          True,
    "ENABLE_H8MAIL":          True,
    "ENABLE_HIBP":            True,
    "ENABLE_EMAILREP":        True,
    "ENABLE_SCYLLA":          False,
    "ENABLE_GHUNT":           True,
    "ENABLE_THEHARVESTER":    False,
    "ENABLE_WHOIS":           True,
    "ENABLE_WAYBACK":         False,
    "ENABLE_EXIF":            True,
    "ENABLE_REVERSE_IMG":     False,
    "ENABLE_NAME_ANALYSIS":   True,
    "ENABLE_EMAIL_GUESS":     True,
    "ENABLE_AI_REPORT":       True,
    "ENABLE_LOCATION":        True,
    "ENABLE_LANGDETECT":      True,
    "ENABLE_PARALLEL_EMAIL":  True,
    "ENABLE_EMAIL_VERIFY":    False,
    "ENABLE_CACHING":         False,
    "ENABLE_GITFIVE":         True,
    "ENABLE_SOCID":           True,
    "ENABLE_SHARETRACE":      True,
    "ENABLE_GOSEARCH":        False,
    "ENABLE_FACE_MATCH":      False,
    "ENABLE_TOUTATIS":        False,
    "SMTP_CHECK":             False,
    "MANUAL_EMAIL":           "",
    "EXTRA_TARGETS":          [],
    "BLACKBIRD_DIR": os.path.join(get_data_dir(), "blackbird"),
    "ENABLE_PIVOTING":        False,
    "PIVOT_EMAIL":            True,
    "PIVOT_USERNAME":         True,
    "PIVOT_MAX_DEPTH":        3,
    "PIVOT_MAX_SEEDS":        5,
    "PIVOT_REQUIRE_CONFIRM":  False,
    "MODE":                   "discord",
    "TARGET_USER_ID":         None,
    "TARGET_GUILD_ID":        None,
    "MANUAL_USERNAME":        "",
    "OUTPUT_FORMAT":          "html",
    "MANUAL_DOMAIN":          "",
    "MANUAL_PHONE":           "",
    "MANUAL_IMAGE_URL":       "",
    "MANUAL_URL":             "",
    "PROBE_STRING":           "",
    "DEBUG":                  False,

    # ── LLM configuration ────────────────────────────────────────────────
    "LLM_PROVIDER":           "groq",
    "LLM_MODEL":              "llama3-8b-8192",
    "LLM_TEMPERATURE":        0.25,
    "LLM_MAX_TOKENS":         4096,
    "LLM_SYSTEM_PROMPT":      "",

    # ── Cost tracking ───────────────────────────────────────────────────
    # USD per 1,000 tokens. Leave at 0.0 to disable cost display and
    # track token counts only.
    "LLM_COST_PER_1K_INPUT":  0.0,
    "LLM_COST_PER_1K_OUTPUT": 0.0,

    # ── Spend caps ──────────────────────────────────────────────────────
    # Hard ceilings for a single investigation. 0.0 = no cap. When a
    # cap is reached, the pipeline aborts at the next checkpoint.
    "MAX_LLM_SPEND_USD":      0.0,
    "MAX_ENRICHMENT_CREDITS": 0.0,

    # ── Intel dump controls ─────────────────────────────────────────────
    "LLM_INTEL_BUDGET":       60000,
    "LLM_INTEL_INCLUDE_RAW":  True,
    "LLM_INTEL_EXCLUDE_META": True,

    # ── Report redaction ────────────────────────────────────────────────
    # List of finding ``type`` strings to strip from the HTML report
    # before it is written. Empty list = no redaction.
    "REDACTED_FINDINGS":      [],

    # ── Retention ───────────────────────────────────────────────────────
    # 0 = never auto-purge. Any positive integer is a number of days.
    "RETENTION_DAYS":         0,

    # Deprecated — kept so old config.json files don't crash
    "ENABLE_SHERLOCK":        False,
    "ENABLE_NAMINTER":        False,
    "ENABLE_SOCIAL_ANALYZER": False,
}

SENSITIVE_KEYS = {
    "DISCORD_TOKEN":      "discord-osint/discord",
    "GITHUB_TOKEN":       "discord-osint/github",
    "GROQ_API_KEY":       "discord-osint/groq",
    "OPENROUTER_API_KEY": "discord-osint/openrouter",
    "INSTAGRAM_SESSION":  "discord-osint/instagram",
    "HIBP_API_KEY":       "discord-osint/hibp",
    "APOLLO_API_KEY":     "discord-osint/apollo",
    "LUSHA_API_KEY":      "discord-osint/lusha",
    "CORD_CAT_API_KEY":   "discord-osint/cordcat",
    "TINEYE_API_KEY":     "discord-osint/tineye",
}

# Module‑level globals (kept in sync by Config class for the CLI path).
USER_TOKEN          = ""
GITHUB_TOKEN        = ""
GROQ_API_KEY        = ""
OPENROUTER_API_KEY  = ""
INSTAGRAM_SESSION   = ""
HIBP_API_KEY        = ""
APOLLO_API_KEY      = ""
LUSHA_API_KEY       = ""
CORD_CAT_API_KEY    = ""
TINEYE_API_KEY      = ""
ENABLE_APOLLO       = False
ENABLE_LUSHA        = False
ENABLE_CORD_CAT     = False
ENABLE_TINEYE       = False
ENRICHMENT_MAX_IDENTIFIERS = 25
ENABLE_ENRICHMENT_PHONE_REVEAL = False
MULTI_GUILD_SEARCH  = False
SKIP_GITHUB         = False
ENABLE_USER_SCANNER = True
ENABLE_MAIGRET      = True
ENABLE_LINKOOK      = True
ENABLE_SOCIALSCAN   = True
ENABLE_SOCIOPATH    = False
ENABLE_BLACKBIRD    = True
ENABLE_WMN          = True
ENABLE_HOLEHE       = True
ENABLE_H8MAIL       = True
ENABLE_HIBP         = True
ENABLE_EMAILREP     = True
ENABLE_SCYLLA       = False
ENABLE_GHUNT        = True
ENABLE_THEHARVESTER = False
ENABLE_WHOIS        = True
ENABLE_WAYBACK      = False
ENABLE_EXIF         = True
ENABLE_REVERSE_IMG  = False
ENABLE_NAME_ANALYSIS= True
ENABLE_EMAIL_GUESS  = True
ENABLE_AI_REPORT    = True
ENABLE_LOCATION     = True
ENABLE_LANGDETECT   = True
ENABLE_PARALLEL_EMAIL = True
ENABLE_EMAIL_VERIFY = False
ENABLE_CACHING      = False
ENABLE_GITFIVE      = True
ENABLE_SOCID        = True
ENABLE_SHARETRACE   = True
ENABLE_GOSEARCH     = False
ENABLE_FACE_MATCH   = False
ENABLE_TOUTATIS     = False
SMTP_CHECK          = False
MANUAL_EMAIL        = ""
EXTRA_TARGETS       = []
BLACKBIRD_DIR = os.path.join(get_data_dir(), "blackbird")
ENABLE_PIVOTING     = False
PIVOT_EMAIL         = True
PIVOT_USERNAME      = True
PIVOT_MAX_DEPTH     = 3
PIVOT_MAX_SEEDS     = 5
PIVOT_REQUIRE_CONFIRM = False
MODE                = "discord"
TARGET_USER_ID      = None
TARGET_GUILD_ID     = None
MANUAL_USERNAME     = ""
MANUAL_DOMAIN       = ""
MANUAL_PHONE        = ""
MANUAL_IMAGE_URL    = ""
MANUAL_URL          = ""
PROBE_STRING        = ""
OUTPUT_FORMAT       = "html"
DEBUG               = False

LLM_PROVIDER          = "groq"
LLM_MODEL             = "llama3-8b-8192"
LLM_TEMPERATURE       = 0.25
LLM_MAX_TOKENS        = 4096
LLM_SYSTEM_PROMPT     = ""
LLM_INTEL_BUDGET      = 60000
LLM_INTEL_INCLUDE_RAW = True
LLM_INTEL_EXCLUDE_META = True

LLM_COST_PER_1K_INPUT  = 0.0
LLM_COST_PER_1K_OUTPUT = 0.0

MAX_LLM_SPEND_USD      = 0.0
MAX_ENRICHMENT_CREDITS = 0.0

REDACTED_FINDINGS      = []

RETENTION_DAYS        = 0

ENABLE_SHERLOCK     = False
ENABLE_NAMINTER     = False
ENABLE_SOCIAL_ANALYZER = False


def _require_keyring_from_env() -> bool:
    v = os.environ.get("WHOCORD_REQUIRE_KEYRING", "0")
    return v.strip().lower() in ("1", "true", "yes", "on")


def _coerce_env(raw: str, default):
    """
    Coerce an environment-variable string to the type of the default
    value.

    Without this, every env override is stored as a string, and
    ``get_flag``'s ``bool(...)`` treats ``DEBUG=0`` as truthy. That is
    a real correctness bug: an operator who exports ``DEBUG=0`` thinks
    they disabled verbose logging and gets it anyway.
    """
    if isinstance(default, bool):
        return str(raw).strip().lower() in ("1", "true", "yes", "on")

    if isinstance(default, int) and not isinstance(default, bool):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    if isinstance(default, float):
        try:
            return float(raw)
        except (TypeError, ValueError):
            return default

    if isinstance(default, list):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else default
        except Exception:
            return [s.strip() for s in str(raw).split(",") if s.strip()]

    return raw


def _sync_globals_from_dict(data):
    for key, val in data.items():
        global_name = key
        if key == "DISCORD_TOKEN":
            global_name = "USER_TOKEN"
        globals()[global_name] = val


class Config:
    def __init__(
        self,
        config_file=CONFIG_FILE,
        require_keyring: bool | None = None,
    ):
        self._config_file = config_file
        self._require_keyring = (
            _require_keyring_from_env()
            if require_keyring is None
            else require_keyring
        )
        self._data = {
            k: (list(v) if isinstance(v, list) else v)
            for k, v in DEFAULT_CONFIG.items()
        }
        self._load()

    def _load(self):
        # Env overrides, coerced to the type of the default.
        for key, default in DEFAULT_CONFIG.items():
            env_val = os.environ.get(key)
            if env_val is not None:
                self._data[key] = _coerce_env(env_val, default)

        if os.path.exists(self._config_file):
            try:
                with open(self._config_file, 'r', encoding='utf-8') as f:
                    file_data = json.load(f)
                if not isinstance(file_data, dict):
                    raise ValueError(
                        f"config root must be an object, got {type(file_data).__name__}"
                    )
                for k, v in file_data.items():
                    if k not in SENSITIVE_KEYS and k in DEFAULT_CONFIG:
                        self._data[k] = v
            except Exception as exc:
                print(
                    f"[config] WARNING: could not read {self._config_file!r}: "
                    f"{type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                print(
                    "[config]          falling back to defaults for unreadable keys",
                    file=sys.stderr,
                )

        for key, service in SENSITIVE_KEYS.items():
            env_val = os.environ.get(key)
            if env_val:
                self._data[key] = env_val
                continue

            try:
                stored = keyring.get_password(service, key)
            except Exception as exc:
                if self._require_keyring:
                    raise ConfigurationError(
                        f"keyring backend unavailable for {key} "
                        f"({type(exc).__name__}: {exc}); set "
                        f"WHOCORD_REQUIRE_KEYRING=0 to allow empty keys"
                    ) from exc
                print(
                    f"[config] WARNING: keyring read failed for {key}: {exc}",
                    file=sys.stderr,
                )
                print(
                    "[config]          sensitive keys will be empty. "
                    "Set WHOCORD_REQUIRE_KEYRING=1 to fail hard instead.",
                    file=sys.stderr,
                )
                stored = None

            if stored:
                self._data[key] = stored

        _sync_globals_from_dict(self._data)

    def save(self):
        """
        Write the non-sensitive config to disk with restrictive
        permissions (dir 0700, file 0600).

        The file contains the last investigation's target identifiers
        (username, email, domain, phone, URL) and is world-readable
        under a default umask. On a shared workstation that exposes
        every case's target to every local user.
        """
        clean = {k: v for k, v in self._data.items() if k not in SENSITIVE_KEYS}

        parent = os.path.dirname(self._config_file) or "."
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

        with open(self._config_file, 'w', encoding='utf-8') as f:
            json.dump(clean, f, indent=2)
        try:
            os.chmod(self._config_file, 0o600)
        except OSError:
            pass

        for key, service in SENSITIVE_KEYS.items():
            value = self._data[key]
            if value:
                keyring.set_password(service, key, value)
            else:
                try:
                    keyring.delete_password(service, key)
                except Exception:
                    pass
        _sync_globals_from_dict(self._data)

    def __getattr__(self, name):
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        if name in DEFAULT_CONFIG:
            return self._data[name]
        raise AttributeError(f"Config has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        if name in DEFAULT_CONFIG:
            self._data[name] = value
            _sync_globals_from_dict({name: value})
            return
        object.__setattr__(self, name, value)

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def to_dict(self):
        return self._data.copy()


config = Config()


# ──────────────────────────────────────────────────────────────────────
# Per-job config snapshot
# ──────────────────────────────────────────────────────────────────────

class JobConfig:
    """A per-investigation config snapshot."""

    def __init__(self, base: dict):
        object.__setattr__(self, "_data", dict(base))

    def __getattr__(self, name):
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(f"JobConfig has no attribute {name!r}")

    def __setattr__(self, name, value):
        if name == "_data":
            object.__setattr__(self, name, value)
            return
        self._data[name] = value

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def to_dict(self):
        return dict(self._data)


_active_job_config: contextvars.ContextVar = contextvars.ContextVar(
    "whocord_active_job_config", default=None,
)


def set_active_config(cfg: JobConfig):
    return _active_job_config.set(cfg)


def reset_active_config(token) -> None:
    _active_job_config.reset(token)


def get_active_config():
    return _active_job_config.get()


def get_flag(name: str, default: bool = False) -> bool:
    cfg = _active_job_config.get()
    if cfg is not None:
        val = cfg.get(name, None)
        if val is not None:
            return bool(val)
    return bool(globals().get(name, default))