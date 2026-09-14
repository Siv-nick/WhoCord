import json
import os
import sys

import keyring

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

    # ── Intel dump controls ─────────────────────────────────────────────
    "LLM_INTEL_BUDGET":       60000,
    "LLM_INTEL_INCLUDE_RAW":  True,
    "LLM_INTEL_EXCLUDE_META": True,

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
}

# Module‑level globals (kept in sync by Config class)
USER_TOKEN          = ""
GITHUB_TOKEN        = ""
GROQ_API_KEY        = ""
OPENROUTER_API_KEY  = ""
INSTAGRAM_SESSION   = ""
HIBP_API_KEY        = ""
APOLLO_API_KEY      = ""
LUSHA_API_KEY       = ""
ENABLE_APOLLO       = False
ENABLE_LUSHA        = False
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

# LLM globals
LLM_PROVIDER          = "groq"
LLM_MODEL             = "llama3-8b-8192"
LLM_TEMPERATURE       = 0.25
LLM_MAX_TOKENS        = 4096
LLM_SYSTEM_PROMPT     = ""
LLM_INTEL_BUDGET      = 60000
LLM_INTEL_INCLUDE_RAW = True
LLM_INTEL_EXCLUDE_META = True

# Deprecated
ENABLE_SHERLOCK     = False
ENABLE_NAMINTER     = False
ENABLE_SOCIAL_ANALYZER = False


def _sync_globals_from_dict(data):
    for key, val in data.items():
        global_name = key
        if key == "DISCORD_TOKEN":
            global_name = "USER_TOKEN"
        globals()[global_name] = val


class Config:
    def __init__(self, config_file=CONFIG_FILE):
        self._config_file = config_file
        self._data = {
            k: (list(v) if isinstance(v, list) else v)
            for k, v in DEFAULT_CONFIG.items()
        }
        self._load()

    def _load(self):
        # 1. Environment variables first.
        for key in DEFAULT_CONFIG:
            env_val = os.environ.get(key)
            if env_val is not None:
                self._data[key] = env_val

        # 2. File overrides (non-sensitive keys only).
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

        # 3. Sensitive keys: env var wins, else keyring.
        for key, service in SENSITIVE_KEYS.items():
            env_val = os.environ.get(key)
            if env_val:
                self._data[key] = env_val
            else:
                try:
                    stored = keyring.get_password(service, key)
                except Exception as exc:
                    print(
                        f"[config] WARNING: keyring read failed for {key}: {exc}",
                        file=sys.stderr,
                    )
                    stored = None
                if stored:
                    self._data[key] = stored

        _sync_globals_from_dict(self._data)

    def save(self):
        clean = {k: v for k, v in self._data.items() if k not in SENSITIVE_KEYS}
        with open(self._config_file, 'w', encoding='utf-8') as f:
            json.dump(clean, f, indent=2)
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