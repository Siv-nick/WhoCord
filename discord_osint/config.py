import json
import os
import keyring
from .utils import get_base_dir, get_data_dir

CONFIG_FILE = os.path.join(get_base_dir(), "config.json")

DEFAULT_CONFIG = {
    "DISCORD_TOKEN":          "",
    "GITHUB_TOKEN":           "",
    "GROQ_API_KEY":           "",
    "INSTAGRAM_SESSION":      "",
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
    # Deprecated — kept so old config.json files don't crash
    "ENABLE_SHERLOCK":        False,
    "ENABLE_NAMINTER":        False,
    "ENABLE_SOCIAL_ANALYZER": False,
}

SENSITIVE_KEYS = {
    "DISCORD_TOKEN":       "discord-osint/discord",
    "GITHUB_TOKEN":        "discord-osint/github",
    "GROQ_API_KEY":        "discord-osint/groq",
    "INSTAGRAM_SESSION":   "discord-osint/instagram",
}

# Module‑level globals (kept in sync by Config class)
USER_TOKEN          = ""
GITHUB_TOKEN        = ""
GROQ_API_KEY        = ""
INSTAGRAM_SESSION   = ""
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
        for key in DEFAULT_CONFIG:
            env_val = os.environ.get(key)
            if env_val is not None:
                self._data[key] = env_val
        if os.path.exists(self._config_file):
            try:
                with open(self._config_file, 'r') as f:
                    file_data = json.load(f)
                for k, v in file_data.items():
                    if k not in SENSITIVE_KEYS and k in DEFAULT_CONFIG:
                        self._data[k] = v
            except Exception:
                pass
        for key, service in SENSITIVE_KEYS.items():
            env_val = os.environ.get(key)
            if env_val:
                self._data[key] = env_val
            else:
                stored = keyring.get_password(service, key)
                if stored:
                    self._data[key] = stored
        _sync_globals_from_dict(self._data)

    def save(self):
        clean = {k: v for k, v in self._data.items() if k not in SENSITIVE_KEYS}
        with open(self._config_file, 'w') as f:
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