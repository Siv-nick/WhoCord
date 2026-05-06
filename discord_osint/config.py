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
    "ENABLE_NAMINTER":        True,
    "ENABLE_SHERLOCK":        True,
    "ENABLE_SOCIAL_ANALYZER": True,
    "ENABLE_LINKOOK":         True,
    "ENABLE_SOCIOPATH":       True,
    "ENABLE_SHARETRACE":      True,
    "ENABLE_SOCID":           True,
    "ENABLE_GITFIVE":         True,
    "ENABLE_TOUTATIS":        False,
    "ENABLE_THEHARVESTER":    False,
    "ENABLE_NAME_ANALYSIS":   True,
    "ENABLE_FACE_MATCH":      False,
    "ENABLE_EMAIL_GUESS":     True,
    "ENABLE_HOLEHE":          True,
    "ENABLE_H8MAIL":          True,
    "ENABLE_GOSEARCH":        False,
    "ENABLE_GHUNT":           True,
    "ENABLE_PHONEINFOGA":     False,
    "ENABLE_AI_REPORT":       True,
    "ENABLE_MAIGRET":         True,
    "ENABLE_REVERSE_IMG":     False,
    "ENABLE_SOCIALSCAN":      False,
    "DEBUG":                  False,
    "ENABLE_EXIF":            True,
    "ENABLE_WHOIS":           True,
    "ENABLE_WAYBACK":         False,
    "ENABLE_HIBP":            True,
    "ENABLE_EMAILREP":        True,
    "ENABLE_SCYLLA":          False,
    "ENABLE_LOCATION":        True,
    "ENABLE_LANGDETECT":      True,
    "ENABLE_PARALLEL_EMAIL":  True,
    "ENABLE_CACHING":         False,
    "SMTP_CHECK":             False,
    "MANUAL_EMAIL":           "",
    "EXTRA_TARGETS":          [],
    "ENABLE_BLACKBIRD":       True,
    "ENABLE_EMAIL_VERIFY":    False,
    "BLACKBIRD_DIR": os.path.join(get_data_dir(), "blackbird"),
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
ENABLE_NAMINTER     = True
ENABLE_SHERLOCK     = True
ENABLE_SOCIAL_ANALYZER = True
ENABLE_LINKOOK      = True
ENABLE_SOCIOPATH    = True
ENABLE_SHARETRACE   = True
ENABLE_SOCID        = True
ENABLE_GITFIVE      = True
ENABLE_TOUTATIS     = False
ENABLE_THEHARVESTER = False
ENABLE_NAME_ANALYSIS= True
ENABLE_FACE_MATCH   = False
ENABLE_EMAIL_GUESS  = True
ENABLE_HOLEHE       = True
ENABLE_H8MAIL       = True
ENABLE_GOSEARCH     = False
ENABLE_GHUNT        = True
ENABLE_PHONEINFOGA  = False
ENABLE_AI_REPORT    = True
ENABLE_MAIGRET      = True
ENABLE_REVERSE_IMG  = False
ENABLE_SOCIALSCAN   = False
ENABLE_EXIF         = True
ENABLE_WHOIS        = True
ENABLE_WAYBACK      = False
ENABLE_HIBP         = True
ENABLE_EMAILREP     = True
ENABLE_SCYLLA       = False
ENABLE_LOCATION     = True
ENABLE_LANGDETECT   = True
ENABLE_PARALLEL_EMAIL = True
ENABLE_CACHING      = False
SMTP_CHECK          = False
MANUAL_EMAIL        = ""
EXTRA_TARGETS       = []
ENABLE_BLACKBIRD    = True
ENABLE_EMAIL_VERIFY = False
BLACKBIRD_DIR = os.path.join(get_data_dir(), "blackbird")

MODE                = "discord"
TARGET_USER_ID      = None
TARGET_GUILD_ID     = None
MANUAL_USERNAME     = ""

def _sync_globals_from_dict(data):
    global USER_TOKEN, GITHUB_TOKEN, GROQ_API_KEY, INSTAGRAM_SESSION
    global MULTI_GUILD_SEARCH, SKIP_GITHUB
    global ENABLE_NAMINTER, ENABLE_SHERLOCK, ENABLE_SOCIAL_ANALYZER, ENABLE_LINKOOK
    global ENABLE_SOCIOPATH, ENABLE_SHARETRACE, ENABLE_SOCID, ENABLE_GITFIVE, ENABLE_TOUTATIS
    global ENABLE_THEHARVESTER, ENABLE_NAME_ANALYSIS, ENABLE_FACE_MATCH, ENABLE_EMAIL_GUESS
    global ENABLE_HOLEHE, ENABLE_H8MAIL, ENABLE_GOSEARCH, ENABLE_GHUNT, ENABLE_PHONEINFOGA
    global ENABLE_AI_REPORT, ENABLE_MAIGRET, ENABLE_REVERSE_IMG, ENABLE_SOCIALSCAN, ENABLE_EXIF
    global ENABLE_WHOIS, ENABLE_WAYBACK, ENABLE_HIBP, ENABLE_EMAILREP, ENABLE_SCYLLA
    global ENABLE_LOCATION, ENABLE_LANGDETECT, ENABLE_PARALLEL_EMAIL, ENABLE_CACHING, SMTP_CHECK
    global MANUAL_EMAIL, EXTRA_TARGETS, ENABLE_BLACKBIRD, ENABLE_EMAIL_VERIFY, BLACKBIRD_DIR

    mapping = {
        "DISCORD_TOKEN": "USER_TOKEN",
        "GITHUB_TOKEN": "GITHUB_TOKEN",
        "GROQ_API_KEY": "GROQ_API_KEY",
        "INSTAGRAM_SESSION": "INSTAGRAM_SESSION",
        "MULTI_GUILD_SEARCH": "MULTI_GUILD_SEARCH",
        "SKIP_GITHUB": "SKIP_GITHUB",
        "ENABLE_NAMINTER": "ENABLE_NAMINTER",
        "ENABLE_SHERLOCK": "ENABLE_SHERLOCK",
        "ENABLE_SOCIAL_ANALYZER": "ENABLE_SOCIAL_ANALYZER",
        "ENABLE_LINKOOK": "ENABLE_LINKOOK",
        "ENABLE_SOCIOPATH": "ENABLE_SOCIOPATH",
        "ENABLE_SHARETRACE": "ENABLE_SHARETRACE",
        "ENABLE_SOCID": "ENABLE_SOCID",
        "ENABLE_GITFIVE": "ENABLE_GITFIVE",
        "ENABLE_TOUTATIS": "ENABLE_TOUTATIS",
        "ENABLE_THEHARVESTER": "ENABLE_THEHARVESTER",
        "ENABLE_NAME_ANALYSIS": "ENABLE_NAME_ANALYSIS",
        "ENABLE_FACE_MATCH": "ENABLE_FACE_MATCH",
        "ENABLE_EMAIL_GUESS": "ENABLE_EMAIL_GUESS",
        "ENABLE_HOLEHE": "ENABLE_HOLEHE",
        "ENABLE_H8MAIL": "ENABLE_H8MAIL",
        "ENABLE_GOSEARCH": "ENABLE_GOSEARCH",
        "ENABLE_GHUNT": "ENABLE_GHUNT",
        "ENABLE_PHONEINFOGA": "ENABLE_PHONEINFOGA",
        "ENABLE_AI_REPORT": "ENABLE_AI_REPORT",
        "ENABLE_MAIGRET": "ENABLE_MAIGRET",
        "ENABLE_REVERSE_IMG": "ENABLE_REVERSE_IMG",
        "ENABLE_SOCIALSCAN": "ENABLE_SOCIALSCAN",
        "ENABLE_EXIF": "ENABLE_EXIF",
        "ENABLE_WHOIS": "ENABLE_WHOIS",
        "ENABLE_WAYBACK": "ENABLE_WAYBACK",
        "ENABLE_HIBP": "ENABLE_HIBP",
        "ENABLE_EMAILREP": "ENABLE_EMAILREP",
        "ENABLE_SCYLLA": "ENABLE_SCYLLA",
        "ENABLE_LOCATION": "ENABLE_LOCATION",
        "ENABLE_LANGDETECT": "ENABLE_LANGDETECT",
        "ENABLE_PARALLEL_EMAIL": "ENABLE_PARALLEL_EMAIL",
        "ENABLE_CACHING": "ENABLE_CACHING",
        "SMTP_CHECK": "SMTP_CHECK",
        "MANUAL_EMAIL":     "MANUAL_EMAIL",
        "EXTRA_TARGETS":    "EXTRA_TARGETS",
        "ENABLE_BLACKBIRD": "ENABLE_BLACKBIRD",
        "ENABLE_EMAIL_VERIFY": "ENABLE_EMAIL_VERIFY",
        "BLACKBIRD_DIR":    "BLACKBIRD_DIR",
    }
    for key, val in data.items():
        global_name = mapping.get(key, key)
        globals()[global_name] = val

class Config:
    def __init__(self, config_file=CONFIG_FILE):
        self._config_file = config_file
        self._data = DEFAULT_CONFIG.copy()
        self.MODE = "discord"
        self.TARGET_USER_ID = None
        self.TARGET_GUILD_ID = None
        self.MANUAL_USERNAME = ""
        self.MANUAL_EMAIL = ""
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
                    if k not in SENSITIVE_KEYS:
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
        globals()["MODE"] = self.MODE
        globals()["TARGET_USER_ID"] = self.TARGET_USER_ID
        globals()["TARGET_GUILD_ID"] = self.TARGET_GUILD_ID
        globals()["MANUAL_USERNAME"] = self.MANUAL_USERNAME
        globals()["MANUAL_EMAIL"] = self.MANUAL_EMAIL

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
        allowed = ("MODE", "TARGET_USER_ID", "TARGET_GUILD_ID", "MANUAL_USERNAME",
                   "MANUAL_EMAIL", "OUTPUT_FORMAT")
        if name.startswith("_") or name in allowed:
            object.__setattr__(self, name, value)
            if name in ("MODE", "TARGET_USER_ID", "TARGET_GUILD_ID", "MANUAL_USERNAME", "MANUAL_EMAIL"):
                globals()[name] = value
        elif name in DEFAULT_CONFIG:
            self._data[name] = value
            _sync_globals_from_dict({name: value})
        else:
            raise AttributeError(f"Cannot set unknown config key '{name}'")

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def to_dict(self):
        return self._data.copy()

config = Config()
