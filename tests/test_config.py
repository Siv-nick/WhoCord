"""
tests/test_config.py
--------------------
Tests for the Config class and ConfigService facade.

Coverage focus for this revision
--------------------------------
- HIBP_API_KEY is a first-class sensitive key (default + keyring path).
- A malformed config.json now emits a warning on stderr instead of
  silently reverting to defaults (the bug fixed in config.py).
- A partial / truncated config.json is handled without crashing.
- ConfigService.set_sensitive accepts every key in SENSITIVE_KEYS.
"""

import json
from unittest.mock import MagicMock

import pytest

from discord_osint.config import (
    Config,
    DEFAULT_CONFIG,
    SENSITIVE_KEYS,
)
from discord_osint.config_service import ConfigService
from discord_osint.errors import ConfigurationError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_keyring(monkeypatch):
    """Replace keyring with in-memory dicts so tests never touch the OS store."""
    store: dict[tuple[str, str], str] = {}

    def fake_get(service, key):
        return store.get((service, key))

    def fake_set(service, key, value):
        store[(service, key)] = value

    def fake_delete(service, key):
        store.pop((service, key), None)

    monkeypatch.setattr("keyring.get_password", fake_get)
    monkeypatch.setattr("keyring.set_password", fake_set)
    monkeypatch.setattr("keyring.delete_password", fake_delete)
    return store


@pytest.fixture
def clean_config(monkeypatch, tmp_path, isolated_keyring):
    """A Config bound to a temp file, with no keyring side effects."""
    test_file = tmp_path / "test_config.json"
    test_file.write_text("{}")
    # Clear any environment overrides that would leak in from the shell.
    for key in DEFAULT_CONFIG:
        monkeypatch.delenv(key, raising=False)
    return Config(config_file=str(test_file))


@pytest.fixture
def clean_config_service(clean_config):
    return ConfigService(clean_config)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

class TestDefaults:
    def test_hibp_key_default_is_empty(self):
        assert DEFAULT_CONFIG["HIBP_API_KEY"] == ""

    def test_hibp_key_is_sensitive(self):
        # Must be in SENSITIVE_KEYS so it round-trips via the keyring rather
        # than landing in the on-disk config.json.
        assert "HIBP_API_KEY" in SENSITIVE_KEYS

    def test_default_config_has_llm_keys(self):
        for key in ("LLM_MODEL", "LLM_TEMPERATURE", "LLM_MAX_TOKENS",
                    "LLM_INTEL_BUDGET", "LLM_INTEL_INCLUDE_RAW",
                    "LLM_INTEL_EXCLUDE_META"):
            assert key in DEFAULT_CONFIG

    def test_legacy_keys_present_so_old_files_dont_crash(self):
        # These are retained so old config.json files don't KeyError.
        for key in ("ENABLE_SHERLOCK", "ENABLE_NAMINTER", "ENABLE_SOCIAL_ANALYZER"):
            assert key in DEFAULT_CONFIG


# ---------------------------------------------------------------------------
# Attribute protocol
# ---------------------------------------------------------------------------

class TestAttributeProtocol:
    def test_unknown_attribute_raises(self, clean_config):
        with pytest.raises(AttributeError):
            _ = clean_config.NOT_A_REAL_KEY

    def test_set_attribute_updates_dict(self, clean_config):
        clean_config.ENABLE_NAMINTER = False
        assert clean_config.ENABLE_NAMINTER is False
        assert clean_config.get("ENABLE_NAMINTER") is False

    def test_to_dict_returns_copy(self, clean_config):
        d = clean_config.to_dict()
        d["ENABLE_NAMINTER"] = "mutated"
        # The original must not have been affected.
        assert clean_config.get("ENABLE_NAMINTER") is not "mutated"


# ---------------------------------------------------------------------------
# Malformed config.json
# ---------------------------------------------------------------------------

class TestMalformedConfig:
    def test_malformed_json_warns_and_does_not_crash(
        self, tmp_path, monkeypatch, isolated_keyring, capsys
    ):
        """The bug: `except Exception: pass` silently reverted to defaults."""
        bad = tmp_path / "bad_config.json"
        # Truncated JSON — common case after a crash mid-save().
        bad.write_text('{"ENABLE_MAIGRET": true, "LLM_MODEL":')

        for key in DEFAULT_CONFIG:
            monkeypatch.delenv(key, raising=False)

        # Must not raise.
        cfg = Config(config_file=str(bad))

        captured = capsys.readouterr()
        # And must be loud about the failure.
        assert "could not read" in captured.err.lower()
        assert str(bad) in captured.err

        # Falls back to defaults for everything.
        assert cfg.ENABLE_MAIGRET == DEFAULT_CONFIG["ENABLE_MAIGRET"]
        assert cfg.LLM_MODEL == DEFAULT_CONFIG["LLM_MODEL"]

    def test_non_object_root_warns(
        self, tmp_path, monkeypatch, isolated_keyring, capsys
    ):
        bad = tmp_path / "list_config.json"
        bad.write_text('["not", "a", "dict"]')

        for key in DEFAULT_CONFIG:
            monkeypatch.delenv(key, raising=False)

        cfg = Config(config_file=str(bad))
        captured = capsys.readouterr()
        assert "could not read" in captured.err.lower()
        # Still usable.
        assert cfg.ENABLE_MAIGRET == DEFAULT_CONFIG["ENABLE_MAIGRET"]

    def test_missing_config_file_is_silent(
        self, tmp_path, monkeypatch, isolated_keyring, capsys
    ):
        """A missing file is not an error — first run, no config saved yet."""
        for key in DEFAULT_CONFIG:
            monkeypatch.delenv(key, raising=False)

        missing = tmp_path / "does_not_exist.json"
        Config(config_file=str(missing))

        captured = capsys.readouterr()
        assert "could not read" not in captured.err.lower()

    def test_partial_file_keeps_present_keys_and_defaults_others(
        self, tmp_path, monkeypatch, isolated_keyring
    ):
        part = tmp_path / "partial.json"
        part.write_text(json.dumps({"ENABLE_MAIGRET": False}))

        for key in DEFAULT_CONFIG:
            monkeypatch.delenv(key, raising=False)

        cfg = Config(config_file=str(part))
        assert cfg.ENABLE_MAIGRET is False
        # Keys absent from the file fall back to defaults.
        assert cfg.ENABLE_USER_SCANNER == DEFAULT_CONFIG["ENABLE_USER_SCANNER"]


# ---------------------------------------------------------------------------
# Sensitive keys
# ---------------------------------------------------------------------------

class TestSensitiveKeys:
    def test_sensitive_keys_not_written_to_disk(
        self, clean_config, tmp_path
    ):
        clean_config.DISCORD_TOKEN = "super-secret-token"
        clean_config.HIBP_API_KEY = "hibp-secret-key"
        clean_config.save()

        on_disk = json.loads((tmp_path / "test_config.json").read_text())
        assert "DISCORD_TOKEN" not in on_disk
        assert "HIBP_API_KEY" not in on_disk

    def test_sensitive_keys_roundtrip_via_keyring(
        self, clean_config, isolated_keyring
    ):
        clean_config.HIBP_API_KEY = "hibp-key-123"
        clean_config.save()

        # Re-read from keyring on a fresh Config against the same file.
        fresh = Config(config_file=clean_config._config_file)
        assert fresh.HIBP_API_KEY == "hibp-key-123"


# ---------------------------------------------------------------------------
# ConfigService facade
# ---------------------------------------------------------------------------

class TestConfigService:
    def test_set_and_get_through_facade(self, clean_config_service):
        clean_config_service.set("ENABLE_NAMINTER", False)
        assert clean_config_service.get("ENABLE_NAMINTER") is False

    def test_set_sensitive_accepts_hibp(self, clean_config_service):
        # HIBP_API_KEY must be recognised as a sensitive key, otherwise the
        # web UI's token form (which uses set_sensitive) can't set it.
        clean_config_service.set_sensitive("HIBP_API_KEY", "key-abc")
        assert clean_config_service.get("HIBP_API_KEY") == "key-abc"

    def test_set_sensitive_rejects_unknown_key(self, clean_config_service):
        with pytest.raises(ConfigurationError):
            clean_config_service.set_sensitive("NOT_A_SENSITIVE_KEY", "x")

    def test_is_enabled_reads_flag(self, clean_config_service):
        clean_config_service.set("ENABLE_MAIGRET", True)
        assert clean_config_service.is_enabled("ENABLE_MAIGRET") is True
        clean_config_service.set("ENABLE_MAIGRET", False)
        assert clean_config_service.is_enabled("ENABLE_MAIGRET") is False

    def test_tools_list_contains_hibp(self, clean_config_service):
        keys = {t["key"] for t in clean_config_service.tools_list()}
        assert "ENABLE_HIBP" in keys