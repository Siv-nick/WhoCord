"""Tests for ConfigService (backed by the legacy Config)."""
import pytest
import os
import tempfile
import json
from unittest.mock import patch, MagicMock
from discord_osint.config_service import ConfigService
from discord_osint.config import DEFAULT_CONFIG, CONFIG_FILE

@pytest.fixture
def clean_config_service(monkeypatch, tmp_path):
    """Provide a ConfigService that uses a temporary config file."""
    test_config = tmp_path / "test_config.json"
    with open(test_config, 'w') as f:
        json.dump({}, f)  # start empty
    monkeypatch.setattr("discord_osint.config.CONFIG_FILE", str(test_config))
    # Also reset the underlying Config singleton so it reads our temp file
    import discord_osint.config
    discord_osint.config.CONFIG_FILE = str(test_config)
    cfg = ConfigService()
    # Clear any keyring accesses
    monkeypatch.setattr("keyring.get_password", MagicMock(return_value=None))
    return cfg

def test_default_values(clean_config_service):
    """New ConfigService should have default values."""
    assert clean_config_service.get("ENABLE_MAIGRET", None) == True
    assert clean_config_service.get("ENABLE_BLACKBIRD", None) == True
    assert clean_config_service.discord_token == ""

def test_set_and_get(clean_config_service):
    """Setting a non‑sensitive key persists in memory."""
    clean_config_service.set("ENABLE_NAMINTER", False)
    assert clean_config_service.get("ENABLE_NAMINTER") == False

def test_set_discord_token(clean_config_service, monkeypatch):
    """Setting a sensitive key goes through keyring setter."""
    set_password_mock = MagicMock()
    monkeypatch.setattr("keyring.set_password", set_password_mock)
    clean_config_service.discord_token = "my_token"
    assert clean_config_service.discord_token == "my_token"
    set_password_mock.assert_called_once_with("discord-osint/discord", "DISCORD_TOKEN", "my_token")

def test_save_persists_non_sensitive(clean_config_service, tmp_path):
    """After saving, changes appear in config.json (for non‑sensitive keys)."""
    clean_config_service.set("ENABLE_NAMINTER", False)
    clean_config_service.save()
    with open(clean_config_service._config._config_file, 'r') as f:
        saved = json.load(f)
    assert saved.get("ENABLE_NAMINTER") == False

def test_to_dict(clean_config_service):
    """to_dict returns a copy of the config."""
    data = clean_config_service.to_dict()
    assert "DISCORD_TOKEN" in data
    # Token should be masked or actual value (depends on implementation)
    # Currently our Config.to_dict returns the actual value; we just test it exists.
