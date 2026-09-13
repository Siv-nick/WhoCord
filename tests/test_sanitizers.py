"""Tests for input sanitizers."""
import pytest
from discord_osint.utils.sanitizers import (
    sanitize_username, sanitize_email, sanitize_user_id,
    validate_mode
)
from discord_osint.errors import InputValidationError

def test_sanitize_username_valid():
    assert sanitize_username("john_doe") == "john_doe"

def test_sanitize_username_leading_dot():
    assert sanitize_username(".john") == "john"

def test_sanitize_username_special_chars():
    assert sanitize_username("john<script>") == "johnscript"

def test_sanitize_username_empty_raises():
    with pytest.raises(InputValidationError):
        sanitize_username("")

def test_sanitize_email_valid():
    assert sanitize_email("test@example.com") == "test@example.com"

def test_sanitize_user_id():
    assert sanitize_user_id("123abc") == "123"

def test_validate_mode():
    assert validate_mode("manual") == "manual"
    with pytest.raises(InputValidationError):
        validate_mode("invalid")