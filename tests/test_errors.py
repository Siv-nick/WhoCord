"""Tests for error hierarchy."""
from discord_osint.errors import (
    WhoCordError, ConfigurationError, ToolExecutionError
)

def test_tool_execution_error():
    err = ToolExecutionError("failed", tool="naminter", details="socket error")
    assert err.tool == "naminter"
    assert err.error_code == "TOOL_EXECUTION"