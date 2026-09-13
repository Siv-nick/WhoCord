"""
discord_osint/errors.py
-----------------------
Custom exception hierarchy for WhoCord.
All application exceptions derive from WhoCordError so callers can
catch the entire family with a single `except WhoCordError`.
"""


class WhoCordError(Exception):
    """Base exception for all WhoCord errors."""

    def __init__(self, message: str, error_code: str = "WHOCORD_ERROR"):
        super().__init__(message)
        self.user_message = message
        self.error_code = error_code

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.error_code!r}, msg={self.user_message!r})"


class ConfigurationError(WhoCordError):
    """Raised when a required config value is missing or invalid."""

    def __init__(self, message: str):
        super().__init__(message, error_code="CONFIG_ERROR")


class InputValidationError(WhoCordError):
    """Raised when user-supplied input fails validation."""

    def __init__(self, field: str, message: str):
        super().__init__(
            f"Invalid {field!r}: {message}",
            error_code="VALIDATION_ERROR",
        )
        self.field = field


class ToolExecutionError(WhoCordError):
    """Raised when an external OSINT tool fails in a non-recoverable way."""

    def __init__(self, tool: str, details: str = ""):
        msg = f"Tool '{tool}' failed"
        if details:
            msg += f": {details}"
        super().__init__(msg, error_code="TOOL_ERROR")
        self.tool = tool
        self.details = details


class ReportGenerationError(WhoCordError):
    """Raised when report generation fails."""

    def __init__(self, message: str):
        super().__init__(message, error_code="REPORT_ERROR")


class PipelineAbortError(WhoCordError):
    """Raised by a stage to signal that the whole pipeline should stop immediately."""

    def __init__(self, stage: str, reason: str):
        super().__init__(
            f"Pipeline aborted at stage '{stage}': {reason}",
            error_code="PIPELINE_ABORT",
        )
        self.stage = stage
        self.reason = reason
