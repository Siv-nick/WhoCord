"""Centralised logging configuration for WhoCord."""
import logging
import sys

LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False

def setup_logging(debug: bool = False) -> None:
    """Initialise logging. Safe to call multiple times."""
    global _configured
    if _configured:
        return
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=DATE_FORMAT,
                        stream=sys.stderr)
    # Quiet noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    _configured = True

def get_logger(name: str) -> logging.Logger:
    """Return a logger for the given module name."""
    return logging.getLogger(name)
