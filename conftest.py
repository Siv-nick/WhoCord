"""
conftest.py — project root.
---------------------------
Ensures the project root is on sys.path so tests can `import discord_osint`
regardless of how pytest is invoked. tests/ has no __init__.py, so pytest's
default "prepend" import mode inserts tests/ rather than the project root.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)