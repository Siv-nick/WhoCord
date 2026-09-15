"""
tests/conftest.py
-----------------
Shared pytest fixtures for the WhoCord test suite.

Critical setup that must run before any test module imports web_app:

- ``WHOCORD_SECRET`` — pins the shared secret so
  ``web_app._load_or_create_secret()`` does not write to
  ``~/.whocord/session_secret`` on the developer's machine.
- ``WHOCORD_SECRET_PATH`` — belt-and-braces: if the env var is somehow
  unset, this is where the fallback file would be written.
- ``WHOCORD_REQUIRE_KEYRING=0`` — an explicit "do not fail hard" so a
  bare venv without an OS keyring backend does not crash on import.

These are set at module level, not inside a fixture, because the import
of ``web_app`` captures them once at module load.
"""

from __future__ import annotations

import os

# Must precede any test module import of web_app.
os.environ.setdefault("WHOCORD_SECRET", "test-secret-not-for-production")
os.environ.setdefault("WHOCORD_SECRET_PATH", "/tmp/whocord-test-secret")
os.environ.setdefault("WHOCORD_REQUIRE_KEYRING", "0")

import pytest


# ---------------------------------------------------------------------------
# Flask app client
# ---------------------------------------------------------------------------

@pytest.fixture
def app_client():
    """
    A Flask test client with TESTING=True.

    TESTING=True means uncaught exceptions propagate to the test rather
    than becoming a 500 response, which makes failures readable.
    """
    import web_app
    web_app.app.config["TESTING"] = True
    with web_app.app.test_client() as client:
        yield client


@pytest.fixture
def session_secret() -> str:
    """The shared secret web_app booted with."""
    import web_app
    return web_app._SESSION_SECRET


@pytest.fixture
def auth_headers(session_secret: str) -> dict:
    """Headers carrying a valid token, for protected-route tests."""
    return {"X-WhoCord-Token": session_secret}


# ---------------------------------------------------------------------------
# Registry isolation
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _disable_registry_disk_scan():
    """
    Mark the JobRegistry as already-scanned so tests never glob the real
    investigation_cache directory. Without this, /api/investigations
    returns whatever reports the developer happens to have on disk,
    making the tests non-deterministic across machines.
    """
    import web_app
    web_app.job_registry._scanned = True
    yield


@pytest.fixture
def clean_registry():
    """
    Yield the live JobRegistry with its state emptied, then restore it.

    Used by tests that need a predictable starting state for the job
    registry — e.g. a test that asserts /api/investigations returns an
    empty list on a fresh install.
    """
    import web_app
    reg = web_app.job_registry

    saved_jobs    = dict(reg._jobs)
    saved_cancel  = dict(reg._cancel_events)
    saved_workers = dict(reg._workers)
    saved_pivots  = dict(reg._pivot_responses)
    saved_scanned = reg._scanned

    reg._jobs.clear()
    reg._cancel_events.clear()
    reg._workers.clear()
    reg._pivot_responses.clear()
    reg._scanned = True

    yield reg

    reg._jobs = saved_jobs
    reg._cancel_events = saved_cancel
    reg._workers = saved_workers
    reg._pivot_responses = saved_pivots
    reg._scanned = saved_scanned