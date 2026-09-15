
"""
tests/test_ssrf_routing.py
--------------------------
Integration invariant: no module outside a small, documented allowlist
constructs a bare requests.Session or calls requests.get / requests.post
directly.

Why this exists
---------------
The SSRF module's own unit tests (test_ssrf_pinning.py) verify that
validate_url and safe_get_pinned reject bad targets. They do NOT verify
that the rest of the codebase routes through them — the gap the code
review flagged when it found bare requests.get in _try_phash and an
unvalidated ssl.get_server_certificate call in _get_ssl_info.

This test closes that gap by grepping the source tree. Any new module
that makes an outbound HTTP call must either:

  * route through ``utils.url_safety.safe_get_pinned`` (attacker-
    influenced URLs), or
  * use the shared ``http_session`` from ``utils`` (fixed hosts), or
  * be added to ``_ALLOWED_FILES`` below with a one-line reason.

Anything else fails CI.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent

_SCAN_TARGETS = (
    "discord_osint",
    "web_services",
    "web_app.py",
)

# Modules permitted to construct a bare requests.Session or issue a
# bare requests.* call. Each entry MUST have a reason. If you add an
# entry, you are asserting that the module's HTTP targets are not
# attacker-influenced.
_ALLOWED_FILES: dict[str, str] = {
    "discord_osint/utils/url_safety.py":
        "SSRF guard itself; constructs requests.Session internally and "
        "is the module every other file routes through.",
    "discord_osint/utils/__init__.py":
        "Shared requests.Session factory; the http_session singleton "
        "is used across the codebase for fixed-host calls.",
    "discord_osint/intelligence/narrative.py":
        "POSTs to a fixed LLM provider endpoint resolved via "
        "config_service.get_llm_endpoint(). Host is not attacker-"
        "influenced; payload is the investigation dump.",
    "web_services/llm_models.py":
        "GETs the model list from a fixed provider endpoint (Groq / "
        "OpenRouter / local Ollama). Host is hardcoded.",
    "web_app.py":
        "Chat streaming needs raw requests for iter_lines() over an "
        "SSE response; the shared session's retry adapter is "
        "incompatible with long-lived streaming. Host is fixed by "
        "config_service.get_llm_endpoint().",
}

# Aliases that appear in the codebase. If you write `import requests as
# foo`, add foo here so the scanner catches it.
_REQUESTS_ALIASES = ("requests", "_req", "req")

_BARE_METHOD_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(a) for a in _REQUESTS_ALIASES) + r")"
    r"\.(get|post|put|delete|patch|head|request)\s*\(",
)
_SESSION_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(a) for a in _REQUESTS_ALIASES) + r")"
    r"\.Session\s*\(",
)

# ``requests`` is not the only way out of the process. ``urlopen`` and
# ``urlretrieve`` bypassed this check entirely until now, which is how
# wmn_scanner and username_search kept making unguarded fetches while
# the suite stayed green.
_URLLIB_RE = re.compile(
    r"\burllib\.request\.(urlopen|urlretrieve)\s*\(|"
    r"\b(urlopen|urlretrieve)\s*\(",
)


def _iter_python_files():
    for entry in _SCAN_TARGETS:
        path = _REPO_ROOT / entry
        if path.is_file() and path.suffix == ".py":
            yield path
            continue
        if path.is_dir():
            for py in path.rglob("*.py"):
                if "__pycache__" in py.parts:
                    continue
                yield py


def _non_code_lines(text: str) -> set[int]:
    """
    Return the set of line numbers that are comments or string
    literals, and therefore cannot be a real call.

    The previous implementation tested ``line.lstrip().startswith``
    against ``#``, ``\"\"\"`` and ``'''``. That only recognises the
    *opening* line of a docstring, so every subsequent line of a module
    docstring was scanned as if it were code — and any docstring that
    described the rule (``"...routes through requests.get..."``) failed
    the test it was documenting. A security test that cries wolf gets
    muted, so this tokenises instead of guessing.
    """
    skip: set[int] = set()

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # Unparseable file — fall back to scanning everything rather
        # than silently skipping it.
        return skip

    for tok in tokens:
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            start_line = tok.start[0]
            end_line = tok.end[0]
            skip.update(range(start_line, end_line + 1))

    return skip


def _scan() -> list[tuple[str, int, str, str]]:
    """
    Return a list of (relpath, lineno, snippet, kind) for every
    violation. Empty when the codebase passes.
    """
    out: list[tuple[str, int, str, str]] = []
    for path in _iter_python_files():
        rel = path.relative_to(_REPO_ROOT).as_posix()
        if rel in _ALLOWED_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue

        skip = _non_code_lines(text)

        for lineno, line in enumerate(text.splitlines(), start=1):
            if lineno in skip:
                continue
            stripped = line.strip()
            if _BARE_METHOD_RE.search(line):
                out.append((rel, lineno, stripped, "bare requests.* call"))
            if _SESSION_RE.search(line):
                out.append((rel, lineno, stripped, "bare requests.Session()"))
            if _URLLIB_RE.search(line):
                out.append((rel, lineno, stripped, "bare urllib.request fetch"))
    return out


def test_no_bare_requests_calls_outside_allowlist():
    violations = _scan()
    if not violations:
        return

    details = "\n".join(
        f"  {rel}:{lineno}  [{kind}]\n    {snippet}"
        for rel, lineno, snippet, kind in violations
    )
    pytest.fail(
        "Found direct requests.* calls outside the SSRF guard "
        "allowlist.\n\n"
        "Fix:\n"
        "  * If the URL is attacker-influenced, route the call through\n"
        "    discord_osint.utils.url_safety.safe_get_pinned.\n"
        "  * If the host is fixed and hardcoded, use the shared\n"
        "    http_session from discord_osint.utils.\n"
        "  * If the module genuinely needs a bare call (e.g. streaming\n"
        "    an SSE response), add it to _ALLOWED_FILES in this test\n"
        "    with a one-line reason.\n\n"
        "Violations:\n" + details
    )


def test_allowlist_entries_still_exist():
    """
    Keep the allowlist honest: an entry for a file that no longer
    exists (or has been renamed) is stale and should be removed.
    """
    missing = [
        rel for rel in _ALLOWED_FILES
        if not (_REPO_ROOT / rel).exists()
    ]
    assert not missing, (
        "Stale entries in _ALLOWED_FILES — these files no longer "
        "exist:\n" + "\n".join(f"  {rel}" for rel in missing)
    )


def test_allowlist_entries_have_reasons():
    """
    Every allowlist entry must explain why it is exempt. An entry
    without a reason is a silent permission that future readers cannot
    audit.
    """
    for rel, reason in _ALLOWED_FILES.items():
        assert reason and len(reason.strip()) >= 20, (
            f"Allowlist entry {rel!r} has no meaningful reason. "
            f"Add one sentence explaining why the module's HTTP "
            f"targets are not attacker-influenced."
        )
