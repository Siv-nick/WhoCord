
"""
tests/test_html_report_escaping.py
----------------------------------
Regression tests for stored XSS in the generated HTML report.

Why this exists
---------------
The report is built by concatenating f-strings. Most interpolations go
through ``_e()``, but several did not, and the values they rendered are
supplied by the *target of the investigation*:

  * DNS record values come off the wire from the target's own
    nameserver. A TXT record is arbitrary text, so anyone who controls a
    domain could put markup in one.
  * SSL certificate fields and IP-geolocation responses are parsed into
    dicts whose *keys* are equally untrusted.
  * ``status_code`` is read out of a JSON blob and is not necessarily
    the integer it looks like.

The report is opened in an iframe and is also forwarded outside the app
as a standalone file, so markup landing in it is a real finding rather
than a theoretical one. The iframe sandbox is a second layer, not a
reason to leave the first one off.

These tests assert on the *rendered output*, not on the presence of an
``_e()`` call, so they keep working if the renderer is ever swapped for
a template engine.
"""

from __future__ import annotations

import json

import pytest

from discord_osint.intelligence import html_report


# A payload that is unambiguous in output: if the report contains the
# raw string, the escape did not happen. If it contains the entity-
# encoded form, it did.
_PAYLOAD = '<img src=x onerror="alert(1)">'
_RAW_MARKER = "<img src=x onerror="
_ESCAPED_MARKER = "&lt;img src=x onerror="


class _FakeCore:
    """Minimal stand-in for InvestigationCore."""

    def __init__(self, intel: dict) -> None:
        self.intel = intel
        self.target_id = "test-target"


def _render(intel: dict) -> str:
    """Render a full report and return the HTML."""
    base = {
        "discord": {},
        "social_profiles": {},
        "emails": {},
        "breaches": {},
        "identity_clues": {},
        "timeline": [],
        "confidence_scores": {},
    }
    base.update(intel)
    return html_report.generate_html_report(_FakeCore(base), "test-target")


def _intel_entry(value):
    """Wrap a value the way InvestigationCore.add_intel does."""
    return {
        "value": json.dumps(value) if not isinstance(value, str) else value,
        "confidence": "medium",
        "source": "test",
        "timestamp": "2026-01-01T00:00:00",
    }


class TestDnsRecordEscaping:
    """
    The original finding: DNS record values rendered unescaped, so a
    malicious TXT record executed inside the report.
    """

    def test_txt_record_value_is_escaped(self):
        html = _render({
            "dns": {"evil.example.com": _intel_entry({"TXT": [_PAYLOAD]})},
        })
        assert _RAW_MARKER not in html
        assert _ESCAPED_MARKER in html

    def test_record_type_key_is_escaped(self):
        # The dict key is attacker-controlled too.
        html = _render({
            "dns": {"evil.example.com": _intel_entry({_PAYLOAD: ["1.2.3.4"]})},
        })
        assert _RAW_MARKER not in html

    def test_non_list_record_value_does_not_crash(self):
        # Defensive: the renderer used to assume a list and would raise
        # on a bare string, losing the whole technical section.
        html = _render({
            "dns": {"example.com": _intel_entry({"A": "1.2.3.4"})},
        })
        assert "1.2.3.4" in html


class TestCertificateAndGeoEscaping:
    def test_ssl_field_key_is_escaped(self):
        html = _render({
            "ssl": {"example.com": _intel_entry({_PAYLOAD: "value"})},
        })
        assert _RAW_MARKER not in html

    def test_ssl_field_value_is_escaped(self):
        html = _render({
            "ssl": {"example.com": _intel_entry({"issuer": _PAYLOAD})},
        })
        assert _RAW_MARKER not in html

    def test_geo_field_key_is_escaped(self):
        html = _render({
            "dns": {"example.com_geo": _intel_entry({_PAYLOAD: "GB"})},
        })
        assert _RAW_MARKER not in html


class TestHrefAndImgGating:
    """
    ``_safe_href`` / ``_safe_img_src`` gate dangerous schemes. These
    guard the other half of the injection surface.
    """

    @pytest.mark.parametrize("bad", [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "  javascript:alert(1)",
        "java\tscript:alert(1)",
    ])
    def test_dangerous_hrefs_are_neutralised(self, bad):
        assert html_report._safe_href(bad) == "#"

    @pytest.mark.parametrize("bad", [
        "javascript:alert(1)",
        "data:image/svg+xml,<svg onload=alert(1)>",
        "not-a-url",
    ])
    def test_dangerous_img_srcs_are_dropped(self, bad):
        assert html_report._safe_img_src(bad) == ""

    def test_ordinary_https_url_survives(self):
        out = html_report._safe_href("https://example.com/a?b=1&c=2")
        assert out.startswith("https://example.com/a")
        # Escaped for attribute context, but not neutralised.
        assert "&amp;" in out


class TestNoRawPayloadAnywhere:
    """
    Belt-and-braces: push the payload through every category the report
    renders and assert it never appears raw. This is the test that
    catches a *newly added* unescaped interpolation, which the
    category-specific tests above would miss.
    """

    def test_payload_never_rendered_raw(self):
        intel = {
            "dns":        {"example.com": _intel_entry({"TXT": [_PAYLOAD]})},
            "ssl":        {"example.com": _intel_entry({"issuer": _PAYLOAD})},
            "whois":      {"example.com": _intel_entry({"registrar": _PAYLOAD})},
            "emails":     {_PAYLOAD: _intel_entry(_PAYLOAD)},
            "breaches":   {_PAYLOAD: _intel_entry({"used_on": [_PAYLOAD]})},
            "identity_clues": {"name": _intel_entry(_PAYLOAD)},
            "social_profiles": {
                "github/user": _intel_entry(_PAYLOAD),
            },
            "subdomains": {"example.com": _intel_entry([_PAYLOAD])},
            "url_intel":  {"page_meta": _intel_entry({"title": _PAYLOAD})},
        }
        html = _render(intel)
        assert _RAW_MARKER not in html, (
            "an unescaped interpolation rendered attacker-controlled "
            "markup into the report"
        )
