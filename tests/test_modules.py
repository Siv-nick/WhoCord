"""
tests/test_modules.py
----------------------
Unit tests for Phase 4 investigation modules.

Coverage focus for this revision
--------------------------------
- HIBP contract: the stage distinguishes ``None`` (check could not be
  performed: no key / auth failure / rate limit) from ``[]`` (not found
  in any breach) from a populated list. Previously all three were
  collapsed into "no breaches."
- URLAnalysisStage honours the pipeline cancel token at stage entry.
- Blackbird API fetch goes through the SSRF guard.
- Existing behaviours (email seeding, WHOIS/DNS/SSL, phone normalisation,
  image handling, builder wiring) preserved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Minimal stubs
# ---------------------------------------------------------------------------

class _FakeIntelCore:
    def __init__(self):
        self.intel: dict = {}

    def add_intel(self, category, key, value, source="test"):
        self.intel.setdefault(category, {})[key] = {"value": value, "source": source}

    def save_state(self):
        return "/tmp/fake.json"


@dataclass
class _FakeCtx:
    intel_core:       Any  = field(default_factory=_FakeIntelCore)
    avatar_urls:      set  = field(default_factory=set)
    discovery:        list = field(default_factory=list)
    all_urls:         list = field(default_factory=list)
    mode:             str  = "manual"
    module_mode:      str  = ""
    username:         str  = ""
    manual_email:     str  = ""
    manual_domain:    str  = ""
    manual_phone:     str  = ""
    manual_image_url: str  = ""
    manual_url:       str  = ""
    probe_string:     str  = ""
    depth:            int  = 0
    seed_type:        str  = ""
    seed_value:       str  = ""

    config: Any = field(default_factory=lambda: MagicMock(
        ENABLE_HOLEHE=True, ENABLE_H8MAIL=True, ENABLE_HIBP=True,
        ENABLE_EMAILREP=True, ENABLE_GHUNT=True, ENABLE_SCYLLA=False,
        ENABLE_BLACKBIRD=False, ENABLE_WHOIS=True, ENABLE_WAYBACK=False,
        ENABLE_REVERSE_IMG=False, ENABLE_THEHARVESTER=False,
        ENABLE_EMAIL_VERIFY=False, ENABLE_SOCID=False,
        GOOGLE_SAFE_BROWSING_KEY="",
        _cancel_event=None,
    ))

    def add_avatar(self, url):
        if url: self.avatar_urls.add(url)

    def add_discovery(self, site, url):
        if url: self.discovery.append({"site": site, "url": url})


_NOOP_EMIT = lambda *_: None


# ===========================================================================
# Data Probe
# ===========================================================================

class TestClassifyProbe:
    def test_http_is_url(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("https://example.com/path") == "url"

    def test_email_detected(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("alice@example.com") == "email"

    def test_email_with_plus_detected(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("alice+tag@example.org") == "email"

    def test_phone_with_plus(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("+1 555 000 0000") == "phone"

    def test_domain_detected(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("example.com") == "domain"

    def test_plain_username(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("johndoe") == "username"


# ===========================================================================
# EmailInvestigationStage — HIBP contract
# ===========================================================================

class TestEmailInvestigationHibp:
    """
    Three distinct HIBP outcomes must produce three distinct effects.
    The old code collapsed all of them into "no breaches."
    """

    def _run_with_hibp(self, hibp_return, enable_hibp=True):
        from discord_osint.pipeline.stages.email_investigation import (
            EmailInvestigationStage,
        )
        ctx = _FakeCtx(manual_email="alice@example.com")
        ctx.config.ENABLE_HIBP = enable_hibp

        emitted: list[tuple[str, dict]] = []
        emit = lambda t, p: emitted.append((t, p))

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe", return_value=[]):
            with patch("discord_osint.pipeline.stages.email_investigation.run_h8mail", return_value=None):
                with patch("discord_osint.pipeline.stages.email_investigation.check_hibp",
                           return_value=hibp_return):
                    with patch("discord_osint.pipeline.stages.email_investigation.check_emailrep", return_value={}):
                        with patch("discord_osint.pipeline.stages.email_investigation.run_ghunt", return_value=None):
                            with patch("discord_osint.pipeline.stages.email_investigation.run_scylla", return_value=None):
                                with patch("discord_osint.pipeline.stages.email_investigation.gravatar_lookup", return_value=None):
                                    EmailInvestigationStage().run(ctx, emit)

        return ctx, emitted

    def test_hibp_none_emits_skipped_finding(self):
        """None = check could not be performed."""
        ctx, emitted = self._run_with_hibp(hibp_return=None)

        findings = [p for t, p in emitted if t == "finding"]
        assert any(f["type"] == "hibp_skipped" for f in findings)
        # Must NOT be recorded as a breach (it wasn't checked).
        assert not any(f["type"] == "hibp" for f in findings)
        assert "hibp_alice@example.com" not in ctx.intel_core.intel.get("breaches", {})

    def test_hibp_empty_list_emits_zero_breach_finding(self):
        """[] = confirmed not in any breach."""
        ctx, emitted = self._run_with_hibp(hibp_return=[])

        findings = [p for t, p in emitted if t == "finding"]
        hibp_findings = [f for f in findings if f["type"] == "hibp"]
        assert len(hibp_findings) == 1
        assert hibp_findings[0]["breaches"] == 0
        # Nothing stored (nothing to store).
        assert "hibp_alice@example.com" not in ctx.intel_core.intel.get("breaches", {})

    def test_hibp_populated_list_emits_and_stores(self):
        breaches = [{"Name": "Adobe"}, {"Name": "LinkedIn"}]
        ctx, emitted = self._run_with_hibp(hibp_return=breaches)

        findings = [p for t, p in emitted if t == "finding"]
        hibp_findings = [f for f in findings if f["type"] == "hibp"]
        assert len(hibp_findings) == 1
        assert hibp_findings[0]["breaches"] == 2

        breaches_intel = ctx.intel_core.intel.get("breaches", {})
        assert "hibp_alice@example.com" in breaches_intel
        assert breaches_intel["hibp_alice@example.com"]["value"] == breaches

    def test_hibp_disabled_produces_no_findings(self):
        ctx, emitted = self._run_with_hibp(hibp_return=[{"Name": "x"}], enable_hibp=False)
        findings = [p for t, p in emitted if t == "finding"]
        assert not any(f["type"] in ("hibp", "hibp_skipped") for f in findings)


class TestEmailInvestigationBasics:
    def test_invalid_email_skips(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx = _FakeCtx(manual_email="not-an-email")

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe") as mock_h:
            EmailInvestigationStage().run(ctx, _NOOP_EMIT)
        mock_h.assert_not_called()

    def test_empty_email_skips(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx = _FakeCtx(manual_email="")
        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe") as mock_h:
            EmailInvestigationStage().run(ctx, _NOOP_EMIT)
        mock_h.assert_not_called()

    def test_holehe_results_stored(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx = _FakeCtx(manual_email="alice@example.com")
        sites = ["github.com", "spotify.com"]

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe", return_value=sites):
            with patch("discord_osint.pipeline.stages.email_investigation.run_h8mail", return_value=None):
                with patch("discord_osint.pipeline.stages.email_investigation.check_hibp", return_value=None):
                    with patch("discord_osint.pipeline.stages.email_investigation.check_emailrep", return_value={}):
                        with patch("discord_osint.pipeline.stages.email_investigation.run_ghunt", return_value=None):
                            with patch("discord_osint.pipeline.stages.email_investigation.run_scylla", return_value=None):
                                with patch("discord_osint.pipeline.stages.email_investigation.gravatar_lookup", return_value=None):
                                    EmailInvestigationStage().run(ctx, _NOOP_EMIT)

        assert "holehe_alice@example.com" in ctx.intel_core.intel.get("breaches", {})

    def test_gravatar_url_added_to_avatars(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx = _FakeCtx(manual_email="alice@example.com")
        grav_url = "https://www.gravatar.com/avatar/abc123"

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe", return_value=[]):
            with patch("discord_osint.pipeline.stages.email_investigation.run_h8mail", return_value=None):
                with patch("discord_osint.pipeline.stages.email_investigation.check_hibp", return_value=None):
                    with patch("discord_osint.pipeline.stages.email_investigation.check_emailrep", return_value={}):
                        with patch("discord_osint.pipeline.stages.email_investigation.run_ghunt", return_value=None):
                            with patch("discord_osint.pipeline.stages.email_investigation.run_scylla", return_value=None):
                                with patch("discord_osint.pipeline.stages.email_investigation.gravatar_lookup",
                                           return_value=grav_url):
                                    EmailInvestigationStage().run(ctx, _NOOP_EMIT)

        assert grav_url in ctx.avatar_urls


class TestBlackbirdSsrf:
    """Blackbird API fetch must route through the SSRF guard."""

    def test_blackbird_api_fetch_uses_safe_get(self):
        from discord_osint.pipeline.stages.email_investigation import (
            EmailInvestigationStage,
        )
        ctx = _FakeCtx(manual_email="alice@example.com")
        stage = EmailInvestigationStage()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.json.return_value = {"ok": True}

        with patch("discord_osint.pipeline.stages.email_investigation.safe_get",
                   return_value=mock_response) as mock_safe_get:
            stage._fetch_and_store_api_data(ctx, "https://example.com/api/x", _NOOP_EMIT)
            mock_safe_get.assert_called_once()

    def test_blackbird_api_fetch_blocks_unsafe_url(self):
        from discord_osint.pipeline.stages.email_investigation import (
            EmailInvestigationStage,
        )
        from discord_osint.utils.url_safety import UnsafeURLError

        ctx = _FakeCtx(manual_email="alice@example.com")
        stage = EmailInvestigationStage()

        with patch("discord_osint.pipeline.stages.email_investigation.safe_get",
                   side_effect=UnsafeURLError("blocked")):
            # Must not raise.
            stage._fetch_and_store_api_data(
                ctx, "http://169.254.169.254/latest/meta-data", _NOOP_EMIT,
            )


# ===========================================================================
# Domain investigation
# ===========================================================================

class TestDomainInvestigation:
    def test_clean_domain_strips_protocol(self):
        from discord_osint.pipeline.stages.domain_investigation import _clean_domain
        assert _clean_domain("https://example.com/path?q=1") == "example.com"

    def test_empty_domain_skips(self):
        from discord_osint.pipeline.stages.domain_investigation import DomainInvestigationStage
        ctx = _FakeCtx(manual_domain="")
        DomainInvestigationStage().run(ctx, _NOOP_EMIT)
        assert "target" not in ctx.intel_core.intel

    def test_domain_seeded_in_intel(self):
        from discord_osint.pipeline.stages.domain_investigation import DomainInvestigationStage
        ctx = _FakeCtx(manual_domain="example.com")

        with patch("discord_osint.pipeline.stages.domain_investigation.whois_domain", return_value="whois"):
            with patch("discord_osint.pipeline.stages.domain_investigation.wayback_available", return_value=None):
                with patch.object(DomainInvestigationStage, "_query_dns", return_value={"A": ["1.2.3.4"]}):
                    with patch.object(DomainInvestigationStage, "_resolve_ip", return_value="1.2.3.4"):
                        with patch.object(DomainInvestigationStage, "_geolocate_ip", return_value={}):
                            with patch.object(DomainInvestigationStage, "_get_ssl_info", return_value={}):
                                with patch.object(DomainInvestigationStage, "_enumerate_subdomains", return_value=[]):
                                    DomainInvestigationStage().run(ctx, _NOOP_EMIT)

        assert ctx.intel_core.intel["target"]["domain"]["value"] == "example.com"


# ===========================================================================
# Phone investigation
# ===========================================================================

class TestPhoneInvestigation:
    def test_normalise_strips_formatting(self):
        from discord_osint.pipeline.stages.phone_investigation import _normalise_phone
        assert _normalise_phone("+1 (555) 000-0000") == "+15550000000"

    def test_empty_phone_skips(self):
        from discord_osint.pipeline.stages.phone_investigation import PhoneInvestigationStage
        ctx = _FakeCtx(manual_phone="")
        PhoneInvestigationStage().run(ctx, _NOOP_EMIT)
        assert "phone" not in ctx.intel_core.intel

    def test_phone_seeded(self):
        from discord_osint.pipeline.stages.phone_investigation import PhoneInvestigationStage
        ctx = _FakeCtx(manual_phone="+15550000000")

        with patch.object(PhoneInvestigationStage, "_validate_phonenumbers", return_value={}):
            with patch.object(PhoneInvestigationStage, "_carrier_lookup", return_value={}):
                with patch.object(PhoneInvestigationStage, "_run_phoneinfoga"):
                    PhoneInvestigationStage().run(ctx, _NOOP_EMIT)

        assert "number" in ctx.intel_core.intel.get("phone", {})


# ===========================================================================
# URL analysis — cancellation short-circuit
# ===========================================================================

class TestUrlAnalysis:
    def test_empty_url_skips(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx = _FakeCtx(manual_url="")
        URLAnalysisStage().run(ctx, _NOOP_EMIT)
        assert "target" not in ctx.intel_core.intel

    def test_cancellation_short_circuits_before_network(self):
        """Cancel token is set at stage entry → no fetch attempted."""
        import threading
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage

        cancel = threading.Event()
        cancel.set()

        ctx = _FakeCtx(manual_url="https://example.com")
        ctx.config._cancel_event = cancel

        with patch.object(URLAnalysisStage, "_fetch_url") as mock_fetch:
            URLAnalysisStage().run(ctx, _NOOP_EMIT)
            mock_fetch.assert_not_called()

    def test_http_metadata_stored(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx = _FakeCtx(manual_url="https://example.com")
        meta = {"status_code": 200, "final_url": "https://example.com",
                "redirect_count": 0, "content_type": "text/html"}

        with patch.object(URLAnalysisStage, "_fetch_url",
                          return_value=(meta, "", "https://example.com")):
            with patch("discord_osint.pipeline.stages.url_analysis.wayback_available", return_value=None):
                URLAnalysisStage().run(ctx, _NOOP_EMIT)

        assert "http_meta" in ctx.intel_core.intel.get("url_intel", {})


# ===========================================================================
# Image analysis
# ===========================================================================

class TestImageAnalysis:
    def test_non_http_url_skips(self):
        from discord_osint.pipeline.stages.image_analysis import ImageAnalysisStage
        ctx = _FakeCtx(manual_image_url="ftp://example.com/img.png")
        ImageAnalysisStage().run(ctx, _NOOP_EMIT)
        assert "target" not in ctx.intel_core.intel

    def test_image_url_added_to_avatars(self):
        from discord_osint.pipeline.stages.image_analysis import ImageAnalysisStage
        url = "https://example.com/avatar.png"
        ctx = _FakeCtx(manual_image_url=url)

        with patch("discord_osint.pipeline.stages.image_analysis.download_avatar", return_value=None):
            ImageAnalysisStage().run(ctx, _NOOP_EMIT)

        assert url in ctx.avatar_urls


# ===========================================================================
# Builder
# ===========================================================================

class TestBuildModulePipeline:
    def _names(self, p):
        return [s.name for s in p.stages]

    def test_email_pipeline_has_email_stage(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="alice@b.com",
            target_id=1, manual_email="alice@b.com", module_mode="email",
            intel_core=_FakeIntelCore(),
        )
        assert "email_investigation" in self._names(build_module_pipeline("email", ctx))

    def test_probe_pipeline_has_probe_and_intelligence(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="x",
            target_id=3, probe_string="test", module_mode="probe",
            intel_core=_FakeIntelCore(),
        )
        names = self._names(build_module_pipeline("probe", ctx))
        assert "data_probe" in names
        assert "intelligence" in names

    def test_invalid_mode_raises(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="x",
            target_id=9, intel_core=_FakeIntelCore(),
        )
        with pytest.raises(ValueError, match="Unknown module_mode"):
            build_module_pipeline("nope", ctx)