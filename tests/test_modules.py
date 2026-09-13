"""
tests/test_modules.py
----------------------
Unit tests for Phase 4 investigation modules.

Coverage
--------
- DataProbeStage.classify_probe() – all classification branches
- EmailInvestigationStage – email seeding, tool calls, Blackbird delegation
- DomainInvestigationStage – WHOIS, DNS, IP resolution, SSL, subdomain helpers
- PhoneInvestigationStage  – normalisation, phonenumbers fallback
- ImageAnalysisStage       – download failure, pHash, OCR stubs
- URLAnalysisStage         – HTTP fetch, page meta, Safe Browsing opt-out
- builder.build_module_pipeline() – correct stage types returned per mode
- pipeline.__init__.run_module_pipeline() – correct target field resolved
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch, call

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
    intel_core:     Any  = field(default_factory=_FakeIntelCore)
    avatar_urls:    set  = field(default_factory=set)
    discovery:      list = field(default_factory=list)
    all_urls:       list = field(default_factory=list)
    mode:           str  = "manual"
    module_mode:    str  = ""
    username:       str  = ""
    manual_email:   str  = ""
    manual_domain:  str  = ""
    manual_phone:   str  = ""
    manual_image_url: str = ""
    manual_url:     str  = ""
    probe_string:   str  = ""
    depth:          int  = 0
    seed_type:      str  = ""
    seed_value:     str  = ""

    # Mock config with all feature flags on
    config: Any = field(default_factory=lambda: MagicMock(
        ENABLE_HOLEHE=True, ENABLE_H8MAIL=True, ENABLE_HIBP=True,
        ENABLE_EMAILREP=True, ENABLE_GHUNT=True, ENABLE_SCYLLA=True,
        ENABLE_BLACKBIRD=True, ENABLE_WHOIS=True, ENABLE_WAYBACK=True,
        ENABLE_REVERSE_IMG=True, ENABLE_THEHARVESTER=False,
        ENABLE_EMAIL_VERIFY=False,
    ))

    def add_avatar(self, url):
        if url: self.avatar_urls.add(url)

    def add_discovery(self, site, url):
        if url: self.discovery.append({"site": site, "url": url})


_NOOP_EMIT = lambda *_: None


# ===========================================================================
# Data Probe – classify_probe()
# ===========================================================================

class TestClassifyProbe:
    from discord_osint.pipeline.stages.data_probe import classify_probe

    def test_http_is_url(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("https://example.com/path") == "url"

    def test_http_no_s_is_url(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("http://example.com") == "url"

    def test_email_detected(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("alice@example.com") == "email"

    def test_email_with_plus_detected(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("alice+tag@example.org") == "email"

    def test_phone_with_plus(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("+1 555 000 0000") == "phone"

    def test_phone_digits_only(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("15550000000") == "phone"

    def test_domain_detected(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("example.com") == "domain"

    def test_subdomain_detected(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("api.example.co.uk") == "domain"

    def test_plain_username(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("johndoe") == "username"

    def test_username_with_numbers(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("user1234") == "username"

    def test_url_takes_priority_over_domain(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("https://github.com") == "url"

    def test_whitespace_stripped(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        assert classify_probe("  alice@example.com  ") == "email"

    def test_empty_string_is_username(self):
        from discord_osint.pipeline.stages.data_probe import classify_probe
        # Empty → no specific match → username fallback
        result = classify_probe("")
        assert result in ("username", "probe")


# ===========================================================================
# DataProbeStage – routing
# ===========================================================================

class TestDataProbeStageRouting:
    def test_routes_email_to_email_stage(self):
        from discord_osint.pipeline.stages.data_probe import DataProbeStage
        ctx           = _FakeCtx(probe_string="alice@example.com")
        calls:list    = []

        with patch(
            "discord_osint.pipeline.stages.data_probe.DataProbeStage._run_email",
            side_effect=lambda c, v, e: calls.append(("email", v)),
        ):
            DataProbeStage().run(ctx, _NOOP_EMIT)

        assert len(calls) == 1
        assert calls[0] == ("email", "alice@example.com")

    def test_routes_domain_to_domain_stage(self):
        from discord_osint.pipeline.stages.data_probe import DataProbeStage
        ctx        = _FakeCtx(probe_string="example.com")
        calls:list = []

        with patch(
            "discord_osint.pipeline.stages.data_probe.DataProbeStage._run_domain",
            side_effect=lambda c, v, e: calls.append(("domain", v)),
        ):
            DataProbeStage().run(ctx, _NOOP_EMIT)

        assert len(calls) == 1

    def test_stores_detected_type_in_intel(self):
        from discord_osint.pipeline.stages.data_probe import DataProbeStage
        ctx = _FakeCtx(probe_string="https://example.com")

        with patch("discord_osint.pipeline.stages.data_probe.DataProbeStage._run_url"):
            DataProbeStage().run(ctx, _NOOP_EMIT)

        probe_intel = ctx.intel_core.intel.get("probe", {})
        assert "type" in probe_intel
        assert probe_intel["type"]["value"] == "url"

    def test_empty_probe_string_exits_early(self):
        from discord_osint.pipeline.stages.data_probe import DataProbeStage
        ctx = _FakeCtx(probe_string="")

        with patch("discord_osint.pipeline.stages.data_probe.DataProbeStage._run_email") as mock_e:
            DataProbeStage().run(ctx, _NOOP_EMIT)

        mock_e.assert_not_called()


# ===========================================================================
# EmailInvestigationStage
# ===========================================================================

class TestEmailInvestigationStage:
    def test_seeds_email_in_intel(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx = _FakeCtx(manual_email="alice@example.com")

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe", return_value=[]):
            with patch("discord_osint.pipeline.stages.email_investigation.run_h8mail", return_value=None):
                with patch("discord_osint.pipeline.stages.email_investigation.check_hibp", return_value=[]):
                    with patch("discord_osint.pipeline.stages.email_investigation.check_emailrep", return_value={}):
                        with patch("discord_osint.pipeline.stages.email_investigation.run_ghunt", return_value=None):
                            with patch("discord_osint.pipeline.stages.email_investigation.run_scylla", return_value=None):
                                with patch("discord_osint.pipeline.stages.email_investigation.gravatar_lookup", return_value=None):
                                    EmailInvestigationStage().run(ctx, _NOOP_EMIT)

        assert "alice@example.com" in ctx.intel_core.intel.get("emails", {})

    def test_holehe_results_stored(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx     = _FakeCtx(manual_email="alice@example.com")
        sites   = ["github.com", "spotify.com"]

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe", return_value=sites):
            with patch("discord_osint.pipeline.stages.email_investigation.run_h8mail", return_value=None):
                with patch("discord_osint.pipeline.stages.email_investigation.check_hibp", return_value=[]):
                    with patch("discord_osint.pipeline.stages.email_investigation.check_emailrep", return_value={}):
                        with patch("discord_osint.pipeline.stages.email_investigation.run_ghunt", return_value=None):
                            with patch("discord_osint.pipeline.stages.email_investigation.run_scylla", return_value=None):
                                with patch("discord_osint.pipeline.stages.email_investigation.gravatar_lookup", return_value=None):
                                    EmailInvestigationStage().run(ctx, _NOOP_EMIT)

        breaches = ctx.intel_core.intel.get("breaches", {})
        assert any("holehe" in k for k in breaches)

    def test_gravatar_url_added_to_avatars(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx      = _FakeCtx(manual_email="alice@example.com")
        grav_url = "https://www.gravatar.com/avatar/abc123"

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe", return_value=[]):
            with patch("discord_osint.pipeline.stages.email_investigation.run_h8mail", return_value=None):
                with patch("discord_osint.pipeline.stages.email_investigation.check_hibp", return_value=[]):
                    with patch("discord_osint.pipeline.stages.email_investigation.check_emailrep", return_value={}):
                        with patch("discord_osint.pipeline.stages.email_investigation.run_ghunt", return_value=None):
                            with patch("discord_osint.pipeline.stages.email_investigation.run_scylla", return_value=None):
                                with patch("discord_osint.pipeline.stages.email_investigation.gravatar_lookup",
                                           return_value=grav_url):
                                    EmailInvestigationStage().run(ctx, _NOOP_EMIT)

        assert grav_url in ctx.avatar_urls

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

    def test_hibp_results_emit_finding(self):
        from discord_osint.pipeline.stages.email_investigation import EmailInvestigationStage
        ctx     = _FakeCtx(manual_email="alice@example.com")
        emitted = []

        fake_hibp = [{"Name": "AdobeData"}, {"Name": "LinkedIn"}]

        with patch("discord_osint.pipeline.stages.email_investigation.run_holehe", return_value=[]):
            with patch("discord_osint.pipeline.stages.email_investigation.run_h8mail", return_value=None):
                with patch("discord_osint.pipeline.stages.email_investigation.check_hibp", return_value=fake_hibp):
                    with patch("discord_osint.pipeline.stages.email_investigation.check_emailrep", return_value={}):
                        with patch("discord_osint.pipeline.stages.email_investigation.run_ghunt", return_value=None):
                            with patch("discord_osint.pipeline.stages.email_investigation.run_scylla", return_value=None):
                                with patch("discord_osint.pipeline.stages.email_investigation.gravatar_lookup", return_value=None):
                                    EmailInvestigationStage().run(
                                        ctx,
                                        lambda t, p: emitted.append((t, p)),
                                    )

        finding_types = [p["type"] for t, p in emitted if t == "finding"]
        assert "hibp" in finding_types


# ===========================================================================
# DomainInvestigationStage helpers
# ===========================================================================

class TestDomainInvestigationHelpers:
    def test_clean_domain_strips_protocol(self):
        from discord_osint.pipeline.stages.domain_investigation import _clean_domain
        assert _clean_domain("https://example.com/path?q=1") == "example.com"

    def test_clean_domain_lowercase(self):
        from discord_osint.pipeline.stages.domain_investigation import _clean_domain
        assert _clean_domain("EXAMPLE.COM") == "example.com"

    def test_clean_domain_no_change(self):
        from discord_osint.pipeline.stages.domain_investigation import _clean_domain
        assert _clean_domain("sub.example.co.uk") == "sub.example.co.uk"

    def test_empty_domain_skips(self):
        from discord_osint.pipeline.stages.domain_investigation import DomainInvestigationStage
        ctx = _FakeCtx(manual_domain="")
        DomainInvestigationStage().run(ctx, _NOOP_EMIT)
        # No intel should be written
        assert "target" not in ctx.intel_core.intel

    def test_domain_seeded_in_intel(self):
        from discord_osint.pipeline.stages.domain_investigation import DomainInvestigationStage
        ctx = _FakeCtx(manual_domain="example.com")

        with patch("discord_osint.pipeline.stages.domain_investigation.whois_domain", return_value="whois data"):
            with patch("discord_osint.pipeline.stages.domain_investigation.wayback_available", return_value=None):
                with patch.object(DomainInvestigationStage, "_query_dns",        return_value={"A": ["1.2.3.4"]}):
                    with patch.object(DomainInvestigationStage, "_resolve_ip",   return_value="1.2.3.4"):
                        with patch.object(DomainInvestigationStage, "_geolocate_ip", return_value={}):
                            with patch.object(DomainInvestigationStage, "_get_ssl_info", return_value={}):
                                with patch.object(DomainInvestigationStage, "_enumerate_subdomains", return_value=[]):
                                    DomainInvestigationStage().run(ctx, _NOOP_EMIT)

        assert ctx.intel_core.intel.get("target", {}).get("domain", {}).get("value") == "example.com"

    def test_whois_result_stored(self):
        from discord_osint.pipeline.stages.domain_investigation import DomainInvestigationStage
        ctx = _FakeCtx(manual_domain="example.com")

        with patch("discord_osint.pipeline.stages.domain_investigation.whois_domain", return_value="WHOIS OUTPUT"):
            with patch("discord_osint.pipeline.stages.domain_investigation.wayback_available", return_value=None):
                with patch.object(DomainInvestigationStage, "_query_dns",           return_value={}):
                    with patch.object(DomainInvestigationStage, "_resolve_ip",      return_value=""):
                        with patch.object(DomainInvestigationStage, "_geolocate_ip", return_value={}):
                            with patch.object(DomainInvestigationStage, "_get_ssl_info", return_value={}):
                                with patch.object(DomainInvestigationStage, "_enumerate_subdomains", return_value=[]):
                                    DomainInvestigationStage().run(ctx, _NOOP_EMIT)

        whois_intel = ctx.intel_core.intel.get("whois", {})
        assert "example.com" in whois_intel

    def test_subdomains_stored(self):
        from discord_osint.pipeline.stages.domain_investigation import DomainInvestigationStage
        ctx = _FakeCtx(manual_domain="example.com")
        subs = ["www.example.com", "mail.example.com"]

        with patch("discord_osint.pipeline.stages.domain_investigation.whois_domain", return_value=None):
            with patch("discord_osint.pipeline.stages.domain_investigation.wayback_available", return_value=None):
                with patch.object(DomainInvestigationStage, "_query_dns",           return_value={}):
                    with patch.object(DomainInvestigationStage, "_resolve_ip",      return_value=""):
                        with patch.object(DomainInvestigationStage, "_geolocate_ip", return_value={}):
                            with patch.object(DomainInvestigationStage, "_get_ssl_info", return_value={}):
                                with patch.object(DomainInvestigationStage, "_enumerate_subdomains",
                                                  return_value=subs):
                                    DomainInvestigationStage().run(ctx, _NOOP_EMIT)

        sub_intel = ctx.intel_core.intel.get("subdomains", {})
        assert "example.com" in sub_intel


# ===========================================================================
# PhoneInvestigationStage
# ===========================================================================

class TestPhoneInvestigationStage:
    def test_normalise_strips_formatting(self):
        from discord_osint.pipeline.stages.phone_investigation import _normalise_phone
        assert _normalise_phone("+1 (555) 000-0000") == "+15550000000"

    def test_empty_phone_skips(self):
        from discord_osint.pipeline.stages.phone_investigation import PhoneInvestigationStage
        ctx = _FakeCtx(manual_phone="")
        PhoneInvestigationStage().run(ctx, _NOOP_EMIT)
        assert "phone" not in ctx.intel_core.intel

    def test_phone_seeded_in_intel(self):
        from discord_osint.pipeline.stages.phone_investigation import PhoneInvestigationStage
        ctx = _FakeCtx(manual_phone="+15550000000")

        with patch.object(PhoneInvestigationStage, "_validate_phonenumbers", return_value={}):
            with patch.object(PhoneInvestigationStage, "_carrier_lookup",    return_value={}):
                with patch.object(PhoneInvestigationStage, "_run_phoneinfoga"):
                    PhoneInvestigationStage().run(ctx, _NOOP_EMIT)

        assert "number" in ctx.intel_core.intel.get("phone", {})

    def test_phonenumbers_data_stored(self):
        from discord_osint.pipeline.stages.phone_investigation import PhoneInvestigationStage
        ctx  = _FakeCtx(manual_phone="+15550000000")
        meta = {"is_valid": True, "country": "United States", "carrier": "AT&T",
                "number_type": "mobile", "e164": "+15550000000"}

        with patch.object(PhoneInvestigationStage, "_validate_phonenumbers", return_value=meta):
            with patch.object(PhoneInvestigationStage, "_carrier_lookup",    return_value={}):
                with patch.object(PhoneInvestigationStage, "_run_phoneinfoga"):
                    PhoneInvestigationStage().run(ctx, _NOOP_EMIT)

        phone_intel = ctx.intel_core.intel.get("phone", {})
        assert "is_valid" in phone_intel


# ===========================================================================
# ImageAnalysisStage
# ===========================================================================

class TestImageAnalysisStage:
    def test_empty_url_skips(self):
        from discord_osint.pipeline.stages.image_analysis import ImageAnalysisStage
        ctx = _FakeCtx(manual_image_url="")
        ImageAnalysisStage().run(ctx, _NOOP_EMIT)
        assert "target" not in ctx.intel_core.intel

    def test_non_http_url_skips(self):
        from discord_osint.pipeline.stages.image_analysis import ImageAnalysisStage
        ctx = _FakeCtx(manual_image_url="ftp://example.com/img.png")
        ImageAnalysisStage().run(ctx, _NOOP_EMIT)
        assert "target" not in ctx.intel_core.intel

    def test_download_failure_exits_gracefully(self):
        from discord_osint.pipeline.stages.image_analysis import ImageAnalysisStage
        ctx = _FakeCtx(manual_image_url="https://example.com/img.png")

        with patch("discord_osint.pipeline.stages.image_analysis.download_avatar", return_value=None):
            ImageAnalysisStage().run(ctx, _NOOP_EMIT)

        # Should seed the URL but produce no media intel
        assert "target" in ctx.intel_core.intel
        assert not ctx.intel_core.intel.get("media", {})

    def test_exif_gps_stored(self):
        from discord_osint.pipeline.stages.image_analysis import ImageAnalysisStage
        ctx = _FakeCtx(manual_image_url="https://example.com/img.png")

        with patch("discord_osint.pipeline.stages.image_analysis.download_avatar", return_value="/tmp/img.png"):
            with patch("discord_osint.pipeline.stages.image_analysis.extract_metadata",
                       return_value={"gps": (51.509865, -0.118092), "date_taken": "2024-01-01", "camera": "Canon"}):
                with patch("discord_osint.pipeline.stages.image_analysis.reverse_image_search", return_value=[]):
                    with patch.object(ImageAnalysisStage, "_compute_phash",   return_value="abc123"):
                        with patch.object(ImageAnalysisStage, "_run_ocr",      return_value=""):
                            with patch.object(ImageAnalysisStage, "_get_image_info", return_value={}):
                                ImageAnalysisStage().run(ctx, _NOOP_EMIT)

        media_intel = ctx.intel_core.intel.get("media", {})
        assert any("exif_gps" in k for k in media_intel)

    def test_image_url_added_to_avatars(self):
        from discord_osint.pipeline.stages.image_analysis import ImageAnalysisStage
        url = "https://example.com/avatar.png"
        ctx = _FakeCtx(manual_image_url=url)

        with patch("discord_osint.pipeline.stages.image_analysis.download_avatar", return_value=None):
            ImageAnalysisStage().run(ctx, _NOOP_EMIT)

        assert url in ctx.avatar_urls


# ===========================================================================
# URLAnalysisStage
# ===========================================================================

class TestURLAnalysisStage:
    def test_empty_url_skips(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx = _FakeCtx(manual_url="")
        URLAnalysisStage().run(ctx, _NOOP_EMIT)
        assert "target" not in ctx.intel_core.intel

    def test_non_http_skips(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx = _FakeCtx(manual_url="ftp://example.com")
        URLAnalysisStage().run(ctx, _NOOP_EMIT)
        assert "target" not in ctx.intel_core.intel

    def test_url_seeded(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx = _FakeCtx(manual_url="https://example.com")

        with patch.object(URLAnalysisStage, "_fetch_url",
                          return_value=({"status_code": 200, "final_url": "https://example.com",
                                         "redirect_count": 0}, "", "https://example.com")):
            with patch("discord_osint.pipeline.stages.url_analysis.wayback_available", return_value=None):
                URLAnalysisStage().run(ctx, _NOOP_EMIT)

        assert ctx.intel_core.intel.get("target", {}).get("url", {}).get("value") == "https://example.com"

    def test_http_metadata_stored(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx  = _FakeCtx(manual_url="https://example.com")
        meta = {"status_code": 200, "final_url": "https://example.com",
                "redirect_count": 0, "content_type": "text/html", "server": "nginx"}

        with patch.object(URLAnalysisStage, "_fetch_url", return_value=(meta, "", "https://example.com")):
            with patch("discord_osint.pipeline.stages.url_analysis.wayback_available", return_value=None):
                URLAnalysisStage().run(ctx, _NOOP_EMIT)

        url_intel = ctx.intel_core.intel.get("url_intel", {})
        assert "http_meta" in url_intel

    def test_emails_extracted_from_page(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx  = _FakeCtx(manual_url="https://example.com")
        html = "<html><body>Contact us at hello@example.com and support@example.org</body></html>"
        meta = {"status_code": 200, "final_url": "https://example.com", "redirect_count": 0,
                "content_type": "text/html"}

        with patch.object(URLAnalysisStage, "_fetch_url", return_value=(meta, html, "https://example.com")):
            with patch.object(URLAnalysisStage, "_parse_page_meta",
                              return_value={"title": "Test", "description": "", "og": {}, "canonical": ""}):
                with patch("discord_osint.pipeline.stages.url_analysis.wayback_available", return_value=None):
                    URLAnalysisStage().run(ctx, _NOOP_EMIT)

        emails_intel = ctx.intel_core.intel.get("emails", {})
        assert "hello@example.com" in emails_intel or "support@example.org" in emails_intel

    def test_safe_browsing_not_called_without_key(self):
        from discord_osint.pipeline.stages.url_analysis import URLAnalysisStage
        ctx = _FakeCtx(manual_url="https://example.com")
        ctx.config.GOOGLE_SAFE_BROWSING_KEY = ""  # No key

        with patch.object(URLAnalysisStage, "_fetch_url", return_value=({}, "", "")):
            with patch.object(URLAnalysisStage, "_check_safe_browsing") as mock_gsb:
                with patch("discord_osint.pipeline.stages.url_analysis.wayback_available", return_value=None):
                    URLAnalysisStage().run(ctx, _NOOP_EMIT)

        mock_gsb.assert_not_called()


# ===========================================================================
# builder.build_module_pipeline()
# ===========================================================================

class TestBuildModulePipeline:
    def _get_stage_names(self, pipeline) -> list[str]:
        return [s.name for s in pipeline.stages]

    def test_email_pipeline_has_email_stage(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="alice@b.com",
            target_id=1, manual_email="alice@b.com", module_mode="email",
            intel_core=_FakeIntelCore(),
        )
        pipeline = build_module_pipeline("email", ctx)
        names    = self._get_stage_names(pipeline)
        assert "email_investigation" in names
        assert "reporting" in names

    def test_domain_pipeline_has_domain_stage(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="example.com",
            target_id=2, manual_domain="example.com", module_mode="domain",
            intel_core=_FakeIntelCore(),
        )
        pipeline = build_module_pipeline("domain", ctx)
        assert "domain_investigation" in self._get_stage_names(pipeline)

    def test_probe_pipeline_has_probe_and_intelligence(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="probe_input",
            target_id=3, probe_string="test", module_mode="probe",
            intel_core=_FakeIntelCore(),
        )
        pipeline = build_module_pipeline("probe", ctx)
        names    = self._get_stage_names(pipeline)
        assert "data_probe"   in names
        assert "intelligence" in names

    def test_invalid_mode_raises_value_error(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="x",
            target_id=9, intel_core=_FakeIntelCore(),
        )
        with pytest.raises(ValueError, match="Unknown module_mode"):
            build_module_pipeline("invalid_mode", ctx)

    def test_module_mode_set_on_ctx(self):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="test",
            target_id=4, manual_phone="+15550000000",
            intel_core=_FakeIntelCore(),
        )
        build_module_pipeline("phone", ctx)
        assert ctx.module_mode == "phone"

    @pytest.mark.parametrize("mode", ["email", "domain", "phone", "image", "url", "probe"])
    def test_all_module_modes_produce_reporting_stage(self, mode):
        from discord_osint.pipeline.builder import build_module_pipeline
        from discord_osint.pipeline.context import InvestigationContext

        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="target",
            target_id=5, intel_core=_FakeIntelCore(),
        )
        pipeline = build_module_pipeline(mode, ctx)
        assert "reporting" in self._get_stage_names(pipeline)


# ===========================================================================
# context.effective_target
# ===========================================================================

class TestContextEffectiveTarget:
    def test_email_mode(self):
        from discord_osint.pipeline.context import InvestigationContext
        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="",
            target_id=1, manual_email="alice@example.com",
            module_mode="email", intel_core=_FakeIntelCore(),
        )
        assert ctx.effective_target == "alice@example.com"

    def test_domain_mode(self):
        from discord_osint.pipeline.context import InvestigationContext
        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="",
            target_id=2, manual_domain="example.com",
            module_mode="domain", intel_core=_FakeIntelCore(),
        )
        assert ctx.effective_target == "example.com"

    def test_probe_mode(self):
        from discord_osint.pipeline.context import InvestigationContext
        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="",
            target_id=3, probe_string="anything",
            module_mode="probe", intel_core=_FakeIntelCore(),
        )
        assert ctx.effective_target == "anything"

    def test_legacy_manual_fallback(self):
        from discord_osint.pipeline.context import InvestigationContext
        ctx = InvestigationContext(
            config=MagicMock(), mode="manual", username="johndoe",
            target_id=4, intel_core=_FakeIntelCore(),
        )
        assert ctx.effective_target == "johndoe"
