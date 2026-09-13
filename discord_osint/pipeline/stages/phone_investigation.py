"""
discord_osint/pipeline/stages/phone_investigation.py
------------------------------------------------------
PhoneInvestigationStage – Phase 4 phone number investigation module.

Reads from ctx
--------------
ctx.manual_phone  – raw phone number string (any format)

Writes to ctx
-------------
ctx.intel_core    – phone metadata, carrier, location, OSINT results
"""

from __future__ import annotations

import re
import json
from ..base import Stage, EmitFn
from ..context import InvestigationContext

# E.164-ish pattern: optional + then 7-15 digits
_PHONE_DIGITS = re.compile(r"[\s\-\(\)\.]")
_PHONE_VALID  = re.compile(r"^\+?\d{7,15}$")


def _normalise_phone(raw: str) -> str:
    """Strip formatting; return digits + optional leading +."""
    cleaned = _PHONE_DIGITS.sub("", raw.strip())
    return cleaned


class PhoneInvestigationStage(Stage):
    name = "phone_investigation"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        raw_phone = ctx.manual_phone.strip()

        if not raw_phone:
            print("  [PhoneInvestigation] No phone number supplied – skipping.")
            return

        phone = _normalise_phone(raw_phone)
        if not _PHONE_VALID.match(phone):
            print(f"  [PhoneInvestigation] Unrecognised phone format: {raw_phone!r}")

        print(f"\n{'=' * 60}")
        print(f"== Phone Investigation: {phone}")
        print(f"{'=' * 60}")
        emit("progress", {"message": f"Phone investigation: {phone}"})

        ctx.intel_core.add_intel("phone", "number", phone, source="manual_input")
        ctx.intel_core.add_intel("phone", "raw_input", raw_phone, source="manual_input")

        cfg = ctx.config

        # ------------------------------------------------------------------ #
        # PhoneInfoga (if installed and enabled)
        # ------------------------------------------------------------------ #
        if getattr(cfg, "ENABLE_PHONEINFOGA", False):
            self._run_phoneinfoga(ctx, phone, emit)
        else:
            print("  PhoneInfoga disabled (ENABLE_PHONEINFOGA=False)")

        # ------------------------------------------------------------------ #
        # phonenumbers library – basic validation + metadata                  #
        # ------------------------------------------------------------------ #
        print("\n-- Number validation --")
        emit("progress", {"message": "Validating phone number"})
        meta = self._validate_phonenumbers(phone)
        if meta:
            for k, v in meta.items():
                ctx.intel_core.add_intel("phone", k, v, source="phonenumbers_lib")
            emit("finding", {"type": "phone_metadata", "value": phone, "data": meta})
            print(f"  Valid: {meta.get('is_valid')}, Type: {meta.get('number_type')}, "
                  f"Country: {meta.get('country')}, Carrier: {meta.get('carrier')}")

        # ------------------------------------------------------------------ #
        # Free carrier/geo lookup via numverify-style API (no key required)  #
        # ------------------------------------------------------------------ #
        print("\n-- Carrier / geo lookup --")
        emit("progress", {"message": "Carrier lookup"})
        carrier_data = self._carrier_lookup(phone)
        if carrier_data:
            ctx.intel_core.add_intel("phone", "carrier_lookup", carrier_data, source="carrier_api")
            emit("finding", {"type": "phone_carrier", "value": phone, "data": carrier_data})
            print(f"  Carrier: {carrier_data.get('carrier','?')}, "
                  f"Line type: {carrier_data.get('line_type','?')}, "
                  f"Country: {carrier_data.get('country_code','?')}")


        print(f"\n== Phone investigation complete: {phone} ==")

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _validate_phonenumbers(phone: str) -> dict:
        """Use the phonenumbers library for rich metadata."""
        try:
            import phonenumbers  # type: ignore
            from phonenumbers import geocoder, carrier as pn_carrier, number_type

            parsed = phonenumbers.parse(phone, None)
            is_valid = phonenumbers.is_valid_number(parsed)
            # Get number type (integer) and map to human-readable name
            type_int = phonenumbers.number_type(parsed)
            type_map = {
                0: "fixed_line",
                1: "mobile",
                2: "fixed_line_or_mobile",
                3: "toll_free",
                4: "premium_rate",
                5: "shared_cost",
                6: "voip",
                7: "personal_number",
                8: "pager",
                9: "uan",
                10: "voicemail",
                11: "unknown"
            }
            ntype = type_map.get(type_int, "unknown")
            country  = geocoder.description_for_number(parsed, "en")
            car      = pn_carrier.name_for_number(parsed, "en")
            e164     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

            return {
                "is_valid":    is_valid,
                "e164":        e164,
                "number_type": ntype,
                "country":     country,
                "carrier":     car,
            }
        except ImportError:
            return {}
        except Exception as exc:
            print(f"  phonenumbers error: {exc}")
            return {}

    @staticmethod
    def _carrier_lookup(phone: str) -> dict:
        """Carrier & location using multiple free sources."""
        result = {}

        # 1. Use phonenumbers carrier (if available)
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder
            parsed = phonenumbers.parse(phone, None)
            if carrier.name_for_number(parsed, "en"):
                result["carrier"] = carrier.name_for_number(parsed, "en")
            if geocoder.description_for_number(parsed, "en"):
                result["country_name"] = geocoder.description_for_number(parsed, "en")
                # We can also get country code from parsed
                result["country_code"] = str(parsed.country_code)
        except Exception:
            pass

        # 2. Try AbstractAPI as backup (free, no key)
        try:
            import requests
            resp = requests.get(
                "https://phonevalidation.abstractapi.com/v1/",
                params={"api_key": "free", "phone": phone},
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                result["carrier"] = result.get("carrier") or data.get("carrier", {}).get("name", "")
                result["line_type"] = data.get("carrier", {}).get("type", "")
                result["country_code"] = result.get("country_code") or data.get("country", {}).get("code", "")
                result["country_name"] = result.get("country_name") or data.get("country", {}).get("name", "")
                result["location"] = data.get("location", "")
                result["valid"] = data.get("valid", False)
        except Exception:
            pass

        return result

    @staticmethod
    def _run_phoneinfoga(
        ctx: InvestigationContext,
        phone: str,
        emit: EmitFn,
    ) -> None:
        from ...utils import tool_available, debug_subprocess
        if not tool_available("phoneinfoga"):
            print("  PhoneInfoga not installed – skipping.")
            return

        print("\n-- PhoneInfoga --")
        emit("progress", {"message": "PhoneInfoga OSINT scan", "tool": "phoneinfoga"})
        try:
            result, stdout, stderr = debug_subprocess(
                ["phoneinfoga", "scan", "-n", phone],
                timeout=60,
            )
            if stdout and stdout.strip():
                # Try to parse as JSON (some versions output JSON without --json)
                try:
                    data = json.loads(stdout)
                    # Store structured data
                    ctx.intel_core.add_intel("phone", "phoneinfoga_data", data, source="phoneinfoga")
                    if "reports" in data:
                        reports = data["reports"]
                        if reports:
                            ctx.intel_core.add_intel("phone", "phoneinfoga_reports", reports, source="phoneinfoga")
                            print(f"  PhoneInfoga: {len(reports)} report(s) found.")
                    if "local" in data:
                        local = data.get("local", {})
                        print(f"  Number valid: {local.get('valid', '?')}, Carrier: {local.get('carrier', '?')}")
                except json.JSONDecodeError:
                    # Store raw output as before
                    ctx.intel_core.add_intel("phone", "phoneinfoga_raw", stdout[:2000], source="phoneinfoga")
                    print("  PhoneInfoga: raw output stored (JSON parse failed).")
            else:
                print("  PhoneInfoga: no output.")
        except Exception as exc:
            print(f"  PhoneInfoga error: {exc}")
