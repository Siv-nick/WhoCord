
"""
discord_osint/pipeline/stages/domain_investigation.py
------------------------------------------------------
DomainInvestigationStage – Phase 4 domain investigation module.

Change log
----------
- ``_geolocate_ip`` runs the two providers concurrently in a
  ThreadPoolExecutor instead of sequentially. The ip-api call and the
  ipinfo.io fallback are independent; running them one-after-the-other
  meant a failed ip-api call added its full timeout to the total.
  Wall-clock is now max(t_ipapi, t_ipinfo) instead of the sum.
  Preference is preserved — ip-api is still tried first.
- ``_get_ssl_info`` resolves through ``resolve_and_validate`` and
  connects to the validated IP with SNI preserved.
- Phase 4: subdomain enumeration merges DNS + crt.sh.
"""

from __future__ import annotations
import concurrent.futures as _cf
import json
import socket
import ssl as _ssl
from urllib.parse import urlparse

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...extras import whois_domain, wayback_available, crt_sh_subdomains
from ...utils import http_session, log_trace
from ...utils.url_safety import resolve_and_validate, UnsafeURLError


def _clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc or raw
    return raw.split("/")[0].split("?")[0]


class DomainInvestigationStage(Stage):
    name = "domain_investigation"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        domain = _clean_domain(ctx.manual_domain)

        if not domain or "." not in domain:
            print("  [DomainInvestigation] No valid domain supplied – skipping.")
            return

        print(f"\n{'=' * 60}")
        print(f"== Domain Investigation: {domain}")
        print(f"{'=' * 60}")
        emit("progress", {"message": f"Domain investigation: {domain}"})

        ctx.intel_core.add_intel("target", "domain", domain, source="manual_input")

        cfg = ctx.config

        # ---- WHOIS ----
        if cfg.ENABLE_WHOIS:
            print("\n-- WHOIS --")
            emit("progress", {"message": "WHOIS lookup", "tool": "whois"})
            try:
                w = whois_domain(domain)
                if w:
                    ctx.intel_core.add_intel("whois", domain, w, source="whois")
                    emit("finding", {"type": "whois", "domain": domain, "data": str(w)[:200]})
                    print(f"  WHOIS: data retrieved.")
            except Exception as exc:
                print(f"  WHOIS error: {exc}")

        # ---- DNS ----
        print("\n-- DNS Records --")
        emit("progress", {"message": "DNS record enumeration"})
        dns_data = self._query_dns(domain)
        if dns_data:
            ctx.intel_core.add_intel("dns", domain, dns_data, source="dns_lookup")
            emit("finding", {"type": "dns", "domain": domain, "records": dns_data})
            for rtype, values in dns_data.items():
                print(f"  {rtype}: {', '.join(str(v) for v in values[:3])}")

        # ---- IP ----
        print("\n-- IP Resolution --")
        emit("progress", {"message": "Resolving IP address"})
        ip = self._resolve_ip(domain)
        if ip:
            ctx.intel_core.add_intel("dns", f"{domain}_ip", ip, source="socket")
            emit("finding", {"type": "ip_address", "domain": domain, "value": ip})
            print(f"  IP: {ip}")
            geo = self._geolocate_ip(ip)
            if geo:
                ctx.intel_core.add_intel("dns", f"{domain}_geo", geo, source="ipapi")
                emit("finding", {"type": "ip_geolocation", "domain": domain, "data": geo})
                print(f"  Geo: {geo.get('country','?')} / {geo.get('city','?')}")

        # ---- SSL ----
        print("\n-- SSL Certificate --")
        emit("progress", {"message": "SSL certificate inspection"})
        ssl_info = self._get_ssl_info(domain)
        if ssl_info:
            ctx.intel_core.add_intel("ssl", domain, ssl_info, source="ssl_module")
            emit("finding", {"type": "ssl_certificate", "domain": domain, "data": ssl_info})
            print(f"  SSL: expires {ssl_info.get('not_after','?')}, "
                  f"issuer {ssl_info.get('issuer','?')[:40]}")

        # ---- Wayback ----
        if cfg.ENABLE_WAYBACK:
            print("\n-- Wayback Machine --")
            emit("progress", {"message": "Wayback Machine snapshot", "tool": "wayback"})
            try:
                snap = wayback_available(f"https://{domain}")
                if snap:
                    ctx.intel_core.add_intel("wayback", domain, snap, source="wayback")
                    emit("finding", {"type": "wayback", "domain": domain, "snapshot": snap})
                    print(f"  Wayback: {snap}")
            except Exception as exc:
                print(f"  Wayback error: {exc}")

        # ---- Subdomains (DNS + Certificate Transparency) ----
        print("\n-- Subdomain Enumeration --")
        emit("progress", {"message": "Subdomain enumeration (DNS + CT logs)"})
        self._enumerate_and_store(ctx, domain, emit)

        # ---- theHarvester ----
        if getattr(cfg, "ENABLE_THEHARVESTER", False):
            print("\n-- theHarvester --")
            emit("progress", {"message": "theHarvester: email/host enumeration", "tool": "theHarvester"})
            self._run_harvester(ctx, domain, emit)

        print(f"\n== Domain investigation complete: {domain} ==")

    # ------------------------------------------------------------------ #
    # Subdomain enumeration — merged DNS + CT
    # ------------------------------------------------------------------ #

    @staticmethod
    def _enumerate_and_store(
        ctx: InvestigationContext,
        domain: str,
        emit: EmitFn,
    ) -> None:
        dns_subdomains: list[str] = []
        try:
            dns_subdomains = DomainInvestigationStage._enumerate_subdomains(domain)
        except Exception as exc:
            print(f"  DNS subdomain enumeration error: {exc}")

        crt_subdomains: list[str] = []
        try:
            crt_subdomains = crt_sh_subdomains(domain) or []
        except Exception as exc:
            print(f"  crt.sh error: {exc}")

        merged = sorted(set(dns_subdomains) | set(crt_subdomains))

        if dns_subdomains:
            print(f"  DNS enumeration: {len(dns_subdomains)} host(s)")
        if crt_subdomains:
            print(f"  Certificate Transparency: {len(crt_subdomains)} host(s)")

        if not merged:
            print("  No subdomains found.")
            return

        ctx.intel_core.add_intel(
            "subdomains", domain, merged, source="subdomain_enum",
        )
        emit("finding", {
            "type":       "subdomains",
            "domain":     domain,
            "count":      len(merged),
            "values":     merged[:10],
            "from_dns":   len(dns_subdomains),
            "from_crt":   len(crt_subdomains),
        })
        print(f"  Total: {len(merged)} unique hostname(s)")

    # ------------------------------------------------------------------ #
    # Private helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _query_dns(domain: str) -> dict:
        results: dict = {}
        try:
            import dns.resolver  # type: ignore
            for rtype in ("A", "MX", "TXT", "NS"):
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    results[rtype] = [str(r) for r in answers]
                except Exception:
                    pass
        except ImportError:
            try:
                ip = socket.gethostbyname(domain)
                results["A"] = [ip]
            except Exception:
                pass
        return results

    @staticmethod
    def _resolve_ip(domain: str) -> str:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return ""

    @staticmethod
    def _try_ipapi(ip: str) -> dict:
        """
        ip-api.com lookup. Returns {} on any failure and logs the
        reason via log_trace. Kept as a standalone helper so the
        ThreadPoolExecutor in _geolocate_ip can submit it.
        """
        try:
            resp = http_session.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "country,regionName,city,isp,org,as"},
                timeout=6,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
                log_trace(
                    f"_geolocate_ip/ipapi: status={data.get('status')!r} "
                    f"for {ip}"
                )
            else:
                log_trace(
                    f"_geolocate_ip/ipapi: HTTP {resp.status_code} for {ip}"
                )
        except Exception as exc:
            log_trace(
                f"_geolocate_ip/ipapi: {type(exc).__name__}: {exc} for {ip}"
            )
        return {}

    @staticmethod
    def _try_ipinfo(ip: str) -> dict:
        """
        ipinfo.io lookup, normalised to the same key set ip-api
        returns. Returns {} on any failure.
        """
        try:
            resp = http_session.get(
                f"https://ipinfo.io/{ip}/json", timeout=6,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "country":    data.get("country", ""),
                    "regionName": data.get("region", ""),
                    "city":       data.get("city", ""),
                    "isp":        data.get("org", ""),
                    "org":        data.get("org", ""),
                    "as":         data.get("as", ""),
                }
            log_trace(
                f"_geolocate_ip/ipinfo: HTTP {resp.status_code} for {ip}"
            )
        except Exception as exc:
            log_trace(
                f"_geolocate_ip/ipinfo: {type(exc).__name__}: {exc} for {ip}"
            )
        return {}

    @staticmethod
    def _geolocate_ip(ip: str) -> dict:
        """
        IP geolocation via ip-api.com with ipinfo.io fallback.

        The two providers are independent. The previous sequential
        implementation added a failed ip-api timeout to the ipinfo
        call; running them concurrently caps wall-clock at
        max(t_ipapi, t_ipinfo). ip-api is preferred — its result is
        used whenever it succeeds, regardless of which future
        completes first.
        """
        with _cf.ThreadPoolExecutor(max_workers=2) as ex:
            f_ipapi  = ex.submit(DomainInvestigationStage._try_ipapi,  ip)
            f_ipinfo = ex.submit(DomainInvestigationStage._try_ipinfo, ip)

            try:
                result = f_ipapi.result(timeout=8)
                if result:
                    return result
            except Exception as exc:
                log_trace(f"_geolocate_ip: ip-api future failed: {exc}")

            try:
                result = f_ipinfo.result(timeout=8)
                if result:
                    return result
            except Exception as exc:
                log_trace(f"_geolocate_ip: ipinfo future failed: {exc}")

        return {}

    @staticmethod
    def _get_ssl_info(domain: str) -> dict:
        """
        Return TLS certificate metadata for *domain*:443.

        SSRF hardening: ``domain`` is user-supplied. The previous
        implementation fed it straight into
        ``ssl.get_server_certificate((domain, 443))``, which opens a
        TCP connection to whatever the name resolves to — an internal
        port-probe primitive independent of the HTTP SSRF guard. The
        new flow resolves and validates first, connects to the
        validated IP, and keeps SNI set to the original hostname so
        certificate verification is unchanged.
        """
        try:
            pinned_ip = resolve_and_validate(domain)
        except UnsafeURLError as exc:
            log_trace(f"_get_ssl_info: SSRF BLOCKED {domain!r} — {exc}")
            print(f"  SSL: blocked unsafe host {domain!r}")
            return {}
        except Exception as exc:
            log_trace(f"_get_ssl_info: resolution error for {domain!r}: "
                      f"{type(exc).__name__}: {exc}")
            print(f"  SSL error: {exc}")
            return {}

        try:
            ctx = _ssl.create_default_context()
            with socket.create_connection((pinned_ip, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    der = tls.getpeercert(binary_form=True)
        except Exception as exc:
            print(f"  SSL error: {exc}")
            return {}

        if not der:
            print("  SSL error: no certificate returned.")
            return {}

        try:
            import OpenSSL.crypto as crypto
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
            subject = dict(cert.get_subject().get_components())
            issuer  = dict(cert.get_issuer().get_components())
            return {
                "issuer":     issuer.get(b"organizationName", b"").decode(errors="replace"),
                "subject":    subject.get(b"commonName",    b"").decode(errors="replace"),
                "not_before": cert.get_notBefore().decode(),
                "not_after":  cert.get_notAfter().decode(),
            }
        except Exception as exc:
            print(f"  SSL parse error: {exc}")
            return {}

    @staticmethod
    def _enumerate_subdomains(domain: str) -> list[str]:
        try:
            import sublist3r  # type: ignore
            results = sublist3r.main(
                domain, 40, savefile=None, ports=None,
                silent=True, verbose=False, enable_bruteforce=False, engines=None,
            )
            return list(results) if results else []
        except Exception as exc:
            # ``ImportError`` was listed alongside ``Exception`` here,
            # which is a no-op — Exception already covers it — and it
            # hid every sublist3r failure (network error, API rate
            # limit, a crash inside the library) behind a silent
            # fallback to the DNS-guess list with no trace of why.
            log_trace(f"_enumerate_subdomains: sublist3r unavailable or "
                      f"failed ({type(exc).__name__}: {exc}); "
                      f"falling back to common-name DNS guessing.")

        common = [
            "www", "mail", "ftp", "smtp", "pop", "api", "dev", "staging",
            "app", "admin", "blog", "shop", "cdn", "vpn", "git", "status",
        ]
        found: list[str] = []
        for sub in common:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                found.append(fqdn)
            except Exception:
                pass
        return found

    @staticmethod
    def _run_harvester(ctx: InvestigationContext, domain: str, emit: EmitFn) -> None:
        from ...utils import tool_available, debug_subprocess
        if not tool_available("theHarvester"):
            print("  theHarvester not installed – skipping.")
            return
        try:
            result, stdout, _ = debug_subprocess(
                ["theHarvester", "-d", domain, "-b",
                 "robtex,urlscan,waybackarchive,duckduckgo,threatcrowd",
                 "-l", "100"],
                timeout=90,
            )
            if not stdout:
                return

            import re as _re
            emails_found = list({
                m.lower() for m in _re.findall(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", stdout
                )
            })
            BAD_EMAILS = {
                "cmartorella@edge-security.com",
                "test@example.com",
                "nobody@example.org",
            }
            emails_found = [e for e in emails_found if e not in BAD_EMAILS]

            hosts_found = list({
                m.lower() for m in _re.findall(
                    rf"[a-zA-Z0-9\-]+\.{_re.escape(domain)}", stdout
                )
            })

            if emails_found:
                ctx.intel_core.add_intel(
                    "harvester_emails", domain,
                    {"emails": emails_found}, source="theharvester",
                )
                for e in emails_found[:10]:
                    ctx.intel_core.add_intel("emails", e, e, source="theharvester")
                emit("finding", {
                    "type": "harvester_emails", "domain": domain,
                    "emails": emails_found[:10], "count": len(emails_found),
                })
                print(f"  theHarvester: {len(emails_found)} email(s)")

            if hosts_found:
                ctx.intel_core.add_intel(
                    "harvester_hosts", domain,
                    {"hosts": hosts_found}, source="theharvester",
                )
                emit("finding", {
                    "type": "harvester_hosts", "domain": domain,
                    "count": len(hosts_found),
                })
                print(f"  theHarvester: {len(hosts_found)} host(s)")
        except Exception as exc:
            print(f"  theHarvester error: {exc}")
