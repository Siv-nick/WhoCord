"""
discord_osint/pipeline/stages/domain_investigation.py
------------------------------------------------------
DomainInvestigationStage – Phase 4 domain investigation module.

Reads from ctx
--------------
ctx.manual_domain   – the target domain (e.g. "example.com")

Writes to ctx
-------------
ctx.intel_core      – whois, dns, ssl, wayback, subdomains,
                      harvester emails/hosts, ip geolocation
"""

from __future__ import annotations
import json
import socket
import ssl as _ssl
from urllib.parse import urlparse

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...extras import whois_domain, wayback_available


def _clean_domain(raw: str) -> str:
    """Strip protocol and path from a domain input."""
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

        # ------------------------------------------------------------------ #
        # WHOIS                                                                #
        # ------------------------------------------------------------------ #
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

        # ------------------------------------------------------------------ #
        # DNS records                                                          #
        # ------------------------------------------------------------------ #
        print("\n-- DNS Records --")
        emit("progress", {"message": "DNS record enumeration"})
        dns_data = self._query_dns(domain)
        if dns_data:
            ctx.intel_core.add_intel("dns", domain, dns_data, source="dns_lookup")
            emit("finding", {"type": "dns", "domain": domain, "records": dns_data})
            for rtype, values in dns_data.items():
                print(f"  {rtype}: {', '.join(str(v) for v in values[:3])}")

        # ------------------------------------------------------------------ #
        # IP + basic geolocation                                               #
        # ------------------------------------------------------------------ #
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

        # ------------------------------------------------------------------ #
        # SSL certificate                                                      #
        # ------------------------------------------------------------------ #
        print("\n-- SSL Certificate --")
        emit("progress", {"message": "SSL certificate inspection"})
        ssl_info = self._get_ssl_info(domain)
        if ssl_info:
            ctx.intel_core.add_intel("ssl", domain, ssl_info, source="ssl_module")
            emit("finding", {"type": "ssl_certificate", "domain": domain, "data": ssl_info})
            print(f"  SSL: expires {ssl_info.get('not_after','?')}, "
                  f"issuer {ssl_info.get('issuer','?')[:40]}")

        # ------------------------------------------------------------------ #
        # Wayback Machine                                                      #
        # ------------------------------------------------------------------ #
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

        # ------------------------------------------------------------------ #
        # Subdomain enumeration (sublist3r or fallback wordlist)              #
        # ------------------------------------------------------------------ #
        print("\n-- Subdomain Enumeration --")
        emit("progress", {"message": "Subdomain enumeration"})
        subdomains = self._enumerate_subdomains(domain)
        if subdomains:
            ctx.intel_core.add_intel("subdomains", domain, subdomains, source="subdomain_enum")
            emit("finding", {"type": "subdomains", "domain": domain,
                             "count": len(subdomains), "values": subdomains[:10]})
            print(f"  Subdomains: {len(subdomains)} found – {', '.join(subdomains[:5])}")

        # ------------------------------------------------------------------ #
        # theHarvester                                                         #
        # ------------------------------------------------------------------ #
        if getattr(cfg, "ENABLE_THEHARVESTER", False):
            print("\n-- theHarvester --")
            emit("progress", {"message": "theHarvester: email/host enumeration", "tool": "theHarvester"})
            self._run_harvester(ctx, domain, emit)

        print(f"\n== Domain investigation complete: {domain} ==")

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _query_dns(domain: str) -> dict:
        """Query MX, A, TXT, NS records using dnspython if available."""
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
            # Fallback: basic A record via socket
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
    def _geolocate_ip(ip: str) -> dict:
        try:
            import requests
            # Try ip-api.com first
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "country,regionName,city,isp,org,as"},
                timeout=6,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
            # Fallback to ipinfo.io (no key)
            resp2 = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6)
            if resp2.status_code == 200:
                data2 = resp2.json()
                return {
                    "country": data2.get("country", ""),
                    "regionName": data2.get("region", ""),
                    "city": data2.get("city", ""),
                    "isp": data2.get("org", ""),
                    "org": data2.get("org", ""),
                    "as": data2.get("as", ""),
                }
        except Exception:
            pass
        return {}

    @staticmethod
    def _get_ssl_info(domain: str) -> dict:
        import ssl
        try:
            cert_pem = ssl.get_server_certificate((domain, 443), timeout=8)
            import OpenSSL.crypto as crypto
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
            subject = dict(cert.get_subject().get_components())
            issuer = dict(cert.get_issuer().get_components())
            return {
                "issuer":    issuer.get(b"organizationName", b"").decode(),
                "subject":   subject.get(b"commonName", b"").decode(),
                "not_before": cert.get_notBefore().decode(),
                "not_after":  cert.get_notAfter().decode(),
            }
        except Exception as e:
            print(f"  SSL error: {e}")
            return {}

    @staticmethod
    def _enumerate_subdomains(domain: str) -> list[str]:
        """
        Try sublist3r first; fall back to a short common-subdomain probe.
        """
        # Try sublist3r
        try:
            import sublist3r  # type: ignore
            results = sublist3r.main(
                domain, 40, savefile=None, ports=None,
                silent=True, verbose=False, enable_bruteforce=False, engines=None,
            )
            return list(results) if results else []
        except (ImportError, Exception):
            pass

        # Fallback: probe a short wordlist
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
    def _run_harvester(
        ctx: InvestigationContext,
        domain: str,
        emit: EmitFn,
    ) -> None:
        """Run theHarvester via subprocess and parse output."""
        from ...utils import tool_available, debug_subprocess
        if not tool_available("theHarvester"):
            print("  theHarvester not installed – skipping.")
            return
        try:
            result, stdout, _ = debug_subprocess(
                ["theHarvester", "-d", domain, "-b", "robtex,urlscan,waybackarchive,duckduckgo,threatcrowd", "-l", "100"],
                timeout=90,
            )
            if not stdout:
                return

            # Extract email-like strings from output
            import re
            emails_found = list({
                m.lower() for m in re.findall(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", stdout
                )
            })
            # Filter out known false‑positive emails (theHarvester author, test addresses)
            BAD_EMAILS = {
                "cmartorella@edge-security.com",
                "test@example.com",
                "nobody@example.org",
            }
            emails_found = [e for e in emails_found if e not in BAD_EMAILS]

            hosts_found = list({
                m.lower() for m in re.findall(
                    rf"[a-zA-Z0-9\-]+\.{re.escape(domain)}", stdout
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
