
"""
discord_osint/pipeline/stages/url_analysis.py
----------------------------------------------
URLAnalysisStage – Phase 4 URL analysis module.

Change log
----------
- ``_fetch_url`` no longer constructs a requests.Session to attach a
  User-Agent. safe_get accepts a headers= argument which it applies to
  the session internally, so the extra object was unnecessary and
  tripped the "no bare requests.Session() outside the allowlist" check
  in tests/test_ssrf_routing.py.
- ``_check_safe_browsing`` uses the shared http_session. The endpoint
  is a fixed Google host; routing through the shared session gets the
  retry adapter for free.
- Every outbound request (initial fetch + each redirect hop) is routed
  through ``utils.url_safety.safe_get`` so a URL pointing at
  ``127.0.0.1``, ``169.254.169.254``, ``10.0.0.0/8``, or an internal
  hostname cannot be reached.
- Stage honours the pipeline-wide cancellation token at entry.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...extras import wayback_available
from ...scraping import is_valid_email
from ...utils import http_session, log_trace
from ...utils.url_safety import safe_get, UnsafeURLError

_MAX_CONTENT = 500_000

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_URL_RE   = re.compile(r"https?://[^\s\"'<>]{6,200}")


class URLAnalysisStage(Stage):
    name = "url_analysis"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        cancel_event = getattr(ctx.config, "_cancel_event", None)
        if cancel_event is not None and cancel_event.is_set():
            print("  [URLAnalysis] cancellation requested – skipping.")
            return

        url = ctx.manual_url.strip()

        if not url or not url.startswith("http"):
            print("  [URLAnalysis] No valid URL supplied – skipping.")
            return

        print(f"\n{'=' * 60}")
        print(f"== URL Analysis: {url[:80]}")
        print(f"{'=' * 60}")
        emit("progress", {"message": f"URL analysis: {url[:60]}"})

        ctx.intel_core.add_intel("target", "url", url, source="manual_input")

        cfg = ctx.config

        print("\n-- HTTP metadata --")
        emit("progress", {"message": "HTTP request and redirect trace"})
        http_meta, content, final_url = self._fetch_url(url)
        if http_meta:
            ctx.intel_core.add_intel("url_intel", "http_meta", http_meta, source="requests")
            emit("finding", {"type": "http_metadata", "url": url, "data": http_meta})
            print(f"  Status: {http_meta.get('status_code')}, "
                  f"Final URL: {http_meta.get('final_url','')[:60]}, "
                  f"Redirects: {http_meta.get('redirect_count',0)}")

        if content:
            print("\n-- Page metadata --")
            emit("progress", {"message": "Parsing page metadata"})
            page_meta = self._parse_page_meta(content, final_url or url)
            if page_meta:
                ctx.intel_core.add_intel("url_intel", "page_meta", page_meta, source="html_parse")
                emit("finding", {"type": "page_metadata", "url": url, "data": page_meta})
                print(f"  Title: {page_meta.get('title','')[:60]}")
                if page_meta.get("description"):
                    print(f"  Description: {page_meta['description'][:80]}")

            emails_on_page = list({
                m.lower() for m in _EMAIL_RE.findall(content)
                if is_valid_email(m)
            })
            if emails_on_page:
                for e in emails_on_page[:10]:
                    ctx.intel_core.add_intel("emails", e, e, source="url_page_scrape")
                emit("finding", {
                    "type":   "emails_on_page",
                    "url":    url,
                    "emails": emails_on_page[:10],
                    "count":  len(emails_on_page),
                })
                print(f"  Emails found: {', '.join(emails_on_page[:5])}")

            interesting_links = self._extract_interesting_links(content, final_url or url)
            if interesting_links:
                ctx.intel_core.add_intel(
                    "url_intel", "interesting_links",
                    interesting_links, source="html_parse",
                )
                emit("finding", {"type": "interesting_links", "url": url,
                                 "count": len(interesting_links)})
                print(f"  Interesting links found: {len(interesting_links)}")
                for link in interesting_links[:5]:
                    ctx.add_discovery("url_page", link)

        if cfg.ENABLE_WAYBACK:
            print("\n-- Wayback Machine --")
            emit("progress", {"message": "Wayback Machine snapshot"})
            try:
                snap = wayback_available(url)
                if snap:
                    ctx.intel_core.add_intel("wayback", url, snap, source="wayback")
                    emit("finding", {"type": "wayback", "url": url, "snapshot": snap})
                    print(f"  Wayback: {snap}")
            except Exception as exc:
                print(f"  Wayback error: {exc}")

        gsb_key = getattr(cfg, "GOOGLE_SAFE_BROWSING_KEY", "")
        if gsb_key:
            print("\n-- Google Safe Browsing --")
            emit("progress", {"message": "Safe Browsing check"})
            threats = self._check_safe_browsing(url, gsb_key)
            if threats is not None:
                ctx.intel_core.add_intel("url_intel", "safe_browsing", threats, source="gsb")
                emit("finding", {
                    "type":    "safe_browsing",
                    "url":     url,
                    "threats": threats,
                    "is_safe": len(threats) == 0,
                })
                if threats:
                    print(f"  ⚠️  Threats: {', '.join(threats)}")
                else:
                    print("  ✓ No threats found.")

        parsed_domain = urlparse(url).netloc
        if parsed_domain:
            ctx.intel_core.add_intel("url_intel", "domain", parsed_domain, source="urlparse")
            emit("finding", {"type": "url_domain", "value": parsed_domain})
            print(f"\n  Domain: {parsed_domain}")

        discovered_urls = [e["url"] for e in ctx.discovery if e.get("url")]
        ctx.all_urls = list(set(ctx.all_urls) | set(discovered_urls))

        print(f"\n== URL analysis complete ==")

    # ------------------------------------------------------------------ #
    # Private helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _fetch_url(url: str) -> tuple[dict, str, str]:
        """
        HTTP GET with redirect following, guarded by safe_get.

        Headers go directly to safe_get rather than through a
        requests.Session constructed here. safe_get applies them to
        its internal session, so the extra object was unnecessary and
        made this file look like it bypassed the SSRF guard.

        Returns (http_meta_dict, page_content, final_url).
        """
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/120 Safari/537.36"
            )
        }
        try:
            trail: list[str] = []
            resp = safe_get(
                url,
                headers=headers,
                timeout=15,
                stream=True,
                redirect_trail=trail,
            )

            final_url = resp.url
            # trail[0] is always the starting URL; everything after it
            # is an actual redirect hop. Previously this compared
            # final_url to the original url and could only ever record
            # zero or one redirect — safe_get follows hops internally
            # (that's what lets it re-resolve and re-pin each one), so
            # response.history is always empty and response.url only
            # shows the destination. A 3-hop redirect chain reported
            # "Redirects: 1" or "Redirects: 0" depending on whether the
            # final URL happened to differ from the first.
            redirect_chain = trail[1:] if len(trail) > 1 else []
            content_type   = resp.headers.get("Content-Type", "")

            meta = {
                "status_code":      resp.status_code,
                "final_url":        final_url,
                "redirect_count":   len(redirect_chain),
                "redirect_chain":   redirect_chain,
                "content_type":     content_type,
                "server":           resp.headers.get("Server", ""),
                "x_powered_by":     resp.headers.get("X-Powered-By", ""),
                "content_length":   resp.headers.get("Content-Length", ""),
                "last_modified":    resp.headers.get("Last-Modified", ""),
                "strict_transport": resp.headers.get("Strict-Transport-Security", ""),
            }

            if "text/html" in content_type or "text/" in content_type:
                content = resp.content[:_MAX_CONTENT].decode("utf-8", errors="replace")
            else:
                content = ""

            return meta, content, final_url

        except UnsafeURLError as exc:
            print(f"  HTTP fetch blocked: {exc}")
            return {}, "", ""
        except Exception as exc:
            print(f"  HTTP fetch error: {exc}")
            return {}, "", ""

    @staticmethod
    def _parse_page_meta(html: str, base_url: str) -> dict:
        """Extract title, description, Open Graph tags from HTML."""
        try:
            from bs4 import BeautifulSoup  # type: ignore
            soup = BeautifulSoup(html, "html.parser")

            title = ""
            title_tag = soup.find("title")
            if title_tag:
                title = title_tag.get_text(strip=True)

            meta_desc = ""
            for attr in [{"name": "description"}, {"property": "og:description"}]:
                tag = soup.find("meta", attrs=attr)
                if tag and tag.get("content"):
                    meta_desc = tag["content"][:300]
                    break

            og: dict = {}
            for prop in ["og:title", "og:image", "og:url", "og:type",
                         "og:site_name", "twitter:title", "twitter:description"]:
                tag = soup.find("meta", attrs={"property": prop}) or \
                      soup.find("meta", attrs={"name": prop})
                if tag and tag.get("content"):
                    og[prop] = tag["content"][:200]

            canonical = ""
            link_tag = soup.find("link", attrs={"rel": "canonical"})
            if link_tag and link_tag.get("href"):
                canonical = link_tag["href"]

            return {
                "title":       title[:200],
                "description": meta_desc,
                "og":          og,
                "canonical":   canonical,
            }
        except ImportError:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            title = title_match.group(1)[:200] if title_match else ""
            return {"title": title, "description": "", "og": {}, "canonical": ""}
        except Exception:
            return {}

    @staticmethod
    def _check_safe_browsing(url: str, api_key: str) -> list[str] | None:
        """
        Query Google Safe Browsing v4 Lookup API.

        Fixed host (safebrowsing.googleapis.com). Uses the shared
        session for the retry adapter.
        """
        try:
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            payload = {
                "client":    {"clientId": "whocord", "clientVersion": "3.0"},
                "threatInfo": {
                    "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                         "UNWANTED_SOFTWARE",
                                         "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes":    ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries":    [{"url": url}],
                },
            }
            resp = http_session.post(
                endpoint,
                params={"key": api_key},
                json=payload,
                timeout=8,
            )
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                return [m.get("threatType", "") for m in matches]
            log_trace(
                f"_check_safe_browsing: HTTP {resp.status_code} for {url[:80]}"
            )
        except Exception as exc:
            log_trace(
                f"_check_safe_browsing: {type(exc).__name__}: {exc} "
                f"for {url[:80]}"
            )
        return None

    def _extract_interesting_links(self, html: str, base_url: str) -> list[str]:
        import re
        interesting = set()
        patterns = [
            r'https?://(?:www\.)?(github|gitlab|bitbucket|twitter|x|instagram|linkedin|facebook|youtube|tiktok|twitch|reddit)\.com/[a-zA-Z0-9_\-\.]+',
            r'https?://[a-z]+\.stackexchange\.com/users/\d+',
            r'https?://(?:www\.)?medium\.com/@[a-zA-Z0-9_\-\.]+',
            r'https?://(?:www\.)?dev\.to/[a-zA-Z0-9_\-\.]+',
            r'https?://(?:www\.)?keybase\.io/[a-zA-Z0-9_\-\.]+',
            r'https?://(?:www\.)?patreon\.com/[a-zA-Z0-9_\-\.]+',
            r'https?://(?:www\.)?tumblr\.com/(?!blog)([a-zA-Z0-9_\-\.]+)',
            r'https?://(?:www\.)?about\.me/[a-zA-Z0-9_\-\.]+',
            r'https?://(?:www\.)?angel\.co/u/[a-zA-Z0-9_\-\.]+',
        ]
        for pat in patterns:
            for match in re.finditer(pat, html, re.IGNORECASE):
                url = match.group(0)
                url = url.rstrip(".,;:!?")
                interesting.add(url)
        return list(interesting)[:20]
