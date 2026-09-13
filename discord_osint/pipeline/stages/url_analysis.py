"""
discord_osint/pipeline/stages/url_analysis.py
----------------------------------------------
URLAnalysisStage – Phase 4 URL analysis module.

Reads from ctx
--------------
ctx.manual_url   – the target URL

Writes to ctx
-------------
ctx.intel_core   – http_meta, redirects, page_meta (title/desc/og),
                   safe_browsing, wayback snapshot, links/emails found
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...extras import wayback_available
from ...scraping import is_valid_email

# Max page content to parse (bytes)
_MAX_CONTENT = 500_000

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_URL_RE   = re.compile(r"https?://[^\s\"'<>]{6,200}")


class URLAnalysisStage(Stage):
    name = "url_analysis"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
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

        # ------------------------------------------------------------------ #
        # HTTP request – status, headers, redirect chain                      #
        # ------------------------------------------------------------------ #
        print("\n-- HTTP metadata --")
        emit("progress", {"message": "HTTP request and redirect trace"})
        http_meta, content, final_url = self._fetch_url(url)
        if http_meta:
            ctx.intel_core.add_intel("url_intel", "http_meta", http_meta, source="requests")
            emit("finding", {"type": "http_metadata", "url": url, "data": http_meta})
            print(f"  Status: {http_meta.get('status_code')}, "
                  f"Final URL: {http_meta.get('final_url','')[:60]}, "
                  f"Redirects: {http_meta.get('redirect_count',0)}")

        # ------------------------------------------------------------------ #
        # Page metadata (title, description, Open Graph)                      #
        # ------------------------------------------------------------------ #
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

            # ---------------------------------------------------------------- #
            # Emails and links extracted from page                             #
            # ---------------------------------------------------------------- #
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

            # Extract interesting links from the page
            interesting_links = self._extract_interesting_links(content, final_url or url)
            if interesting_links:
                ctx.intel_core.add_intel(
                    "url_intel", "interesting_links",
                    interesting_links, source="html_parse",
                )
                emit("finding", {"type": "interesting_links", "url": url, "count": len(interesting_links)})
                print(f"  Interesting links found: {len(interesting_links)}")
                for link in interesting_links[:5]:
                    ctx.add_discovery("url_page", link)

        # ------------------------------------------------------------------ #
        # Wayback Machine                                                      #
        # ------------------------------------------------------------------ #
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

        # ------------------------------------------------------------------ #
        # Google Safe Browsing (optional, needs API key)                      #
        # ------------------------------------------------------------------ #
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

        # ------------------------------------------------------------------ #
        # TLD / domain intel                                                  #
        # ------------------------------------------------------------------ #
        parsed_domain = urlparse(url).netloc
        if parsed_domain:
            ctx.intel_core.add_intel("url_intel", "domain", parsed_domain, source="urlparse")
            emit("finding", {"type": "url_domain", "value": parsed_domain})
            print(f"\n  Domain: {parsed_domain}")

        discovered_urls = [e["url"] for e in ctx.discovery if e.get("url")]
        ctx.all_urls = list(set(ctx.all_urls) | set(discovered_urls))

        print(f"\n== URL analysis complete ==")

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _fetch_url(url: str) -> tuple[dict, str, str]:
        """
        Perform HTTP GET with redirect following.
        Returns (http_meta_dict, page_content, final_url).
        """
        try:
            import requests
            session = requests.Session()
            session.headers.update({
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120 Safari/537.36"
                )
            })
            resp = session.get(url, timeout=15, stream=True, allow_redirects=True)
            # Collect redirect chain
            redirects = [r.url for r in resp.history]
            content_type = resp.headers.get("Content-Type", "")

            meta = {
                "status_code":    resp.status_code,
                "final_url":      resp.url,
                "redirect_count": len(redirects),
                "redirect_chain": redirects,
                "content_type":   content_type,
                "server":         resp.headers.get("Server", ""),
                "x_powered_by":   resp.headers.get("X-Powered-By", ""),
                "content_length": resp.headers.get("Content-Length", ""),
                "last_modified":  resp.headers.get("Last-Modified", ""),
                "strict_transport": resp.headers.get("Strict-Transport-Security", ""),
            }

            # Only parse HTML content
            if "text/html" in content_type or "text/" in content_type:
                content = resp.content[:_MAX_CONTENT].decode("utf-8", errors="replace")
            else:
                content = ""

            return meta, content, resp.url

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
            # Fallback: regex
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            title = title_match.group(1)[:200] if title_match else ""
            return {"title": title, "description": "", "og": {}, "canonical": ""}
        except Exception:
            return {}

    @staticmethod
    def _check_safe_browsing(url: str, api_key: str) -> list[str] | None:
        """
        Query Google Safe Browsing v4 Lookup API.
        Returns list of threat types (empty = safe), or None on error.
        """
        try:
            import requests
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            payload = {
                "client":    {"clientId": "whocord", "clientVersion": "3.0"},
                "threatInfo": {
                    "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                         "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes":    ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries":    [{"url": url}],
                },
            }
            resp = requests.post(
                endpoint,
                params={"key": api_key},
                json=payload,
                timeout=8,
            )
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                return [m.get("threatType", "") for m in matches]
        except Exception:
            pass
        return None

    def _extract_interesting_links(self, html: str, base_url: str) -> list[str]:
        """
        Extract URLs from the page that look like social profiles, GitHub repos,
        or other interesting resources. Uses a simple heuristic.
        """
        import re
        interesting = set()
        # Common patterns for profile pages
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
                # Remove trailing punctuation
                url = url.rstrip(".,;:!?")
                interesting.add(url)
        return list(interesting)[:20]  # limit

