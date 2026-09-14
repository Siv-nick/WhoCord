import re
import tempfile
import os
import json
import subprocess as _sp

import requests

from urllib.parse import urlparse
from bs4 import BeautifulSoup

from . import utils
from .utils import http_session, github_session, resilient_task
from .utils.mosint_wrapper import mosint_confirms_link
from .utils import clean_username
from .utils.url_safety import safe_get, UnsafeURLError

# ── Bug 3 fix: never bind tool flags at import time. ──────────────────
from . import config as _config_module


def _flag(name: str, default: bool = False) -> bool:
    """Read a config flag dynamically (Bug 3 fix)."""
    return bool(getattr(_config_module, name, default))


try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

DOMAINS_TO_SKIP_GENERIC = {
    "accounts.google.com", "docs.github.com", "api.github.com", "collector.github.com",
    "gql.twitch.tv", "assets.twitch.tv", "codecademy.com", "youtube.com/s/",
    "youtube.com/error_204/", "youtube.com/csi_204/", "youtube.com/about/",
    "youtube.com/creators/", "youtube.com/howyoutubeworks?",
    "github.com/security", "github.com/orgs", "github.com/newrelic",
    "github.com/greasyfork-org", "github.com/ppy", "github.com/tetrio",
    "github.com/truckersmp", "github.com/mcp", "github.com/collections",
    "github.com/trending", "github.com/customer-stories", "github.com/sponsors",
    "github.com/enterprise", "github.com/features", "github.com/pricing",
    "github.com/accelerator", "github.com/partners", "github.com/premium-support",
    "github.com/trust-center", "github.com/why-github",
}

BANNED_NAME_PHRASES = {
    "greasy fork","uuid javascript module","new relic","bootstrap","grav","codewars","tetr.io",
    "mastodon","keybase","liberapay","alpine iq","org","com","net","user","users","account",
    "sign in","sign up","login","log in","security measure","profile not available",
    "imgur the magic of the internet","image shack","revolut me","fansly",
    "search for the best onlyfans creators",
    "a paradise of lost thoughts and love that is found",
    "the roadmap that changes runescape forever",
    "setup a network namespace with internet access","keybase io.md",
    "understanding github code search syntax","sign in to github","keyboard shortcuts",
    "reporting abuse or spam","github terms of service","github general privacy statement",
    "blocking a user from your personal account","houzz tv","chess.com","sentimente.ro",
    "flickr","docker","envato","stream elements","teletype",
    "client challenge","castingcallclub","truth social","1of1photography","meh",
    "twitter share url","facebook share url","livejournal redirect"
}

GENERIC_WORDS = {"the","and","for","you","your","this","that","with","from","they","will",
                 "have","not","are","can","had","been","were","did","does","has","its","each",
                 "all","many","more","most","other","some","such","what","them","then","than"}


# ── Fix: reject HTML escape artifacts like `u003eguidelines@...` ──────
_ESCAPE_PREFIX_RE = re.compile(r'^u00[0-9a-f]{2}', re.IGNORECASE)


def is_likely_profile_url_v2(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    path = parsed.path.lower()
    domain = parsed.netloc.lower()
    if re.search(r'\.(js|css|png|jpe?g|gif|svg|ico|webp|woff2?|json|xml|pdf|zip|gz|bz2|rar|7z|mp[34]|mov|avi)$', path):
        return False
    if any(domain.endswith(d) for d in DOMAINS_TO_SKIP_GENERIC):
        return False
    if not re.search(r'/(users?|u|@|profile|channel|id)/[^/]+', url.lower()):
        clean_path = path.strip('/')
        if not clean_path or '/' in clean_path or '?' in clean_path or len(clean_path) < 3:
            return False
    return True


def looks_like_real_name_v2(name: str) -> bool:
    if not isinstance(name, str):
        return False
    s = name.strip()
    if len(s) < 2 or len(s) > 40:
        return False
    if any(c.isdigit() for c in s):
        return False
    if s.count(',') > 0:
        return False
    low = s.lower()
    if low in BANNED_NAME_PHRASES:
        return False
    words = s.split()
    if len(words) > 3:
        return False
    if len(words) == 1:
        w = words[0]
        if re.fullmatch(r'[A-ZÀ-ÿ][a-zà-ÿ]+([A-Z][a-zà-ÿ]+)*', w):
            if w.lower() in GENERIC_WORDS and w.lower() not in {"will","may","june","rose","chase","hope"}:
                return False
            return True
        return False
    for w in words:
        if re.fullmatch(r'[A-Z]\.?', w):
            continue
        if not re.fullmatch(r"[A-ZÀ-ÿ][a-zà-ÿ]+(['\-][A-Za-zà-ÿ]+)*", w):
            return False
        if len(w) > 1 and w.lower() in GENERIC_WORDS:
            if w.lower() in {"will", "may", "june", "rose", "chase", "hope"}:
                continue
            return False
    return True


def is_valid_email(email):
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False
    # ── Fix: reject HTML escape artifacts (`u003e`, `u0026`, etc.) ─────
    local = email.split('@', 1)[0]
    if _ESCAPE_PREFIX_RE.match(local):
        return False
    if "\\u" in email or "%" in local:
        return False

    domain = email.split('@')[1].lower()
    bad_tlds = {'jpg','jpeg','png','gif','svg','bmp','ico','mp4','mov','avi','css','js','json','xml','pdf','doc','xls','zip','gz','bz2','rar','7z','webp','mp3','wav','flac'}
    if '.' not in domain:
        return False
    tld = domain.rsplit('.', 1)[-1]
    return tld not in bad_tlds


_EXTRA_BAD_EMAILS = {
    "email@example.com",
    "test@example.com",
    "hello+support@hashnode.com",
    "git@hf.co",
    "support@hashnode.com",
}


def is_valid_personal_email(email: str) -> bool:
    """Return True only if the email looks like a real personal address."""
    if not is_valid_email(email):
        return False
    local, domain = email.split('@', 1)
    domain = domain.lower()

    # ── Fix: reject HTML escape prefixes ──────────────────────────────
    if _ESCAPE_PREFIX_RE.match(local):
        return False

    if domain in {"example.com", "example.org", "test.com", "test.org"}:
        return False
    if email.lower() in _EXTRA_BAD_EMAILS:
        return False
    if domain.startswith("www."):
        return False
    if "+" in local:
        return False
    if local.lower() in {"hello", "contact", "info", "support", "admin",
                         "help", "noreply", "no-reply", "0_10_",
                         "mailbox", "email", "webmaster", "postmaster"}:
        return False
    if local.isdigit():
        return False
    if re.search(r'^[a-f0-9]{20,}$', local):
        return False

    noisy_domains = {"mixcloud.com", "discogs.com", "etsy.com", "ebay.com",
                     "poshmark.com", "freelancer.com", "flickr.com",
                     "soundcloud.com", "sourceforge.net", "bandcamp.com",
                     "archive.org", "google.com", "huggingface.co",
                     "lichess.org", "stackoverflow.com", "github.com",
                     "gitlab.com", "bitbucket.org"}
    if domain in noisy_domains:
        return False
    return True


def is_email_linked_to_target(email: str, target_username: str) -> bool:
    """Return True if *email* is plausibly linked to *target_username*."""
    if not target_username:
        return True

    local = email.split("@")[0].lower()
    local_clean = local.replace(".", "").replace("_", "").replace("-", "")
    clean_uname = clean_username(target_username).lower()
    if clean_uname in local_clean or local_clean in clean_uname:
        return True

    if mosint_confirms_link(email, target_username):
        return True

    return False


@resilient_task(max_retries=1)
def run_socid_extractor(html: str) -> dict:
    try:
        import socid_extractor
        result = socid_extractor.extract(html)
        return result if isinstance(result, dict) else {}
    except Exception:
        return {}


@resilient_task(max_retries=2)
def scrape_profile_info(platform, username):
    """
    Scrape a known-platform profile.

    Bug 8 fix: the returned dict now includes the extra GitHub fields
    (location / company / followers / created_at / twitter_username /
    public_repos / public_gists) that ScrapingStage._emit_enrichment
    expects.

    SSRF note: GitHub's API endpoint is a fixed host, so no guard is
    needed there. The GitHub profile *HTML* fetch (for socid) and the
    Twitter/Reddit/YouTube fetches are also fixed hosts. Only the
    ``scrape_generic_url`` path and the derived-API fetches accept
    arbitrary hosts and are guarded.
    """
    info = {
        "name": "", "email": "", "bio": "", "blog": "",
        "socid": None, "avatar": None,
        "location": "", "company": "", "followers": "", "created_at": "",
        "twitter_username": "", "public_repos": "", "public_gists": "",
    }
    if platform in {"facebook", "instagram", "tiktok", "pinterest", "snapchat", "linkedin"}:
        return info
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    if platform == "github":
        if _flag("SKIP_GITHUB"):
            return info
        gh_headers = headers.copy()
        token = _config_module.GITHUB_TOKEN
        if token:
            gh_headers["Authorization"] = f"token {token}"
        try:
            r = github_session.get(
                f"https://api.github.com/users/{username}",
                headers=gh_headers, timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                info["name"] = data.get("name") or ""
                raw_email = data.get("email") or ""
                if raw_email and is_valid_personal_email(raw_email):
                    info["email"] = raw_email
                info["bio"]    = data.get("bio")    or ""
                info["blog"]   = data.get("blog")   or ""
                info["avatar"] = data.get("avatar_url")

                # Bug 8: extra GitHub fields
                info["location"]         = data.get("location")         or ""
                info["company"]          = data.get("company")          or ""
                info["followers"]        = str(data.get("followers")    or "")
                info["created_at"]       = data.get("created_at")       or ""
                info["twitter_username"] = data.get("twitter_username") or ""
                info["public_repos"]     = str(data.get("public_repos") or "")
                info["public_gists"]     = str(data.get("public_gists") or "")

                if not info["email"] and info["bio"]:
                    emails = re.findall(
                        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                        info["bio"],
                    )
                    personal_emails = [e for e in emails if is_valid_personal_email(e)]
                    if personal_emails:
                        info["email"] = personal_emails[0]
                if _flag("ENABLE_SOCID"):
                    try:
                        html_resp = http_session.get(
                            data.get("html_url"), headers=headers, timeout=10,
                        )
                        if html_resp.status_code == 200:
                            info["socid"] = run_socid_extractor(html_resp.text)
                    except Exception:
                        pass
        except Exception as e:
            print(f"  GitHub scrape error {username}: {e}")
        return info

    clean_user = username.lstrip("@") if platform == "youtube" else username
    url_map = {
        "twitter":   f"https://twitter.com/{clean_user}",
        "instagram": f"https://instagram.com/{clean_user}",
        "tiktok":    f"https://tiktok.com/@{clean_user}",
        "reddit":    f"https://reddit.com/user/{clean_user}",
        "youtube":   f"https://youtube.com/@{clean_user}",
    }
    if platform in url_map:
        try:
            r = http_session.get(url_map[platform], headers=headers, timeout=10)
            if r.status_code == 200:
                if _flag("ENABLE_SOCID"):
                    info["socid"] = run_socid_extractor(r.text)
                emails = re.findall(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text,
                )
                if emails:
                    personal_emails = [e for e in emails if is_valid_personal_email(e)]
                    if personal_emails:
                        info["email"] = personal_emails[0]
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(r.text, 'html.parser')
                    og_image = soup.find("meta", property="og:image")
                    if og_image:
                        info["avatar"] = og_image.get("content")
                    if platform == "twitter":
                        name_tag = soup.find("div", {"data-testid": "UserName"})
                        if name_tag:
                            info["name"] = (name_tag.text.strip() or "")
                except ImportError:
                    m = re.search(
                        r'<meta property="og:image" content="([^"]+)"', r.text,
                    )
                    if m:
                        info["avatar"] = m.group(1)
        except Exception as e:
            print(f"  Scrape error {platform}/{username}: {e}")
    return info


@resilient_task(max_retries=1)
def scrape_generic_url(url):
    """
    Fetch a generic profile URL discovered by the discovery stage.

    SSRF guard
    ----------
    The URL comes from scraped content — it is attacker-controlled. Every
    request goes through ``safe_get``, which rejects private / loopback /
    link-local / metadata targets on the initial URL and on every
    redirect hop. A profile that links to ``http://127.0.0.1:8080`` no
    longer causes the tool to probe its own host.
    """
    info = {
        "name": "", "email": "", "bio": "", "blog": url,
        "socid": None, "avatar": None,
        "location": "", "company": "", "followers": "", "created_at": "",
    }
    try:
        domain = urlparse(url).netloc.lower()
    except Exception:
        return info
    if any(domain.endswith(d) for d in {"facebook.com", "instagram.com",
                                        "tiktok.com", "pinterest.com",
                                        "snapchat.com", "linkedin.com"}):
        return info
    if not is_likely_profile_url_v2(url):
        return info

    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        r = safe_get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            return info

        content_type = r.headers.get("Content-Type", "").lower()

        if "application/json" in content_type or url.lower().endswith(".json"):
            try:
                parsed = r.json()
                if isinstance(parsed, dict):
                    socid_data = {}
                    for key in ("country", "country_code", "country_group",
                                "location", "region"):
                        val = parsed.get(key)
                        if val is not None:
                            socid_data[key] = str(val)
                    if "errors" in parsed and isinstance(parsed["errors"], dict):
                        email_err = parsed["errors"].get("email", "")
                        if "already registered" in str(email_err):
                            socid_data["email_status"] = "already registered"
                    for key in ("minimum_age", "is_country_launched"):
                        val = parsed.get(key)
                        if val is not None:
                            socid_data[key] = str(val)
                    for key in ("status", "can_accept_licenses_in_one_step",
                                "requires_marketing_opt_in", "use_all_genders"):
                        val = parsed.get(key)
                        if val is not None:
                            socid_data[key] = str(val)
                    if socid_data:
                        info["socid"] = socid_data
                return info
            except Exception:
                return info

        if _flag("ENABLE_SOCID"):
            info["socid"] = run_socid_extractor(r.text)
        emails = re.findall(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text,
        )
        for email in emails:
            if is_valid_personal_email(email):
                info["email"] = email
                break
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, 'html.parser')
            og_img = soup.find("meta", property="og:image")
            if og_img:
                info["avatar"] = og_img.get("content")
        except Exception:
            pass
    except UnsafeURLError as exc:
        print(f"  Generic scrape blocked for {url[:60]}: {exc}")
    except Exception:
        pass
    return info


def is_likely_github_user(slug):
    if len(slug) < 2:
        return False
    if '-' in slug and len(slug) > 15:
        return False
    if slug in {"security","mcp","orgs","collections","trending","customer-stories","sponsors",
                "enterprise","features","pricing","topics","marketplace","solutions","resources",
                "newrelic","truckersmp","ppy","tetrio","greasyfork-org"}:
        return False
    return True


@resilient_task(max_retries=1)
def run_gitfive(github_username):
    if not _flag("ENABLE_GITFIVE"):
        return {}
    _, stdout, _ = utils.run_external_tool(
        "gitfive", "user", github_username, "--json", timeout=120,
    )
    if stdout is None:
        return {}
    try:
        data = json.loads(stdout)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"  GitFive error: {e}")
        return {}