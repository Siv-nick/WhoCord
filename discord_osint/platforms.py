"""
discord_osint/platforms.py
--------------------------
Central registry of platforms WhoCord knows about.

The registry is the single source of truth for:

* how to recognise a platform from a URL (``url_patterns``),
* how to display it in reports (``display_name``, ``icon``),
* how the pipeline should treat it (``scrape_supported`` /
  ``scrape_skip``).

Before this module existed, the same set of platforms was described in
four separate places:

* ``discord_api.PLATFORM_MAP`` + ``discord_api.classify_url``
* ``scraping_stage._skip_platforms``
* ``scraping.scrape_profile_info`` (the ``url_map`` and early-return
  domain set)
* ``intelligence.html_report._PLATFORM_META``

Adding a platform meant editing three or four of those, and there was
no enforcement that they stayed consistent — which is how ``linkedin``
ended up in ``_skip_platforms`` without ever being recognised by
``classify_url``.

Change log
----------
- Initial. Consolidates platform identity, display metadata, and
  scraping hints from the four modules above into one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Platform:
    """
    A known platform.

    Parameters
    ----------
    key:
        Canonical identifier used everywhere in the codebase.
        Lowercase, no spaces. ``"github"``, ``"twitter"``, ...
    display_name:
        Human-readable name shown in reports.
    icon:
        Emoji used in the HTML report.
    url_patterns:
        Regexes that match a profile URL for this platform. Each must
        contain exactly one ``(?P<slug>...)`` group naming the
        username / handle / id that the URL identifies. Anchored at
        the start with ``^https?://``.
    scrape_supported:
        True when ``scraping.scrape_profile_info`` has dedicated
        handling for this platform.
    scrape_skip:
        True when the platform is explicitly excluded from scraping —
        either because it requires authentication we do not have, or
        because its public pages are not useful profile sources.
    """

    key: str
    display_name: str
    icon: str
    url_patterns: tuple[str, ...] = ()
    scrape_supported: bool = False
    scrape_skip: bool = False


# Path segments that look like a username but are actually site
# infrastructure. Never treated as a profile slug.
INVALID_SLUGS = frozenset({
    "r", "i", "c", "user", "watch", "play", "wiki", "blog",
    "channel", "u", "explore", "search", "status", "share",
    "groups", "pages", "events", "help", "settings",
})


# ──────────────────────────────────────────────────────────────────────
# The registry
# ──────────────────────────────────────────────────────────────────────

PLATFORMS: Mapping[str, Platform] = {
    # ── Platforms with dedicated scrapers ──────────────────────────
    "github": Platform(
        "github", "GitHub", "🐙",
        url_patterns=(
            r"^https?://(?:www\.)?github\.com/(?P<slug>[^/?#]+)",
        ),
        scrape_supported=True,
    ),
    "twitter": Platform(
        "twitter", "Twitter / X", "🐦",
        url_patterns=(
            r"^https?://(?:www\.)?twitter\.com/(?P<slug>[^/?#]+)",
            r"^https?://(?:www\.)?x\.com/(?P<slug>[^/?#]+)",
        ),
        scrape_supported=True,
    ),
    "reddit": Platform(
        "reddit", "Reddit", "🤖",
        url_patterns=(
            r"^https?://(?:www\.)?reddit\.com/(?:user|u)/(?P<slug>[^/?#]+)",
        ),
        scrape_supported=True,
    ),
    "youtube": Platform(
        "youtube", "YouTube", "▶️",
        url_patterns=(
            r"^https?://(?:www\.)?youtube\.com/@(?P<slug>[^/?#]+)",
            r"^https?://(?:www\.)?youtube\.com/(?:user|c|channel)/(?P<slug>[^/?#]+)",
        ),
        scrape_supported=True,
    ),

    # ── Classified but explicitly not scraped ─────────────────────
    "instagram": Platform(
        "instagram", "Instagram", "📸",
        url_patterns=(
            r"^https?://(?:www\.)?instagram\.com/(?P<slug>[^/?#]+)",
        ),
        scrape_skip=True,
    ),
    "tiktok": Platform(
        "tiktok", "TikTok", "🎵",
        url_patterns=(
            r"^https?://(?:www\.)?tiktok\.com/@(?P<slug>[^/?#]+)",
        ),
        scrape_skip=True,
    ),
    "facebook": Platform(
        "facebook", "Facebook", "📘",
        url_patterns=(
            r"^https?://(?:www\.)?facebook\.com/profile\.php\?(?:[^&]*&)*id=(?P<slug>\d+)",
            r"^https?://(?:www\.)?facebook\.com/(?P<slug>[^/?#]+)",
        ),
        scrape_skip=True,
    ),
    "linkedin": Platform(
        "linkedin", "LinkedIn", "💼",
        url_patterns=(
            r"^https?://(?:[a-z]{2,3}\.)?linkedin\.com/in/(?P<slug>[^/?#]+)",
        ),
        scrape_skip=True,
    ),
    "pinterest": Platform(
        "pinterest", "Pinterest", "📌",
        url_patterns=(
            r"^https?://(?:www\.)?pinterest\.com/(?P<slug>[^/?#]+)",
        ),
        scrape_skip=True,
    ),
    "snapchat": Platform(
        "snapchat", "Snapchat", "👻",
        url_patterns=(
            r"^https?://(?:www\.)?snapchat\.com/add/(?P<slug>[^/?#]+)",
        ),
        scrape_skip=True,
    ),

    # ── Classified, scraped by the generic path ───────────────────
    "twitch": Platform(
        "twitch", "Twitch", "🎮",
        url_patterns=(
            r"^https?://(?:www\.)?twitch\.tv/(?P<slug>[^/?#]+)",
        ),
    ),
    "steam": Platform(
        "steam", "Steam", "🎮",
        url_patterns=(
            r"^https?://steamcommunity\.com/id/(?P<slug>[^/?#]+)",
            r"^https?://steamcommunity\.com/profiles/(?P<slug>[^/?#]+)",
        ),
    ),
    "gitlab": Platform(
        "gitlab", "GitLab", "🦊",
        url_patterns=(
            r"^https?://(?:www\.)?gitlab\.com/(?P<slug>[^/?#]+)",
        ),
    ),
    "bitbucket": Platform(
        "bitbucket", "Bitbucket", "🪣",
        url_patterns=(
            r"^https?://(?:www\.)?bitbucket\.org/(?P<slug>[^/?#]+)",
        ),
    ),
    "keybase": Platform(
        "keybase", "Keybase", "🔑",
        url_patterns=(
            r"^https?://keybase\.io/(?P<slug>[^/?#]+)",
        ),
    ),
    "soundcloud": Platform(
        "soundcloud", "SoundCloud", "🎵",
        url_patterns=(
            r"^https?://(?:www\.)?soundcloud\.com/(?P<slug>[^/?#]+)",
        ),
    ),
    "medium": Platform(
        "medium", "Medium", "✍️",
        url_patterns=(
            r"^https?://(?:www\.)?medium\.com/@(?P<slug>[^/?#]+)",
            r"^https?://(?!www\.)(?P<slug>[a-z0-9-]+)\.medium\.com(?:/|$)",
        ),
    ),
    "dev": Platform(
        "dev", "Dev.to", "💻",
        url_patterns=(
            r"^https?://dev\.to/(?P<slug>[^/?#]+)",
        ),
    ),
    "telegram": Platform(
        "telegram", "Telegram", "✈️",
        url_patterns=(
            r"^https?://t\.me/(?P<slug>[^/?#]+)",
        ),
    ),
    "gravatar": Platform(
        "gravatar", "Gravatar", "🌐",
        url_patterns=(
            r"^https?://(?:www\.)?gravatar\.com/(?P<slug>[^/?#]+)",
        ),
    ),
    "patreon": Platform(
        "patreon", "Patreon", "🎨",
        url_patterns=(
            r"^https?://(?:www\.)?patreon\.com/(?P<slug>[^/?#]+)",
        ),
    ),
    "tumblr": Platform(
        "tumblr", "Tumblr", "📝",
        url_patterns=(
            r"^https?://(?!www\.)(?P<slug>[a-z0-9-]+)\.tumblr\.com(?:/|$)",
        ),
    ),
    "producthunt": Platform(
        "producthunt", "Product Hunt", "🚀",
        url_patterns=(
            r"^https?://(?:www\.)?producthunt\.com/@(?P<slug>[^/?#]+)",
        ),
    ),
    "hackernews": Platform(
        "hackernews", "Hacker News", "🔶",
        url_patterns=(
            r"^https?://news\.ycombinator\.com/user\?id=(?P<slug>[^&#]+)",
        ),
    ),

    # ── Display-only platforms ────────────────────────────────────
    # No URL patterns: either their URLs are not profile-shaped, or
    # the platform shows up via a non-URL signal (Discord connected
    # account, GHunt, gravatar email hash). Listed so reports can show
    # the right icon and name.
    "google":     Platform("google",     "Google",     "🔍"),
    "spotify":    Platform("spotify",    "Spotify",    "🎧"),
    "discord":    Platform("discord",    "Discord",    "💬"),
    "mastodon":   Platform("mastodon",   "Mastodon",   "🐘"),
    "whatsapp":   Platform("whatsapp",   "WhatsApp",   "💬"),
    "viber":      Platform("viber",      "Viber",      "📱"),
    "line":       Platform("line",       "Line",       "💚"),
}


DEFAULT_PLATFORM: Platform = Platform(
    "unknown", "Unknown Platform", "🌐",
)


def get(key: str) -> Platform:
    """Return the Platform for *key*, or the unknown fallback."""
    return PLATFORMS.get((key or "").lower(), DEFAULT_PLATFORM)