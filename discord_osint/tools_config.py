"""
discord_osint/tools_config.py
-----------------------------
The list of toggleable investigation tools that the CLI menu and the
web UI both render.

Change log
----------
- Added ``ENABLE_APOLLO`` and ``ENABLE_LUSHA``. Both default to off; the
  descriptions make the paid-credit nature explicit so an analyst does
  not enable them without understanding the cost.
- HIBP description now states that a v3 API key is required.
"""

TOOLS_LIST = [
    ("ENABLE_USER_SCANNER", "User Scanner (username + email, 550+ sites)"),
    ("ENABLE_MAIGRET", "Maigret (broad username fallback, ~3000 sites)"),
    ("ENABLE_LINKOOK", "Linkook (deep URL discovery)"),
    ("ENABLE_SOCIALSCAN", "socialscan (URL availability filter)"),
    ("ENABLE_SOCIOPATH", "Sociopath (URL spider)"),
    ("ENABLE_BLACKBIRD", "Blackbird (email search + JSON API detection)"),
    ("ENABLE_WMN", "WhatsMyName (bundled 600+ site API endpoint dataset)"),
    ("ENABLE_HOLEHE", "Holehe (email site registrations)"),
    ("ENABLE_H8MAIL", "h8mail (breach check)"),
    ("ENABLE_HIBP", "HaveIBeenPwned (HIBP v3 — requires HIBP_API_KEY)"),
    ("ENABLE_EMAILREP", "EmailRep.io"),
    ("ENABLE_SCYLLA", "Scylla (leak DB)"),
    ("ENABLE_GHUNT", "GHunt (Google account info)"),
    ("ENABLE_THEHARVESTER", "theHarvester (domain emails)"),
    ("ENABLE_WHOIS", "WHOIS domain lookups"),
    ("ENABLE_WAYBACK", "Wayback Machine check"),
    ("ENABLE_EXIF", "EXIF metadata extraction"),
    ("ENABLE_REVERSE_IMG", "Reverse image search (SauceNAO)"),
    ("ENABLE_NAME_ANALYSIS", "NameTrace & Fuzzy matching"),
    ("ENABLE_EMAIL_GUESS", "Email permuter/guesser"),
    ("ENABLE_AI_REPORT", "AI report generation (Groq)"),
    ("ENABLE_LOCATION", "Location inference from bio"),
    ("ENABLE_LANGDETECT", "Language detection"),
    ("ENABLE_PARALLEL_EMAIL", "Parallel email checks"),
    ("ENABLE_EMAIL_VERIFY", "Advanced email verification (SMTP)"),
    ("ENABLE_CACHING", "Cache intel between runs"),
    ("ENABLE_GITFIVE", "GitFive (GitHub emails/history)"),
    ("ENABLE_SOCID", "Socid Extractor (profile data)"),
    ("ENABLE_SHARETRACE", "ShareTrace (tracking link resolver)"),
    ("ENABLE_GOSEARCH", "Gosearch"),
    ("ENABLE_FACE_MATCH", "Face matching (disabled)"),
    ("ENABLE_TOUTATIS", "Toutatis (Instagram, needs session)"),
    # ── Paid contact-enrichment providers (both default OFF) ──────────
    ("ENABLE_APOLLO", "Apollo.io enrichment (PAID CREDITS — requires APOLLO_API_KEY)"),
    ("ENABLE_LUSHA",  "Lusha enrichment (PAID CREDITS — requires LUSHA_API_KEY)"),
    ("ENABLE_SHERLOCK", "[deprecated] Sherlock — replaced by User Scanner"),
    ("ENABLE_NAMINTER", "[deprecated] Naminter — replaced by User Scanner"),
    ("ENABLE_SOCIAL_ANALYZER", "[deprecated] Social Analyzer — replaced by User Scanner"),
]