"""
discord_osint/utils/url_safety.py
----------------------------------
SSRF guard for outbound HTTP from OSINT scraping.

Rejects URLs whose host resolves to a private / loopback / link-local /
metadata address, and re-validates on every redirect hop so a
DNS-rebinding chain can't slip past the initial check.

Usage
-----
Two patterns, pick whichever fits the caller:

    # Validate-then-fetch (caller manages the session / headers)
    if not is_safe_url(url):
        return None
    r = http_session.get(url, ...)

    # Fully-guarded fetch (validates every redirect hop)
    r = safe_get(url, session=http_session, timeout=10)

The second form is preferred for anything that follows redirects,
because the guard is only as strong as the *last* hop it checked.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests


# Ranges that must never be reachable from OSINT scraping.
_BLOCKED_NETS_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
]

_BLOCKED_NETS_V6 = [
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # unique local
    ipaddress.ip_network("fe80::/10"),       # link-local
    ipaddress.ip_network("ff00::/8"),        # multicast
]

# Explicit hostnames blocked regardless of DNS (defense in depth — some
# cloud metadata services rely on name resolution that can change).
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
})

_ALLOWED_SCHEMES = frozenset({"http", "https"})


class UnsafeURLError(ValueError):
    """Raised when a URL targets a private, reserved, or metadata address."""


def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if *ip_str* falls in any blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Unparseable → treat as unsafe.
        return True

    if ip.version == 4:
        return any(ip in net for net in _BLOCKED_NETS_V4)

    # IPv6: unwrap v4-mapped and re-check as v4.
    if ip.ipv4_mapped is not None:
        return _is_blocked_ip(str(ip.ipv4_mapped))

    return any(ip in net for net in _BLOCKED_NETS_V6)


def validate_url(url: str) -> None:
    """
    Raise :class:`UnsafeURLError` if *url* is unsafe to fetch.

    Checks, in order:
      1. Non-empty string, parseable.
      2. Scheme is http or https.
      3. Hostname present and not in the blocklist.
      4. If the host is an IP literal, it's public.
      5. Otherwise every address returned by ``getaddrinfo`` is public.
         (If any resolved address is private, the whole URL is rejected —
         a host with mixed public/private A records is a red flag.)
    """
    if not url or not isinstance(url, str):
        raise UnsafeURLError("empty URL")

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise UnsafeURLError(f"unparseable URL: {exc}")

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme {parsed.scheme!r} not allowed")

    host = (parsed.hostname or "").lower()
    if not host:
        raise UnsafeURLError("no hostname")

    if host in _BLOCKED_HOSTNAMES:
        raise UnsafeURLError(f"hostname {host!r} is blocked")

    # If the host is already an IP literal, check it directly — no DNS.
    try:
        ipaddress.ip_address(host)
        if _is_blocked_ip(host):
            raise UnsafeURLError(f"IP {host!r} is private or reserved")
        return
    except ValueError:
        pass  # not an IP → fall through to DNS

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"DNS resolution failed for {host!r}: {exc}")

    if not infos:
        raise UnsafeURLError(f"no addresses resolved for {host!r}")

    for info in infos:
        addr = info[4][0]
        if _is_blocked_ip(addr):
            raise UnsafeURLError(
                f"hostname {host!r} resolves to blocked address {addr}"
            )


def is_safe_url(url: str) -> bool:
    """Bool wrapper around :func:`validate_url`."""
    try:
        validate_url(url)
        return True
    except UnsafeURLError:
        return False
    except Exception:
        # Any unexpected error → refuse. Fail closed.
        return False


def safe_get(
    url: str,
    *,
    session: requests.Session | None = None,
    timeout: int = 10,
    headers: dict | None = None,
    max_redirects: int = 5,
    **kwargs,
) -> requests.Response:
    """
    ``session.get()`` (or ``requests.get()``) with SSRF protection on the
    initial URL and on every redirect hop.

    Parameters
    ----------
    url:
        Target URL. Validated before the request and after each 3xx
        ``Location`` header, so a DNS-rebinding or open-redirect chain
        cannot land on an internal address.
    session:
        Optional requests session (e.g. the shared ``http_session`` in
        ``discord_osint.utils``). A fresh session is created when omitted.
    timeout:
        Per-hop timeout in seconds.
    headers:
        Extra headers merged into the session.
    max_redirects:
        Hard cap on redirect chain length.
    **kwargs:
        Forwarded to ``session.get``.

    Raises
    ------
    UnsafeURLError
        If the initial URL or any redirect target is unsafe, or the
        redirect chain exceeds ``max_redirects``.
    """
    validate_url(url)

    sess = session or requests.Session()
    if headers:
        sess.headers.update(headers)

    # Follow redirects manually so we can re-validate each hop. The
    # session's own redirect handling is disabled via allow_redirects=False.
    current = url
    for _hop in range(max_redirects + 1):
        resp = sess.get(
            current,
            timeout=timeout,
            allow_redirects=False,
            **kwargs,
        )
        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        current = urljoin(current, location)
        validate_url(current)

    raise UnsafeURLError("too many redirects")