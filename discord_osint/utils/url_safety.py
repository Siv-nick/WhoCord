
"""
discord_osint/utils/url_safety.py
----------------------------------
SSRF guard for outbound HTTP from OSINT scraping.

Change log
----------
- ``resolve_and_validate`` is now public. The SSL-certificate path in
  ``pipeline/stages/domain_investigation.py`` needs to resolve-then-pin
  before opening a TCP connection; it was previously reimplementing
  the blocklist check itself. Same function, wider visibility.
- ``safe_get_pinned`` is the recommended fetch helper. It resolves
  DNS once, validates every address, then forces the actual TCP connect
  to the validated IP for the duration of the request — closing the
  validate-then-reconnect TOCTOU where an attacker could flip the DNS
  record between ``validate_url`` and the fetch.
- TLS SNI, the Host header, and certificate verification are unaffected.
  The pin is achieved by overriding ``socket.getaddrinfo`` for the
  current thread, for one hostname, for the duration of the request.
  The URL is never rewritten to the raw IP, so the request still
  presents the original hostname end-to-end.
- Every redirect hop is re-resolved, re-validated, and re-pinned.
- ``safe_get`` is retained as a thin wrapper over ``safe_get_pinned`` for
  backward compatibility.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from contextlib import contextmanager
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

# Explicit hostnames blocked regardless of DNS. Defense in depth: some
# cloud metadata endpoints rely on a name that can be re-pointed.
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
        # Unparseable → treat as unsafe. Fail closed.
        return True

    if ip.version == 4:
        return any(ip in net for net in _BLOCKED_NETS_V4)

    # IPv6: unwrap v4-mapped and re-check as v4.
    if ip.ipv4_mapped is not None:
        return _is_blocked_ip(str(ip.ipv4_mapped))

    return any(ip in net for net in _BLOCKED_NETS_V6)


# ──────────────────────────────────────────────────────────────────────
# Thread-local DNS pinning
# ──────────────────────────────────────────────────────────────────────
#
# We install a wrapper around socket.getaddrinfo that consults a
# thread-local override table. The wrapper is installed once at import
# time so that urllib3/requests — which reach the OS through
# ``socket.getaddrinfo`` on the connect path — see the pin without any
# cooperation from requests itself.
#
# The alternative (rewriting the URL to the raw IP and setting a Host
# header) breaks HTTPS: the SNI sent in the ClientHello would be the IP
# literal, so the server presents a certificate for the wrong name and
# verification fails. Overriding DNS keeps the URL untouched, so SNI,
# the Host header, and cert verification all use the original hostname.
#
# Threading: overrides are stored on a thread-local. Two concurrent
# pinned requests from different threads cannot see each other's pins,
# and nested pins for the same host in the same thread restore the
# previous value on exit.

_original_getaddrinfo = socket.getaddrinfo
_pin_local            = threading.local()


def _pinned_getaddrinfo(host, port, *args, **kwargs):
    overrides = getattr(_pin_local, "overrides", None)
    if overrides and host in overrides:
        ip = overrides[host]
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return _original_getaddrinfo(host, port, *args, **kwargs)
        family = socket.AF_INET if ip_obj.version == 4 else socket.AF_INET6
        return [
            (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0))
        ]
    return _original_getaddrinfo(host, port, *args, **kwargs)


socket.getaddrinfo = _pinned_getaddrinfo


@contextmanager
def _pin_host(host: str, ip: str):
    """Force DNS resolution of *host* to *ip* for the current thread only."""
    overrides = getattr(_pin_local, "overrides", None)
    if overrides is None:
        overrides = {}
        _pin_local.overrides = overrides
    sentinel = object()
    previous = overrides.get(host, sentinel)
    overrides[host] = ip
    try:
        yield
    finally:
        if previous is sentinel:
            overrides.pop(host, None)
        else:
            overrides[host] = previous


# ──────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────

def resolve_and_validate(host: str) -> str:
    """
    Resolve *host* via the real getaddrinfo and return the first IP.

    Raises ``UnsafeURLError`` when resolution fails, returns nothing, or
    any resolved address is blocked. Rejecting the whole URL when *any*
    address is blocked is deliberate: a host with mixed public/private A
    records is a DNS-rebinding red flag.

    Public because the SSL-cert path in ``domain_investigation.py``
    needs to pin the connection to a validated IP before calling
    ``socket.create_connection``. Every caller that has a fully-formed
    URL should be using ``safe_get_pinned`` or ``validate_url`` instead.
    """
    try:
        infos = _original_getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"DNS resolution failed for {host!r}: {exc}")
    except Exception as exc:
        raise UnsafeURLError(f"DNS resolution error for {host!r}: {exc}")

    if not infos:
        raise UnsafeURLError(f"no addresses resolved for {host!r}")

    for info in infos:
        addr = info[4][0]
        if _is_blocked_ip(addr):
            raise UnsafeURLError(
                f"hostname {host!r} resolves to blocked address {addr}"
            )
    return infos[0][4][0]


def validate_url(url: str) -> None:
    """
    Raise :class:`UnsafeURLError` if *url* is unsafe to fetch.

    Checks, in order:
      1. Non-empty string, parseable.
      2. Scheme is http or https.
      3. Hostname present and not in the blocklist.
      4. If the host is an IP literal, it's public.
      5. Otherwise every address returned by ``getaddrinfo`` is public.
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

    try:
        ipaddress.ip_address(host)
        if _is_blocked_ip(host):
            raise UnsafeURLError(f"IP {host!r} is private or reserved")
        return
    except ValueError:
        pass  # not an IP literal → fall through to DNS

    resolve_and_validate(host)


def is_safe_url(url: str) -> bool:
    """Bool wrapper around :func:`validate_url`. Never raises."""
    try:
        validate_url(url)
        return True
    except UnsafeURLError:
        return False
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────
# Pinned fetch
# ──────────────────────────────────────────────────────────────────────

def safe_get_pinned(
    url: str,
    *,
    session: requests.Session | None = None,
    timeout: int = 10,
    headers: dict | None = None,
    max_redirects: int = 5,
    redirect_trail: list[str] | None = None,
    **kwargs,
) -> requests.Response:
    """
    ``session.get()`` with SSRF protection and DNS pinning.

    Difference from the old ``safe_get``: the old implementation validated
    the host, then handed the URL to requests, which resolved DNS *again*
    during the connect. Between the two resolutions the attacker could
    flip the record and land the connection on an internal address. This
    function resolves once, validates every address, and pins the actual
    TCP connect to the validated IP.

    TLS is unaffected: the URL is left alone, so SNI, Host, and
    certificate verification all use the original hostname.

    Parameters
    ----------
    session:
        Optional requests session. When omitted a fresh session is
        created and discarded. Reusing a *shared* session across pinned
        requests to the same host with a different pinned IP can leak a
        pooled keep-alive connection — omit this parameter unless you
        have a reason.
    redirect_trail:
        Optional list. When supplied, every URL visited — the starting
        URL and each redirect target, in order — is appended to it.
        ``requests`` normally exposes this as ``response.history``, but
        this function follows redirects manually (that's how each hop
        gets re-resolved and re-pinned) so ``response.history`` is
        always empty and ``response.url`` only ever shows the *final*
        URL. Callers that need to show or log the actual chain — the
        URL-analysis report does — could not do so without this, and
        were rendering ``final_url == url`` as "zero redirects" even
        when several had happened.
    """
    sess = session or requests.Session()
    if headers:
        sess.headers.update(headers)

    current = url
    for _hop in range(max_redirects + 1):
        if redirect_trail is not None:
            redirect_trail.append(current)

        parsed = urlparse(current)
        if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
            raise UnsafeURLError(f"scheme {parsed.scheme!r} not allowed")
        host = (parsed.hostname or "").lower()
        if not host:
            raise UnsafeURLError("no hostname")
        if host in _BLOCKED_HOSTNAMES:
            raise UnsafeURLError(f"hostname {host!r} is blocked")

        try:
            ipaddress.ip_address(host)
            if _is_blocked_ip(host):
                raise UnsafeURLError(f"IP {host!r} is private or reserved")
            pinned_ip = host  # already an IP literal
        except ValueError:
            pinned_ip = resolve_and_validate(host)

        with _pin_host(host, pinned_ip):
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

    raise UnsafeURLError("too many redirects")


def safe_get(
    url: str,
    *,
    session: requests.Session | None = None,
    timeout: int = 10,
    headers: dict | None = None,
    max_redirects: int = 5,
    redirect_trail: list[str] | None = None,
    **kwargs,
) -> requests.Response:
    """Backward-compatible alias for :func:`safe_get_pinned`."""
    return safe_get_pinned(
        url,
        session=session,
        timeout=timeout,
        headers=headers,
        max_redirects=max_redirects,
        redirect_trail=redirect_trail,
        **kwargs,
    )
