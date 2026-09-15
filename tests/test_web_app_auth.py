
"""
tests/test_web_app_auth.py
--------------------------
Auth matrix for the Flask routes (Tier 1, item 1.1).

Public routes: `/`, `/index.html`, `/favicon.ico`, `/assets/*`,
`/static/*`, and any path not under `/api/` that isn't in the protected
set.

Protected routes: `/run`, `/config`, `/get_config`, `/stop`, `/report`,
`/upgrade_tools`, `/shutdown`, and everything under `/api/`.

Every protected route requires:
- a same-origin or absent Origin header,
- Sec-Fetch-Site not in {cross-site, same-site},
- a valid shared-secret token from X-WhoCord-Token or ?token=.

These tests exercise the gate, not the handlers. They use the Flask
test client with TESTING=True, so a request that passes the gate
reaches the view function and returns whatever it would return.
"""

from __future__ import annotations

import pytest


# ===========================================================================
# Public routes
# ===========================================================================

class TestPublicRoutes:
    def test_root_served_without_token(self, app_client):
        r = app_client.get("/")
        assert r.status_code == 200

    def test_favicon_public(self, app_client):
        r = app_client.get("/favicon.ico")
        # No route is defined for /favicon.ico; the important thing
        # is that it is not 401. 404 is fine.
        assert r.status_code != 401

    def test_spa_fallback_is_public(self, app_client):
        # A client-side route like /canvas serves the SPA shell, which
        # is public (its fetches carry the token from the meta tag).
        r = app_client.get("/canvas")
        assert r.status_code != 401


# ===========================================================================
# Protected routes — no token
# ===========================================================================

class TestProtectedNoToken:
    @pytest.mark.parametrize("method,path", [
        ("GET",  "/get_config"),
        ("POST", "/config"),
        ("POST", "/run"),
        ("POST", "/stop"),
        ("POST", "/shutdown"),
        ("POST", "/upgrade_tools"),
        ("GET",  "/api/investigations"),
        ("GET",  "/api/llm/models"),
    ])
    def test_no_token_is_401(self, app_client, method, path):
        r = app_client.open(path, method=method)
        assert r.status_code == 401, (
            f"{method} {path} returned {r.status_code}, expected 401"
        )


# ===========================================================================
# Protected routes — bad token
# ===========================================================================

class TestProtectedBadToken:
    def test_wrong_token_in_header(self, app_client):
        r = app_client.get("/get_config",
                           headers={"X-WhoCord-Token": "wrong-token"})
        assert r.status_code == 401

    def test_wrong_token_in_query(self, app_client):
        r = app_client.get("/get_config?token=wrong-token")
        assert r.status_code == 401

    def test_empty_token(self, app_client):
        r = app_client.get("/get_config", headers={"X-WhoCord-Token": ""})
        assert r.status_code == 401


# ===========================================================================
# Protected routes — valid token
# ===========================================================================

class TestProtectedValidToken:
    def test_valid_token_in_header(self, app_client, auth_headers):
        r = app_client.get("/get_config", headers=auth_headers)
        assert r.status_code == 200

    def test_valid_token_in_query(self, app_client, session_secret):
        r = app_client.get(f"/get_config?token={session_secret}")
        assert r.status_code == 200

    def test_header_takes_precedence_over_query(
        self, app_client, session_secret
    ):
        # Header wins when both are present.
        r = app_client.get(
            f"/get_config?token=bogus",
            headers={"X-WhoCord-Token": session_secret},
        )
        assert r.status_code == 200

    def test_protected_api_reachable_with_token(self, app_client, auth_headers):
        r = app_client.get("/api/investigations", headers=auth_headers)
        assert r.status_code == 200


# ===========================================================================
# Cross-origin rejection
# ===========================================================================

class TestCrossOriginRejection:
    def test_cross_origin_blocked(self, app_client, auth_headers):
        h = dict(auth_headers)
        h["Origin"] = "https://evil.example"
        r = app_client.get("/get_config", headers=h)
        assert r.status_code == 403
        assert b"cross-origin" in r.data.lower()

    def test_cross_site_sec_fetch_blocked(self, app_client, auth_headers):
        h = dict(auth_headers)
        h["Sec-Fetch-Site"] = "cross-site"
        r = app_client.get("/get_config", headers=h)
        assert r.status_code == 403

    def test_same_site_sec_fetch_blocked(self, app_client, auth_headers):
        h = dict(auth_headers)
        h["Sec-Fetch-Site"] = "same-site"
        r = app_client.get("/get_config", headers=h)
        assert r.status_code == 403

    def test_localhost_origin_allowed(self, app_client, auth_headers):
        h = dict(auth_headers)
        h["Origin"] = "http://localhost:5173"  # vite dev server
        r = app_client.get("/get_config", headers=h)
        assert r.status_code == 200

    def test_127_0_0_1_origin_allowed(self, app_client, auth_headers):
        h = dict(auth_headers)
        h["Origin"] = "http://127.0.0.1:5000"
        r = app_client.get("/get_config", headers=h)
        assert r.status_code == 200

    def test_missing_origin_allowed(self, app_client, auth_headers):
        # Non-browser clients (curl, tests) do not send Origin.
        r = app_client.get("/get_config", headers=auth_headers)
        assert r.status_code == 200


# ===========================================================================
# Security headers
# ===========================================================================

class TestSecurityHeaders:
    def test_headers_on_public_route(self, app_client):
        r = app_client.get("/")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "SAMEORIGIN"
        assert r.headers["Referrer-Policy"] == "no-referrer"
        assert "frame-ancestors 'self'" in r.headers["Content-Security-Policy"]

    def test_headers_on_401(self, app_client):
        r = app_client.get("/get_config")
        assert r.status_code == 401
        # Headers are added by after_request, which runs on the 401 too.
        assert r.headers["X-Content-Type-Options"] == "nosniff"

    def test_headers_on_403(self, app_client, auth_headers):
        h = dict(auth_headers)
        h["Origin"] = "https://evil.example"
        r = app_client.get("/get_config", headers=h)
        assert r.status_code == 403
        assert r.headers["X-Content-Type-Options"] == "nosniff"


# ===========================================================================
# Session cookie issuance
# ===========================================================================

class TestSessionCookieIssuance:
    """
    Auth moved from a <meta name="whocord-token"> tag to an HttpOnly
    session cookie. These tests replace the old meta-tag test, which
    asserted the opposite of the current (better) design: that the
    install-wide shared secret was embedded in the served HTML where
    any script on the page could read it.
    """

    def test_index_sets_session_cookie(self, app_client):
        r = app_client.get("/")
        if r.status_code != 200:
            pytest.skip("index route did not serve HTML")

        cookie_header = "; ".join(
            v for k, v in r.headers.items() if k.lower() == "set-cookie"
        )
        assert "whocord_session=" in cookie_header, (
            "index did not issue a session cookie — the frontend "
            "cannot authenticate"
        )
        assert "HttpOnly" in cookie_header, (
            "session cookie must be HttpOnly so page scripts cannot "
            "read it"
        )
        assert "SameSite=Lax" in cookie_header, (
            "session cookie must be SameSite=Lax to blunt cross-site "
            "state-changing requests"
        )

    def test_index_does_not_leak_shared_secret(self, app_client, session_secret):
        r = app_client.get("/")
        if r.status_code != 200:
            pytest.skip("index route did not serve HTML")
        body = r.data.decode("utf-8", errors="replace")

        assert session_secret not in body, (
            "the install-wide shared secret must never be embedded in "
            "served HTML"
        )
        assert "whocord-token" not in body, (
            "the token meta tag was removed in the cookie migration; "
            "reintroducing it puts the secret back in the DOM"
        )

    def test_session_cookie_authenticates_protected_route(self, app_client):
        # Visiting the index issues the cookie; the test client keeps it.
        app_client.get("/")
        r = app_client.get("/get_config")
        assert r.status_code == 200, (
            "a browser that has been served the index should be able to "
            "reach a protected route using only its session cookie"
        )
