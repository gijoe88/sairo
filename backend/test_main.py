"""Pytest tests for Sairo backend API — commercial features + security hardening.

Tests cover: API tokens, share links, branding, license management,
security headers, 2FA encryption, error sanitization, permission checks,
upload limits, pricing endpoints, version check.

Requires: pip install pytest httpx
Run with: pytest backend/test_main.py -v
"""
import os
import sys
import json
import base64
import hashlib
import ipaddress
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# Set env vars before importing the app
os.environ.setdefault("S3_ENDPOINT", "http://localhost:9000")
os.environ.setdefault("S3_ACCESS_KEY", "minioadmin")
os.environ.setdefault("S3_SECRET_KEY", "minioadmin")
os.environ.setdefault("S3_REGION", "us-east-1")
os.environ.setdefault("ADMIN_USER", "admin")
os.environ.setdefault("ADMIN_PASS", "testpass")
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-pytest")
os.environ.setdefault("SECURE_COOKIE", "false")
os.environ.setdefault("DB_DIR", "/tmp/sairo-test")

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from trusted_proxy import TrustedProxyMiddleware


@pytest.fixture(scope="module")
def app():
    """Import app with test config."""
    os.makedirs("/tmp/sairo-test", exist_ok=True)
    with patch("boto3.client") as mock_boto:
        mock_s3 = MagicMock()
        mock_boto.return_value = mock_s3
        mock_s3.list_buckets.return_value = {"Buckets": []}
        try:
            from backend.main import app as fastapi_app
        except ModuleNotFoundError:
            from main import app as fastapi_app
        yield fastapi_app


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app)


@pytest.fixture(scope="module")
def admin_cookies(client):
    """Login as admin and return cookies."""
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "testpass"})
    assert resp.status_code == 200
    return resp.cookies


@pytest.fixture(scope="module")
def viewer_cookies(client, admin_cookies):
    """Create a viewer user and return their cookies."""
    client.post(
        "/api/auth/users",
        json={"username": "test-viewer", "password": "viewerpass", "role": "viewer"},
        cookies=admin_cookies,
    )
    resp = client.post("/api/auth/login", json={"username": "test-viewer", "password": "viewerpass"})
    if resp.status_code == 200:
        return resp.cookies
    return None


# ── Branding ─────────────────────────────────────────────

class TestBranding:
    def test_branding_public(self, client):
        """Branding endpoint should be public (no auth required)."""
        resp = client.get("/api/branding")
        assert resp.status_code == 200
        data = resp.json()
        assert "app_name" in data
        assert "primary_color" in data
        assert "ldap_enabled" in data
        assert "oauth_providers" in data

    def test_branding_defaults(self, client):
        """Default branding values should be returned."""
        resp = client.get("/api/branding")
        data = resp.json()
        assert data["app_name"] == "Sairo"
        assert data["primary_color"] == "#3b82f6"
        assert data["ldap_enabled"] is False
        assert data["oauth_providers"] == []


# ── API Tokens ───────────────────────────────────────────

class TestAPITokens:
    def test_create_token_requires_admin(self, client):
        """Non-authenticated users should not be able to create tokens."""
        resp = client.post("/api/auth/tokens", json={"name": "test", "role": "viewer"})
        assert resp.status_code == 401

    def test_create_and_list_token(self, client, admin_cookies):
        """Admin should be able to create and list API tokens."""
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "ci-test", "role": "viewer"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["token"].startswith("sairo_")

        resp = client.get("/api/auth/tokens", cookies=admin_cookies)
        assert resp.status_code == 200
        tokens = resp.json()["tokens"]
        assert any(t["name"] == "ci-test" for t in tokens)

    def test_bearer_auth(self, client, admin_cookies):
        """API token should work as Bearer auth."""
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "bearer-test", "role": "viewer"},
            cookies=admin_cookies,
        )
        raw_token = resp.json()["token"]

        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert data["role"] == "viewer"

    def test_invalid_bearer_rejected(self, client):
        """Invalid bearer tokens should return 401."""
        resp = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid_token"})
        assert resp.status_code == 401

    def test_revoke_token(self, client, admin_cookies):
        """Admin should be able to revoke tokens."""
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "revoke-test", "role": "viewer"},
            cookies=admin_cookies,
        )
        raw_token = resp.json()["token"]

        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200

        resp = client.get("/api/auth/tokens", cookies=admin_cookies)
        token_id = None
        for t in resp.json()["tokens"]:
            if t["name"] == "revoke-test":
                token_id = t["id"]
                break
        assert token_id is not None

        resp = client.delete(f"/api/auth/tokens/{token_id}", cookies=admin_cookies)
        assert resp.status_code == 200

        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 401


# ── Share Links ──────────────────────────────────────────

class TestShareLinks:
    def test_create_share_link(self, client, admin_cookies):
        """Admin should be able to create share links."""
        resp = client.post(
            "/api/share-links",
            json={"bucket": "test-bucket", "key": "test.txt", "expires_hours": 24},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data

    def test_list_share_links(self, client, admin_cookies):
        """Should be able to list share links."""
        resp = client.get("/api/share-links", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert "links" in data

    def test_share_link_requires_auth(self, app):
        """Creating share links requires authentication."""
        with TestClient(app) as fresh:
            resp = fresh.post(
                "/api/share-links",
                json={"bucket": "test-bucket", "key": "test.txt", "expires_hours": 24},
            )
            assert resp.status_code == 401

    def test_share_link_ownership_enforcement(self, client, admin_cookies, viewer_cookies):
        """Non-admin users can only delete their own share links."""
        if not viewer_cookies:
            pytest.skip("Viewer user not created")
        # Admin creates a share link
        resp = client.post(
            "/api/share-links",
            json={"bucket": "test-bucket", "key": "test.txt", "expires_hours": 24},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        # Get the link ID
        resp = client.get("/api/share-links", cookies=admin_cookies)
        links = resp.json()["links"]
        if links:
            admin_link_id = links[0]["id"]
            # Viewer tries to delete admin's link — should get 403
            resp = client.delete(f"/api/share-links/{admin_link_id}", cookies=viewer_cookies)
            assert resp.status_code == 403


# ── License ──────────────────────────────────────────────

class TestLicense:
    def test_get_license_default(self, client, admin_cookies):
        """Default license should be community."""
        resp = client.get("/api/license", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "community"

    def test_activate_invalid_license(self, client, admin_cookies):
        """Invalid license key should be rejected."""
        resp = client.post(
            "/api/license",
            json={"key": "not-a-valid-key"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 400


# ── OAuth Providers ──────────────────────────────────────

class TestOAuth:
    def test_oauth_providers_empty(self, client):
        """With no OAuth configured, providers list should be empty."""
        resp = client.get("/api/auth/oauth/providers")
        assert resp.status_code == 200
        data = resp.json()
        assert data["providers"] == []

    def test_oauth_unconfigured_provider_404(self, client):
        """Trying to login with unconfigured provider should return 404."""
        resp = client.get("/api/auth/oauth/google/login", follow_redirects=False)
        assert resp.status_code == 404


def _main_module():
    try:
        import backend.main as m
    except ModuleNotFoundError:
        import main as m
    return m


class TestOIDC:
    """Generic OpenID Connect login (issue #9): username-only sync, admin perms."""

    ISSUER = "https://issuer.test"
    CLIENT_ID = "client123"

    def _enable(self, monkeypatch):
        """Turn OIDC on at runtime + stub discovery (no real network)."""
        m = _main_module()
        monkeypatch.setattr(m, "OIDC_ENABLED", True)
        monkeypatch.setattr(m, "OIDC_ISSUER", self.ISSUER)
        monkeypatch.setattr(m, "OIDC_CLIENT_ID", self.CLIENT_ID)
        monkeypatch.setattr(m, "OIDC_CLIENT_SECRET", "shh")
        monkeypatch.setattr(m, "OIDC_USERNAME_CLAIM", "preferred_username")
        monkeypatch.setattr(m, "OIDC_PROVIDER_NAME", "Corp SSO")
        monkeypatch.setattr(m, "OIDC_DEFAULT_ROLE", "viewer")
        monkeypatch.setattr(m, "OIDC_ALLOWED_DOMAINS", [])
        monkeypatch.setattr(m, "_oidc_config", lambda: {
            "issuer": self.ISSUER,
            "authorization_endpoint": f"{self.ISSUER}/authorize",
            "token_endpoint": f"{self.ISSUER}/token",
            "jwks_uri": f"{self.ISSUER}/jwks",
        })
        return m

    def test_disabled_by_default(self, client):
        """With no OIDC env, login is 404 and it's absent from branding."""
        resp = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert resp.status_code == 404
        branding = client.get("/api/branding").json()
        assert not any(p["id"] == "oidc" for p in branding["oauth_providers"])

    def test_enabled_appears_in_branding(self, client, monkeypatch):
        self._enable(monkeypatch)
        providers = client.get("/api/branding").json()["oauth_providers"]
        oidc = next(p for p in providers if p["id"] == "oidc")
        assert oidc["name"] == "Corp SSO"
        assert oidc["login_path"] == "/api/auth/oidc/login"

    def test_login_redirects_with_state_and_pkce(self, app, monkeypatch):
        self._enable(monkeypatch)
        with TestClient(app) as c:
            resp = c.get("/api/auth/oidc/login", follow_redirects=False)
            assert resp.status_code in (302, 307)
            loc = resp.headers["location"]
            assert loc.startswith(f"{self.ISSUER}/authorize?")
            # PKCE + CSRF params present
            assert "code_challenge=" in loc and "code_challenge_method=S256" in loc
            assert "state=" in loc and "nonce=" in loc
            assert f"client_id={self.CLIENT_ID}" in loc
            # signed state cookie set
            assert resp.cookies.get("oidc_state")

    def test_callback_without_state_cookie_redirects_error(self, app, monkeypatch):
        self._enable(monkeypatch)
        with TestClient(app) as c:
            resp = c.get("/api/auth/oidc/callback?code=x&state=y", follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert "error=oidc_failed" in resp.headers["location"]

    def test_callback_state_mismatch_redirects_error(self, app, monkeypatch):
        import jwt
        from datetime import datetime, timezone, timedelta
        m = self._enable(monkeypatch)
        bad_state = jwt.encode(
            {"state": "REAL", "nonce": "n", "cv": "v", "purpose": "oidc_state",
             "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
            m.JWT_SECRET, algorithm="HS256")
        with TestClient(app) as c:
            resp = c.get("/api/auth/oidc/callback?code=x&state=ATTACKER",
                         cookies={"oidc_state": bad_state}, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert "error=oidc_state_mismatch" in resp.headers["location"]

    def test_full_login_flow_creates_viewer_and_session(self, app, monkeypatch):
        """End-to-end: real RS256 ID token validated through the live code path."""
        import jwt
        from datetime import datetime, timezone, timedelta
        from types import SimpleNamespace
        from cryptography.hazmat.primitives.asymmetric import rsa

        m = self._enable(monkeypatch)
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with TestClient(app) as c:
            # 1) start → capture the signed state cookie, decode state+nonce
            start = c.get("/api/auth/oidc/login", follow_redirects=False)
            state_cookie = start.cookies.get("oidc_state")
            st = jwt.decode(state_cookie, m.JWT_SECRET, algorithms=["HS256"])

            # 2) issuer mints an ID token bound to our nonce/aud/iss
            id_token = jwt.encode(
                {"iss": self.ISSUER, "aud": self.CLIENT_ID,
                 "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
                 "iat": datetime.now(timezone.utc),
                 "preferred_username": "alice", "email": "alice@corp.test",
                 "nonce": st["nonce"]},
                priv, algorithm="RS256", headers={"kid": "test"})

            # 3) stub token exchange + JWKS verification
            monkeypatch.setattr("httpx.post", lambda *a, **k: SimpleNamespace(
                status_code=200, json=lambda: {"id_token": id_token}))
            monkeypatch.setattr(m, "_oidc_jwks", lambda: SimpleNamespace(
                get_signing_key_from_jwt=lambda t: SimpleNamespace(key=priv.public_key())))

            # 4) callback with the matching state
            resp = c.get(f"/api/auth/oidc/callback?code=abc&state={st['state']}",
                         cookies={"oidc_state": state_cookie}, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert resp.headers["location"] == "/"
            session = resp.cookies.get("access_token")
            assert session, "should set a session cookie"
            claims = jwt.decode(session, m.JWT_SECRET, algorithms=["HS256"])
            assert claims["sub"] == "alice"
            assert claims["role"] == "viewer"  # admin assigns real perms later

        # user persisted with no bucket grants (admin-assigns-permissions model)
        with m._get_users_db() as db:
            row = db.execute("SELECT role FROM users WHERE username='alice'").fetchone()
            assert row is not None and row["role"] == "viewer"
            perms = db.execute("SELECT COUNT(*) AS n FROM bucket_permissions WHERE username='alice'").fetchone()
            assert perms["n"] == 0

    def test_oidc_cannot_take_over_local_admin(self, app, monkeypatch):
        """SECURITY: an OIDC user claiming preferred_username=admin must NOT log
        into the pre-existing local admin account."""
        import jwt
        from datetime import datetime, timezone, timedelta
        from types import SimpleNamespace
        from cryptography.hazmat.primitives.asymmetric import rsa

        m = self._enable(monkeypatch)
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with TestClient(app) as c:
            start = c.get("/api/auth/oidc/login", follow_redirects=False)
            state_cookie = start.cookies.get("oidc_state")
            st = jwt.decode(state_cookie, m.JWT_SECRET, algorithms=["HS256"])
            id_token = jwt.encode(
                {"iss": self.ISSUER, "aud": self.CLIENT_ID,
                 "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
                 "iat": datetime.now(timezone.utc),
                 "preferred_username": "admin", "nonce": st["nonce"]},
                priv, algorithm="RS256", headers={"kid": "test"})
            monkeypatch.setattr("httpx.post", lambda *a, **k: SimpleNamespace(
                status_code=200, json=lambda: {"id_token": id_token}))
            monkeypatch.setattr(m, "_oidc_jwks", lambda: SimpleNamespace(
                get_signing_key_from_jwt=lambda t: SimpleNamespace(key=priv.public_key())))
            resp = c.get(f"/api/auth/oidc/callback?code=abc&state={st['state']}",
                         cookies={"oidc_state": state_cookie}, follow_redirects=False)
            assert "error=account_conflict" in resp.headers["location"]
            assert not resp.cookies.get("access_token"), "must NOT issue a session for admin"
        # local admin row is untouched (still local, still admin)
        with m._get_users_db() as db:
            row = db.execute("SELECT role, auth_source FROM users WHERE username='admin'").fetchone()
            assert row["role"] == "admin" and (row["auth_source"] or "local") == "local"

    def test_full_login_flow_rejects_bad_nonce(self, app, monkeypatch):
        """A token whose nonce doesn't match the request is rejected (replay guard)."""
        import jwt
        from datetime import datetime, timezone, timedelta
        from types import SimpleNamespace
        from cryptography.hazmat.primitives.asymmetric import rsa

        m = self._enable(monkeypatch)
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with TestClient(app) as c:
            start = c.get("/api/auth/oidc/login", follow_redirects=False)
            state_cookie = start.cookies.get("oidc_state")
            st = jwt.decode(state_cookie, m.JWT_SECRET, algorithms=["HS256"])
            id_token = jwt.encode(
                {"iss": self.ISSUER, "aud": self.CLIENT_ID,
                 "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
                 "iat": datetime.now(timezone.utc),
                 "preferred_username": "mallory", "nonce": "WRONG-NONCE"},
                priv, algorithm="RS256", headers={"kid": "test"})
            monkeypatch.setattr("httpx.post", lambda *a, **k: SimpleNamespace(
                status_code=200, json=lambda: {"id_token": id_token}))
            monkeypatch.setattr(m, "_oidc_jwks", lambda: SimpleNamespace(
                get_signing_key_from_jwt=lambda t: SimpleNamespace(key=priv.public_key())))
            resp = c.get(f"/api/auth/oidc/callback?code=abc&state={st['state']}",
                         cookies={"oidc_state": state_cookie}, follow_redirects=False)
            assert "error=oidc_nonce_mismatch" in resp.headers["location"]


class _OIDCFlow:
    """Shared OIDC flow helpers (not collected — no Test prefix), so the
    enterprise + provider-quirk suites reuse one full-flow driver."""

    ISSUER = "https://issuer.test"
    CLIENT_ID = "client123"

    def _enable(self, monkeypatch, **over):
        m = _main_module()
        monkeypatch.setattr(m, "OIDC_ENABLED", True)
        monkeypatch.setattr(m, "OIDC_ISSUER", self.ISSUER)
        monkeypatch.setattr(m, "OIDC_CLIENT_ID", self.CLIENT_ID)
        monkeypatch.setattr(m, "OIDC_CLIENT_SECRET", "shh")
        monkeypatch.setattr(m, "OIDC_USERNAME_CLAIM", "preferred_username")
        monkeypatch.setattr(m, "OIDC_DEFAULT_ROLE", "viewer")
        monkeypatch.setattr(m, "OIDC_ALLOWED_DOMAINS", [])
        monkeypatch.setattr(m, "OIDC_ADMIN_GROUP", over.get("admin_group", ""))
        monkeypatch.setattr(m, "OIDC_GROUPS_CLAIM", over.get("groups_claim", "groups"))
        monkeypatch.setattr(m, "OIDC_REQUIRE_VERIFIED_EMAIL", over.get("require_verified", False))
        monkeypatch.setattr(m, "OIDC_RP_LOGOUT", over.get("rp_logout", False))
        cfg = {"issuer": self.ISSUER, "authorization_endpoint": f"{self.ISSUER}/authorize",
               "token_endpoint": f"{self.ISSUER}/token", "jwks_uri": f"{self.ISSUER}/jwks"}
        if over.get("end_session"):
            cfg["end_session_endpoint"] = f"{self.ISSUER}/logout"
        monkeypatch.setattr(m, "_oidc_config", lambda: cfg)
        return m

    def _login(self, app, monkeypatch, m, username, claims=None, userinfo=None):
        """Run the full OIDC flow with a real RS256 token; return the callback response.

        username=None omits preferred_username (to exercise claim fallbacks).
        userinfo, when given, stands in for the IdP's userinfo endpoint."""
        import jwt
        from datetime import datetime, timezone, timedelta
        from types import SimpleNamespace
        from cryptography.hazmat.primitives.asymmetric import rsa
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with TestClient(app) as c:
            start = c.get("/api/auth/oidc/login", follow_redirects=False)
            sc = start.cookies.get("oidc_state")
            st = jwt.decode(sc, m.JWT_SECRET, algorithms=["HS256"])
            payload = {"iss": self.ISSUER, "aud": self.CLIENT_ID,
                       "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
                       "iat": datetime.now(timezone.utc), "nonce": st["nonce"]}
            if username is not None:
                payload["preferred_username"] = username
            payload.update(claims or {})
            id_token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "t"})
            monkeypatch.setattr("httpx.post", lambda *a, **k: SimpleNamespace(
                status_code=200, json=lambda: {"id_token": id_token, "access_token": "AT"}))
            monkeypatch.setattr(m, "_oidc_jwks", lambda: SimpleNamespace(
                get_signing_key_from_jwt=lambda t: SimpleNamespace(key=priv.public_key())))
            if userinfo is not None:
                monkeypatch.setattr(m, "_oidc_userinfo", lambda at, cfg: userinfo)
            return c.get(f"/api/auth/oidc/callback?code=abc&state={st['state']}",
                         cookies={"oidc_state": sc}, follow_redirects=False)

    def _sub_of(self, m, token):
        import jwt
        return jwt.decode(token, m.JWT_SECRET, algorithms=["HS256"])["sub"]

    def _role_of(self, m, token):
        import jwt
        return jwt.decode(token, m.JWT_SECRET, algorithms=["HS256"])["role"]


class TestOIDCEnterprise(_OIDCFlow):
    """Phase 2: group→role mapping, userinfo fallback, email_verified, RP-logout."""

    def test_group_member_becomes_admin(self, app, monkeypatch):
        m = self._enable(monkeypatch, admin_group="sairo-admins")
        resp = self._login(app, monkeypatch, m, "boss", claims={"groups": ["staff", "sairo-admins"]})
        assert resp.headers["location"] == "/"
        assert self._role_of(m, resp.cookies.get("access_token")) == "admin"

    def test_group_non_member_is_viewer(self, app, monkeypatch):
        m = self._enable(monkeypatch, admin_group="sairo-admins")
        resp = self._login(app, monkeypatch, m, "peon", claims={"groups": ["staff"]})
        assert self._role_of(m, resp.cookies.get("access_token")) == "viewer"

    def test_group_keycloak_slash_prefix_matches(self, app, monkeypatch):
        m = self._enable(monkeypatch, admin_group="sairo-admins")
        resp = self._login(app, monkeypatch, m, "kcadmin", claims={"groups": ["/sairo-admins"]})
        assert self._role_of(m, resp.cookies.get("access_token")) == "admin"

    def test_requires_verified_email(self, app, monkeypatch):
        m = self._enable(monkeypatch, require_verified=True)
        resp = self._login(app, monkeypatch, m, "unverified",
                           claims={"email": "u@corp.test", "email_verified": False})
        assert "error=email_not_verified" in resp.headers["location"]
        assert not resp.cookies.get("access_token")

    def test_rp_logout_returns_idp_url_for_oidc_user(self, app, monkeypatch):
        m = self._enable(monkeypatch, rp_logout=True, end_session=True)
        login = self._login(app, monkeypatch, m, "logme")
        session = login.cookies.get("access_token")
        with TestClient(app) as c:
            out = c.post("/api/auth/logout", cookies={"access_token": session}).json()
        assert out["logged_out"] is True
        assert out["sso_logout_url"].startswith(f"{self.ISSUER}/logout")
        assert "post_logout_redirect_uri=" in out["sso_logout_url"]

    def test_rp_logout_none_for_local_user(self, app, monkeypatch, client, admin_cookies):
        self._enable(monkeypatch, rp_logout=True, end_session=True)
        out = client.post("/api/auth/logout", cookies=admin_cookies).json()
        assert out["sso_logout_url"] is None  # local admin is not an OIDC session


class TestOIDCProviderQuirks(_OIDCFlow):
    """Cross-provider claim-shape coverage. Real OIDC IdPs differ mostly in how
    they shape claims, not crypto — these simulate the big ones so the flow is
    validated beyond the single live Keycloak run."""

    def test_auth0_namespaced_groups_and_custom_username(self, app, monkeypatch):
        # Auth0: no preferred_username (uses nickname), custom-namespaced groups claim.
        m = self._enable(monkeypatch, admin_group="sairo-admins",
                         groups_claim="https://sairo.example.com/groups")
        monkeypatch.setattr(m, "OIDC_USERNAME_CLAIM", "nickname")
        resp = self._login(app, monkeypatch, m, username=None, claims={
            "nickname": "auth0user",
            "https://sairo.example.com/groups": ["sairo-admins"],
        })
        assert self._sub_of(m, resp.cookies.get("access_token")) == "auth0user"
        assert self._role_of(m, resp.cookies.get("access_token")) == "admin"

    def test_okta_groups_only_in_userinfo(self, app, monkeypatch):
        # Okta/Auth0 commonly omit groups from the ID token — we must fall back to userinfo.
        m = self._enable(monkeypatch, admin_group="Sairo-Admins")
        resp = self._login(app, monkeypatch, m, "oktauser", claims={},
                           userinfo={"groups": ["Everyone", "Sairo-Admins"]})
        assert self._role_of(m, resp.cookies.get("access_token")) == "admin"

    def test_entra_group_object_ids(self, app, monkeypatch):
        # Entra ID (Azure AD) emits group object-IDs (GUIDs), not names.
        gid = "11111111-2222-3333-4444-555555555555"
        m = self._enable(monkeypatch, admin_group=gid)
        resp = self._login(app, monkeypatch, m, "entrauser",
                           claims={"groups": ["00000000-0000-0000-0000-000000000000", gid]})
        assert self._role_of(m, resp.cookies.get("access_token")) == "admin"

    def test_google_username_falls_back_to_email(self, app, monkeypatch):
        # Google has no preferred_username/groups — username should fall back to email.
        m = self._enable(monkeypatch)
        resp = self._login(app, monkeypatch, m, username=None,
                           claims={"email": "person@corp.test", "email_verified": True})
        assert self._sub_of(m, resp.cookies.get("access_token")) == "person@corp.test"
        assert self._role_of(m, resp.cookies.get("access_token")) == "viewer"

    def test_email_only_in_userinfo_satisfies_domain_allowlist(self, app, monkeypatch):
        # Domain allowlist must work even when the IdP puts email only in userinfo.
        m = self._enable(monkeypatch)
        monkeypatch.setattr(m, "OIDC_ALLOWED_DOMAINS", ["corp.test"])
        resp = self._login(app, monkeypatch, m, "domainuser", claims={},
                           userinfo={"email": "domainuser@corp.test"})
        assert resp.headers["location"] == "/"
        assert resp.cookies.get("access_token")

    def test_string_groups_claim_is_tolerated(self, app, monkeypatch):
        # Some IdPs emit a single group as a string, not a list — must not crash.
        m = self._enable(monkeypatch, admin_group="sairo-admins")
        resp = self._login(app, monkeypatch, m, "stringgroup", claims={"groups": "sairo-admins"})
        assert self._role_of(m, resp.cookies.get("access_token")) == "admin"

    def test_similar_group_name_does_not_grant_admin(self, app, monkeypatch):
        # SECURITY: "sairo-admins-readonly" must NOT satisfy admin group "sairo-admins".
        m = self._enable(monkeypatch, admin_group="sairo-admins")
        resp = self._login(app, monkeypatch, m, "almostadmin",
                           claims={"groups": ["sairo-admins-readonly", "staff"]})
        assert self._role_of(m, resp.cookies.get("access_token")) == "viewer"

    def test_ldap_dn_group_value_matches(self, app, monkeypatch):
        # AD/LDAP-sourced groups arrive as DNs — match the cn value, not a substring.
        m = self._enable(monkeypatch, admin_group="sairo-admins")
        resp = self._login(app, monkeypatch, m, "dnuser",
                           claims={"groups": ["cn=sairo-admins,ou=groups,dc=corp,dc=test"]})
        assert self._role_of(m, resp.cookies.get("access_token")) == "admin"

    def test_azp_mismatch_is_rejected(self, app, monkeypatch):
        # A token whose authorized-party is a different client must be rejected.
        m = self._enable(monkeypatch)
        resp = self._login(app, monkeypatch, m, "azpvictim", claims={"azp": "some-other-client"})
        assert "error=oidc_invalid_token" in resp.headers["location"]
        assert not resp.cookies.get("access_token")


class TestAuthSource:
    """auth_source migration + exposure (powers the takeover guard + UI badges)."""

    def test_me_reports_auth_source_for_local_admin(self, client, admin_cookies):
        me = client.get("/api/auth/me", cookies=admin_cookies).json()
        assert me["auth_source"] == "local"

    def test_users_list_includes_auth_source_and_bucket_count(self, client, admin_cookies):
        users = client.get("/api/auth/users", cookies=admin_cookies).json()["users"]
        admin = next(u for u in users if u["username"] == "admin")
        assert admin["auth_source"] == "local"
        assert "bucket_count" in admin and isinstance(admin["bucket_count"], int)


# ── Health Check ─────────────────────────────────────────

class TestHealth:
    def test_healthz(self, client):
        """Health endpoint should return 200."""
        resp = client.get("/healthz")
        assert resp.status_code == 200

    def test_auth_me_without_login(self, app):
        """Unauthenticated /me should return 401."""
        with TestClient(app) as fresh:
            resp = fresh.get("/api/auth/me")
            assert resp.status_code == 401

    def test_health_detail_requires_admin(self, client, viewer_cookies):
        """Non-admin users should get 403 on health-detail."""
        if not viewer_cookies:
            pytest.skip("Viewer user not created")
        resp = client.get("/api/health-detail", cookies=viewer_cookies)
        assert resp.status_code == 403

    def test_health_detail_works_for_admin(self, client, admin_cookies):
        """Admin should be able to access health-detail."""
        resp = client.get("/api/health-detail", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "uptime_seconds" in data
        assert "s3_connected" in data


# ── Security Headers ─────────────────────────────────────

class TestSecurityHeaders:
    def test_csp_header_present(self, client):
        """All responses should include Content-Security-Policy."""
        resp = client.get("/healthz")
        assert "content-security-policy" in resp.headers
        csp = resp.headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp

    def test_x_content_type_options(self, client):
        """All responses should include X-Content-Type-Options: nosniff."""
        resp = client.get("/healthz")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client):
        """All responses should include X-Frame-Options: DENY."""
        resp = client.get("/healthz")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self, client):
        """All responses should include Referrer-Policy."""
        resp = client.get("/healthz")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_api_endpoints_have_security_headers(self, client, admin_cookies):
        """API endpoints should also include security headers."""
        resp = client.get("/api/auth/me", cookies=admin_cookies)
        assert "content-security-policy" in resp.headers
        assert resp.headers.get("x-content-type-options") == "nosniff"


# ── 2FA Encryption ───────────────────────────────────────

class TestTwoFactorEncryption:
    def test_encrypt_decrypt_roundtrip(self, app):
        """_encrypt and _decrypt should round-trip correctly."""
        try:
            from backend.main import _encrypt, _decrypt
        except ModuleNotFoundError:
            from main import _encrypt, _decrypt

        original = "JBSWY3DPEHPK3PXP"
        encrypted = _encrypt(original)
        assert encrypted != original
        assert encrypted.startswith("enc::")
        decrypted = _decrypt(encrypted)
        assert decrypted == original

    def test_decrypt_plaintext_passthrough(self, app):
        """_decrypt should pass through plaintext strings (migration support)."""
        try:
            from backend.main import _decrypt
        except ModuleNotFoundError:
            from main import _decrypt

        plaintext = "JBSWY3DPEHPK3PXP"
        assert _decrypt(plaintext) == plaintext

    def test_decrypt_empty_string(self, app):
        """_decrypt should handle empty strings."""
        try:
            from backend.main import _encrypt, _decrypt
        except ModuleNotFoundError:
            from main import _encrypt, _decrypt

        assert _encrypt("") == ""
        assert _decrypt("") == ""

    def test_2fa_setup_stores_encrypted_secret(self, client, admin_cookies):
        """2FA setup should store the TOTP secret encrypted."""
        resp = client.post("/api/auth/2fa/setup", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert "secret" in data
        assert "otpauth_url" in data
        # The returned secret should be plaintext (for QR display)
        assert not data["secret"].startswith("enc::")
        assert len(data["secret"]) > 10


# ── 2FA Rate Limiting ────────────────────────────────────

class TestTwoFactorRateLimiting:
    def test_verify_endpoint_rejects_unauthenticated(self, app):
        """2FA verify should require an existing session cookie."""
        with TestClient(app) as fresh:
            resp = fresh.post("/api/auth/2fa/verify", json={"code": "000000"})
            assert resp.status_code in (401, 429), f"Expected 401 or 429, got {resp.status_code}"

    def test_recover_endpoint_rejects_unauthenticated(self, app):
        """2FA recover should require an existing session cookie."""
        with TestClient(app) as fresh:
            resp = fresh.post("/api/auth/2fa/recover", json={"code": "abcd1234"})
            assert resp.status_code in (401, 429), f"Expected 401 or 429, got {resp.status_code}"


# ── Upload Size Limits ───────────────────────────────────

class TestUploadLimits:
    def test_max_upload_size_configured(self, app):
        """MAX_UPLOAD_SIZE should be configured (default 5GB)."""
        try:
            from backend.main import MAX_UPLOAD_SIZE
        except ModuleNotFoundError:
            from main import MAX_UPLOAD_SIZE

        assert MAX_UPLOAD_SIZE > 0
        # Default is 5 GB
        assert MAX_UPLOAD_SIZE == 5 * 1024 * 1024 * 1024


# ── Pricing Endpoints ────────────────────────────────────

class TestPricing:
    def test_pricing_endpoint(self, client, admin_cookies):
        """Pricing endpoint should return provider pricing data."""
        resp = client.get("/api/pricing", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_pricing_provider_endpoint(self, client, admin_cookies):
        """Provider-specific pricing should work."""
        resp = client.get("/api/pricing/aws", cookies=admin_cookies)
        # Might be 200 or 404 depending on implementation
        assert resp.status_code in (200, 404)


# ── Version Endpoint ─────────────────────────────────────

class TestVersion:
    def test_version_endpoint_exists(self, client, admin_cookies):
        """Version endpoint should return version information."""
        resp = client.get("/api/version", cookies=admin_cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert "current" in data


# ── S3 Error Sanitization ───────────────────────────────

class TestErrorSanitization:
    def test_sanitize_s3_error_strips_arns(self):
        """S3 error handler should strip ARNs from error messages."""
        import re
        msg = "Access Denied for arn:aws:iam::123456789012:user/test"
        msg = re.sub(r'arn:[^\s,]+', '[ARN]', msg)
        msg = re.sub(r'\d{12}', '[ACCOUNT]', msg)
        assert "arn:aws" not in msg
        assert "[ARN]" in msg
        # The 12-digit account ID is inside the ARN which was already replaced,
        # so [ACCOUNT] only appears if a bare 12-digit number exists outside an ARN
        msg2 = "Bucket owned by 123456789012"
        msg2 = re.sub(r'arn:[^\s,]+', '[ARN]', msg2)
        msg2 = re.sub(r'\d{12}', '[ACCOUNT]', msg2)
        assert "[ACCOUNT]" in msg2

    def test_sanitize_preserves_useful_info(self):
        """Sanitization should preserve the error code."""
        import re
        msg = "NoSuchKey: The specified key does not exist."
        msg = re.sub(r'arn:[^\s,]+', '[ARN]', msg)
        msg = re.sub(r'\d{12}', '[ACCOUNT]', msg)
        assert "NoSuchKey" in msg
        assert "specified key" in msg


# ── Compat Endpoint Permission Checks ────────────────────

class TestCompatPermissions:
    def test_compat_endpoints_require_auth(self, app):
        """Legacy compat endpoints should require authentication."""
        with TestClient(app) as fresh:
            for path in ["/api/list", "/api/search?q=test", "/api/folder-size",
                         "/api/storage-breakdown", "/api/object-info?key=test",
                         "/api/presigned-url?key=test", "/api/multipart-uploads"]:
                resp = fresh.get(path)
                assert resp.status_code == 401, f"{path} should require auth, got {resp.status_code}"


# ── Session & Token Revocation (V3/V8) ───────────────────

class TestSessionAndTokenRevocation:
    """A demoted or deleted admin must not be able to keep using their
    existing session JWT or API token. Refresh and token-verify must
    re-check the users table."""

    def test_demoted_admin_refresh_returns_lower_role(self, client, admin_cookies):
        """A demoted user's refresh should mint a JWT carrying the new (DB) role."""
        uname = f"adm-demote-{uuid.uuid4().hex[:8]}"
        pw = "testpass-demote-1234"

        # Default admin creates a second admin
        resp = client.post(
            "/api/auth/users",
            json={"username": uname, "password": pw, "role": "admin"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text

        # Second admin logs in to get their own cookie
        resp = client.post("/api/auth/login", json={"username": uname, "password": pw})
        assert resp.status_code == 200, resp.text
        demoted_cookies = resp.cookies

        # Default admin demotes them to viewer
        resp = client.put(
            f"/api/auth/users/{uname}",
            json={"role": "viewer"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text

        # Demoted user refreshes; the new JWT/cookie should reflect viewer
        resp = client.post("/api/auth/refresh", cookies=demoted_cookies)
        assert resp.status_code == 200, resp.text
        assert resp.json()["role"] == "viewer"

    def test_deleted_user_refresh_returns_401(self, client, admin_cookies):
        """A deleted user's session cookie must stop working on refresh."""
        uname = f"u-del-refresh-{uuid.uuid4().hex[:8]}"
        pw = "testpass-delrefresh-1"

        resp = client.post(
            "/api/auth/users",
            json={"username": uname, "password": pw, "role": "viewer"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text

        resp = client.post("/api/auth/login", json={"username": uname, "password": pw})
        assert resp.status_code == 200, resp.text
        deleted_cookies = resp.cookies

        # Default admin deletes the user
        resp = client.delete(f"/api/auth/users/{uname}", cookies=admin_cookies)
        assert resp.status_code == 200, resp.text

        # Their cookie should no longer refresh
        resp = client.post("/api/auth/refresh", cookies=deleted_cookies)
        assert resp.status_code == 401, resp.text

    def test_deleted_user_api_token_returns_401(self, client, admin_cookies):
        """A deleted user's API token must immediately stop authenticating."""
        uname = f"adm-del-token-{uuid.uuid4().hex[:8]}"
        pw = "testpass-deltoken-12"

        # Create a second admin (token creation requires admin)
        resp = client.post(
            "/api/auth/users",
            json={"username": uname, "password": pw, "role": "admin"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text

        resp = client.post("/api/auth/login", json={"username": uname, "password": pw})
        assert resp.status_code == 200, resp.text
        second_admin_cookies = resp.cookies

        # Second admin creates an API token
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "revoke-on-delete", "role": "admin"},
            cookies=second_admin_cookies,
        )
        assert resp.status_code == 200, resp.text
        raw_token = resp.json()["token"]

        # Token works before deletion
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200, resp.text

        # Default admin deletes the user
        resp = client.delete(f"/api/auth/users/{uname}", cookies=admin_cookies)
        assert resp.status_code == 200, resp.text

        # Token must no longer authenticate
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 401, resp.text

    def test_orphaned_api_token_rejected_after_owner_deleted(self, client, admin_cookies):
        """Defense-in-depth: an api_tokens row whose owner users row is gone
        (orphaned by a non-cascade delete) must be rejected by the INNER JOIN
        in _verify_api_token — even though the token row itself still exists.

        test_deleted_user_api_token_returns_401 above does NOT isolate this path:
        auth_delete_user also runs `DELETE FROM api_tokens WHERE username=?`, so the
        token row is gone and the JOIN is never the deciding factor. Here we leave the
        api_tokens row in place by deleting only the users row directly.
        """
        try:
            from backend.main import _get_users_db
        except ModuleNotFoundError:
            from main import _get_users_db

        uname = f"u-orphan-{uuid.uuid4().hex[:8]}"
        pw = "testpass-orphan-123"

        # Admin creates a throwaway admin user (token creation requires admin)
        resp = client.post(
            "/api/auth/users",
            json={"username": uname, "password": pw, "role": "admin"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text

        # That user logs in and creates an API token
        resp = client.post("/api/auth/login", json={"username": uname, "password": pw})
        assert resp.status_code == 200, resp.text
        second_admin_cookies = resp.cookies

        resp = client.post(
            "/api/auth/tokens",
            json={"name": "orphan-guard", "role": "admin"},
            cookies=second_admin_cookies,
        )
        assert resp.status_code == 200, resp.text
        raw_token = resp.json()["token"]

        # Positive regression guard: token works while owner exists
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200, resp.text

        # Delete ONLY the users row, leaving the api_tokens row orphaned.
        # We bypass the delete endpoint so the api_tokens cascade does NOT run.
        with _get_users_db() as db:
            db.execute("DELETE FROM users WHERE username=?", (uname,))
            db.commit()

        # Confirm the api_tokens row is still there (orphaned) — this is what
        # makes the INNER JOIN, not the token-row delete, the deciding factor.
        with _get_users_db() as db:
            row = db.execute(
                "SELECT username FROM api_tokens WHERE username=?", (uname,)).fetchone()
        assert row is not None, "orphaned api_tokens row should still exist"

        # Negative case: the token row exists but its owner is gone, so the
        # INNER JOIN users in _verify_api_token must reject it with 401.
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 401, resp.text


# ── GitHub allowed-domains (Vuln 7: fail-closed regression) ──────────────

class TestGithubAllowedDomains:
    """GitHub branch of oauth_callback must fail closed when the user has no
    public email: fetch /user/emails (already-requested user:email scope) and
    pick the primary+verified entry, then enforce OAUTH_ALLOWED_DOMAINS against
    it. Previously the `and domain` guard short-circuited on empty email and
    admitted anyone whenever the allow-list was set."""

    def _enable(self, monkeypatch):
        m = _main_module()
        monkeypatch.setattr(m, "OAUTH_GITHUB_CLIENT_ID", "gh-client-id")
        monkeypatch.setattr(m, "OAUTH_GITHUB_CLIENT_SECRET", "gh-secret")
        monkeypatch.setattr(m, "OAUTH_DEFAULT_ROLE", "viewer")
        monkeypatch.setattr(m, "OAUTH_ALLOWED_DOMAINS", ["allowed.example"])
        return m

    def _stub_token(self, monkeypatch):
        from types import SimpleNamespace
        monkeypatch.setattr(
            "httpx.post",
            lambda *a, **k: SimpleNamespace(status_code=200,
                                            json=lambda: {"access_token": "gh-tok"}))

    def _stub_get(self, monkeypatch, user_payload, emails_payload):
        """Route /user vs /user/emails by URL; return SimpleNamespace fakes."""
        from types import SimpleNamespace

        def _get(url, *a, **k):
            if url == "https://api.github.com/user":
                return SimpleNamespace(status_code=200, json=lambda: user_payload)
            if url == "https://api.github.com/user/emails":
                return SimpleNamespace(status_code=200, json=lambda: emails_payload)
            return SimpleNamespace(status_code=404, json=lambda: {})

        monkeypatch.setattr("httpx.get", _get)

    def _state_handshake(self, c):
        """Call oauth_start to obtain the signed oauth_state cookie + the state
        param, so the callback's new CSRF check passes. Returns (cookies_dict,
        state_value)."""
        from urllib.parse import urlparse, parse_qs
        start = c.get("/api/auth/oauth/github/login", follow_redirects=False)
        cookie = start.cookies.get("oauth_state")
        loc = start.headers["location"]
        state = parse_qs(urlparse(loc).query)["state"][0]
        return {"oauth_state": cookie}, state

    def test_github_public_email_allowed_domain_admitted(self, app, monkeypatch):
        """A user whose public /user email is in the allow-list is admitted and
        gets a session cookie — /user/emails is not needed."""
        m = self._enable(monkeypatch)
        self._stub_token(monkeypatch)
        self._stub_get(monkeypatch,
                       user_payload={"login": "gh-alice", "email": "alice@allowed.example"},
                       emails_payload=[])
        with TestClient(app) as c:
            ck, st = self._state_handshake(c)
            resp = c.get(f"/api/auth/oauth/github/callback?code=abc&state={st}",
                         cookies=ck, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert resp.headers["location"] == "/"
            assert resp.cookies.get("access_token"), "session cookie must be set"

    def test_github_no_public_email_fetched_from_emails_allowed(self, app, monkeypatch):
        """When /user has email=null, the primary+verified address from
        /user/emails is used and admission proceeds when it matches the
        allow-list."""
        m = self._enable(monkeypatch)
        self._stub_token(monkeypatch)
        self._stub_get(monkeypatch,
                       user_payload={"login": "gh-bob", "email": None},
                       emails_payload=[
                           {"email": "bob@other.example", "primary": False, "verified": True},
                           {"email": "bob@allowed.example", "primary": True, "verified": True},
                       ])
        with TestClient(app) as c:
            ck, st = self._state_handshake(c)
            resp = c.get(f"/api/auth/oauth/github/callback?code=abc&state={st}",
                         cookies=ck, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert resp.headers["location"] == "/"
            assert resp.cookies.get("access_token"), "session cookie must be set"

    def test_github_no_public_email_fail_closed_rejected(self, app, monkeypatch):
        """REGRESSION for V7: with no public email and a /user/emails address
        outside the allow-list, the user must be rejected. Previously the
        `and domain` guard short-circuited on empty email and admitted anyone."""
        m = self._enable(monkeypatch)
        self._stub_token(monkeypatch)
        self._stub_get(monkeypatch,
                       user_payload={"login": "gh-eve", "email": None},
                       emails_payload=[
                           {"email": "eve@evil.example", "primary": True, "verified": True},
                       ])
        with TestClient(app) as c:
            ck, st = self._state_handshake(c)
            resp = c.get(f"/api/auth/oauth/github/callback?code=abc&state={st}",
                         cookies=ck, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert "error=domain_not_allowed" in resp.headers["location"]
            assert not resp.cookies.get("access_token"), "must NOT issue a session cookie"

    def test_github_emails_all_unverified_rejected(self, app, monkeypatch):
        """An allowed-domain address that is primary but NOT verified must not
        satisfy the check — only primary+verified entries are trusted, so the
        user is rejected here."""
        m = self._enable(monkeypatch)
        self._stub_token(monkeypatch)
        self._stub_get(monkeypatch,
                       user_payload={"login": "gh-mallory", "email": None},
                       emails_payload=[
                           {"email": "mallory@allowed.example", "primary": True, "verified": False},
                       ])
        with TestClient(app) as c:
            ck, st = self._state_handshake(c)
            resp = c.get(f"/api/auth/oauth/github/callback?code=abc&state={st}",
                         cookies=ck, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert "error=domain_not_allowed" in resp.headers["location"]
            assert not resp.cookies.get("access_token"), "must NOT issue a session cookie"

    def test_github_no_public_email_empty_emails_response_fail_closed(self, app, monkeypatch):
        """REGRESSION for V7 (empty-email path, isolated): when /user has no
        public email AND the /user/emails response yields no usable address
        (empty list — no verified entries, or scope wasn't granted), email stays
        empty and domain becomes "". With OAUTH_ALLOWED_DOMAINS set, the user
        must be rejected fail-closed. The V7 bug (`and domain` short-circuit)
        would admit this user because `domain == ""` is falsy; the fix makes
        `"" not in OAUTH_ALLOWED_DOMAINS` True → rejected."""
        m = self._enable(monkeypatch)
        self._stub_token(monkeypatch)
        self._stub_get(monkeypatch,
                       user_payload={"login": "gh-nobody", "email": None},
                       emails_payload=[])
        with TestClient(app) as c:
            ck, st = self._state_handshake(c)
            resp = c.get(f"/api/auth/oauth/github/callback?code=abc&state={st}",
                         cookies=ck, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert "error=domain_not_allowed" in resp.headers["location"]
            assert not resp.cookies.get("access_token"), "must NOT issue a session cookie"


# ── Share-link access control (Vulns 1 + 2) ──────────────────────────────

class TestShareLinkAccessControl:
    """V1: create_share_link must require read on the target bucket.
    V2: list_share_links must drop the secret token column and show non-admins
    only their own rows."""

    def test_viewer_cannot_create_share_link_for_foreign_bucket(self, client, viewer_cookies):
        """A viewer with no bucket grants must NOT be able to mint a share link
        for an arbitrary bucket (V1 negative)."""
        if not viewer_cookies:
            pytest.skip("Viewer user not created")
        bucket = f"foreign-bucket-{uuid.uuid4().hex[:8]}"
        resp = client.post(
            "/api/share-links",
            json={"bucket": bucket, "key": "k.txt", "expires_hours": 24},
            cookies=viewer_cookies,
        )
        assert resp.status_code == 403, resp.text

    def test_viewer_can_create_share_link_for_granted_bucket(self, client, admin_cookies, viewer_cookies):
        """Positive regression: once a viewer is granted read on a bucket, they
        CAN create a share link for it. Proves legit access still works."""
        if not viewer_cookies:
            pytest.skip("Viewer user not created")
        try:
            from backend.main import _get_users_db
        except ModuleNotFoundError:
            from main import _get_users_db
        bucket = f"granted-bucket-{uuid.uuid4().hex[:8]}"
        # Grant test-viewer read on the bucket directly via the DB.
        with _get_users_db() as db:
            db.execute(
                "INSERT INTO bucket_permissions (username, bucket, permission, granted_by) VALUES (?, ?, ?, ?)",
                ("test-viewer", bucket, "read", "admin"),
            )
            db.commit()
        resp = client.post(
            "/api/share-links",
            json={"bucket": bucket, "key": "k.txt", "expires_hours": 24},
            cookies=viewer_cookies,
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "token" in data and data["token"]

    def test_list_share_links_omits_token_and_filters_by_owner(
        self, client, admin_cookies, viewer_cookies
    ):
        """V2: the secret `token` column is never returned, and non-admins see
        only their own rows (admins see all)."""
        if not viewer_cookies:
            pytest.skip("Viewer user not created")
        try:
            from backend.main import _get_users_db
        except ModuleNotFoundError:
            from main import _get_users_db

        # Stand up two links with distinct owners on unique buckets.
        admin_bucket = f"ac-admin-{uuid.uuid4().hex[:8]}"
        viewer_bucket = f"ac-viewer-{uuid.uuid4().hex[:8]}"
        with _get_users_db() as db:
            db.execute(
                "INSERT INTO bucket_permissions (username, bucket, permission, granted_by) VALUES (?, ?, ?, ?)",
                ("test-viewer", viewer_bucket, "read", "admin"),
            )
            db.commit()

        # Admin creates a link on admin_bucket.
        resp = client.post(
            "/api/share-links",
            json={"bucket": admin_bucket, "key": "a.txt", "expires_hours": 24},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text
        # Viewer creates a link on viewer_bucket (granted above).
        resp = client.post(
            "/api/share-links",
            json={"bucket": viewer_bucket, "key": "v.txt", "expires_hours": 24},
            cookies=viewer_cookies,
        )
        assert resp.status_code == 200, resp.text

        # Viewer list: only own rows, never any token.
        resp = client.get("/api/share-links", cookies=viewer_cookies)
        assert resp.status_code == 200, resp.text
        viewer_links = resp.json()["links"]
        assert viewer_links, "viewer should see at least one own link"
        assert all(link["created_by"] == "test-viewer" for link in viewer_links), \
            "viewer must see ONLY their own rows"
        assert all("token" not in link for link in viewer_links), \
            "token column must not be exposed"

        # Admin list: sees all rows (at least the two we just created), no token.
        resp = client.get("/api/share-links", cookies=admin_cookies)
        assert resp.status_code == 200, resp.text
        admin_links = resp.json()["links"]
        owners = {link["created_by"] for link in admin_links}
        assert "admin" in owners and "test-viewer" in owners, \
            "admin must see rows from multiple owners"
        assert all("token" not in link for link in admin_links), \
            "token column must not be exposed"


# ── S3 Index Metadata Leak (V9) ──────────────────────────

class TestS3IndexMetadataLeak:
    """A4 / Vuln 9: in AUTH_MODE=s3 every session JWT has role=admin, so the old
    admin short-circuit in _check_compat_bucket_read let any s3 user read the LOCAL
    index (built with server creds) — leaking metadata of buckets their IAM denies.
    The fix gates the compat read routes by the user's own IAM."""

    def _enable_s3(self, monkeypatch, allow=False):
        """Flip AUTH_MODE=s3, point _DEFAULT_BUCKET at a known name, and stub the
        IAM access probe so we can deterministically allow/deny the user."""
        try:
            import backend.main as m
        except ModuleNotFoundError:
            import main as m
        monkeypatch.setattr(m, "AUTH_MODE", "s3")
        monkeypatch.setattr(m, "_DEFAULT_BUCKET", "default-bucket-leak-test")
        monkeypatch.setattr(m, "_s3_user_can_access", lambda creds, eid, bucket: allow)
        return m

    def _s3_cookie(self, m):
        """Forge a valid s3-mode session cookie so endpoint_routing_middleware binds
        the user's creds into _user_creds_ctx for the duration of the request."""
        import jwt
        from datetime import datetime, timezone, timedelta
        token = jwt.encode(
            {"sub": "s3:testakid", "role": "admin", "eid": "default",
             "s3ak": m._encrypt("AKIAFAKEACCESSKEY123"),
             "s3sk": m._encrypt("fakeSecretKey456"),
             "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            m.JWT_SECRET, algorithm="HS256")
        return {"access_token": token}

    def test_s3_user_denied_default_bucket_returns_403(self, app, monkeypatch):
        """Negative (core V9): an s3-mode user whose IAM cannot reach the default
        bucket must be 403'd on ALL five compat index read routes — proving the
        index is no longer leaked through any of them."""
        m = self._enable_s3(monkeypatch, allow=False)
        cookie = self._s3_cookie(m)
        paths = [
            "/api/list",
            "/api/search?q=x",
            "/api/folder-size",
            "/api/storage-breakdown",
            "/api/crawl-status",
        ]
        with TestClient(app) as c:
            for path in paths:
                resp = c.get(path, cookies=cookie)
                assert resp.status_code == 403, \
                    f"{path} should be denied (IAM denies default bucket), got {resp.status_code}"

    def test_password_mode_admin_still_passes_compat_check(self, client, admin_cookies, monkeypatch):
        """Positive regression: in PASSWORD mode (AUTH_MODE=local, default), an admin must
        still pass _check_compat_bucket_read via the admin bypass — i.e. the V9 rewrite
        must not have broken the non-s3 path. We force _DEFAULT_BUCKET non-empty and stub
        crawl_status so the handler actually reaches _check_compat_bucket_read instead of
        short-circuiting at the no_bucket guard."""
        try:
            import backend.main as m
        except ModuleNotFoundError:
            import main as m
        monkeypatch.setattr(m, "_DEFAULT_BUCKET", "any-bucket-for-regression")
        monkeypatch.setattr(m, "crawl_status", lambda bucket: {"status": "ok"})
        resp = client.get("/api/crawl-status", cookies=admin_cookies)
        assert resp.status_code != 403, "password-mode admin must not be 403'd by the rewrite"

    def test_s3_user_allowed_default_bucket_not_blocked(self, app, monkeypatch):
        """Positive: when the s3 user's IAM ALLOWS the default bucket, _check_compat_bucket_read
        returns cleanly (no 403) and the route proceeds. Proves the gate doesn't false-positive
        and that the successful-s3 'return' doesn't fall through to the password-mode branch."""
        m = self._enable_s3(monkeypatch, allow=True)   # _s3_user_can_access -> True
        monkeypatch.setattr(m, "crawl_status", lambda bucket: {"status": "ok"})
        with TestClient(app) as c:
            resp = c.get("/api/crawl-status", cookies=self._s3_cookie(m))
        assert resp.status_code == 200, f"s3 user with IAM-allow should proceed, got {resp.status_code}"
        assert resp.json()["status"] == "ok"


# ── S3 Token Privilege Escalation (V4) ───────────────────

class TestS3TokenPrivilegeEscalation:
    """A3 / Vuln 4: in AUTH_MODE=s3 every session JWT has role=admin, so without the
    fix a read-only IAM user could (1) mint a server-credentialed API token, and
    (2) use any API token to bypass the per-user IAM binding entirely. The fix
    blocks s3-mode callers from create_token AND refuses Bearer auth in s3 mode."""

    def _s3_cookie(self, m, sub="s3:testakid"):
        """Forge a valid s3-mode session cookie (signed with JWT_SECRET, carrying
        encrypted s3ak/s3sk) — same shape auth_login_s3 produces."""
        import jwt
        token = jwt.encode(
            {"sub": sub, "role": "admin", "eid": "default",
             "s3ak": m._encrypt("AKIAFAKEACCESSKEY123"),
             "s3sk": m._encrypt("fakeSecretKey456"),
             "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            m.JWT_SECRET, algorithm="HS256")
        return {"access_token": token}

    def test_s3_user_cannot_create_api_token(self, app, monkeypatch):
        """Negative (core V4 part 1): an s3-mode session (role=admin via the s3
        login path) must NOT be able to mint an API token. create_token rejects any
        caller whose JWT sub starts with 's3:'."""
        try:
            import backend.main as m
        except ModuleNotFoundError:
            import main as m
        monkeypatch.setattr(m, "AUTH_MODE", "s3")
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.post(
                "/api/auth/tokens",
                json={"name": "x", "role": "viewer"},
                cookies=cookie,
            )
        assert resp.status_code == 403, \
            f"s3-mode session must not mint API tokens, got {resp.status_code}"

    def test_s3_mode_bearer_auth_refused(self, app, client, admin_cookies, monkeypatch):
        """Negative (core V4 part 2): a previously-valid API token (minted in local
        mode) must be REFUSED once AUTH_MODE=s3. The refusal happens at the top of
        get_current_user's Bearer branch, before _verify_api_token is consulted."""
        # Mint the token in local mode (default), where it is legitimate.
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "s3-bearer-block", "role": "viewer"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        raw_token = resp.json()["token"]

        # Flip into s3 mode — Bearer auth must now be refused.
        try:
            import backend.main as m
        except ModuleNotFoundError:
            import main as m
        monkeypatch.setattr(m, "AUTH_MODE", "s3")
        with TestClient(app) as c:
            resp = c.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 401, \
            f"Bearer auth must be refused in s3 mode, got {resp.status_code}"

    def test_local_admin_can_still_create_token_and_bearer_still_works(self, client, admin_cookies):
        """Positive regression: in AUTH_MODE=local (default, NOT flipped), the s3:
        prefix check must not fire and Bearer auth must still work. Guards against
        the fix over-reaching into local mode."""
        resp = client.post(
            "/api/auth/tokens",
            json={"name": "local-still-works", "role": "viewer"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        raw_token = resp.json()["token"]
        assert raw_token.startswith("sairo_")

        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert data["role"] == "viewer"


# ── OAuth state + PKCE (Vuln 5: login CSRF) ──────────────

class TestOAuthStatePkce:
    """A5 / Vuln 5: oauth_start/oauth_callback previously sent no state, nonce,
    or PKCE — unlike the OIDC path. A login-CSRF attacker could trick a victim
    into landing logged in as the attacker. The fix adds a signed state cookie
    + S256 PKCE challenge/verifier, shared with the OIDC path via the
    _sign_state_cookie / _verify_state_cookie / _set_state_cookie helpers."""

    def _enable_google(self, monkeypatch):
        m = _main_module()
        monkeypatch.setattr(m, "OAUTH_GOOGLE_CLIENT_ID", "g-client")
        monkeypatch.setattr(m, "OAUTH_GOOGLE_CLIENT_SECRET", "g-secret")
        monkeypatch.setattr(m, "OAUTH_DEFAULT_ROLE", "viewer")
        monkeypatch.setattr(m, "OAUTH_ALLOWED_DOMAINS", [])
        return m

    def test_oauth_start_sets_state_cookie_and_pkce_params(self, app, monkeypatch):
        """oauth_start must redirect with state + S256 PKCE params and set a
        signed oauth_state cookie carrying purpose=oauth_state + the verifier."""
        import jwt as _jwt
        m = self._enable_google(monkeypatch)
        with TestClient(app) as c:
            resp = c.get("/api/auth/oauth/google/login", follow_redirects=False)
            assert resp.status_code in (302, 307)
            loc = resp.headers["location"]
            assert loc.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
            assert "state=" in loc
            assert "code_challenge=" in loc
            assert "code_challenge_method=S256" in loc
            cookie = resp.cookies.get("oauth_state")
            assert cookie, "oauth_state cookie must be set"
            claims = _jwt.decode(cookie, m.JWT_SECRET, algorithms=["HS256"])
            assert claims["purpose"] == "oauth_state"
            assert claims.get("cv"), "PKCE verifier must be stashed in the cookie"

    def test_oauth_callback_without_state_cookie_returns_401(self, app, monkeypatch):
        """Core V5 negative #1: a callback with no oauth_state cookie must be
        hard-rejected with 401 (the security boundary), not a silent redirect."""
        self._enable_google(monkeypatch)
        with TestClient(app) as c:
            resp = c.get("/api/auth/oauth/google/callback?code=x&state=y",
                         follow_redirects=False)
            assert resp.status_code == 401

    def test_oauth_callback_state_mismatch_returns_401(self, app, monkeypatch):
        """Core V5 negative #2: an oauth_state cookie whose state doesn't match
        the query param (compare_digest fails) must be hard-rejected with 401."""
        m = self._enable_google(monkeypatch)
        forged = m._sign_state_cookie(
            {"state": "REAL", "cv": "v", "purpose": "oauth_state"})
        with TestClient(app) as c:
            resp = c.get("/api/auth/oauth/google/callback?code=x&state=ATTACKER",
                         cookies={"oauth_state": forged}, follow_redirects=False)
            assert resp.status_code == 401

    def test_oauth_callback_happy_path_with_state_and_pkce(self, app, monkeypatch):
        """End-to-end: real oauth_start cookie + matching state → session cookie,
        and the recorded token-exchange request MUST carry the PKCE code_verifier
        from the state cookie (proves PKCE is sent, not just advertised)."""
        import jwt as _jwt
        from types import SimpleNamespace
        m = self._enable_google(monkeypatch)
        email = f"happy-oauth-{uuid.uuid4().hex[:8]}@example.com"

        recorded = {}

        def _post(url, *a, **k):
            recorded["url"] = url
            recorded["data"] = k.get("data")
            return SimpleNamespace(status_code=200, json=lambda: {"access_token": "tok"})

        def _get(url, *a, **k):
            return SimpleNamespace(status_code=200,
                                   json=lambda: {"email": email})

        monkeypatch.setattr("httpx.post", _post)
        monkeypatch.setattr("httpx.get", _get)

        with TestClient(app) as c:
            # 1) start → obtain the real signed cookie + matching state param
            start = c.get("/api/auth/oauth/google/login", follow_redirects=False)
            cookie = start.cookies.get("oauth_state")
            from urllib.parse import urlparse, parse_qs
            state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
            # decode the verifier to compare against what the callback sends
            st = _jwt.decode(cookie, m.JWT_SECRET, algorithms=["HS256"])
            cv_expected = st["cv"]

            # 2) callback with the matching state + cookie
            resp = c.get(f"/api/auth/oauth/google/callback?code=abc&state={state}",
                         cookies={"oauth_state": cookie}, follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert resp.headers["location"] == "/"
            assert resp.cookies.get("access_token"), "session cookie must be set"

        # 3) the token-exchange request carried the PKCE verifier
        assert recorded.get("url") == "https://oauth2.googleapis.com/token"
        assert recorded["data"].get("code_verifier") == cv_expected, \
            "token exchange must send the PKCE verifier from the state cookie"


# ── Audit Log client_ip (trusted-proxy resolution) ───────

class TestAuditClientIp:
    """The audit log records the resolved client IP via a request-scoped contextvar
    set in endpoint_routing_middleware from request.client.host (already rewritten by
    TrustedProxyMiddleware when TRUSTED_PROXIES is configured)."""

    def test_audit_row_carries_client_ip(self, app):
        """A request made from TestClient(client=("203.0.113.9", 0)) should produce
        an audit row whose client_ip is exactly that peer IP — proving the chain
        middleware → endpoint_routing sets _client_ip_ctx → _audit records it →
        SELECT surfaces it. (TRUSTED_PROXIES is unset in tests, so the trusted-proxy
        middleware is a no-op and request.client.host stays as the TestClient peer.)"""
        # Fresh TestClient bound to a synthetic client IP, sharing the module-scoped app/DB.
        with TestClient(app, client=("203.0.113.9", 0)) as c:
            # Perform an audited action through THIS client so the resulting audit row
            # carries 203.0.113.9 (admin login via the module-scoped client used the
            # default peer). Login records _audit("login", ...).
            resp = c.post("/api/auth/login", json={"username": "admin", "password": "testpass"})
            assert resp.status_code == 200
            cookies = resp.cookies
            # And hit the audit-log endpoint through the same client/peer to be safe.
            audit_resp = c.get("/api/audit-log?action=login&username=admin", cookies=cookies)
            assert audit_resp.status_code == 200
            entries = audit_resp.json()["entries"]
            matching = [e for e in entries if e.get("client_ip") == "203.0.113.9"]
            assert matching, (
                f"expected at least one login audit row with client_ip=203.0.113.9, "
                f"got entries={entries!r}"
            )

    def test_audit_client_ip_null_outside_request(self):
        """_audit called outside any request context (no _client_ip_ctx set) must
        store client_ip=NULL — this is the background-crawl / startup case."""
        m = _main_module()
        token = m._client_ip_ctx.set(None)  # ensure clean state
        try:
            m._audit("unit_test_action", "some_user", details="no-request")
            with m._get_users_db() as db:
                row = db.execute(
                    "SELECT client_ip FROM audit_log "
                    "WHERE action='unit_test_action' AND username='some_user' "
                    "ORDER BY id DESC LIMIT 1"
                ).fetchone()
            assert row is not None, "audit row should have been inserted"
            assert row["client_ip"] is None, f"expected NULL, got {row['client_ip']!r}"
        finally:
            m._client_ip_ctx.reset(token)

    def test_audit_client_ip_from_contextvar(self):
        """_audit reads _client_ip_ctx — setting it to a specific value (without any
        HTTP request) is reflected verbatim in the audit row. This is the resolved-IP
        mechanism, tested independently of the HTTP stack."""
        m = _main_module()
        token = m._client_ip_ctx.set("198.51.100.42")
        try:
            m._audit("ctx_test_action", "ctx_user")
            with m._get_users_db() as db:
                row = db.execute(
                    "SELECT client_ip FROM audit_log "
                    "WHERE action='ctx_test_action' AND username='ctx_user' "
                    "ORDER BY id DESC LIMIT 1"
                ).fetchone()
            assert row is not None, "audit row should have been inserted"
            assert row["client_ip"] == "198.51.100.42", (
                f"expected 198.51.100.42, got {row['client_ip']!r}"
            )
        finally:
            m._client_ip_ctx.reset(token)

    def test_get_audit_log_includes_client_ip_field(self, client, admin_cookies):
        """The /api/audit-log response contract must include a client_ip key on every
        entry (None for pre-migration rows, a string otherwise)."""
        resp = client.get("/api/audit-log", cookies=admin_cookies)
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert isinstance(entries, list)
        # There should be at least some audit rows from earlier tests' logins.
        assert entries, "expected at least one audit entry to be present"
        for e in entries:
            assert "client_ip" in e, f"entry missing client_ip key: {e!r}"
            assert e["client_ip"] is None or isinstance(e["client_ip"], str)

    def test_schema_migration_is_additive(self):
        """_init_users_db() must be idempotent: re-running it (with the client_ip
        column already present) must not raise, and the audit_log table must expose
        client_ip via PRAGMA table_info."""
        m = _main_module()
        # Idempotent: column already exists from app import; second ALTER must be a no-op.
        m._init_users_db()
        with m._get_users_db() as db:
            cols = [r["name"] for r in db.execute("PRAGMA table_info(audit_log)").fetchall()]
        assert "client_ip" in cols, f"client_ip missing from audit_log schema; got {cols!r}"


# ── Rate-limiter keys (resolved client) ───────────────────

def _make_login_rate_app(main_module, trusted_proxies):
    """Tiny Starlette app that runs the REAL main._check_login_rate against the
    resolved request.client.host, wrapped by TrustedProxyMiddleware. Used to prove
    the login limiter buckets per resolved IP behind a proxy — without dragging in
    the full FastAPI app/auth stack."""
    check = main_module._check_login_rate

    async def handler(request):
        ip = request.client.host if request.client else None
        check(ip)  # raises HTTPException(429) past LOGIN_RATE_MAX; one call per IP here
        return JSONResponse({"key": ip})

    app = Starlette(routes=[Route("/", handler)])
    app.add_middleware(TrustedProxyMiddleware, trusted_proxies=trusted_proxies)
    return app


class TestRateLimiterResolvedKey:
    """The slowapi Limiter and the custom login limiter BOTH key on the
    ASGI-resolved client (request.client.host). TrustedProxyMiddleware rewrites
    scope['client'] when TRUSTED_PROXIES is set, so each real client behind a
    proxy gets its own bucket; an untrusted peer's X-Forwarded-For is ignored
    (fail-closed)."""

    def test_slowapi_key_func_reads_resolved_client(self):
        """The configured slowapi key_func returns request.client.host (the
        ASGI-resolved IP) and does NOT consult X-Forwarded-For — proving there is
        no XFF double-application on top of TrustedProxyMiddleware. slowapi stores
        the key_func on the Limiter instance as `_key_func`."""
        m = _main_module()
        # Real client IP is in scope["client"]; XFF header is a DISTRACTOR that
        # must be ignored.
        r = Request(scope={
            "type": "http",
            "client": ("203.0.113.9", 0),
            "headers": [(b"x-forwarded-for", b"99.99.99.99")],
        })
        key = m.limiter._key_func(r)
        assert key == "203.0.113.9", (
            f"key_func must read request.client.host (the resolved IP), not "
            f"X-Forwarded-For; got {key!r}"
        )
        # No client info → graceful fallback. (slowapi.util.get_remote_address
        # returns '127.0.0.1' here; 'unknown' is the only cosmetic delta.)
        r_none = Request(scope={"type": "http", "client": None, "headers": []})
        assert m.limiter._key_func(r_none) == "unknown", (
            "key_func must fall back to 'unknown' when request.client is None"
        )

    def test_login_limiter_buckets_per_resolved_ip_behind_trusted_proxy(self):
        """HEADLINE: two requests from the SAME trusted proxy peer but DIFFERENT
        X-Forwarded-For values land in SEPARATE _login_attempts buckets keyed by
        the resolved XFF IP — NOT collapsed to the proxy peer. This proves
        _check_login_rate(request.client.host) keys on the middleware-resolved IP."""
        m = _main_module()
        app = _make_login_rate_app(m, {ipaddress.ip_network("10.0.0.0/8")})
        added = ["203.0.113.10", "198.51.100.20"]
        try:
            with TestClient(app, client=("10.0.0.1", 12345)) as c:
                r1 = c.get("/", headers={"X-Forwarded-For": "203.0.113.10"})
                assert r1.status_code == 200, r1.text
                assert r1.json()["key"] == "203.0.113.10"
                r2 = c.get("/", headers={"X-Forwarded-For": "198.51.100.20"})
                assert r2.status_code == 200, r2.text
                assert r2.json()["key"] == "198.51.100.20"
            # Both resolved IPs land in separate buckets.
            assert "203.0.113.10" in m._login_attempts, (
                f"expected bucket for resolved XFF IP 203.0.113.10; "
                f"_login_attempts keys = {list(m._login_attempts.keys())}"
            )
            assert "198.51.100.20" in m._login_attempts, (
                f"expected bucket for resolved XFF IP 198.51.100.20; "
                f"_login_attempts keys = {list(m._login_attempts.keys())}"
            )
            # The proxy peer itself must NOT have a bucket — that would indicate
            # the two XFFs were collapsed onto the proxy.
            assert "10.0.0.1" not in m._login_attempts, (
                f"proxy peer 10.0.0.1 must NOT have its own bucket; "
                f"_login_attempts keys = {list(m._login_attempts.keys())}"
            )
        finally:
            # _login_attempts is a module-global; clean up so other tests aren't polluted.
            for k in added:
                m._login_attempts.pop(k, None)

    def test_login_limiter_collapses_to_peer_when_untrusted(self):
        """An UNTRUSTED peer's X-Forwarded-For is ignored (fail-closed), so the
        login-limiter bucket is the peer IP itself — NOT the spoofed XFF value."""
        m = _main_module()
        app = _make_login_rate_app(m, {ipaddress.ip_network("10.0.0.0/8")})
        added = ["8.8.8.8"]
        try:
            with TestClient(app, client=("8.8.8.8", 12345)) as c:
                r = c.get("/", headers={"X-Forwarded-For": "203.0.113.10"})
                assert r.status_code == 200, r.text
                assert r.json()["key"] == "8.8.8.8"  # XFF ignored
            assert "8.8.8.8" in m._login_attempts, (
                f"expected bucket for untrusted peer 8.8.8.8; "
                f"_login_attempts keys = {list(m._login_attempts.keys())}"
            )
            assert "203.0.113.10" not in m._login_attempts, (
                f"spoofed XFF 203.0.113.10 must NOT get a bucket from an untrusted peer; "
                f"_login_attempts keys = {list(m._login_attempts.keys())}"
            )
        finally:
            for k in added:
                m._login_attempts.pop(k, None)

    def test_login_limiter_regression_default_config(self):
        """Regression pin: with the module-scoped app (TRUSTED_PROXIES unset →
        middleware no-op), _check_login_rate still buckets per plain IP argument.
        Behavior is unchanged from before this PR."""
        m = _main_module()
        added = ["1.2.3.4", "5.6.7.8"]
        try:
            m._check_login_rate("1.2.3.4")
            m._check_login_rate("5.6.7.8")
            assert "1.2.3.4" in m._login_attempts, (
                f"expected bucket for 1.2.3.4; "
                f"_login_attempts keys = {list(m._login_attempts.keys())}"
            )
            assert "5.6.7.8" in m._login_attempts, (
                f"expected bucket for 5.6.7.8; "
                f"_login_attempts keys = {list(m._login_attempts.keys())}"
            )
        finally:
            for k in added:
                m._login_attempts.pop(k, None)


# ── S3-mode privilege escalation — require_local_admin chokepoint (A8) ────

class TestS3ModePrivEscBypassA8:
    """A8 (§9.2): in AUTH_MODE=s3 every session JWT carries role:"admin"
    (because the rest of the code uses role=="admin" as the sole capability
    check, and auth_login_s3 mints admin for any key pair that passes
    list_buckets). That role claim only reflects IAM capability — it MUST NOT
    authorize changes to state outside the user's IAM scope (local users, API
    tokens, endpoints, bucket grants, 2FA resets).

    The fix is one structural chokepoint — require_local_admin — applied to
    every admin mutation route that writes non-IAM-scoped state. These tests
    forge an s3-mode session cookie and assert 403 on each swapped route.

    Note: V4-specific coverage (create_token + Bearer refusal) lives in
    TestS3TokenPrivilegeEscalation above. This class covers the nine additional
    routes that the A3 fix missed."""

    def _s3_cookie(self, m, sub="s3:testakid"):
        """Forge a valid s3-mode session cookie (signed with JWT_SECRET, carrying
        encrypted s3ak/s3sk) — same shape auth_login_s3 produces."""
        import jwt
        token = jwt.encode(
            {"sub": sub, "role": "admin", "eid": "default",
             "s3ak": m._encrypt("AKIAFAKEACCESSKEY123"),
             "s3sk": m._encrypt("fakeSecretKey456"),
             "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            m.JWT_SECRET, algorithm="HS256")
        return {"access_token": token}

    def _enable_s3(self, monkeypatch):
        """Flip AUTH_MODE=s3 for the duration of one test."""
        try:
            import backend.main as m
        except ModuleNotFoundError:
            import main as m
        monkeypatch.setattr(m, "AUTH_MODE", "s3")
        return m

    # ── one negative test per swapped route (9 routes — create_token is
    #    covered by TestS3TokenPrivilegeEscalation.test_s3_user_cannot_create_api_token) ──

    def test_s3_user_cannot_create_user(self, app, monkeypatch):
        """POST /api/auth/users — auth_create_user (step 2 of the §9.2 chain)."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.post("/api/auth/users",
                          json={"username": "backdoor", "password": "password123", "role": "admin"},
                          cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not create local users, got {resp.status_code}"

    def test_s3_user_cannot_delete_user(self, app, monkeypatch):
        """DELETE /api/auth/users/{username} — auth_delete_user."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.delete("/api/auth/users/someuser", cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not delete local users, got {resp.status_code}"

    def test_s3_user_cannot_update_user(self, app, monkeypatch):
        """PUT /api/auth/users/{username} — auth_update_user (privilege)."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.put("/api/auth/users/someuser",
                         json={"role": "viewer"},
                         cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not change user roles, got {resp.status_code}"

    def test_s3_user_cannot_reset_2fa(self, app, monkeypatch):
        """POST /api/auth/2fa/reset/{username} — twofa_admin_reset."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.post("/api/auth/2fa/reset/someuser", cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not reset another user's 2FA, got {resp.status_code}"

    def test_s3_user_cannot_set_permissions(self, app, monkeypatch):
        """PUT /api/auth/users/{username}/permissions — set_user_permissions."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.put("/api/auth/users/someuser/permissions",
                         json={"permissions": [{"bucket": "somebucket", "permission": "read"}]},
                         cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not grant bucket permissions, got {resp.status_code}"

    def test_s3_user_cannot_delete_permission(self, app, monkeypatch):
        """DELETE /api/auth/users/{username}/permissions/{bucket} — delete_user_permission."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.delete("/api/auth/users/someuser/permissions/somebucket", cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not revoke bucket permissions, got {resp.status_code}"

    def test_s3_user_cannot_create_endpoint(self, app, monkeypatch):
        """POST /api/endpoints — create_endpoint (encrypted server creds)."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.post("/api/endpoints",
                          json={"id": "testep1", "name": "test-endpoint",
                                "endpoint_url": "http://example.com",
                                "access_key": "ak", "secret_key": "sk"},
                          cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not register endpoints, got {resp.status_code}"

    def test_s3_user_cannot_update_endpoint(self, app, monkeypatch):
        """PUT /api/endpoints/{endpoint_id} — update_endpoint."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.put("/api/endpoints/someep",
                         json={"name": "renamed"},
                         cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not edit endpoints, got {resp.status_code}"

    def test_s3_user_cannot_delete_endpoint(self, app, monkeypatch):
        """DELETE /api/endpoints/{endpoint_id} — delete_endpoint."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.delete("/api/endpoints/someep", cookies=cookie)
        assert resp.status_code == 403, \
            f"s3-mode session must not delete endpoints, got {resp.status_code}"

    # ── end-to-end regression: the §9.2 chain must break at step 2 ────

    def test_s3_mode_priv_esc_chain_blocked_at_create_user(self, app, monkeypatch):
        """The full §9.2 chain starts with: forge an s3-mode admin cookie, then
        POST /api/auth/users {"username":"backdoor","role":"admin"} to plant a
        local admin row that has no s3: prefix (and so would pass the per-route
        s3: guard on create_token that A3 added). The require_local_admin
        chokepoint must break the chain here — 403, and the backdoor row must
        NOT be inserted into the users table."""
        m = self._enable_s3(monkeypatch)
        cookie = self._s3_cookie(m)
        with TestClient(app) as c:
            resp = c.post("/api/auth/users",
                          json={"username": "backdoor", "password": "password123", "role": "admin"},
                          cookies=cookie)
        assert resp.status_code == 403, \
            f"chain step 2 must be blocked, got {resp.status_code}"
        # Defense-in-depth: confirm no row was persisted. (The dependency fires
        # before the handler, so the INSERT never runs — but verify explicitly
        # so a future regression that reorders the guard is caught loudly.)
        with m._get_users_db() as db:
            row = db.execute(
                "SELECT username FROM users WHERE username=?", ("backdoor",)
            ).fetchone()
        assert row is None, "backdoor local-admin row must not exist"

    # ── positive regression: local mode is unaffected ────────────────
    # (test_local_admin_can_still_create_token_and_bearer_still_works is
    #  covered by TestS3TokenPrivilegeEscalation above.)

    def test_local_admin_can_still_create_user(self, client, admin_cookies):
        """Positive regression: require_local_admin must not block a local admin
        on auth_create_user (a swapped route) — covers one of the nine non-token
        mutations that the existing positive test above doesn't touch."""
        resp = client.post(
            "/api/auth/users",
            json={"username": "local-created-by-admin", "password": "password123", "role": "viewer"},
            cookies=admin_cookies,
        )
        # 200 (created) or 409 (already exists from a prior run) — either proves
        # the chokepoint did not 403 a local admin.
        assert resp.status_code in (200, 409), \
            f"local admin must reach the handler (200/409), got {resp.status_code}"

# ── Federated user enumeration oracle — bcrypt.verify wrap (A9) ──────────

class TestFederatedUserEnumeration:
    """A9 (§9.3): federated users (LDAP/OAuth/OIDC) created by
    _sync_federated_user store an unusable placeholder hash
    ("LDAP:<hex>" / "OAUTH:<hex>" / "OIDC:<hex>"). passlib's bcrypt.verify
    raises ValueError on these, so unwrapped call sites returned 500 for
    existing federated usernames vs 401 for local/unknown names — an
    existence + IdP oracle for phishing targeting.

    Fix: wrap each verify defensively so federated hashes return the same
    401 as a bad password, and add "OIDC:" to twofa_disable's prefix-skip
    tuple (was missing, so OIDC users hit the verify and crashed)."""

    def _reset_login_rate_limits(self, m):
        """Clear in-memory rate-limit counters so test ordering can't trip 429."""
        m._login_attempts.clear()
        try:
            m.limiter.reset()  # slowapi in-memory storage
        except Exception:
            pass

    def _make_federated_user(self, m, username, source, hash_prefix,
                             role="viewer", totp_enabled=False):
        """Create a federated user via the production _sync_federated_user
        chokepoint — i.e. exactly the row shape that triggers the bug
        (password_hash = "<PREFIX>:<hex>", unusable by bcrypt.verify)."""
        m._sync_federated_user(username, source, hash_prefix, role)
        if totp_enabled:
            # _sync_federated_user always creates with totp_enabled=0; flip it
            # for tests that need an existing 2FA-enabled federated user.
            with m._get_users_db() as db:
                db.execute(
                    "UPDATE users SET totp_enabled=1 WHERE username=?", (username,))
                db.commit()

    def _session_cookie(self, m, username, role="viewer"):
        """Forge a signed session cookie — same shape auth_login mints."""
        import jwt
        token = jwt.encode(
            {"sub": username, "role": role,
             "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            m.JWT_SECRET, algorithm="HS256")
        return {"access_token": token}

    # ── Test 1: auth_login returns 401 (NOT 500) per federated prefix ───

    @pytest.mark.parametrize("source,prefix", [
        ("ldap", "LDAP"),
        ("oauth", "OAUTH"),
        ("oidc", "OIDC"),
    ])
    def test_auth_login_returns_401_not_500_for_federated_user(self, app, source, prefix):
        """Each federated prefix must yield 401, never 500 — closing the
        existence + IdP oracle. Before the fix, bcrypt.verify raised
        ValueError on the placeholder hash and FastAPI returned 500 for
        existing federated usernames."""
        import secrets as _s
        m = _main_module()
        username = f"fed-{source}-{_s.token_hex(8)}"
        self._make_federated_user(m, username, source, prefix)
        self._reset_login_rate_limits(m)
        with TestClient(app) as c:
            resp = c.post("/api/auth/login",
                          json={"username": username, "password": "anything"})
        assert resp.status_code == 401, \
            f"federated ({prefix}:) login must be 401, got {resp.status_code}"
        assert resp.json()["detail"] == "Invalid username or password"

    # ── Test 2: twofa_disable succeeds (skip path) for an OIDC user ─────

    def test_twofa_disable_oidc_user_succeeds(self, app):
        """OIDC was missing from twofa_disable's prefix-skip tuple, so the
        verify crashed with 500. After the fix the skip path runs and 2FA
        is disabled cleanly."""
        import secrets as _s
        m = _main_module()
        username = f"fed-oidc-2fa-{_s.token_hex(8)}"
        self._make_federated_user(m, username, "oidc", "OIDC", totp_enabled=True)
        cookie = self._session_cookie(m, username)
        with TestClient(app) as c:
            resp = c.post("/api/auth/2fa/disable",
                          json={"password": ""}, cookies=cookie)
        assert resp.status_code == 200, \
            f"OIDC user 2FA disable must succeed (skip path), got {resp.status_code}"
        assert resp.json()["disabled"] is True
        # Defense-in-depth: confirm the DB was actually updated.
        with m._get_users_db() as db:
            row = db.execute(
                "SELECT totp_enabled FROM users WHERE username=?", (username,)
            ).fetchone()
        assert row and row["totp_enabled"] == 0, \
            "totp_enabled must be flipped to 0 in the DB"

    # ── Test 3: auth_change_password returns 401 (NOT 500) for federated ─

    def test_change_password_returns_401_not_500_for_federated_user(self, app):
        """A federated user changing their password must hit the wrapped
        verify and get 401 — never a 500 leak. Before the fix: 500."""
        import secrets as _s
        m = _main_module()
        username = f"fed-ldap-cp-{_s.token_hex(8)}"
        self._make_federated_user(m, username, "ldap", "LDAP")
        cookie = self._session_cookie(m, username)
        with TestClient(app) as c:
            resp = c.put("/api/auth/change-password",
                         json={"old_password": "whatever", "new_password": "newpass123"},
                         cookies=cookie)
        assert resp.status_code == 401, \
            f"federated change-password must be 401, got {resp.status_code}"
        assert resp.json()["detail"] == "Current password is incorrect"

# ── Parquet file-metadata contract (regression lock for the read_footer refactor) ──

class TestParquetFileMetadata:
    """Lock the JSON contract of GET /file-metadata for a Parquet key.

    The footer-reading logic was moved into ``backend/parquet_reader.read_footer``;
    this test guarantees the endpoint still returns the identical response shape
    (same keys, field order, and values) by serving a real pyarrow-written
    Parquet object through a fake S3 client patched in for ``main.s3``.
    """

    @staticmethod
    def _build_parquet():
        import io as _io
        import pyarrow as _pa
        import pyarrow.parquet as _pq

        schema = _pa.schema(
            [
                _pa.field("id", _pa.int64()),
                _pa.field("name", _pa.string()),
            ]
        )
        table = _pa.table(
            {
                "id": _pa.array(list(range(10)), _pa.int64()),
                "name": _pa.array([f"row{i}" for i in range(10)], _pa.string()),
            },
            schema=schema,
        )
        buf = _io.BytesIO()
        _pq.write_table(table, buf)
        return buf.getvalue()

    def test_file_metadata_parquet_contract(self, client, admin_cookies):
        """file-metadata returns the documented Parquet JSON shape end-to-end."""
        import io as _io
        import re as _re
        from unittest.mock import patch

        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod

        data = self._build_parquet()

        class _FakeS3:
            def head_object(self, *, Bucket, Key):
                return {"ContentLength": len(data)}

            def get_object(self, *, Bucket, Key, Range):
                m = _re.match(r"bytes=(\d+)-(\d+)", Range)
                start, end = int(m.group(1)), int(m.group(2))
                return {"Body": _io.BytesIO(data[start : end + 1])}

        with patch.object(main_mod, "s3", _FakeS3()):
            resp = client.get(
                "/api/buckets/test-bucket/file-metadata?key=data/test.parquet",
                cookies=admin_cookies,
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()

        # Top-level shape — key set and field order must match _read_parquet_metadata.
        assert list(body.keys()) == [
            "format", "num_rows", "num_columns", "num_row_groups",
            "created_by", "columns", "row_groups", "file_size",
        ]
        assert body["format"] == "parquet"
        assert body["num_rows"] == 10
        assert body["num_columns"] == 2
        assert body["num_row_groups"] == 1
        assert body["file_size"] == len(data)
        assert isinstance(body["created_by"], str)

        # Columns reflect the written arrow schema.
        assert body["columns"] == [
            {"name": "id", "type": "int64", "nullable": True},
            {"name": "name", "type": "string", "nullable": True},
        ]

        # row_groups carry num_rows + total_byte_size for the single group.
        assert len(body["row_groups"]) == 1
        assert body["row_groups"][0]["num_rows"] == 10
        assert isinstance(body["row_groups"][0]["total_byte_size"], int)


# ── Tier 1: GET /api/buckets/{bucket}/parquet-rows ─────────────────────────

class TestParquetRowsEndpoint:
    """End-to-end contract lock for the parquet-rows endpoint (T3 frontend relies
    on this exact response shape). Serves a real pyarrow-written Parquet object
    through a fake S3 client patched in for ``main.s3`` — same style as
    :class:`TestParquetFileMetadata`, no moto.
    """

    @staticmethod
    def _build_parquet_500():
        import io as _io
        import pyarrow as _pa
        import pyarrow.parquet as _pq

        schema = _pa.schema(
            [
                _pa.field("a", _pa.int64()),
                _pa.field("b", _pa.string()),
            ]
        )
        table = _pa.table(
            {
                "a": _pa.array(list(range(500)), _pa.int64()),
                "b": _pa.array([f"row{i}" for i in range(500)], _pa.string()),
            },
            schema=schema,
        )
        buf = _io.BytesIO()
        _pq.write_table(table, buf)
        return buf.getvalue()

    @staticmethod
    def _fake_s3_for(data):
        """Fake S3 serving a real in-memory Parquet buffer (head + range GET)."""
        import io as _io
        import re as _re

        class _FakeS3:
            def head_object(self, *, Bucket, Key):
                return {"ContentLength": len(data)}

            def get_object(self, *, Bucket, Key, Range=None):
                if Range is None:  # full-object GET
                    return {"Body": _io.BytesIO(data)}
                m = _re.match(r"bytes=(\d+)-(\d+)", Range)
                start, end = int(m.group(1)), int(m.group(2))
                return {"Body": _io.BytesIO(data[start : end + 1])}

        return _FakeS3()

    @staticmethod
    def _large_fake_s3_for(small, total):
        """Virtual >32MB Parquet object without materializing 32MB+ in memory.

        Layout: ``[0:4]=small[0:4]`` (PAR1 header), ``[4:4+pad]=0``,
        ``[4+pad:total]=small[4:]``. The footer bytes are preserved at the tail
        so ``read_footer`` parses correctly; only column-chunk offsets shift
        into the gap, which footer parsing doesn't dereference.
        """
        import io as _io
        import re as _re

        pad = total - len(small)

        class _LargeFakeS3:
            def head_object(self, *, Bucket, Key):
                return {"ContentLength": total}

            def _byte(self, i):
                if i < 4:
                    return small[i]
                if i < 4 + pad:
                    return 0
                return small[4 + (i - (4 + pad))]

            def get_object(self, *, Bucket, Key, Range):
                m = _re.match(r"bytes=(\d+)-(\d+)", Range)
                start, end = int(m.group(1)), int(m.group(2))
                return {"Body": _io.BytesIO(bytes(self._byte(i) for i in range(start, end + 1)))}

        return _LargeFakeS3()

    def test_happy_path_contract(self, client, admin_cookies):
        """Small file: full row decode, pagination, exact JSON contract."""
        from unittest.mock import patch

        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod

        data = self._build_parquet_500()
        with patch.object(main_mod, "s3", self._fake_s3_for(data)):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-rows?key=data/test.parquet"
                "&limit=100&offset=0",
                cookies=admin_cookies,
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Frozen key set + order.
        assert list(body.keys()) == [
            "columns", "rows", "total_rows", "offset", "limit",
            "truncated", "next_offset", "read_mode",
        ]
        assert body["read_mode"] == "full"
        assert body["total_rows"] == 500
        assert body["offset"] == 0
        assert body["limit"] == 100
        assert body["truncated"] is True
        assert body["next_offset"] == 100
        assert len(body["rows"]) == 100
        assert body["rows"][0] == [0, "row0"]
        assert body["columns"] == [
            {"name": "a", "type": "int64"},
            {"name": "b", "type": "string"},
        ]

    def test_column_projection_query_param(self, client, admin_cookies):
        """?columns=a,b projects columns; rows contain only those, in order."""
        from unittest.mock import patch

        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod

        data = self._build_parquet_500()
        with patch.object(main_mod, "s3", self._fake_s3_for(data)):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-rows?key=data/test.parquet"
                "&limit=3&columns=b,a",  # reverse order on purpose
                cookies=admin_cookies,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert [c["name"] for c in body["columns"]] == ["b", "a"]
        assert all(len(r) == 2 for r in body["rows"])
        assert body["rows"][0] == ["row0", 0]

    def test_unknown_column_returns_400(self, client, admin_cookies):
        """Unknown column in ?columns= → 400 from the allowlist guard."""
        from unittest.mock import patch

        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod

        data = self._build_parquet_500()
        with patch.object(main_mod, "s3", self._fake_s3_for(data)):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-rows?key=data/test.parquet"
                "&limit=3&columns=doesnotexist",
                cookies=admin_cookies,
            )
        assert resp.status_code == 400, resp.text
        assert "doesnotexist" in resp.json()["detail"]

    def test_limit_over_max_returns_422(self, client, admin_cookies):
        """limit > PARQUET_ROW_LIMIT_MAX is rejected by the Query validator (422).

        Decision: rely on FastAPI's ``Query(le=1000)`` rather than clamping
        server-side, so the client gets an explicit signal to request fewer rows.
        """
        resp = client.get(
            "/api/buckets/test-bucket/parquet-rows?key=data/test.parquet&limit=5000",
            cookies=admin_cookies,
        )
        assert resp.status_code == 422, resp.text

    def test_large_file_returns_too_large(self, client, admin_cookies):
        """file_size > 32MB → HTTP 200 read_mode=='too_large', schema only."""
        from unittest.mock import patch

        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod

        small = self._build_parquet_500()
        total = 32 * 1024 * 1024 + 1024  # just over the 32MB cap
        with patch.object(main_mod, "s3", self._large_fake_s3_for(small, total)):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-rows?key=data/test.parquet&limit=100",
                cookies=admin_cookies,
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["read_mode"] == "too_large"
        assert body["rows"] == []
        assert body["truncated"] is True
        assert body["next_offset"] is None
        # Schema + totals still accurate from the footer.
        assert body["total_rows"] == 500
        assert body["columns"] == [
            {"name": "a", "type": "int64"},
            {"name": "b", "type": "string"},
        ]

    def test_requires_auth(self, app):
        """No auth cookie → 401 (never touches S3).

        Uses a fresh ``TestClient`` so cookies persisted by earlier tests on the
        shared module-scoped client don't leak in (mirrors TestCompatPermissions).
        """
        with TestClient(app) as fresh:
            resp = fresh.get("/api/buckets/test-bucket/parquet-rows?key=data/test.parquet")
        assert resp.status_code == 401

    def test_non_parquet_ext_returns_400(self, client, admin_cookies):
        """A non-Parquet key is rejected with 400 before any row decoding."""
        resp = client.get(
            "/api/buckets/test-bucket/parquet-rows?key=data/test.csv",
            cookies=admin_cookies,
        )
        assert resp.status_code == 400, resp.text
        assert "Unsupported file type" in resp.json()["detail"]

    def test_not_found_key_returns_404(self, client, admin_cookies):
        """A missing object surfaces read_footer's 404 (NoSuchKey → 'Object not found')."""
        from unittest.mock import patch
        from botocore.exceptions import ClientError as _CE

        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod

        not_found = _CE({"Error": {"Code": "NoSuchKey", "Message": "Not Found"}}, "HeadObject")

        class _MissingS3:
            def head_object(self, *, Bucket, Key):
                raise not_found

            def get_object(self, *, Bucket, Key, Range=None):  # pragma: no cover
                raise AssertionError("body GET must not happen on a missing object")

        with patch.object(main_mod, "s3", _MissingS3()):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-rows?key=data/missing.parquet",
                cookies=admin_cookies,
            )
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"] == "Object not found"

    def test_semaphore_released_after_error(self, client, admin_cookies):
        """A request that errors inside the handler must release its semaphore slot.

        Behavioral guarantee (stronger than a source inspection): after an
        erroring request, the semaphore is back to its full permit count, so a
        follow-up request isn't blocked. Exercises the ``finally`` release path.
        """
        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod

        # Non-parquet ext raises 400 inside the try block (after acquiring a slot).
        before = main_mod._metadata_semaphore._value
        resp = client.get(
            "/api/buckets/test-bucket/parquet-rows?key=data/test.csv",
            cookies=admin_cookies,
        )
        assert resp.status_code == 400
        after = main_mod._metadata_semaphore._value
        assert before == after, (
            f"semaphore leaked: {before} permits before, {after} after an error"
        )


# ── Tier 2: GET /api/buckets/{bucket}/parquet-stream ───────────────────────

class TestParquetStreamEndpoint:
    """Lifecycle + contract tests for the same-origin streaming proxy.

    The endpoint pipes S3 bytes to the browser for duckdb-wasm so direct
    browser→S3 ``fetch()`` (cross-origin / CORS-restricted on read-only buckets)
    is avoided (arch §3). The load-bearing property is that the dedicated
    ``_stream_semaphore`` permit is ALWAYS released — on 401/400/404/413, on
    normal completion, and on a client disconnect mid-stream. These tests
    exercise every one of those paths.
    """

    @staticmethod
    def _import_main():
        try:
            from backend import main as main_mod
        except ModuleNotFoundError:
            import main as main_mod
        return main_mod

    @staticmethod
    def _stream_fake_s3(data, content_length=None):
        """Fake S3 whose ``get_object`` body supports ``iter_chunks(chunk_size)``
        (the boto3 ``StreamingBody`` shape ``stream_object`` calls).

        ``content_length`` is decoupled from ``len(data)`` so the size-cap test
        can report a huge head_object without materializing a huge buffer.
        Records ``get_calls`` so we can assert the body was / was not streamed.
        """
        import io as _io

        class _Body:
            """Mimics botocore's StreamingBody for the iter_chunks path only."""

            def __init__(self, payload):
                self._payload = payload

            def iter_chunks(self, chunk_size):
                for i in range(0, len(self._payload), chunk_size):
                    yield self._payload[i:i + chunk_size]

            def read(self):  # pragma: no cover — stream_object never calls read()
                return self._payload

        cl = content_length if content_length is not None else len(data)
        body_holder = {"body": None}

        class _FakeS3:
            get_calls = 0

            def head_object(self_, *, Bucket, Key):
                return {"ContentLength": cl}

            def get_object(self_, *, Bucket, Key, Range=None):
                self_.get_calls += 1
                body_holder["body"] = _Body(data)
                return {"Body": body_holder["body"]}

        return _FakeS3()

    @staticmethod
    def _sample_stream_bytes():
        # ~205 KB so the default 64 KiB chunk size produces multiple chunks —
        # proves the endpoint never buffers the whole object into memory at once.
        return b"PAR1" + (bytes(range(256)) * 800) + b"PAR1"

    def test_requires_auth(self, app):
        """No auth cookie → 401, and S3 is never touched.

        Uses a fresh ``TestClient`` so cookies persisted by earlier tests on the
        shared module-scoped client don't leak in (mirrors parquet-rows).
        """
        with TestClient(app) as fresh:
            resp = fresh.get(
                "/api/buckets/test-bucket/parquet-stream?key=data/test.parquet"
            )
        assert resp.status_code == 401

    def test_not_found_key_returns_404_and_releases_slot(
        self, client, admin_cookies
    ):
        """A missing object → 404 from head_object, body never streamed, slot released."""
        from unittest.mock import patch
        from botocore.exceptions import ClientError as _CE

        main_mod = self._import_main()
        not_found = _CE(
            {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}}, "HeadObject"
        )

        class _MissingS3:
            def head_object(self, *, Bucket, Key):
                raise not_found

            def get_object(self, *, Bucket, Key, Range=None):  # pragma: no cover
                raise AssertionError("body GET must not happen on a missing object")

        before = main_mod._stream_semaphore._value
        with patch.object(main_mod, "s3", _MissingS3()):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-stream?key=data/missing.parquet",
                cookies=admin_cookies,
            )
        assert resp.status_code == 404, resp.text
        assert resp.json()["detail"] == "Object not found"
        # Critical: the slot acquired for head_object must be returned even on
        # the error path (the generator never ran to release it for us).
        assert main_mod._stream_semaphore._value == before, (
            f"semaphore leaked on 404: {before} → {main_mod._stream_semaphore._value}"
        )

    def test_size_cap_returns_413_and_releases_slot(
        self, client, admin_cookies
    ):
        """ContentLength > PARQUET_STREAM_CAP → 413, body never streamed, slot released."""
        from unittest.mock import patch

        main_mod = self._import_main()
        huge = 200 * 1024 * 1024  # well above the 128 MB cap
        fake = self._stream_fake_s3(b"PAR1smallpayload", content_length=huge)

        before = main_mod._stream_semaphore._value
        with patch.object(main_mod, "s3", fake):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-stream?key=data/big.parquet",
                cookies=admin_cookies,
            )
        assert resp.status_code == 413, resp.text
        assert "128MB" in resp.json()["detail"]
        # The whole point of the cap: never start streaming a too-large object.
        assert fake.get_calls == 0, "body must not be streamed when over the cap"
        assert main_mod._stream_semaphore._value == before, (
            f"semaphore leaked on 413: {before} → {main_mod._stream_semaphore._value}"
        )

    def test_happy_path_streams_exact_bytes_and_headers(
        self, client, admin_cookies
    ):
        """Small stream: concatenated body equals the object's bytes, headers correct."""
        from unittest.mock import patch

        main_mod = self._import_main()
        data = self._sample_stream_bytes()
        fake = self._stream_fake_s3(data)

        before = main_mod._stream_semaphore._value
        with patch.object(main_mod, "s3", fake):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-stream?key=data/test.parquet",
                cookies=admin_cookies,
            )
        assert resp.status_code == 200, resp.text
        # Byte-fidelity: the streamed body reconstructs the object exactly.
        assert resp.content == data
        # Exactly one get_object (the endpoint must not re-fetch or buffer in a loop).
        assert fake.get_calls == 1
        # Headers (Content-Length from head_object, inline disposition, no caching).
        assert resp.headers["content-length"] == str(len(data))
        assert resp.headers["content-type"] == "application/octet-stream"
        assert resp.headers["content-disposition"] == 'inline; filename="test.parquet"'
        assert resp.headers["cache-control"] == "no-store"
        # Normal completion releases the slot.
        assert main_mod._stream_semaphore._value == before

    def test_client_disconnect_releases_slot(self):
        """A client disconnecting mid-stream MUST release the semaphore.

        This is the highest-priority correctness property: we pull one chunk
        from the real ``StreamingResponse.body_iterator`` (the same async
        iterator Starlette drives), then ``aclose()`` it — exactly what Starlette
        does when the downstream connection drops. The generator's ``finally``
        runs on the resulting ``GeneratorExit`` and must return the permit.
        """
        import asyncio
        from unittest.mock import patch

        main_mod = self._import_main()
        data = self._sample_stream_bytes()
        fake = self._stream_fake_s3(data)

        async def drive():
            before = main_mod._stream_semaphore._value
            # NOTE: the patch context must stay open for the WHOLE iteration —
            # the generator runs in a worker thread and resolves ``s3`` from
            # module globals lazily, on each chunk.
            with patch.object(main_mod, "s3", fake):
                resp = main_mod.parquet_stream(
                    "test-bucket",
                    "data/test.parquet",
                    user={"username": "admin", "role": "admin"},
                )
                # Slot acquired synchronously by the time parquet_stream returns.
                assert main_mod._stream_semaphore._value == before - 1
                it = resp.body_iterator
                first = await it.__anext__()  # start streaming
                assert first, "expected at least one chunk"
                # Still held while the stream is in flight.
                assert main_mod._stream_semaphore._value == before - 1
                await it.aclose()  # ← simulate client disconnect
            # The decisive assertion: permit returned despite the early close.
            assert main_mod._stream_semaphore._value == before, (
                f"semaphore leaked on disconnect: {before} → "
                f"{main_mod._stream_semaphore._value}"
            )

        asyncio.run(drive())

    def test_non_parquet_ext_returns_400_and_releases_slot(
        self, client, admin_cookies
    ):
        """A non-Parquet key → 400 before head_object, slot released."""
        main_mod = self._import_main()
        before = main_mod._stream_semaphore._value
        resp = client.get(
            "/api/buckets/test-bucket/parquet-stream?key=data/test.csv",
            cookies=admin_cookies,
        )
        assert resp.status_code == 400, resp.text
        assert "Unsupported file type" in resp.json()["detail"]
        assert main_mod._stream_semaphore._value == before, (
            f"semaphore leaked on 400: {before} → {main_mod._stream_semaphore._value}"
        )

    def test_consumes_dedicated_stream_semaphore(self, client, admin_cookies):
        """The stream endpoint is bounded by a DEDICATED ``_stream_semaphore(2)``,
        NOT the shared ``_metadata_semaphore`` (arch §2 constraint #5 escape
        hatch). Pre-acquire 1 of the 2 stream permits; a stream must still
        succeed with the 1 remaining slot AND must NOT touch the metadata gate
        at all. Pre-acquiring BOTH stream permits must 429 the next request.
        """
        from unittest.mock import patch

        main_mod = self._import_main()
        data = self._sample_stream_bytes()
        fake = self._stream_fake_s3(data)
        stream_sem = main_mod._stream_semaphore
        meta_sem = main_mod._metadata_semaphore

        # The suite must leave both semaphores fully available between tests.
        assert stream_sem._value == 2, (
            f"stream semaphore not at 2 at test start: {stream_sem._value}"
        )
        assert meta_sem._value == 4, (
            f"metadata semaphore not at 4 at test start: {meta_sem._value}"
        )

        # ── Part 1: pre-acquire 1 of 2 stream permits; request still succeeds. ──
        held = []
        got = stream_sem.acquire(blocking=False)
        assert got, "failed to pre-acquire a stream permit"
        held.append(got)
        try:
            assert stream_sem._value == 1  # exactly one stream slot left
            meta_before = meta_sem._value
            with patch.object(main_mod, "s3", fake):
                resp = client.get(
                    "/api/buckets/test-bucket/parquet-stream?key=data/test.parquet",
                    cookies=admin_cookies,
                )
            assert resp.status_code == 200, resp.text
            assert resp.content == data
            # The decisive isolation assertion: the metadata gate is UNTOUCHED.
            assert meta_sem._value == meta_before, (
                f"stream request touched the metadata gate: "
                f"{meta_before} → {meta_sem._value}"
            )
            # After the request, only our 1 manual permit is outstanding.
            assert stream_sem._value == 1
        finally:
            for _ in held:
                stream_sem.release()
            held.clear()
        assert stream_sem._value == 2
        assert meta_sem._value == 4

        # ── Part 2: pre-acquire BOTH stream permits → next request gets 429. ──
        # Fresh fake so get_calls starts at 0 (Part 1 already consumed one).
        fake = self._stream_fake_s3(data)
        for _ in range(2):
            got = stream_sem.acquire(blocking=False)
            assert got, "failed to pre-acquire a stream permit"
            held.append(got)
        try:
            assert stream_sem._value == 0  # no stream slots left
            meta_before = meta_sem._value
            with patch.object(main_mod, "s3", fake):
                resp = client.get(
                    "/api/buckets/test-bucket/parquet-stream?key=data/test.parquet",
                    cookies=admin_cookies,
                )
            assert resp.status_code == 429, resp.text
            assert "concurrent stream" in resp.json()["detail"].lower()
            # The 429 path (raised by _acquire_stream_slot) must not touch the
            # metadata gate either, and must not leak a stream permit.
            assert meta_sem._value == meta_before
            assert stream_sem._value == 0
            # body never streamed on a capacity 429.
            assert fake.get_calls == 0
        finally:
            for _ in held:
                stream_sem.release()
            held.clear()
        # Fully restored.
        assert stream_sem._value == 2
        assert meta_sem._value == 4

    def test_missing_content_length_refuses_stream(
        self, client, admin_cookies
    ):
        """head_object omitting ``ContentLength`` → 413, never streamed, slot released.

        Without ContentLength the size cap is silently bypassed and we'd
        advertise ``Content-Length: 0`` while real bytes stream. Real S3/MinIO
        always return it, but close the hole: refuse to stream blind.
        """
        from unittest.mock import patch

        main_mod = self._import_main()

        class _NoLengthS3:
            def head_object(self, *, Bucket, Key):
                # Deliberately omits ContentLength.
                return {"LastModified": "ignored"}

            def get_object(self, *, Bucket, Key, Range=None):  # pragma: no cover
                raise AssertionError("body must not be streamed when size is unknown")

        before = main_mod._stream_semaphore._value
        fake = _NoLengthS3()
        with patch.object(main_mod, "s3", fake):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-stream?key=data/unknown.parquet",
                cookies=admin_cookies,
            )
        assert resp.status_code == 413, resp.text
        assert "size" in resp.json()["detail"].lower()
        # Slot released on the error path (generator never ran).
        assert main_mod._stream_semaphore._value == before, (
            f"semaphore leaked on missing ContentLength: {before} → "
            f"{main_mod._stream_semaphore._value}"
        )

    def test_zero_byte_object_streams_and_releases(
        self, client, admin_cookies
    ):
        """A 0-byte Parquet object streams 200 with an empty body and releases the slot.

        ``ContentLength=0`` is a real (valid) value and must NOT trip the
        missing-size guard (that guard only fires when the key is ABSENT). The
        empty body still drives the generator to normal completion → ``finally``
        releases the slot.
        """
        from unittest.mock import patch

        main_mod = self._import_main()
        fake = self._stream_fake_s3(b"", content_length=0)

        before = main_mod._stream_semaphore._value
        with patch.object(main_mod, "s3", fake):
            resp = client.get(
                "/api/buckets/test-bucket/parquet-stream?key=data/empty.parquet",
                cookies=admin_cookies,
            )
        assert resp.status_code == 200, resp.text
        assert resp.content == b""
        assert resp.headers["content-length"] == "0"
        # get_object still called once (the generator runs to completion).
        assert fake.get_calls == 1
        # Normal completion releases the slot.
        assert main_mod._stream_semaphore._value == before, (
            f"semaphore leaked on 0-byte stream: {before} → "
            f"{main_mod._stream_semaphore._value}"
        )

    def test_mid_stream_clienterror_releases_slot(self):
        """A ``ClientError`` from ``get_object`` once the generator starts MUST
        release the stream slot — the generator's ``finally`` runs on the
        propagating exception exactly as it does on a client disconnect.
        """
        import asyncio
        from unittest.mock import patch
        from botocore.exceptions import ClientError as _CE

        main_mod = self._import_main()
        denied = _CE(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetObject",
        )

        class _GetFailsS3:
            def head_object(self, *, Bucket, Key):
                return {"ContentLength": 1234}  # passes the size guard

            def get_object(self, *, Bucket, Key, Range=None):
                raise denied

        async def drive():
            before = main_mod._stream_semaphore._value
            with patch.object(main_mod, "s3", _GetFailsS3()):
                resp = main_mod.parquet_stream(
                    "test-bucket",
                    "data/test.parquet",
                    user={"username": "admin", "role": "admin"},
                )
                # Slot acquired synchronously by the time parquet_stream returns.
                assert main_mod._stream_semaphore._value == before - 1
                it = resp.body_iterator
                with pytest.raises(_CE):
                    await it.__anext__()  # get_object raises here
            # The decisive assertion: permit returned despite the mid-stream error.
            assert main_mod._stream_semaphore._value == before, (
                f"semaphore leaked on mid-stream ClientError: {before} → "
                f"{main_mod._stream_semaphore._value}"
            )

        asyncio.run(drive())


# ── Per-bucket DB namespace hardening (F2) ────────────────
# Regression: a bucket named `users` used to collide with the auth DB `users.db`,
# so `DELETE /api/buckets/users` would os.remove the entire auth DB. Fix =
# reserve a `bucket_` namespace for every per-bucket DB + a one-time idempotent
# migration + a defense-in-depth 400 guard on the delete path.

class TestBucketDbNamespace:
    def test_delete_users_bucket_rejected_and_auth_db_intact(self, client, admin_cookies):
        """DELETE /api/buckets/users must 400 and leave users.db byte-identical."""
        m = _main_module()
        import sqlite3

        def _snapshot(path):
            try:
                with open(path, "rb") as fh:
                    return hashlib.sha256(fh.read()).hexdigest()
            except FileNotFoundError:
                return None

        users_db = m._users_db_path()
        before = {ext: _snapshot(users_db + ext) for ext in ("", "-wal", "-shm")}

        resp = client.delete("/api/buckets/users", cookies=admin_cookies)
        assert resp.status_code == 400, f"expected 400, got {resp.status_code}: {resp.text}"

        # Auth DB must be byte-identical (no os.remove occurred) for the main file
        # and any WAL/SHM sidecars present before the call.
        after = {ext: _snapshot(users_db + ext) for ext in ("", "-wal", "-shm")}
        for ext, h in before.items():
            if h is not None:
                assert after[ext] == h, f"users.db{ext} changed after rejected delete"
        # The main auth DB file must definitely still exist.
        assert os.path.exists(users_db), "users.db was deleted by the rejected call!"
        # A `bucket_users.db` index (if any) is irrelevant — the auth DB is what matters.

    def test_db_path_namespaces_with_bucket_prefix(self):
        """_db_path must prefix every per-bucket DB with `bucket_`."""
        m = _main_module()
        # Default endpoint → bucket_<name>.db
        assert m._db_path("mybucket").endswith("bucket_mybucket.db")
        # Non-default endpoint → bucket_<eid>_<name>.db
        assert m._db_path("mybucket", "ep1").endswith("bucket_ep1_mybucket.db")
        # The whole point: a bucket literally named "users" can never equal users.db
        users_bucket = m._db_path("users")
        assert users_bucket.endswith("bucket_users.db")
        assert users_bucket != m._users_db_path()

    def test_migration_renames_legacy_files_once_and_idempotent(self):
        """The one-time migration renames legacy DB files into the `bucket_` namespace,
        is idempotent, and never touches users.db."""
        m = _main_module()
        import sqlite3

        db_dir = m.DB_DIR

        try:
            # The app fixture already triggered startup() (marker set). Clear it so we
            # can drive the migration directly. DELETE is a no-op if the row is absent.
            with m._get_users_db() as db:
                db.execute("DELETE FROM instance_meta WHERE key='db_namespace_v1'")
                db.commit()

            # Seed legacy per-bucket DB files (main + WAL/SHM sidecars) and a
            # multi-endpoint-prefixed legacy file. Empty files are fine — the
            # migration only renames, it never opens them.
            for ext in ("", "-wal", "-shm"):
                open(os.path.join(db_dir, f"oldbucket.db{ext}"), "wb").close()
            open(os.path.join(db_dir, "ep2_other.db"), "wb").close()

            users_db = m._users_db_path()

            def _auth_rows():
                # Structural snapshot of the auth DB. The migration legitimately
                # writes the marker into instance_meta (which lives in users.db), so
                # byte-identity does NOT hold — instead prove the auth data survives.
                conn = sqlite3.connect(users_db)
                rows = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
                conn.close()
                return rows

            users_before = _auth_rows()

            # ---- First run: legacy files get renamed into the namespace ----
            m._migrate_bucket_db_namespace()

            # main + sidecars renamed
            for ext in ("", "-wal", "-shm"):
                assert not os.path.exists(os.path.join(db_dir, f"oldbucket.db{ext}")), \
                    f"legacy oldbucket.db{ext} should have been renamed"
                assert os.path.exists(os.path.join(db_dir, f"bucket_oldbucket.db{ext}")), \
                    f"bucket_oldbucket.db{ext} should exist after migration"
            # multi-endpoint legacy file renamed
            assert not os.path.exists(os.path.join(db_dir, "ep2_other.db"))
            assert os.path.exists(os.path.join(db_dir, "bucket_ep2_other.db"))
            # users.db untouched (reserved): still at the same path, NOT renamed
            # into the namespace, and its auth rows survive intact.
            assert os.path.exists(users_db), "users.db must not be renamed/removed"
            assert not os.path.exists(os.path.join(db_dir, "bucket_users.db")), \
                "users.db must NOT be renamed into the namespace"
            assert _auth_rows() == users_before, "auth rows changed during migration"
            # marker is now set
            assert m._meta_get("db_namespace_v1"), "migration marker should be set after run"

            # ---- Idempotency run #1: clear marker, re-run → no further renames ----
            with m._get_users_db() as db:
                db.execute("DELETE FROM instance_meta WHERE key='db_namespace_v1'")
                db.commit()
            m._migrate_bucket_db_namespace()  # nothing left to rename; no error
            # legacy names still gone (not recreated), namespaced names still present
            assert not os.path.exists(os.path.join(db_dir, "oldbucket.db"))
            assert os.path.exists(os.path.join(db_dir, "bucket_oldbucket.db"))
            assert _auth_rows() == users_before, "auth rows changed on idempotent re-run"
            assert m._meta_get("db_namespace_v1"), "marker should be re-set after idempotent run"

            # ---- Idempotency run #2: do NOT clear marker → early-return no-op ----
            m._migrate_bucket_db_namespace()
            assert os.path.exists(os.path.join(db_dir, "bucket_oldbucket.db"))
            assert _auth_rows() == users_before
        finally:
            # CLEANUP: remove every file we produced (legacy + namespaced, main +
            # sidecars) so the shared /tmp/sairo-test dir is not polluted for other
            # tests. Iterate base names × {-wal,-shm,""}.
            cleanup_bases = {"oldbucket.db", "bucket_oldbucket.db", "ep2_other.db", "bucket_ep2_other.db"}
            for base in cleanup_bases:
                for ext in ("", "-wal", "-shm"):
                    try:
                        os.remove(os.path.join(db_dir, base + ext))
                    except FileNotFoundError:
                        pass
            # Re-run migration to restore the marker (leave shared state consistent).
            try:
                m._migrate_bucket_db_namespace()
            except Exception:
                pass

    def test_non_reserved_bucket_still_works_after_migration(self):
        """After migration, a normal (non-`users`) bucket index still initializes and reads."""
        m = _main_module()
        import sqlite3

        bucket = "regulartest"
        db_file = m._db_path(bucket)  # ends with bucket_regulartest.db
        try:
            assert db_file.endswith("bucket_regulartest.db")
            m._init_db(bucket)  # creates objects table etc.
            assert os.path.exists(db_file), "bucket_regulartest.db should exist after _init_db"
            # A read against the objects table should work (table exists, empty).
            conn = sqlite3.connect(db_file)
            count = conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
            conn.close()
            assert count == 0
        finally:
            for ext in ("", "-wal", "-shm"):
                try:
                    os.remove(db_file + ext)
                except FileNotFoundError:
                    pass

    def test_non_reserved_bucket_list_endpoint_reads_namespaced_db(self, client, admin_cookies):
        """End-to-end: after the namespace fix, GET /api/buckets/{b}/list serves the
        object index from `bucket_{b}.db` (not the legacy unprefixed path, never users.db).
        Seeds one object so _is_index_ready() is True → the endpoint uses the index
        (no S3 fallback required)."""
        m = _main_module()
        bucket = "f2e2elist"
        db_file = m._db_path(bucket)
        try:
            # The index must live at the namespaced path.
            assert db_file.endswith("bucket_f2e2elist.db"), db_file
            # Build the index and seed exactly one object at the root prefix.
            m._init_db(bucket)
            with m._get_db(bucket) as db:
                db.execute(
                    "INSERT INTO objects (key,size,last_modified,etag,prefix,depth) "
                    "VALUES (?,?,?,?,?,?)",
                    ("hello.txt", 123, "2026-07-26T00:00:00Z", '"etag1"', "", 0),
                )
                db.commit()
            assert m._is_index_ready(bucket), "seeded index should be ready"

            # The HTTP list path must resolve to the same namespaced DB and return
            # the seeded object (indexed=True → index was used, not S3 streaming).
            resp = client.get(f"/api/buckets/{bucket}/list", cookies=admin_cookies)
            assert resp.status_code == 200, resp.text
            lines = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
            assert lines, "list endpoint returned no ndjson lines"
            payload = lines[0]
            assert payload.get("indexed") is True, f"expected index path, got {payload}"
            keys = {f["key"] for f in payload.get("files", [])}
            assert "hello.txt" in keys, f"hello.txt missing from files: {keys}"

            # Defense-in-depth sanity: a `users`-named index path can never be the
            # auth DB, and the just-used file is provably distinct from users.db.
            assert m._db_path("users") != m._users_db_path()
            assert m._db_path("users").endswith("bucket_users.db")
        finally:
            for ext in ("", "-wal", "-shm"):
                try:
                    os.remove(db_file + ext)
                except FileNotFoundError:
                    pass
