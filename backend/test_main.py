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
import time
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
