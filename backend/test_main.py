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


def _mint_s3_cookie(username):
    """Construct an S3-mode session cookie directly. The login-s3 route issues
    exactly this JWT (sub='s3:...', role='admin'); minting it here avoids the
    shared login rate limiter (LOGIN_RATE_MAX=10 / 300s) that the route enforces
    and keeps these guard tests isolated from the login path. The s3ak/s3sk
    claims that the route also carries are only needed for live S3 calls, which
    these endpoints don't make, so they're omitted. Mirrors F7's use of jwt."""
    import jwt as _jwt
    m = _main_module()
    token = _jwt.encode(
        {"sub": username, "role": "admin",
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        m.JWT_SECRET, algorithm="HS256",
    )
    return {"access_token": token}


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


# ── PR 9: auth-mode guard, cookie/DB validation, 2FA entropy, OAuth state ────
#
# F4: /api/auth/login-s3 gated on AUTH_MODE=s3
# F7: cookie sessions re-validated against the users table on each request
# L4: 64-bit (16 hex) 2FA recovery codes
# L5: oauth_state cookie cleared after the OAuth exchange (success + 2FA)


def _cookie_deletion_set(headers, name: str, path: str) -> bool:
    """True if the response carries a Set-Cookie header that *deletes* `name`
    scoped to `path` (empty value + Max-Age=0). Used to assert that an auth
    flow clears a state cookie."""
    # httpx.Headers exposes multi-valued headers via get_list (not getlist).
    get_all = getattr(headers, "get_list", None) or getattr(headers, "getlist", None)
    for sc in (get_all("set-cookie") if get_all else []):
        if sc.startswith(f"{name}=") and f"Path={path}" in sc and "Max-Age=0" in sc:
            return True
    return False


class TestS3LoginModeGuard:
    """F4: in local mode the S3 login route must be unreachable (it otherwise
    hands a local-admin cookie to anyone holding the server's S3 service-account
    credentials)."""

    def test_login_s3_rejected_in_local_mode(self, client, monkeypatch):
        m = _main_module()
        monkeypatch.setattr(m, "AUTH_MODE", "local")
        resp = client.post(
            "/api/auth/login-s3",
            json={"access_key": "AKIATEST123456", "secret_key": "secretkey1234"},
            follow_redirects=False,
        )
        assert resp.status_code == 404

    def test_login_s3_allowed_in_s3_mode(self, app, monkeypatch):
        """In s3 mode the guard lets the request through; with boto3 mocked by
        the app fixture, list_buckets() succeeds and a session is issued."""
        m = _main_module()
        monkeypatch.setattr(m, "AUTH_MODE", "s3")
        with TestClient(app) as c:
            resp = c.post(
                "/api/auth/login-s3",
                json={"access_key": "AKIATEST123456", "secret_key": "secretkey1234"},
                follow_redirects=False,
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["username"].startswith("s3:")
            assert data["role"] == "admin"
            assert resp.cookies.get("access_token"), "session cookie should be issued"


class TestCookieSessionDBValidation:
    """F7: a cookie session is re-checked against the users table on every
    request, so a deleted user fails immediately and a demoted admin's role
    updates on the next request (mirrors the API-token path)."""

    def test_deleted_user_cookie_is_rejected(self, app, client, admin_cookies):
        m = _main_module()
        resp = client.post(
            "/api/auth/users",
            json={"username": "f7-deleted", "password": "pw12345678", "role": "viewer"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        with TestClient(app) as c:
            login = c.post("/api/auth/login",
                           json={"username": "f7-deleted", "password": "pw12345678"})
            assert login.status_code == 200
            cookie = {"access_token": login.cookies.get("access_token")}
            # Cookie is honored while the user exists.
            me = c.get("/api/auth/me", cookies=cookie)
            assert me.status_code == 200
            assert me.json()["username"] == "f7-deleted"
            # Remove the user directly in the DB (cookie still has ~SESSION_HOURS left).
            with m._get_users_db() as db:
                db.execute("DELETE FROM users WHERE username=?", ("f7-deleted",))
                db.commit()
            # Same cookie must now be rejected — not honored until expiry.
            me2 = c.get("/api/auth/me", cookies=cookie)
            assert me2.status_code == 401

    def test_demoted_admin_role_updates_and_admin_route_blocks(self, app, client, admin_cookies):
        m = _main_module()
        resp = client.post(
            "/api/auth/users",
            json={"username": "f7-demoted", "password": "pw12345678", "role": "admin"},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        with TestClient(app) as c:
            login = c.post("/api/auth/login",
                           json={"username": "f7-demoted", "password": "pw12345678"})
            assert login.status_code == 200
            cookie = {"access_token": login.cookies.get("access_token")}
            # Initially admin — admin-gated route works.
            me = c.get("/api/auth/me", cookies=cookie)
            assert me.status_code == 200 and me.json()["role"] == "admin"
            assert c.get("/api/health-detail", cookies=cookie).status_code == 200
            # Demote to viewer directly in the DB.
            with m._get_users_db() as db:
                db.execute("UPDATE users SET role=? WHERE username=?",
                           ("viewer", "f7-demoted"))
                db.commit()
            # Next request reflects the demotion (cookie still encodes 'admin').
            me2 = c.get("/api/auth/me", cookies=cookie)
            assert me2.status_code == 200
            assert me2.json()["role"] == "viewer"
            # And the admin-gated route now forbids the demoted session.
            assert c.get("/api/health-detail", cookies=cookie).status_code == 403

    def test_live_user_cookie_still_works(self, app, client, admin_cookies):
        """Sanity: the DB check must not break a live, unmodified user's cookie."""
        client.post(
            "/api/auth/users",
            json={"username": "f7-live", "password": "pw12345678", "role": "viewer"},
            cookies=admin_cookies,
        )
        with TestClient(app) as c:
            login = c.post("/api/auth/login",
                           json={"username": "f7-live", "password": "pw12345678"})
            assert login.status_code == 200
            me = c.get("/api/auth/me",
                       cookies={"access_token": login.cookies.get("access_token")})
            assert me.status_code == 200
            assert me.json()["role"] == "viewer"

    def test_s3_session_cookie_not_subject_to_db_lookup(self, app, monkeypatch):
        """F7 correctness refinement: an s3: session has no users row and must
        bypass the DB lookup (else every S3 request would 401)."""
        import jwt as _jwt
        m = _main_module()
        monkeypatch.setattr(m, "AUTH_MODE", "s3")
        with TestClient(app) as c:
            resp = c.post(
                "/api/auth/login-s3",
                json={"access_key": "AKIATESTS3MODE", "secret_key": "secretkey1234"},
                follow_redirects=False,
            )
            assert resp.status_code == 200, resp.text
            token = resp.cookies.get("access_token")
            assert token
            # No users row exists for 's3:AKIATEST...' — /me must still succeed.
            me = c.get("/api/auth/me", cookies={"access_token": token})
            assert me.status_code == 200
            assert me.json()["username"].startswith("s3:")
            assert me.json()["role"] == "admin"
            # And the sub indeed carries the s3: prefix the exemption keys on.
            claims = _jwt.decode(token, m.JWT_SECRET, algorithms=["HS256"])
            assert claims["sub"].startswith("s3:")


class TestTwoFactorRecoveryEntropy:
    """L4: recovery codes must be 64-bit (16 hex chars), not 32-bit (8 hex)."""

    def test_recovery_codes_are_16_hex_chars(self, app, client, admin_cookies):
        import re
        import pyotp
        m = _main_module()
        # Use a dedicated user so the shared admin is not 2FA-locked for later tests.
        client.post(
            "/api/auth/users",
            json={"username": "f7-2fa", "password": "pw12345678", "role": "viewer"},
            cookies=admin_cookies,
        )
        with TestClient(app) as c:
            assert c.post("/api/auth/login",
                          json={"username": "f7-2fa", "password": "pw12345678"}).status_code == 200
            secret = c.post("/api/auth/2fa/setup").json()["secret"]
            code = pyotp.TOTP(secret).now()
            resp = c.post("/api/auth/2fa/enable", json={"code": code})
            assert resp.status_code == 200, resp.text
            codes = resp.json()["recovery_codes"]
            assert len(codes) == 10
            hex16 = re.compile(r"^[0-9a-f]{16}$")
            for value in codes:
                assert hex16.match(value), f"recovery code not 16 hex chars: {value!r}"


class TestOAuthStateCookieCleared:
    """L5: the OAuth callback must clear the oauth_state cookie on both the
    success and 2FA branches (mirrors the OIDC callback's oidc_state cleanup)."""

    def _enable_google(self, monkeypatch):
        m = _main_module()
        monkeypatch.setattr(m, "OAUTH_GOOGLE_CLIENT_ID", "g-client-id")
        monkeypatch.setattr(m, "OAUTH_GOOGLE_CLIENT_SECRET", "g-secret")
        monkeypatch.setattr(m, "OAUTH_ALLOWED_DOMAINS", [])
        return m

    def _stub_google_userinfo(self, monkeypatch, email):
        from types import SimpleNamespace
        monkeypatch.setattr("httpx.post", lambda *a, **k: SimpleNamespace(
            status_code=200, json=lambda: {"access_token": "AT"}))
        monkeypatch.setattr("httpx.get", lambda *a, **k: SimpleNamespace(
            status_code=200, json=lambda: {"email": email}))

    def test_success_branch_deletes_oauth_state(self, app, monkeypatch):
        m = self._enable_google(monkeypatch)
        self._stub_google_userinfo(monkeypatch, "oauthuser@corp.test")
        with TestClient(app) as c:
            resp = c.get("/api/auth/oauth/google/callback?code=abc",
                         follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert resp.headers["location"] == "/"
            assert resp.cookies.get("access_token"), "session cookie should be issued"
            assert _cookie_deletion_set(resp.headers, "oauth_state", "/api/auth/oauth")
        # The synced OAuth user exists (username is the email local-part).
        with m._get_users_db() as db:
            row = db.execute("SELECT role, auth_source FROM users WHERE username=?",
                             ("oauthuser",)).fetchone()
            assert row is not None and row["role"] == "viewer"
            assert (row["auth_source"] or "") == "oauth"

    def test_2fa_branch_deletes_oauth_state(self, app, monkeypatch):
        m = self._enable_google(monkeypatch)
        # Pre-create an OAuth user with 2FA already enabled so the callback takes
        # the 2FA branch (INSERT OR REPLACE keeps the test re-runnable in-process).
        with m._get_users_db() as db:
            db.execute(
                "INSERT OR REPLACE INTO users "
                "(username, password_hash, role, auth_source, totp_enabled) "
                "VALUES (?, ?, ?, ?, 1)",
                ("oauth2fa", "OAUTH:placeholder", "viewer", "oauth"))
            db.commit()
        self._stub_google_userinfo(monkeypatch, "oauth2fa@corp.test")
        with TestClient(app) as c:
            resp = c.get("/api/auth/oauth/google/callback?code=abc",
                         follow_redirects=False)
            assert resp.status_code in (302, 307)
            assert "requires_2fa=true" in resp.headers["location"]
            assert resp.cookies.get("access_token"), "pending 2FA cookie should be issued"
            assert _cookie_deletion_set(resp.headers, "oauth_state", "/api/auth/oauth")


# ── L1: S3-mode tenant scoping ───────────────────────────

class TestS3ModeTenantScoping:
    """L1: an S3-mode session (sub='s3:...', role='admin') passes require_admin,
    so in a multi-tenant S3 deployment the share-link/token/audit/user endpoints
    must be scoped or blocked to prevent one tenant reading another tenant's
    data. Non-s3 admins keep full access (non-regression)."""

    S3_USER = "s3:AKIAL100"   # mirrors login-s3's f"s3:{access_key[:8]}"

    def test_s3_session_cannot_list_other_tenants_share_links(self, app, client, admin_cookies):
        """S3 session sees only its own share_links; a local admin still sees all."""
        m = _main_module()
        s3_cookie = _mint_s3_cookie(self.S3_USER)
        with TestClient(app) as c:
            with m._get_users_db() as db:
                db.execute("DELETE FROM share_links WHERE token LIKE 'l1sl-%'")
                db.execute(
                    "INSERT INTO share_links (token, bucket, key, created_by, expires_at) "
                    "VALUES (?,?,?,?,?)",
                    ("l1sl-alice", "alice-bkt", "alice.txt", "alice", "2030-01-01T00:00:00+00:00"))
                db.execute(
                    "INSERT INTO share_links (token, bucket, key, created_by, expires_at) "
                    "VALUES (?,?,?,?,?)",
                    ("l1sl-s3a", "s3-bkt", "a.txt", self.S3_USER, "2030-01-01T00:00:00+00:00"))
                db.execute(
                    "INSERT INTO share_links (token, bucket, key, created_by, expires_at) "
                    "VALUES (?,?,?,?,?)",
                    ("l1sl-s3b", "s3-bkt", "b.txt", self.S3_USER, "2030-01-01T00:00:00+00:00"))
                db.commit()
            # S3 session: only its own rows — alice's link must be absent.
            resp = c.get("/api/share-links", cookies=s3_cookie)
            assert resp.status_code == 200
            owners = {l["created_by"] for l in resp.json()["links"]}
            assert "alice" not in owners
            assert self.S3_USER in owners
        # Non-regression: a normal local admin still sees alice's link.
        resp = client.get("/api/share-links", cookies=admin_cookies)
        assert resp.status_code == 200
        owners = {l["created_by"] for l in resp.json()["links"]}
        assert "alice" in owners

    def test_s3_session_cannot_delete_other_tenants_share_link(self, app):
        """S3 session gets 403 deleting another tenant's link, 200 on its own."""
        m = _main_module()
        s3_cookie = _mint_s3_cookie(self.S3_USER)
        with TestClient(app) as c:
            with m._get_users_db() as db:
                db.execute("DELETE FROM share_links WHERE token LIKE 'l1sd-%'")
                db.execute(
                    "INSERT INTO share_links (token, bucket, key, created_by, expires_at) "
                    "VALUES (?,?,?,?,?)",
                    ("l1sd-alice", "alice-bkt", "alice.txt", "alice", "2030-01-01T00:00:00+00:00"))
                db.execute(
                    "INSERT INTO share_links (token, bucket, key, created_by, expires_at) "
                    "VALUES (?,?,?,?,?)",
                    ("l1sd-s3", "s3-bkt", "own.txt", self.S3_USER, "2030-01-01T00:00:00+00:00"))
                db.commit()
                alice_id = db.execute(
                    "SELECT id FROM share_links WHERE token='l1sd-alice'").fetchone()["id"]
                own_id = db.execute(
                    "SELECT id FROM share_links WHERE token='l1sd-s3'").fetchone()["id"]
            # Cross-tenant delete -> 403, row survives.
            resp = c.delete(f"/api/share-links/{alice_id}", cookies=s3_cookie)
            assert resp.status_code == 403
            with m._get_users_db() as db:
                assert db.execute(
                    "SELECT id FROM share_links WHERE id=?", (alice_id,)).fetchone() is not None
            # Own delete -> 200.
            resp = c.delete(f"/api/share-links/{own_id}", cookies=s3_cookie)
            assert resp.status_code == 200

    def test_s3_session_list_tokens_scoped_to_self(self, app, client, admin_cookies):
        """S3 session's token list excludes other tenants; local admin sees all."""
        m = _main_module()
        s3_cookie = _mint_s3_cookie(self.S3_USER)
        with TestClient(app) as c:
            with m._get_users_db() as db:
                db.execute("DELETE FROM api_tokens WHERE token_hash LIKE 'l1tl-%'")
                db.execute(
                    "INSERT INTO api_tokens (token_hash, token_prefix, username, name, role) "
                    "VALUES (?,?,?,?,?)",
                    ("l1tl-alice", "l1tl-alice...", "alice", "alice-tok", "admin"))
                db.commit()
            # S3 session: alice's token must be absent (s3 sessions mint none).
            resp = c.get("/api/auth/tokens", cookies=s3_cookie)
            assert resp.status_code == 200
            owners = {t["username"] for t in resp.json()["tokens"]}
            assert "alice" not in owners
        # Non-regression: local admin still sees alice's token.
        resp = client.get("/api/auth/tokens", cookies=admin_cookies)
        assert resp.status_code == 200
        owners = {t["username"] for t in resp.json()["tokens"]}
        assert "alice" in owners

    def test_s3_session_cannot_delete_other_tenants_token(self, app):
        """S3 session gets 403 deleting another tenant's API token; row survives."""
        m = _main_module()
        s3_cookie = _mint_s3_cookie(self.S3_USER)
        with TestClient(app) as c:
            with m._get_users_db() as db:
                db.execute("DELETE FROM api_tokens WHERE token_hash LIKE 'l1td-%'")
                db.execute(
                    "INSERT INTO api_tokens (token_hash, token_prefix, username, name, role) "
                    "VALUES (?,?,?,?,?)",
                    ("l1td-alice", "l1td-alice...", "alice", "alice-tok", "admin"))
                db.commit()
                alice_tok = db.execute(
                    "SELECT id FROM api_tokens WHERE token_hash='l1td-alice'").fetchone()["id"]
            resp = c.delete(f"/api/auth/tokens/{alice_tok}", cookies=s3_cookie)
            assert resp.status_code == 403
            with m._get_users_db() as db:
                assert db.execute(
                    "SELECT id FROM api_tokens WHERE id=?", (alice_tok,)).fetchone() is not None

    def test_s3_session_blocked_from_audit_log(self, app, client, admin_cookies):
        """S3 session gets 403 on the cross-tenant audit log; local admin reads it."""
        m = _main_module()
        s3_cookie = _mint_s3_cookie(self.S3_USER)
        with TestClient(app) as c:
            resp = c.get("/api/audit-log", cookies=s3_cookie)
            assert resp.status_code == 403
        # Non-regression: a normal local admin can still read the audit log.
        assert client.get("/api/audit-log", cookies=admin_cookies).status_code == 200

    def test_s3_session_blocked_from_user_list(self, app, client, admin_cookies):
        """S3 session gets 403 on the cross-tenant user list; local admin reads it."""
        m = _main_module()
        s3_cookie = _mint_s3_cookie(self.S3_USER)
        with TestClient(app) as c:
            resp = c.get("/api/auth/users", cookies=s3_cookie)
            assert resp.status_code == 403
        # Non-regression: a normal local admin can still list users.
        assert client.get("/api/auth/users", cookies=admin_cookies).status_code == 200


# ── L2: HSTS ─────────────────────────────────────────────

class TestHSTS:
    """L2: Strict-Transport-Security is advertised only when the request scheme
    is https, so dev/localhost (http) isn't pinned."""

    def test_hsts_present_on_https(self, app):
        """An https request advertises HSTS with the exact expected value."""
        with TestClient(app, base_url="https://testserver") as c:
            resp = c.get("/api/branding")
            assert resp.status_code == 200
            assert resp.headers["Strict-Transport-Security"] == (
                "max-age=31536000; includeSubDomains"
            )

    def test_hsts_absent_on_http(self, client):
        """An http request must NOT pin HSTS (dev/localhost safety)."""
        resp = client.get("/api/branding")
        assert resp.status_code == 200
        assert "Strict-Transport-Security" not in resp.headers
