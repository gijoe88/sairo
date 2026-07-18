"""Unit tests for TrustedProxyMiddleware + parse_trusted_proxies.

These tests deliberately use a minimal inline Starlette app (NOT Sairo's
main.py) so they stay isolated, fast, and focused on the middleware contract.
The peer IP is set via ``TestClient(app, client=(host, port))`` (supported by
the installed Starlette), and forwarded headers are passed as normal headers.

Run with: pytest backend/test_trusted_proxy.py -v
"""
import ipaddress
import warnings

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from trusted_proxy import TrustedProxyMiddleware, parse_trusted_proxies

warnings.filterwarnings("ignore")  # silence the httpx/starlette deprecation notice

# A typical corporate/proxy CIDR used across these tests.
NET_10 = ipaddress.ip_network("10.0.0.0/8")


def _make_app(trusted_proxies):
    """Build a tiny Starlette app that reports what it sees, wrapped by the
    TrustedProxyMiddleware. The handler echoes back the values the downstream
    code would observe."""
    async def handler(request):
        return JSONResponse({
            "client": request.client.host if request.client else None,
            "port": request.client[1] if request.client else None,
            "scheme": request.url.scheme,
            "base_url": str(request.base_url),
            "host": request.headers.get("host"),
        })

    app = Starlette(routes=[Route("/", handler)])
    app.add_middleware(TrustedProxyMiddleware, trusted_proxies=trusted_proxies)
    return app


def _get(trusted_proxies, peer, headers=None):
    """Helper: build an app for the given trust set, fire a GET from ``peer``
    with optional ``headers``, return the parsed JSON the handler saw."""
    app = _make_app(trusted_proxies)
    client = TestClient(app, client=(peer, 12345))
    resp = client.get("/", headers=headers or {})
    assert resp.status_code == 200, resp.text
    return resp.json()


# ── X-Forwarded-For resolution ─────────────────────────────────────────────

class TestForwardedFor:
    def test_trusted_peer_xff_resolved(self):
        """Peer inside TRUSTED_PROXIES, XFF set → handler sees the XFF value."""
        out = _get({NET_10}, "10.0.0.1", headers={"X-Forwarded-For": "203.0.113.9"})
        assert out["client"] == "203.0.113.9"

    def test_untrusted_peer_xff_ignored(self):
        """Peer NOT in TRUSTED_PROXIES → XFF ignored, handler sees the peer."""
        out = _get({NET_10}, "8.8.8.8", headers={"X-Forwarded-For": "203.0.113.9"})
        assert out["client"] == "8.8.8.8"

    def test_multihop_xff_rightmost_untrusted(self):
        """Multi-hop XFF: walk right-to-left past trusted proxies to the first
        untrusted entry (the real client)."""
        out = _get(
            {NET_10}, "10.0.0.1",
            headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.2, 10.0.0.3"},
        )
        assert out["client"] == "203.0.113.9"

    def test_all_trusted_xff_falls_back_leftmost(self):
        """Every XFF entry is trusted → fall back to the leftmost entry."""
        out = _get(
            {NET_10}, "10.0.0.1",
            headers={"X-Forwarded-For": "10.0.0.2, 10.0.0.3"},
        )
        assert out["client"] == "10.0.0.2"

    def test_invalid_xff_entry_skipped(self):
        """A malformed XFF entry is skipped (no crash); the valid one wins."""
        out = _get(
            {NET_10}, "10.0.0.1",
            headers={"X-Forwarded-For": "not-an-ip, 203.0.113.9"},
        )
        assert out["client"] == "203.0.113.9"

    def test_xff_peer_entry_skipped(self):
        """An XFF entry equal to the peer is skipped during the right-to-left
        walk, so a non-trusted entry further left still wins."""
        out = _get(
            {NET_10}, "10.0.0.1",
            headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"},
        )
        assert out["client"] == "203.0.113.9"


# ── X-Real-IP fallback ─────────────────────────────────────────────────────

class TestRealIp:
    def test_x_real_ip_used_when_no_xff(self):
        """No XFF → X-Real-IP used when valid."""
        out = _get({NET_10}, "10.0.0.1", headers={"X-Real-IP": "198.51.100.7"})
        assert out["client"] == "198.51.100.7"

    def test_invalid_x_real_ip_ignored(self):
        """Invalid X-Real-IP → peer kept (no crash)."""
        out = _get({NET_10}, "10.0.0.1", headers={"X-Real-IP": "garbage"})
        assert out["client"] == "10.0.0.1"

    def test_xff_takes_precedence_over_x_real_ip(self):
        """When both are present, XFF wins."""
        out = _get(
            {NET_10}, "10.0.0.1",
            headers={"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "198.51.100.7"},
        )
        assert out["client"] == "203.0.113.9"


# ── scheme / host rewrites ─────────────────────────────────────────────────

class TestProtoHostRewrite:
    def test_x_forwarded_proto_rewrites_scheme(self):
        out = _get({NET_10}, "10.0.0.1", headers={"X-Forwarded-Proto": "https"})
        assert out["scheme"] == "https"

    def test_x_forwarded_host_rewrites_base_url(self):
        out = _get({NET_10}, "10.0.0.1", headers={"X-Forwarded-Host": "example.com"})
        assert out["base_url"].startswith("http://example.com/")
        assert out["host"] == "example.com"

    def test_proto_and_host_rewrites_combine(self):
        """https + custom host → base_url uses both."""
        out = _get(
            {NET_10}, "10.0.0.1",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "example.com",
            },
        )
        assert out["scheme"] == "https"
        assert out["base_url"] == "https://example.com/"

    def test_proto_rewrite_ignored_for_untrusted_peer(self):
        out = _get(
            {NET_10}, "8.8.8.8",
            headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "example.com"},
        )
        assert out["scheme"] == "http"          # TestClient default
        assert out["host"] != "example.com"     # untouched

    def test_empty_x_forwarded_proto_ignored(self):
        """Empty proto value must NOT blank out the scheme."""
        out = _get({NET_10}, "10.0.0.1", headers={"X-Forwarded-Proto": "  "})
        assert out["scheme"] == "http"


# ── CIDR matching ──────────────────────────────────────────────────────────

class TestCidrMatching:
    def test_cidr_matches_inside_range(self):
        out = _get({NET_10}, "10.1.2.3", headers={"X-Forwarded-For": "203.0.113.9"})
        assert out["client"] == "203.0.113.9"

    def test_cidr_rejects_outside_range(self):
        out = _get({NET_10}, "11.0.0.1", headers={"X-Forwarded-For": "203.0.113.9"})
        assert out["client"] == "11.0.0.1"

    def test_bare_ip_token_treated_as_host(self):
        """A bare IP token (no /CIDR) parses as a /32 and matches only itself."""
        net = ipaddress.ip_network("10.0.0.5")  # → 10.0.0.5/32
        assert _get({net}, "10.0.0.5", headers={"X-Forwarded-For": "203.0.113.9"})["client"] == "203.0.113.9"
        assert _get({net}, "10.0.0.6", headers={"X-Forwarded-For": "203.0.113.9"})["client"] == "10.0.0.6"


# ── Fail-closed default ────────────────────────────────────────────────────

class TestFailClosed:
    def test_empty_trusted_proxies_is_noop(self):
        """Empty trust set → middleware is a complete no-op even with headers."""
        out = _get(set(), "10.0.0.1",
                   headers={"X-Forwarded-For": "203.0.113.9",
                            "X-Forwarded-Proto": "https",
                            "X-Forwarded-Host": "example.com"})
        assert out["client"] == "10.0.0.1"
        assert out["scheme"] == "http"
        assert out["host"] != "example.com"

    def test_original_port_preserved(self):
        """The real client IP replaces the host part of scope['client'] but the
        original port is preserved."""
        out = _get({NET_10}, "10.0.0.1", headers={"X-Forwarded-For": "203.0.113.9"})
        assert out["port"] == 12345


# ── parse_trusted_proxies ──────────────────────────────────────────────────

class TestParseTrustedProxies:
    def test_empty_string_returns_empty_set(self):
        assert parse_trusted_proxies("") == set()

    def test_whitespace_only_returns_empty_set(self):
        assert parse_trusted_proxies("   ") == set()

    def test_none_returns_empty_set(self):
        assert parse_trusted_proxies(None) == set()

    def test_single_cidr(self):
        out = parse_trusted_proxies("10.0.0.0/8")
        assert out == {ipaddress.ip_network("10.0.0.0/8")}

    def test_single_bare_ip_becomes_host_route(self):
        out = parse_trusted_proxies("10.0.0.5")
        assert out == {ipaddress.ip_network("10.0.0.5/32")}

    def test_multiple_tokens(self):
        out = parse_trusted_proxies("10.0.0.0/8, 192.168.0.0/16, 172.16.0.1")
        assert out == {
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("172.16.0.1/32"),
        }

    def test_whitespace_and_empty_tokens_skipped(self):
        out = parse_trusted_proxies("  10.0.0.0/8  , ,  ,192.168.0.0/16 ")
        assert out == {
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("192.168.0.0/16"),
        }

    def test_ipv6_supported(self):
        out = parse_trusted_proxies("2001:db8::/32")
        assert out == {ipaddress.ip_network("2001:db8::/32")}

    def test_invalid_token_raises_value_error(self):
        """Invalid tokens fail fast — the app must refuse to boot."""
        with pytest.raises(ValueError, match="Invalid TRUSTED_PROXIES"):
            parse_trusted_proxies("10.0.0.0/8, not-a-network")

    def test_invalid_token_message_includes_token(self):
        with pytest.raises(ValueError, match=r"'bogus'"):
            parse_trusted_proxies("bogus")

    def test_invalid_cidr_prefix_raises(self):
        """Out-of-range prefix lengths are invalid, not silently widened."""
        with pytest.raises(ValueError):
            parse_trusted_proxies("10.0.0.0/99")


# ── Structural / ordering ─────────────────────────────────────────────────

class TestMiddlewareOrdering:
    def test_middleware_is_outermost(self):
        """TrustedProxyMiddleware, registered last via add_middleware, lands at
        position 0 of user_middleware — i.e. OUTERMOST (runs first on the way
        in, last on the way out)."""
        from fastapi import FastAPI

        app = FastAPI()

        @app.middleware("http")
        async def first(request, call_next):
            return await call_next(request)

        @app.middleware("http")
        async def second(request, call_next):
            return await call_next(request)

        app.add_middleware(TrustedProxyMiddleware, trusted_proxies={NET_10})

        assert app.user_middleware[0].cls is TrustedProxyMiddleware
        # The two decorators sit inside it.
        assert len([m for m in app.user_middleware
                    if m.cls.__name__ == "BaseHTTPMiddleware"]) == 2


# ── Integration: all three rewrites in one request ─────────────────────────

class TestIntegration:
    def test_all_three_rewrites_in_one_request(self):
        """A single trusted request sees client, scheme, AND base_url all
        rewritten together — the effective-across-the-stack check."""
        out = _get(
            {NET_10}, "10.0.0.1",
            headers={
                "X-Forwarded-For": "203.0.113.9",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "example.com",
            },
        )
        assert out["client"] == "203.0.113.9"
        assert out["scheme"] == "https"
        assert out["base_url"] == "https://example.com/"
        assert out["host"] == "example.com"
