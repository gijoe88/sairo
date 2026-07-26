"""
Per-request auth + ContextVar-propagation regression tests (HTTP transport).

These are the automated checks required by the design (audit-2026-07-fixes §7)
for PR 6 (``fix/mcp-per-request-auth-v2``). They exercise the FULL HTTP path:

    httpx AsyncClient ──ASGI──► Starlette app
                                 └─ SairoBearerAuthMiddleware (outermost)
                                     └─ FastMCP streamable_http (stateless)
                                         └─ lifespan (per-request)
                                             └─ tool / resource
                                                 └─ current_session()

instead of the in-memory transport the rest of the suite uses. The in-memory
transport never runs the bearer middleware, so it cannot catch HTTP-only
regressions; that is precisely the gap these tests close.

JSON-RPC request sequence (settled on after spiking):
    For a ``stateless_http=True, json_response=True`` server a SINGLE request
    is fully self-contained — each POST is its own session, so a *direct*
    ``tools/call`` (or ``resources/read``) with no ``initialize`` handshake
    returns the result synchronously as ``application/json``::

        POST /mcp
        Content-Type: application/json
        Accept: application/json
        Authorization: Bearer <token>

        {"jsonrpc":"2.0","id":1,"method":"tools/call",
         "params":{"name":"list_buckets","arguments":{}}}

    The tool text is at ``result.content[0].text`` (tools) /
    ``result.contents[0].text`` (resources). An ``AuthorizationError`` raised
    inside a tool is surfaced by FastMCP as a result with ``isError: true``
    (and a ``structuredContent`` describing the error) rather than a JSON-RPC
    top-level error, so the result parser below checks both.

Regression-guard status: an earlier lifespan-clobber bug on this transport
(the per-request ``lifespan()`` re-binding the session ContextVar AFTER the
bearer middleware had set it, so every HTTP request ran as the service /
dev-admin identity instead of the caller) was found and fixed. T2/T3/T4/T8
now run live and enforce that the bearer middleware's session wins; any future
regression (SDK bump, middleware rewrite, task-group re-parenting) fails the
suite instead of silently leaking the service/admin identity.
"""

# ─── Imports & test-only bucket DBs ───────────────────────────────────────────
#
# NOTE: unlike tests/test_e2e.py we deliberately do NOT mutate os.environ or
# db_module.DB_DIR at module import time — doing so leaks across the session and
# breaks tests/test_tools.py (which calls get_db("test-bucket") against whatever
# db.DB_DIR is currently pointed at). All env / db.DB_DIR mutation is scoped to
# the mcp_app_client fixture via monkeypatch so it is auto-restored on teardown.
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import AsyncMock

import asyncio
import pytest

# alpha/beta bucket DBs — created once (pure file I/O, no global state).
# db.DB_DIR is repointed at this dir only inside the fixture below.
_PERREQ_DB_DIR = tempfile.mkdtemp(prefix="sairo-mcp-perreq-")
from tests.conftest import _create_test_bucket_db
_create_test_bucket_db(_PERREQ_DB_DIR, "alpha", num_objects=20)
_create_test_bucket_db(_PERREQ_DB_DIR, "beta", num_objects=20)

import db as db_module  # noqa: E402
import server as srv  # noqa: E402
from auth import AuthorizationError, UserSession  # noqa: E402

import httpx  # noqa: E402


# ─── Deterministic tokens / sessions ──────────────────────────────────────────

ADMIN_TOKEN = "tok-admin"
ALPHA_TOKEN = "tok-alpha"
BETA_TOKEN = "tok-beta"


async def _fake_authenticate(token: str) -> UserSession:
    """Deterministic token→session map used in place of ``auth_manager.authenticate``.

    The bearer middleware calls ``auth_manager.authenticate(token)``; we patch
    that method on the module-global ``auth_manager`` singleton so each token
    resolves to a fixed identity:
        ADMIN_TOKEN → admin (sees every bucket)
        ALPHA_TOKEN → viewer scoped to {alpha: read}
        BETA_TOKEN  → viewer scoped to {beta: read}
        anything else → AuthorizationError (drives the 401 paths)
    """
    if token == ADMIN_TOKEN:
        return UserSession("admin", "admin", ADMIN_TOKEN, {})
    if token == ALPHA_TOKEN:
        return UserSession("alpha-viewer", "viewer", ALPHA_TOKEN, {"alpha": "read"})
    if token == BETA_TOKEN:
        return UserSession("beta-viewer", "viewer", BETA_TOKEN, {"beta": "read"})
    raise AuthorizationError("unknown token")


# ─── ASGI lifespan driver (asgi-lifespan pattern, no extra dep) ────────────────

class _LifespanManager:
    """Drive ASGI lifespan startup/shutdown for an app.

    ``httpx.ASGITransport`` only speaks the HTTP scope; the FastMCP
    streamable_http app needs its lifespan started (to initialise the session
    manager's task group) or every request raises
    ``RuntimeError: Task group is not initialized``.
    """

    def __init__(self, app):
        self.app = app
        self._startup = asyncio.Event()
        self._shutdown = asyncio.Event()
        self._queue: "asyncio.Queue" = asyncio.Queue()
        self._task = None

    async def __aenter__(self):
        self._task = asyncio.create_task(self._run())
        await self._queue.put({"type": "lifespan.startup"})
        await self._startup.wait()
        return self

    async def __aexit__(self, *exc):
        await self._queue.put({"type": "lifespan.shutdown"})
        await self._shutdown.wait()

    async def _run(self):
        async def receive():
            return await self._queue.get()

        async def send(message):
            t = message["type"]
            if t == "lifespan.startup.complete":
                self._startup.set()
            elif t == "lifespan.shutdown.complete":
                self._shutdown.set()

        await self.app({"type": "lifespan", "asgi": {"version": "3.0"}},
                        receive, send)


# ─── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
async def mcp_app_client(monkeypatch):
    """An httpx AsyncClient over the real ASGI app + bearer middleware.

    Replicates ``main()``'s HTTP wiring without running uvicorn, and patches the
    module-global ``auth_manager.authenticate`` (the exact symbol the middleware
    dereferences as ``auth_manager.authenticate(token)``) with the deterministic
    map. Network bits of ``sairo_client`` are stubbed so the per-request lifespan
    is instant.

    All env / ``db_module.DB_DIR`` mutation is done via ``monkeypatch`` so it is
    scoped to this test and cannot leak into other test modules (see the module
    header note). MCP_DEV_MODE=true + SAIRO_API_TOKEN="" makes the per-request
    lifespan bind a dev-admin session; this is the adversarial configuration T8
    must stay correct under — the bearer middleware's caller session must still
    win over the lifespan-bound dev-admin session.
    """
    # Env for the per-request lifespan (read at request time, so monkeypatch works).
    monkeypatch.setenv("SAIRO_API_URL", "http://localhost:9999")
    monkeypatch.setenv("SAIRO_API_TOKEN", "")        # no service token
    monkeypatch.setenv("MCP_DEV_MODE", "true")        # dev bootstrap → dev admin
    monkeypatch.setenv("MCP_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("MCP_LOG_FORMAT", "text")
    # Point the db module at the alpha/beta bucket DBs (auto-restored on teardown).
    monkeypatch.setattr(db_module, "DB_DIR", _PERREQ_DB_DIR)

    # Patch the method on the singleton the middleware uses.
    monkeypatch.setattr(srv.auth_manager, "authenticate", _fake_authenticate)
    # Stub the API client so the lifespan / tools never touch the network.
    monkeypatch.setattr(srv.sairo_client, "start", AsyncMock(return_value=None))
    monkeypatch.setattr(srv.sairo_client, "close", AsyncMock(return_value=None))
    monkeypatch.setattr(srv.sairo_client, "health_check", AsyncMock(return_value=False))
    monkeypatch.setattr(srv.sairo_client, "get_audit_log",
                        AsyncMock(return_value=[
                            {"timestamp": "2026-07-26T10:00:00", "username": "admin",
                             "action": "upload", "bucket": "alpha",
                             "details": "uploaded file.csv"}
                        ]))

    # Build a fresh app/session-manager per test (reusing the cached
    # ``_session_manager`` across start/stop cycles hangs the task group).
    srv.mcp._session_manager = None
    app = srv.mcp.streamable_http_app()
    app.add_middleware(srv.SairoBearerAuthMiddleware)

    async with _LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8100",  # Host must satisfy SDK host allow-list
            timeout=10.0,
        ) as client:
            yield client


# ─── JSON-RPC helpers ──────────────────────────────────────────────────────────

def _headers(token):
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    return h


def _result_text(resp):
    """Robustly extract (kind, payload) from a JSON-RPC HTTP response.

    Returns one of:
        ("__http__",    (status, text))          non-200 (e.g. 401/406)
        ("__error__",   error_obj)               top-level JSON-RPC error
        ("__iserror__", structured|content)      tool result with isError=True
        ("__text__",    text)                     normal text payload (tools/resources)
        ("__empty__",   result)                   result present but no text
    """
    if resp.status_code != 200:
        return ("__http__", (resp.status_code, resp.text))
    data = resp.json()
    if isinstance(data, dict) and "error" in data:
        return ("__error__", data["error"])
    res = data.get("result", {}) if isinstance(data, dict) else {}
    if res.get("isError"):
        return ("__iserror__", res.get("structuredContent", res.get("content", [])))
    # tools use result.content[] (items with type=="text");
    # resources use result.contents[] (items with "text" but no "type").
    content = res.get("content") or res.get("contents") or []
    for c in content:
        if isinstance(c, dict) and (c.get("type") == "text" or "text" in c):
            return ("__text__", c.get("text", ""))
    if content:
        return ("__empty__", content)
    return ("__empty__", res)


async def _tools_call(client, name, arguments, token):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}
    return await client.post("/mcp", json=body, headers=_headers(token))


async def _resources_read(client, uri, token):
    body = {"jsonrpc": "2.0", "id": 1, "method": "resources/read",
            "params": {"uri": uri}}
    return await client.post("/mcp", json=body, headers=_headers(token))


# ─── T1: no Authorization → 401 ────────────────────────────────────────────────

async def test_t1_no_authorization_returns_401(mcp_app_client):
    """T1: a POST /mcp with no Authorization header is rejected with 401 and a
    WWW-Authenticate: Bearer challenge before any tool runs."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "list_buckets", "arguments": {}}}
    r = await mcp_app_client.post("/mcp", json=body, headers=_headers(None))
    assert r.status_code == 401
    assert r.headers.get("www-authenticate", "").lower() == "bearer"


# ─── T2: valid viewer Bearer → tool runs as caller identity ────────────────────

async def test_t2_viewer_bearer_lists_only_authorized_bucket(mcp_app_client):
    """T2 — core ContextVar-propagation proof.

    ``list_buckets`` with ALPHA_TOKEN must return ONLY ``alpha`` (the caller has
    ``{alpha: read}``). This proves: middleware built the alpha-viewer session →
    bound it to the per-request ContextVar → ``list_buckets`` read
    ``current_session()`` → ``can_read_bucket`` filtered to alpha. This is an
    enforced regression guard: if a future change leaks the session and the
    caller appears as admin, ``beta`` shows up too and this test fails.
    """
    r = await _tools_call(mcp_app_client, "list_buckets", {}, ALPHA_TOKEN)
    kind, payload = _result_text(r)
    assert kind == "__text__", payload
    assert "alpha" in payload
    assert "beta" not in payload


# ─── T3: admin-only tool + viewer token → authorization denied ─────────────────

async def test_t3_admin_tool_denied_for_viewer(mcp_app_client):
    """T3: ``get_audit_log`` (admin-only) called with a viewer token must be
    denied (``require_admin`` raises AuthorizationError → isError result), not
    return an audit-log table. Paired assertion: the same call with the admin
    token succeeds."""
    # Viewer → must be denied.
    r = await _tools_call(mcp_app_client, "get_audit_log", {}, ALPHA_TOKEN)
    kind, payload = _result_text(r)
    assert kind in ("__iserror__", "__error__"), payload
    blob = payload if isinstance(payload, str) else repr(payload)
    assert "Recent activity" not in blob  # not a normal audit table

    # Admin → succeeds (returns the table text).
    r2 = await _tools_call(mcp_app_client, "get_audit_log", {}, ADMIN_TOKEN)
    kind2, payload2 = _result_text(r2)
    assert kind2 == "__text__", payload2


# ─── T4: resources/read overview scoped to caller ───────────────────────────────

async def test_t4_overview_resource_scoped_to_caller(mcp_app_client):
    """T4 (V3 per-bucket resource authz): ``resources/read objex://overview``
    with ALPHA_TOKEN must contain ``alpha`` and NOT ``beta``."""
    r = await _resources_read(mcp_app_client, "objex://overview", ALPHA_TOKEN)
    kind, payload = _result_text(r)
    assert kind == "__text__", payload
    assert "alpha" in payload
    assert "beta" not in payload


# ─── T5: fail-closed startup (no token + no dev) ────────────────────────────────

async def test_t5_fail_closed_no_token_no_dev(monkeypatch):
    """T5: with SAIRO_API_TOKEN unset and MCP_DEV_MODE=false the server must
    refuse to start (sys.exit non-zero) — no anonymous session is ever created."""
    monkeypatch.delenv("SAIRO_API_TOKEN", raising=False)
    monkeypatch.setenv("MCP_DEV_MODE", "false")
    monkeypatch.setattr(sys, "argv", ["server.py"])
    with pytest.raises(SystemExit) as exc:
        srv.main()
    assert exc.value.code != 0


# ─── T6: dev mode + non-loopback bind → refuse ──────────────────────────────────

async def test_t6_dev_mode_non_loopback_refuses(monkeypatch):
    """T6: MCP_DEV_MODE=true with a non-loopback MCP_BIND_HOST must refuse to
    start (sys.exit non-zero) so the dev admin is never exposed on a socket."""
    monkeypatch.setenv("MCP_DEV_MODE", "true")
    monkeypatch.setenv("SAIRO_API_TOKEN", "")
    monkeypatch.setattr(srv, "MCP_HOST", "0.0.0.0")  # non-loopback (module global)
    monkeypatch.setattr(sys, "argv", ["server.py"])  # default transport (non-stdio)
    with pytest.raises(SystemExit) as exc:
        srv.main()
    assert exc.value.code != 0


# ─── T7: cross-Origin browser request rejected ─────────────────────────────────

async def test_t7_cross_origin_rejected(mcp_app_client, monkeypatch):
    """T7: a POST /mcp with a cross-site Origin is rejected with 406 even when a
    valid bearer token is present (DNS-rebinding guard runs before/around auth).
    A same-host Origin is NOT rejected by this layer."""
    monkeypatch.delenv("MCP_ALLOWED_ORIGINS", raising=False)
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "list_buckets", "arguments": {}}}

    # Cross-origin → 406 regardless of valid token.
    evil = _headers(ADMIN_TOKEN)
    evil["Origin"] = "https://evil.example"
    r = await mcp_app_client.post("/mcp", json=body, headers=evil)
    assert r.status_code == 406
    assert r.json().get("error", {}).get("code") == -32026

    # Same-host Origin → not rejected by this layer (proceeds downstream).
    same = _headers(ADMIN_TOKEN)
    same["Origin"] = "http://127.0.0.1:8100"
    r2 = await mcp_app_client.post("/mcp", json=body, headers=same)
    assert r2.status_code != 406


# ─── T8: CRITICAL — ContextVar propagation / concurrent identity isolation ──────

async def test_t8_concurrent_contextvar_isolation(mcp_app_client):
    """T8 — regression guard for the §4.1.7 ContextVar-propagation spike.

    Two ``list_buckets`` requests are fired CONCURRENTLY (``asyncio.gather``)
    over the SAME ASGI app — one with ALPHA_TOKEN, one with BETA_TOKEN. Each
    must see ONLY its own bucket. If a future change (SDK bump, middleware
    rewrite, task-group re-parenting) breaks per-request ContextVar isolation,
    the two sessions bleed and BOTH requests see BOTH buckets → this test fails.
    """
    async def call(token):
        return await _tools_call(mcp_app_client, "list_buckets", {}, token)

    r_alpha, r_beta = await asyncio.gather(call(ALPHA_TOKEN), call(BETA_TOKEN))

    kind_a, payload_a = _result_text(r_alpha)
    kind_b, payload_b = _result_text(r_beta)
    assert kind_a == "__text__", payload_a
    assert kind_b == "__text__", payload_b

    assert "alpha" in payload_a and "beta" not in payload_a
    assert "beta" in payload_b and "alpha" not in payload_b
