"""
Sairo MCP Server — AI-powered storage intelligence.

This is the entry point that wires everything together:
- FastMCP server with Streamable HTTP + stdio transports
- Lifespan for DB and API client initialization
- Server instructions that teach the AI how to answer storage questions
- All tool, resource, and prompt registrations

Run with:
    python server.py                        # Streamable HTTP (default)
    python server.py --transport stdio      # stdio for Claude Desktop / CLI
"""

import hmac
import os
import sys
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from auth import AuthManager, AuthorizationError, UserSession
from db import close_all as close_db_pool
from observability import logger, metrics
from sairo_client import SairoClient
from session_ctx import has_session, reset_session, set_session

# --- Configuration ---

MCP_NAME = os.environ.get("MCP_NAME", "Sairo Storage Intelligence")
MCP_PORT = int(os.environ.get("MCP_PORT", "8100"))
MCP_HOST = os.environ.get("MCP_BIND_HOST", "127.0.0.1")

# --- Shared singletons ---
# Constructed once at import time so the ASGI middleware and the FastMCP
# lifespan share the same AuthManager / SairoClient (and its session cache).
# Network startup/shutdown happens inside the lifespan.
sairo_client = SairoClient()
auth_manager = AuthManager(sairo_client)

# --- Server Instructions ---

SERVER_INSTRUCTIONS = """
You are a storage intelligence assistant connected to Sairo, an S3-compatible
object storage browser. You have full analytical access to the user's storage
infrastructure including all buckets, objects, metadata, and historical trends.

## How to Answer Questions

The user will ask natural language questions about their storage. They do NOT
know tool names and should never need to. Your job is to pick the right tools,
chain them together, and synthesize clear answers.

### Common Question Patterns

**"What buckets do I have?" / "Show me my storage"**
→ Call `list_buckets` to get the full picture.

**"What's in [bucket]?" / "Show me [bucket]"**
→ Call `list_folders` first (instant, shows structure), then `list_objects` for specific folders.

**"Find [filename/pattern]" / "Where is [file]?"**
→ Call `search_objects` with the search query.

**"How big is [bucket/folder]?" / "Where is all the space going?"**
→ Call `get_storage_breakdown`. For deeper drill-downs, call it again with a specific prefix.

**"What's this file?" / "Show me [file]"**
→ For text/log/CSV/JSON: call `read_object_content` or `sample_csv_data`/`sample_json_data`.
→ For Parquet/ORC/Avro: call `get_file_schema`.
→ For metadata: call `get_object_metadata`.

**"How much is this costing?" / "What are my storage costs?"**
→ Call `estimate_storage_cost`. If the user doesn't specify a provider, ask or default to AWS.

**"How can I save money?" / "Optimize costs"**
→ Chain: `estimate_storage_cost` → `find_cold_data` → `find_duplicates` → `suggest_lifecycle_rules`.

**"What changed recently?" / "Why did storage grow?"**
→ Call `compare_snapshots` and `get_storage_trends`. If investigating, add `get_audit_log`.

**"Is my data pipeline healthy?" / "Is this still being updated?"**
→ Call `detect_data_freshness` to check which folders are active vs stale.

**"Are there any duplicates?" / "Find wasted space"**
→ Call `find_duplicates`. Also consider `get_age_distribution` for archival candidates.

**"Tell me everything about [bucket]"**
→ Chain: `list_folders` → `get_storage_breakdown` → `get_file_type_distribution` → `get_age_distribution`.

**"Check the index" / "Is search up to date?"**
→ Call `get_crawl_status`. If outdated, offer to `trigger_crawl`.

### Important Behaviors

1. **Start broad, then drill down.** For unfamiliar buckets, start with `list_folders` or
   `get_storage_breakdown` to understand the structure before diving into specific files.

2. **Always show human-readable sizes.** Say "163.7 TB" not "163700000000000 bytes".

3. **Proactively suggest next steps.** If you show storage breakdown, mention that you can
   drill deeper into the biggest folder. If you find duplicates, mention potential savings.

4. **Combine tools for complete answers.** Most real questions need 2-3 tool calls.
   "How much is this bucket costing and can we optimize it?" needs cost estimation,
   cold data analysis, and lifecycle suggestions.

5. **Be honest about data freshness.** If the index was last updated 3 days ago,
   mention that. If data seems stale, suggest triggering a re-index.

6. **Format responses for readability.** Use markdown tables for comparisons,
   bullet points for lists, and bold for key numbers.

7. **Don't overwhelm with raw data.** Summarize first, then offer to show details.
   "Your bucket has 533K objects across 12 folders. The largest is data/ at 140TB.
   Want me to break that down further?"

### What You Cannot Do

- You cannot modify, delete, or upload objects (read-only access)
- You cannot change bucket configurations
- You cannot create or delete buckets
- You can only trigger re-indexing (with write permission)
- Cost estimates are approximations based on public pricing
"""


# --- Lifespan ---

@asynccontextmanager
async def lifespan(server: FastMCP):
    """
    Initialize shared resources on startup, clean up on shutdown.

    Authenticates using the SAIRO_API_TOKEN env var once at startup and binds
    the resulting session to the process-default ContextVar (so the stdio and
    in-memory transports populate ``current_session()`` for tool execution).
    On the HTTP path, ``SairoBearerAuthMiddleware`` overrides this per request.
    """
    await sairo_client.start()
    logger.info("Sairo MCP server starting", extra={"tool": "server"})

    # Verify connectivity
    healthy = await sairo_client.health_check()
    if healthy:
        logger.info("Connected to Sairo API", extra={"tool": "server"})
    else:
        logger.warning(
            "Could not reach Sairo API — some tools may not work",
            extra={"tool": "server"},
        )

    token = os.environ.get("SAIRO_API_TOKEN", "")
    dev_mode = os.environ.get("MCP_DEV_MODE", "false").lower() == "true"

    # Pre-authenticate using the service token (if any)
    session = None
    if token:
        try:
            session = await auth_manager.authenticate(token)
            logger.info(
                f"Authenticated as {session.username} (role={session.role})",
                extra={"tool": "server"},
            )
        except Exception as e:
            logger.warning(
                f"Auth failed: {e}. Tools requiring auth will fail.",
                extra={"tool": "server"},
            )

    # Admin bootstrap is only minted in explicit dev mode.
    if session is None and dev_mode:
        logger.warning(
            "MCP_DEV_MODE=true — running with default admin session (local dev only)",
            extra={"tool": "server"},
        )
        session = UserSession(
            username="mcp-local",
            role="admin",
            token="",
        )

    # Only bind the bootstrap session when none is already bound. On the HTTP
    # path the bearer middleware binds the caller's session per-request (and
    # this lifespan runs inside that request's task, inheriting that binding);
    # on the stdio / in-memory path nothing else binds one, so the bootstrap
    # session applies there.
    if session is not None and not has_session():
        set_session(session)

    try:
        yield {
            "sairo": sairo_client,
            "auth": auth_manager,
            "session": session,
        }
    finally:
        await sairo_client.close()
        close_db_pool()
        logger.info("Sairo MCP server stopped", extra={"tool": "server"})


# --- Server Instance ---

mcp = FastMCP(
    name=MCP_NAME,
    instructions=SERVER_INSTRUCTIONS,
    lifespan=lifespan,
    host=MCP_HOST,
    port=MCP_PORT,
    stateless_http=True,
    json_response=True,
)


# --- Register All Components ---

def _register_all():
    """Register all tools, resources, and prompts."""
    from tools import discovery, inspection, analytics, cost, pipeline, operations
    from resources import providers
    from prompts import workflows

    discovery.register(mcp)
    inspection.register(mcp)
    analytics.register(mcp)
    cost.register(mcp)
    pipeline.register(mcp)
    operations.register(mcp)
    providers.register(mcp)
    workflows.register(mcp)


_register_all()


# --- Health Endpoints ---

@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):
    """Liveness probe."""
    from starlette.responses import JSONResponse
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/readyz", methods=["GET"])
async def readyz(request):
    """Readiness probe."""
    from starlette.responses import JSONResponse
    try:
        db_dir = os.environ.get("DB_DIR", "/data")
        if not os.path.isdir(db_dir):
            return JSONResponse({"status": "not ready", "reason": "DB dir not found"}, status_code=503)
        return JSONResponse({"status": "ready"})
    except Exception as e:
        return JSONResponse({"status": "not ready", "reason": str(e)}, status_code=503)


@mcp.custom_route("/metrics", methods=["GET"])
async def metrics_endpoint(request):
    """Prometheus-style metrics.

    Authentication is enforced by ``SairoBearerAuthMiddleware`` (a valid
    Sairo bearer token is required; ``/healthz`` and ``/readyz`` are the only
    public paths).
    """
    return JSONResponse(metrics.get_summary())


# --- Bearer Auth Middleware ---

class SairoBearerAuthMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that gates every non-public path behind a Sairo bearer
    token and binds the resulting session to the per-request ContextVar.

    - Public paths (``/healthz``, ``/readyz``) are allowed through unconditionally.
    - On the MCP ``/mcp`` route, browser ``Origin`` headers are checked against an
      allow-list to block DNS-rebinding (406 on mismatch).
    - The bearer scheme prefix is compared constant-time (``hmac.compare_digest``)
      to avoid a timing oracle on the auth scheme.
    - A valid ``UserSession`` is bound via :func:`session_ctx.set_session` for the
      duration of the request and reset in ``finally``.
    """

    PUBLIC_PATHS = {"/healthz", "/readyz"}
    LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

    async def dispatch(self, request, call_next):
        # 1. Public allow-list (health/readiness probes).
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)

        # 2. DNS-rebinding / Origin guard for the Streamable HTTP route. Browsers
        #    always send Origin; non-browser MCP clients typically don't, so we
        #    only enforce when the header is present.
        if request.url.path == "/mcp":
            origin = request.headers.get("origin")
            if origin:
                allowed_raw = os.environ.get("MCP_ALLOWED_ORIGINS", "")
                if allowed_raw:
                    allowed = {
                        o.strip().rstrip("/") for o in allowed_raw.split(",") if o.strip()
                    }
                else:
                    allowed = {
                        f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
                    }
                if origin.rstrip("/") not in allowed:
                    return JSONResponse(
                        {"jsonrpc": "2.0",
                         "error": {"code": -32026, "message": "Origin not allowed"}},
                        status_code=406,
                    )

        # 3. Extract bearer token (constant-time on the scheme prefix).
        auth_header = request.headers.get("authorization", "")
        parts = auth_header.split(" ", 1)
        if (
            len(parts) != 2
            or not hmac.compare_digest(parts[0].lower().encode(), b"bearer")
            or not parts[1]
        ):
            return JSONResponse(
                {"error": "missing or malformed Authorization header"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = parts[1].strip()

        # 4. Validate token and build a session. AuthorizationError -> 401;
        #    unexpected errors propagate as 5xx (do not mask them).
        try:
            session = await auth_manager.authenticate(token)
        except AuthorizationError:
            return JSONResponse(
                {"error": "invalid or expired token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 5. Propagate the session via ContextVar for the request body, then reset.
        reset_token = set_session(session)
        try:
            response = await call_next(request)
        finally:
            reset_session(reset_token)
        return response


# --- Entry Point ---

def main():
    """Run the MCP server (with fail-closed startup + dev loopback guard)."""
    transport = "streamable-http"
    if "--transport" in sys.argv:
        idx = sys.argv.index("--transport")
        if idx + 1 < len(sys.argv):
            transport = sys.argv[idx + 1]
    elif "--stdio" in sys.argv:
        transport = "stdio"

    token = os.environ.get("SAIRO_API_TOKEN", "")
    dev_mode = os.environ.get("MCP_DEV_MODE", "false").lower() == "true"

    # Fail-closed (V4): refuse to boot without a token unless dev mode is explicit.
    if not token and not dev_mode:
        logger.error(
            "SAIRO_API_TOKEN is unset and MCP_DEV_MODE is not enabled. "
            "Refusing to start (fail-closed). Set SAIRO_API_TOKEN or "
            "MCP_DEV_MODE=true for local dev."
        )
        sys.exit(1)

    # Dev mode must bind to loopback (no socket exposure of the dev admin).
    if dev_mode and transport != "stdio":
        if MCP_HOST.lower() not in SairoBearerAuthMiddleware.LOOPBACK_HOSTS:
            logger.error(
                f"MCP_DEV_MODE=true requires a loopback bind (MCP_BIND_HOST), "
                f"got: {MCP_HOST}"
            )
            sys.exit(1)

    if transport == "stdio":
        logger.info("Starting MCP server (stdio transport)")
        mcp.run(transport="stdio")
    else:
        logger.info(f"Starting MCP server (HTTP on {MCP_HOST}:{MCP_PORT})")
        app = mcp.streamable_http_app()
        app.add_middleware(SairoBearerAuthMiddleware)
        import uvicorn
        uvicorn.run(app, host=MCP_HOST, port=MCP_PORT)


if __name__ == "__main__":
    main()
