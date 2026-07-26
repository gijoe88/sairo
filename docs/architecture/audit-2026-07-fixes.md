# Sairo — Whole-Project Audit (`main`, 2026-07) & Fix Design

**Status:** Proposed · **Author:** architect · **Base:** fork `main` @ `85f3ad6`
**Scope:** (C) close the findings from the 2026-07 whole-project audit; (D) bump/stabilize the MCP SDK dependency.

This is a fork-internal design doc. It must **not** be included in any PR branch (see `AGENTS.md`). It extends `security-and-proxy-design.md` (rounds A/B and the §9 follow-up); where this doc and that one disagree about A7's status, **this one is correct** — A7 was never implemented (see §1.2).

---

## 1. Context

### 1.1 What this audit covered
A full-project audit of `main` @ `85f3ad6` across six domains (auth & sessions, authz & access control, SQL/injection, path-traversal/FS/SSRF, MCP server, crypto/OIDC/headers/Docker/XSS). Each domain was investigated independently; headline findings were re-verified directly against current code. Domains that came back **clean** (no findings ≥ conf 7): SQL/injection (parameterization is consistent; the FTS5 escape helper `_search_fts` at `main.py:5013` is correct), path traversal beyond the one issue below (`_db_path` realpath defense is sound; object keys never touch the FS; `parquet_reader.py` is fully in-memory; no archive extraction; no manual XML parsing), crypto (JWT `algorithms` pinned everywhere; OIDC JWKS validation correct; Fernet key never logged; bcrypt `.verify()`; `secrets.*` throughout; no `random.*`), frontend (no `dangerouslySetInnerHTML`/`innerHTML`; no CORS middleware = secure default; `samesite=strict`), and the `TrustedProxyMiddleware` (verified spoof-resistant: fail-closed default, correct rightmost-untrusted XFF walk, CIDR matching).

### 1.2 The headline: A7 was never actually implemented
The merge `50e6fd3` "fix/mcp-per-request-auth" changed **zero lines** in `mcp/` (`git show 50e6fd3 --stat -- mcp/` is empty). It brought in the **Parquet feature** + a doc-only commit + one tiny prerequisite commit (`a5e8850`, "forward caller token in `get_user_permissions`"). Repo-wide grep for `streamable_http_app | add_middleware | request.state.sairo | RequireAuth` in `mcp/` returns **nothing**. So the original Vuln 6 is **still live**: the entire `/mcp` HTTP surface is unauthenticated, all tool/resource calls run as one shared **admin** session minted at startup, resources leak every bucket's name/size/counts with no auth at all, and the anonymous-viewer fallback is still minted when `SAIRO_API_TOKEN` is unset. See §4.1 — this is the bulk of the work.

### 1.3 MCP SDK version situation (urgent, time-sensitive)
- `mcp/requirements.txt` pins `mcp[cli]>=1.9.0`. The floor (1.9.0, early 2025) is stale; the latest stable v1.x is **1.28.1** (~19 minor versions of fixes/features).
- There is **no upper bound**. The SDK's v2 line is in alpha/beta (`2.0.0a1`–`2.0.0b2`) and **v2 stable is targeted for 2026-07-28** — two days from this doc's base date. v2 is a breaking rework (e.g. `FastMCP` → `MCPServer`). Any Docker build after the 28th will resolve `>=1.9.0` to 2.x and **fail to start**.
- The SDK README explicitly instructs dependents to add `mcp>=1.27,<2` (or similar) before v2 stable lands.

**Decision (see §3):** bump the floor to a current v1.x and add the `<2` ceiling now. This is a prerequisite for the A7 re-do (we design against the current v1.x API) and is independently urgent.

---

## 2. Findings recap

| # | Finding | Sev | Conf | Status |
|---|---------|-----|------|--------|
| V1 | MCP `/mcp` route has **no HTTP auth** at all | HIGH | 10 | A7 not implemented |
| V2 | All MCP tools run as a single **shared admin** session | HIGH | 10 | A7 not implemented |
| V3 | MCP resources (`storage_overview`/`bucket_summary`) leak all buckets, **zero auth/authz** | HIGH | 10 | A7 not implemented |
| V4 | MCP fail-closed missing — anonymous viewer fallback still minted when `SAIRO_API_TOKEN` unset | HIGH | 9 | A7 not implemented |
| V5 | `delete_bucket("users")` **destroys the auth DB** (`{bucket}.db` collides with `users.db`) | HIGH | 8 | New |
| V6 | `bucket_permissions` has no `endpoint_id` → cross-endpoint authz pivot | MEDIUM | 9 | New |
| V7 | `/api/auth/login-s3` has no `AUTH_MODE` guard (open in `local` mode) | MEDIUM | 8 | New (the item deferred in §8 risk #6) |
| V8 | `.env.example` ships `SECURE_COOKIE=false` → insecure cookies in the common path | MEDIUM | 8 | New |
| V9 | OAuth provider confusion: Google ↔ GitHub share `auth_source="oauth"` (account takeover) | MEDIUM | 7 | New |
| V10 | Cookie JWTs not re-validated against DB → deleted/demoted users keep access up to 24h | MEDIUM | 7 | New |
| L1 | S3-mode sessions are global admin over shared local DB rows (share-links/tokens/audit-log list & delete) | LOW | 8 | New |
| L2 | No `Strict-Transport-Security` header | LOW | 8 | New |
| L3 | `TrustedProxyMiddleware` doesn't validate `X-Forwarded-Proto`/`Host` charset | LOW | 7 | New |
| L4 | 2FA recovery codes are 32-bit (`secrets.token_hex(4)`) | LOW | 7 | New |
| L5 | OAuth `oauth_state` cookie not cleared post-exchange (parity gap vs OIDC) | LOW | 7 | New |
| L6 | MCP `/metrics` token check non-constant-time (`!=`) | LOW | 8 | New |
| L7 | MCP auth cache (300s TTL) has no revocation path | LOW | 7 | New (latent until V2 lands) |

**Verified correctly fixed in `main`** (no further action): A1 (share links), A2 (token revocation / refresh DB lookup / cascade), A3 (s3 Bearer refusal), A4 (compat routes use `_s3_user_can_access`), A5 (OAuth state+PKCE parity), A6 (GitHub fail-closed + `/user/emails`), A8 (`require_local_admin` on 10 routes), A9 (bcrypt wrap + `OIDC:` prefix), Subject B (`TrustedProxyMiddleware` + audit `client_ip`).

---

## 3. Cross-cutting: MCP SDK version stabilization (do first)

**Change `mcp/requirements.txt`:**
```
mcp[cli]>=1.28.0,<2
```
- **Floor 1.9.0 → 1.28.0:** the user requested a bump if stale; 1.9.0 is ~19 minor versions behind. All APIs the A7 re-do depends on (`streamable_http_app()`, `stateless_http`, `json_response`, the Starlette mounting seam) are documented on the current v1.x branch and present in 1.28.x.
- **Add `<2`:** prevents the 2026-07-28 v2-stable break. This is the urgent part — land it before the 28th.
- **Stricter alternative (acceptable):** pin exact `mcp[cli]==1.28.1` for fully reproducible image builds; the project otherwise uses `>=` ranges, so the range form matches convention.

**Verification gate before the A7 spike:** `uv pip show mcp` reports `1.28.x`. Re-run `pytest mcp/` against 1.28.1 to catch any in-v1.x API drift. (Low risk — v1.x is backward-compatible — but the spike in §4.1 must confirm `streamable_http_app()` returns a `Starlette` app and that the ContextVar propagates to tools, on **1.28.1 specifically**.)

---

## 4. Fix designs

### 4.1 F1 — MCP per-request authentication (RE-DO of A7) — `mcp/` only

This is the largest piece and the highest-risk. The prior design (`security-and-proxy-design.md` §4.A7) had the right *intent* but two technical errors that this design corrects:

> **Correction 1.** The prior design said tools would read per-request identity from `ctx.request_context.request.state.sairo_session`. **Wrong.** The v1.x SDK docs state `ctx.request_context.request` is *"the original MCP request object"*, not the Starlette `Request`. Tools cannot reach the Starlette request through the context. Per-request identity must be propagated via a Python **`ContextVar`** set by the middleware.
>
> **Correction 2.** The prior design did not include MCP-spec-mandated **`Origin` header validation** (DNS-rebinding defense), which the Streamable HTTP spec REQUIRES.

#### 4.1.1 Transport seam (the integration path)

Build the Starlette app ourselves and attach the middleware, instead of `mcp.run(...)`:

```python
# mcp/server.py main() — pseudocode, contract not implementation
app = mcp.streamable_http_app()          # v1.x FastMCP → Starlette (confirmed in SDK docs/examples)
app.add_middleware(SairoBearerAuthMiddleware)   # validates every request, sets ContextVar
uvicorn.run(app, host=MCP_HOST, port=MCP_PORT)
```
- Switch the `FastMCP(...)` construction to `stateless_http=True, json_response=True` (recommended for production in the v1.x docs; also makes per-request auth clean — no `Mcp-Session-Id` affinity). Confirm no client relies on stateful sessions (the docs/Quickstart use stateless clients).
- Keep the `--transport stdio` branch as-is; the middleware only applies to the HTTP app.
- Fallback shape if `add_middleware` on the returned app misbehaves: wrap manually — build an outer `Starlette(middleware=[...], routes=[Mount(mcp.settings.streamable_http_path, app=...)])` and run a combined lifespan that enters `mcp.session_manager.run()` (this is the SDK's own `streamable_starlette_mount.py` example pattern). Prefer the first shape; only fall back if the spike finds a problem.

#### 4.1.2 The Bearer middleware (authenticates every request)

`SairoBearerAuthMiddleware(starlette.middleware.base.BaseHTTPMiddleware)`:
- **Allow-list:** `/healthz`, `/readyz` pass through unauthenticated (liveness/readiness probes). Everything else — `/mcp`, `/metrics`, any custom route — requires a valid Bearer.
- **Extract:** `Authorization: Bearer <token>`. Missing/empty/malformed → **401** (JSON error, `WWW-Authenticate: Bearer`).
- **Validate:** call the Sairo backend token-verify path (the MCP `AuthManager.authenticate` already does this; reuse it). On failure → 401. Use `hmac.compare_digest` on the raw header prefix before extraction (defense-in-depth; also fixes L6).
- **Build per-request `UserSession`** from the validated token (username, role, bucket perms via `get_user_permissions` forwarding the caller token — already wired by `a5e8850`).
- **Propagate via ContextVar:** `_request_session: ContextVar[UserSession | None]` — `_request_session.set(session)` before `await call_next(request)`. Reset/`reset(token)` in a `finally`. This is the bridge the prior design got wrong; tools read it (§4.1.4).
- **Origin / DNS-rebinding (spec-mandated):** for the `/mcp` route, validate `Origin` (and `Host`) — reject cross-origin browser requests that aren't from an allowed origin. Default allow-list = same host; configurable via `MCP_ALLOWED_ORIGINS` (env). This is REQUIRED by the Streamable HTTP spec ("Servers MUST validate the Origin header") and is especially important for the loopback/dev bind.
- **CORS:** none by default (the secure default; the main backend already ships no `CORSMiddleware`). Only add permissive CORS if an operator explicitly configures browser clients.

> **Why not the SDK's `token_verifier=` / `AuthSettings` resource-server hook?** It exists (`mcp.server.auth.provider.TokenVerifier`, `AccessToken`) and is the SDK-idiomatic path — but it is OAuth 2.1 / RFC 9728-shaped: it advertises Protected Resource Metadata, expects an `issuer_url` + `required_scopes`, and makes MCP clients attempt OAuth discovery. Sairo's model is "validate a single static Bearer against the Sairo backend" — the custom middleware is simpler, decouples us from SDK auth reshuffles, and doesn't change the server's externally-advertised auth metadata. Revisit if/when we want MCP clients to handle auth generically.

#### 4.1.3 Fail-closed startup + dev-mode loopback

- **Fail-closed (V4):** in `lifespan` (or `main`), if `SAIRO_API_TOKEN` is unset **and** `MCP_DEV_MODE != "true"` → `raise RuntimeError(...)` / `sys.exit(1)`. Do **not** mint the `mcp-anonymous` viewer session. A misconfigured production deploy must fail loud and fast, not run degraded-but-open.
- **Dev-mode loopback (new, spec-aligned):** when `MCP_DEV_MODE=true`, assert `MCP_HOST` resolves to a loopback address (`127.0.0.1` / `::1` / `localhost`). Refuse to start if bound on a non-loopback interface. The current code mints a full **admin** session on the flag alone — combined with no HTTP auth that's a network-reachable admin bypass.
- The dev-mode admin session remains useful for local `mcp dev` workflows; it must simply never be network-reachable.

#### 4.1.4 Per-request session in tools & resources

- Add `mcp/session_ctx.py` (tiny): the `ContextVar` + `current_session()` accessor + `AuthorizationError` re-export.
- Rewrite every `_ctx_session(ctx)` in `mcp/tools/*.py` (`discovery`, `inspection`, `analytics`, `cost`, `pipeline`, `operations`) from
  `return ctx.request_context.lifespan_context["session"]` → `return current_session()` (reads the ContextVar; raises `AuthorizationError` if unset, which surfaces as a clean 401-ish tool error).
- `require_bucket_read` / `require_admin` in `mcp/auth.py` now evaluate against the **per-request** session → a viewer token can no longer call admin tools, and a user-scoped token can't read buckets its IAM/grants deny.

#### 4.1.5 Resources get auth + per-bucket authz (V3)

`mcp/resources/providers.py`:
- Switch both handlers to the **context-aware** signature: `async def storage_overview(ctx: Context)` / `async def bucket_summary(bucket: str, ctx: Context)`.
- `storage_overview`: after `list_bucket_dbs()`, filter through `session.can_read_bucket(name)` exactly like `tools/discovery.py:60-62`. Non-admins see only their buckets; the leaked-metadata problem goes away.
- `bucket_summary`: call `_ctx_auth(ctx).require_bucket_read(session, bucket)` before any DB read → 403-equivalent tool error on unauthorized buckets.
- The Bearer middleware (§4.1.2) already blocks unauthenticated `resources/read` entirely; this adds the per-bucket scoping for authenticated-but-unauthorized callers.

#### 4.1.6 Audit attribution
With per-request sessions, every tool's `user=session.username` / `user_token=session.token` (e.g. `operations.py:126,159-167`) now points at the **real caller**, not the startup service account. No code change beyond the session source.

#### 4.1.7 Highest-risk item (the spike, before committing to the full re-do)
1. Confirm `mcp.streamable_http_app()` exists on 1.28.1 and returns a `Starlette` app whose `add_middleware(...)` actually wraps the `/mcp` route.
2. **Confirm the ContextVar propagates** from `SairoBearerAuthMiddleware` (set before `await call_next`) into the tool coroutine invoked by the SDK's streamable-HTTP handler. Starlette `BaseHTTPMiddleware` runs the downstream app in a child task that inherits the parent context, so a `ContextVar.set` before `call_next` *should* be visible downstream — but this must be verified empirically on 1.28.1 because the SDK's session manager may run tools in a separate task/copy. If it does **not** propagate, fall back to: (a) stashing the session in ASGI `scope["state"]` from a raw ASGI middleware (not `BaseHTTPMiddleware`) and reading it via a thread/async-local bridged in the tool, or (b) the Starlette-mount shape (§4.1.1 fallback) where the middleware is unconditionally outermost.
3. **Pause and escalate** if neither shape can securely host per-request identity — the threat model then changes to "loopback-only / reverse-proxy-gated" (enforce `MCP_BIND_HOST=127.0.0.1`, document public exposure via the operator's auth-fronting proxy). This is the original §8 risk #1 and it still stands.

**Files:** `mcp/requirements.txt`, `mcp/server.py`, new `mcp/session_ctx.py`, `mcp/auth.py`, `mcp/sairo_client.py` (no change — already forwards `user_token`), every `mcp/tools/*.py`, `mcp/resources/providers.py`, `mcp/tests/`. Docs correction (`website/.../mcp.mdx`: "every tool call is gated by authentication" is currently false until this lands; the "mint an admin token" guidance should become "least-privilege viewer by default") goes on **fork `main`**, not the PR branch.

---

### 4.2 F2 — Reserved bucket-name namespace (`users.db` collision) — `backend/main.py`

`_db_path` builds `os.path.join(DB_DIR, f"{safe_bucket}.db")` and the auth DB is `os.path.join(DB_DIR, "users.db")`. A bucket named `users` collides; `delete_bucket("users")` runs `os.remove` on `users.db[-wal][-shm]` and **destroys auth**. The code already knows they share the dir (telemetry excludes `users.db` at `main.py:2727`) — `_db_path` just never got the guard.

**Fix (namespace prefix, also closes the broader collision class):**
```python
# _db_path — contract
path = os.path.join(DB_DIR, f"bucket_{safe_eid_prefix}{safe_bucket}.db" if eid!="default" else f"bucket_{safe_bucket}.db")
```
- Prefixing every per-bucket DB with `bucket_` reserves the namespace so no bucket name can ever collide with `users.db` (or any future reserved stem), and fixes the secondary `{eid}_{bucket}` vs `{bucket}` collision class noted by the investigator.
- **Migration:** existing files are named `{bucket}.db` / `{eid}_{bucket}.db`. On boot, add a one-time idempotent migration that renames `*.db` (excluding `users.db` and anything already `bucket_`-prefixed) to the `bucket_`-prefixed form, preserving `-wal`/`-shm`. Gate behind a marker row in `instance_meta` so it runs once. **This is the one irreversible-ish step in the whole plan** — flag for the user (§8). Alternative (reversible, smaller): just reject `safe_bucket == "users"` in `_validate_name`/`_db_path` with HTTP 400. Recommend the **prefix** approach (complete) but offer the **reject** approach as the minimal/reversible option if the migration is deemed too risky.
- Mirror the same guard in `mcp/db.py:_safe_name`/`_resolve_db_path` for consistency (MCP opens DBs read-only, so it's non-destructive there, but the filenames must match the new scheme).

**Files:** `backend/main.py` (`_db_path`, `_validate_name`, the boot migration block, `delete_bucket` defense-in-depth `assert _db_path(bucket) != _users_db_path()`), `mcp/db.py`, `backend/test_main.py` (negative: `delete_bucket("users")` → 400 and `users.db` untouched).

---

### 4.3 F3 — Endpoint-scoped `bucket_permissions` — `backend/main.py`

`bucket_permissions` PK is `(username, bucket)` with no `endpoint_id` (`main.py:645`). Every lookup (`main.py:220, 768, 7045, 7160`, list-all at `3377, 4711, 4764`, cascade at `3170, 3393, 3396, 3409`) keys on name only. A non-admin password-mode user with a grant on bucket name `data` reaches **every** endpoint's `data` bucket via `/api/e/<other_eid>/api/buckets/data/...` using that endpoint's **server** credentials. (S3 mode is unaffected — `endpoint_routing_middleware` forces the session endpoint.)

**Fix:**
- Schema: add `endpoint_id TEXT NOT NULL DEFAULT 'default'`; PK becomes `(username, endpoint_id, bucket)`. Additive `ALTER TABLE` for existing rows (all become `'default'` — correct, since pre-multi-endpoint grants were always against the default endpoint).
- Include `endpoint_id` in every lookup, keyed on the **resolved** `request.state.endpoint_id` / `_endpoint_ctx`: `bucket_permission_middleware` (`:220`), `_caller_can_read_bucket` (`:768`), the password-mode branch of `_s3_user_can_access` (`:7045`), `_check_compat_bucket_read` (`:7160`). The list endpoints (`get_user_permissions :3377`, `/api/all-buckets :4711`, the other `:4764`) should `SELECT endpoint_id` too and return/filter grouped, so the UI can show grants per endpoint.
- `set_user_permissions` (`:3382`) + `SetPermissionsRequest`: add optional `endpoint_id` (default `'default'`); the permissions UI gains an endpoint picker. `delete_user_permission` (`:3403`) takes `endpoint_id` in the path or query. Cascade deletes on user delete (`:3170, :3393`) already key on `username` — unchanged.
- Keep the admin short-circuit (admins see all endpoints).

**Files:** `backend/main.py` (schema, ~9 lookup sites, request models, the permission UI route), `backend/test_main.py` (negative: non-admin granted `read` on `default:data` gets 403 on `/api/e/internal/api/buckets/data/list`), `frontend/` permissions UI (endpoint picker — client-side, no security logic).

---

### 4.4 F4 — Gate `/api/auth/login-s3` on `AUTH_MODE` — `backend/main.py`

`auth_login_s3` (`main.py:3018`) has no `AUTH_MODE` guard. In `local` mode, `_extract_s3_session()` returns `None` so the resulting session is a plain **local admin** cookie; anyone holding the server's own S3 service-account creds (`S3_ACCESS_KEY`/`S3_SECRET_KEY`) gets full Sairo admin that bypasses the local user/grant model. (This is the item explicitly deferred in `security-and-proxy-design.md` §8 risk #6 — now in scope.)

**Fix:** first line of the handler:
```python
if AUTH_MODE != "s3":
    raise HTTPException(404, "S3 login is not enabled")
```
Mirror the `if not LDAP_ENABLED:` guard already used in `auth_ldap` (`main.py:3711`). The default-admin-seeding question (also in §8 risk #6) stays **out of scope** — emergency local access is a legitimate operator workflow and the random default password makes it non-exploitable; the one-line guard above fully closes the route-exposure issue.

**Files:** `backend/main.py` (1 line + comment), `backend/test_main.py` (negative: `login-s3` in local mode → 404; in s3 mode → still works).

---

### 4.5 F5 — `.env.example` `SECURE_COOKIE` default — `.env.example`

`.env.example:17` sets `SECURE_COOKIE=false`. The code default is secure (`os.environ.get("SECURE_COOKIE","true")`) and `docker-compose.yml:15` uses `${SECURE_COOKIE:-true}` — but the documented `cp .env.example .env` workflow sets `false` explicitly, so the compose `:-true` fallback never fires and all 12 `access_token` cookie issuances drop the `Secure` attribute. Behind an HTTPS proxy, a single induced `http://` request leaks the cookie in cleartext → full account takeover.

**Fix (docs, on `main` only — no PR):** comment the line out and default to true:
```
# SECURE_COOKIE=true   # leave unset (defaults to true); set "false" only for plain-HTTP local dev
```
Also consider hardening `docker-compose.yml` to `SECURE_COOKIE: ${SECURE_COOKIE:-true}` is already correct — leave it. (The `.env.example` fix is the change that matters.)

**Files:** `.env.example` (fork `main` only).

---

### 4.6 F6 — Distinct OAuth `auth_source` per provider — `backend/main.py`

Google and GitHub both pass `source="oauth"` to `_sync_federated_user`; the takeover guard (`main.py:877`) only rejects when sources *differ*. Their username namespaces differ (Google = email local-part, GitHub = `login`) and can collide (`alice@corp.com` → `alice`; GitHub user `alice` → `alice`). On collision the second provider logs into the first's account, inheriting role/2FA/grants. The schema comment (`main.py:661`) already documents the intended per-provider values (`oauth_google` / `oauth_github`) — they were never wired at runtime.

**Fix (per-provider source + lazy legacy upgrade):**
- Google callback: `source="oauth_google"`. GitHub callback: `source="oauth_github"`. OIDC stays `"oidc"`.
- `_sync_federated_user` takeover guard: tighten so an incoming `oauth_<provider>` is rejected against an existing *different* `oauth_<provider>` or `"oidc"`/`"ldap"`/`"local"`.
- **Legacy `oauth` rows:** the backfill (`main.py:672-678`) collapsed `OAUTH:` → `'oauth'`, so existing rows can't be auto-attributed to Google vs GitHub. Add a **lazy upgrade**: if `existing_source == "oauth"` and incoming is `oauth_google`/`oauth_github`, allow the login **once** (compatible) and `UPDATE users SET auth_source=?` to the specific source. After that first post-fix login the row is pinned; a subsequent different-provider login for the same username is then blocked. This avoids locking out existing OAuth users while closing the cross-provider takeover going forward. (The one-login ambiguity window is the same risk that existed pre-fix for that single transition — acceptable and documented.)
- **Hardening (recommended):** when both Google and GitHub are configured, treat `OAUTH_ALLOWED_DOMAINS` as effectively required for GitHub (GitHub `login` is not email-domain-bounded) and log a startup warning if it's unset.

**Decision needed (§8):** confirm the lazy-upgrade migration shape vs. the stricter "namespace the federated username" alternative (e.g. `gh:<login>`) — the latter is more robust but renames existing users and breaks their grants/audit history. Recommend lazy-upgrade.

**Files:** `backend/main.py` (`_sync_federated_user`, the two OAuth callback sources, backfill comment update), `backend/test_main.py` (positive: same-provider re-login works; negative: Google user `alice` then GitHub `alice` → rejected; lazy-upgrade: legacy `oauth` row → first `oauth_google` login upgrades and succeeds).

---

### 4.7 F7 — Validate cookie sessions against the DB — `backend/main.py`

The cookie path of `get_current_user` (`main.py:800-825`) returns claims straight from the JWT with no DB check. So a **deleted** user's cookie (or a stolen one) stays valid up to `SESSION_HOURS` (24h), and a **demoted** admin keeps `role:"admin"` until expiry. Asymmetry: API tokens are already revoked instantly because `_verify_api_token` JOINs `users`. `auth_refresh` re-checks the DB only at the next refresh.

**Fix (minimal, sufficient):** add a cheap per-request existence+role lookup in the cookie path:
```python
# pseudocode in get_current_user cookie branch
row = db.execute("SELECT role FROM users WHERE username=?", (payload["sub"],)).fetchone()
if not row:
    raise HTTPException(401, "User no longer exists")
role = row["role"]            # DB role is authoritative, NOT the JWT claim
```
- This makes the JWT a proof-of-possession and the DB the authority. The cost is one indexed `users` PK lookup per authenticated cookie request — cheap.
- Deleted users → 401 immediately. Demotions propagate on the next request (not just at refresh). Stolen cookies still expire normally (a `jti` denylist is the full design and stays deferred — `security-and-proxy-design.md` §4.A2 already flagged this).
- **Optional stronger variant (flag, don't include unless approved):** a per-user `sessions_invalidated_at` column bumped on delete/demotion/password-change/2FA-reset, compared against the JWT `iat`. Adds a column + 4 bump sites; only worth it if the user wants revocation faster than "next request sees the DB role."

**Files:** `backend/main.py` (`get_current_user` cookie branch), `backend/test_main.py` (deleted user's cookie → 401; demoted admin's cookie → no longer admin on next request).

---

### 4.8 F8 — LOW / hardening bundle

Small, independent, can ride together on a single backend hardening PR (or be cherry-picked onto the others):

- **L1 (s3-mode shared-local-row scoping):** for routes that operate on local DB rows owned by a user (`list_share_links`/`delete_share_link`, `list_tokens`/`delete_token`, `get_audit_log`, `list_users`), scope by ownership when `user["username"].startswith("s3:")` (mirror `require_local_admin`'s `s3:` check), or switch them from `require_admin` → `require_local_admin`. Prevents cross-tenant list/delete in multi-tenant S3 deployments.
- **L2 (HSTS):** in `security_headers_middleware`, when the trusted-proxy-resolved `request.url.scheme == "https"`, emit `Strict-Transport-Security: max-age=31536000; includeSubDomains`. (Scheme is already resolved by the time this middleware runs.)
- **L3 (XFP/XFH validation):** in `TrustedProxyMiddleware`, allowlist `X-Forwarded-Proto` to `http|https` (reject anything else / ignore), and reject `X-Forwarded-Host` values containing CR/LF or RFC-7230-illegal chars. Bounds the SSO-redirectURI tampering surface.
- **L4 (2FA entropy):** `secrets.token_hex(4)` → `secrets.token_hex(8)` (64-bit) in the recovery-code generator.
- **L5 (oauth_state clear):** in `oauth_callback` success + 2FA branches, `response.delete_cookie("oauth_state", path="/api/auth/oauth")` to match the OIDC pattern.
- **L6 (MCP metrics compare_digest):** folded into F1's middleware (constant-time Bearer compare); if F1 is delayed, do this one-liner standalone on `/metrics`.
- **L7 (MCP auth cache revocation):** latent today (single shared session); becomes live when F1 lands. As part of F1, either shorten the cache TTL for the per-request path or re-verify role on `is_admin`. Track here so it isn't forgotten.

---

## 5. Branch & PR strategy

Fork policy (also in `AGENTS.md`): every PR branch is cut from **`upstream-main`** (clean), never from fork `main`. Docs live only on `main`. Before each PR, verify `git diff upstream-main...<branch>` contains **no** `docs/`, `AGENTS.md`, or `*.md` changes.

**Note on A7 history:** `fix/mcp-per-request-auth` is already merged on `main` but contains none of the work. **Do not revert/rebase that merge** (it carried the Parquet feature, which must stay). Cut a **fresh** branch from `upstream-main` for the re-do. Suggested name: `fix/mcp-per-request-auth-v2` (or `fix/mcp-auth-actual`) so the PR title makes the relationship to the prior PR clear to reviewers.

| PR | Branch (from `upstream-main`) | Contents | Depends on |
|----|-------------------------------|----------|------------|
| 5  | `chore/mcp-pin-bump` | §3: `mcp[cli]>=1.28.0,<2`. Tiny, urgent, lands before 2026-07-28. | — |
| 6  | `fix/mcp-per-request-auth-v2` | F1 (the A7 re-do). Isolated to `mcp/`. Highest-risk; own review. | PR 5 (so the spike + tests run on 1.28.1) |
| 7  | `fix/bucket-db-namespace` | F2 (reserved-name/`bucket_` prefix + migration). | — (but coordinate with F3 if both touch `_db_path` lookups) |
| 8  | `fix/endpoint-scoped-permissions` | F3 (`bucket_permissions.endpoint_id`). Backend + frontend UI. | — |
| 9  | `fix/auth-mode-and-cookie-hardening` | F4 (login-s3 guard) + F7 (cookie DB check) + L1/L2/L3/L4/L5 (backend hardening bundle, minus L6/L7 which ride with F1). All small backend changes, ride together. | — |
| 10 | `fix/oauth-provider-source` | F6 (per-provider `auth_source` + lazy upgrade). Backend only; decision needed first (§8). | — |

Docs (on `main`, not in any PR): this design doc + `security-and-proxy-design.md` §4.A7/§9 status update (§7 of this doc), the `.env.example` SECURE_COOKIE fix (F5), the MCP security correction in `website/.../mcp.mdx`, and a short "MCP version pinning" operator note.

PR 5 first (urgent, unblocks PR 6). PRs 7/8/9/10 are independent and can proceed in parallel after their respective decisions. PR 6 is the highest-risk and deserves its own focused review — **pause for the user** if the §4.1.7 spike finds the transport can't host per-request auth.

---

## 6. Implementation sequence (for project-manager)

Ordered by dependency and urgency.

1. **PR 5 (now):** bump `mcp[cli]>=1.28.0,<2`; rebuild MCP image; `pytest mcp/` green on 1.28.1. Land before 2026-07-28.
2. **A7 spike (PR 6 prep):** on a throwaway branch, validate §4.1.7 items 1–3 on 1.28.1. **Decision gate** before writing the rest of F1.
3. **PR 6 (F1):** middleware → ContextVar → fail-closed/loopback → tool/resource rewrites → tests. Pause if spike fails.
4. **PR 9 (F4 + F7 + backend hardening):** lowest risk, land early. F4 is one line; F7 is one DB lookup; L1–L5 are small.
5. **PR 7 (F2):** pick prefix-vs-reject after the §8 decision; write the one-time migration carefully; test `delete_bucket("users")`.
6. **PR 8 (F3):** schema migration + ~9 lookup sites + frontend picker.
7. **PR 10 (F6):** after the lazy-upgrade decision.
8. **Docs on `main`:** status updates, `.env.example`, MCP doc correction.

Estimated effort: PR 5 ≈ 15 min; PR 6 ≈ 1–2 days (spike-dependent); PRs 7/8/9/10 ≈ 2–4 hours each.

---

## 7. Testing strategy

- **PR 5:** `pytest mcp/` passes on 1.28.1; `uv pip show mcp` shows 1.28.x in the built image.
- **PR 6 (MCP):** no `Authorization` → 401 on `/mcp`; valid viewer Bearer → per-request `UserSession` with the caller's identity/role; admin-only tool with viewer token → tool error (authz denied); `resources/read objex://overview` with a scoped token returns only the caller's buckets; `SAIRO_API_TOKEN` unset + `MCP_DEV_MODE=false` → server exits non-zero at startup; `MCP_DEV_MODE=true` + non-loopback bind → refuse to start; cross-`Origin` browser request → rejected. Plus a dedicated test that the **ContextVar propagates** into a tool (the §4.1.7 risk) — this must be an automated regression so a future SDK bump can't silently break it.
- **PR 7 (F2):** `DELETE /api/buckets/users` → 400 and `users.db` byte-identical; migration renames old `{bucket}.db` → `bucket_{bucket}.db` once and idempotently; `pytest backend/` 3× from cold and warm `/tmp/sairo-test`.
- **PR 8 (F3):** non-admin granted `read` on `default:data` → 403 on `/api/e/internal/api/buckets/data/list`; admin sees all endpoints; UI picker round-trips.
- **PR 9:** `login-s3` in local mode → 404; deleted user's cookie → 401; demoted admin → no longer admin next request; HSTS present only on https-scheme; 2FA recovery code is 16 hex chars.
- **PR 10 (F6):** same-provider re-login OK; Google→GitHub same-username → rejected; legacy `oauth` row first `oauth_google` login upgrades + succeeds.
- **Regression baseline:** the audit's "verified-OK" list (parameterized SQL, Fernet, OIDC, trusted-proxy spoof-resistance) must stay green.

---

## 8. Risks & decisions needed (flag for the user)

1. **A7 transport seam (highest risk, unchanged from the original design's #1).** The §4.1.7 spike decides whether per-request auth is achievable on 1.28.1. If the ContextVar doesn't propagate through the SDK's session manager and neither fallback shape works, the threat model changes to **loopback-only / operator-proxy-fronted** (`MCP_BIND_HOST=127.0.0.1` enforced; document public exposure via the operator's auth-fronting reverse proxy). **Decision gate before PR 6.**
2. **F2 migration shape (irreversible-ish).** Prefixing every DB filename + a one-time rename is complete but touches disk state. The minimal reversible alternative is "reject the reserved name `users`". **Pick prefix vs. reject.** (Recommend prefix.)
3. **F6 legacy-`oauth` migration shape.** Lazy-upgrade (recommended) vs. username-namespacing (more robust, renames existing users + breaks grants/audit). **Confirm lazy-upgrade.**
4. **F7 depth.** Minimal (per-request DB lookup) closes the exploit; the stronger `sessions_invalidated_at` column is only worth it if the user wants faster-than-next-request revocation. **Default: minimal.**
5. **PR 6 history.** Confirm the "fresh branch, don't touch the old merge" approach for the A7 re-do. (Recommend yes — the old merge carries Parquet.)
6. **Git rights.** Local commit/push-to-origin are permitted; opening upstream PRs via `gh` and any force-push/rebase-on-shared-branch may need additional rights — flag when PR 5/6 are ready.
7. **Timing.** PR 5 (the `<2` pin) is genuinely urgent — v2 stable is targeted 2026-07-28. If it slips, the MCP image breaks on the next build.
