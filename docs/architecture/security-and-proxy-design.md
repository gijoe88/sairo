# Sairo — Security Hardening (post-v3.6.0) & Trusted-Proxy Design

**Status:** Proposed · **Author:** architect · **Base:** `upstream/main` @ `64bdb2f` (tree-identical to tag `v3.6.0`)
**Scope:** (A) fix the 9 vulnerabilities found in the v3.6.0 audit; (B) add `X-Forwarded-*` support gated by a `TRUSTED_PROXIES` config.

This is a fork-internal design doc. It must **not** be included in any PR branch (see §3 and `AGENTS.md`).

---

## 1. Context

The v3.6.0 audit (6 HIGH, 3 MEDIUM, all confidence ≥ 8/10 after false-positive filtering) is documented in the session thread. `main` at `64bdb2f` is a rollback that is **byte-for-byte identical** to `v3.6.0` (`git diff v3.6.0 HEAD --stat` is empty), so every line reference below is current.

Two independent workstreams share this doc because they touch the same middleware stack and config conventions, and because the proxy feature changes how several security-relevant consumers (rate limiters, audit log) identify clients.

---

## 2. Verified current state

- Backend is a single FastAPI app: `backend/main.py` (~6893 lines). MCP server in `mcp/`.
- Middleware registration order (`main.py:93, 167, 216`): `security_headers_middleware`, `bucket_permission_middleware`, `endpoint_routing_middleware`. Starlette wraps in reverse, so effective request order is **endpoint-routing → bucket-permission → security-headers**.
- Audit log schema (`main.py:539`) is `(id, timestamp, username, action, bucket, details)` — **no `client_ip` column**. INSERT at `main.py:821`.
- Client identity today:
  - `_check_login_rate(request.client.host)` at `main.py:2874, 2909, 3549` — uses the **raw TCP peer**, so behind a proxy every login appears to originate from the proxy IP (global rate-limit collision / trivial bypass).
  - `slowapi.Limiter(key_func=get_remote_address, …)` at `main.py:36, 62` — `slowapi.util.get_remote_address` reads `X-Forwarded-For` **blindly** (first entry, no trusted-proxy gate) → spoofable. The two limiters are inconsistent; both must be unified on the trusted-proxy resolver.
- Absolute URLs are built from `request.base_url` (derived from the **Host** header + scheme) at `main.py:2962, 3656, 3682, 3894, 3949` for **OAuth/OIDC redirect URIs and OIDC RP-logout**. Behind a TLS-terminating proxy these resolve to `http://internal-host:8000/…` and **break SSO** unless `X-Forwarded-Host` / `X-Forwarded-Proto` are honored.
- Container launch (`Dockerfile:23`): `uvicorn main:app --host 0.0.0.0 --port 8000`. No reverse proxy inside the container; operators front it with nginx/Caddy/Traefik/Cloudflare. → XFF arrives from the operator's proxy, so trust must be **explicit** (`TRUSTED_PROXIES`), not implicit.
- Config convention (`.env.example`): flat `KEY=value` with inline comments, grouped by section, optional vars commented out. A `# Deployment` section already exists — natural home for `TRUSTED_PROXIES`.

---

## 3. Branch & PR strategy

Fork-internal policy (also in `AGENTS.md`):

```
upstream  AshwathStephen/sairo   (source of truth; PR target)
origin    gijoe88/sairo          (this fork)

local branches:
  main            tracks origin/main
                  = upstream/main + fork-only docs (AGENTS.md, docs/architecture/*)
                  NEVER opened as a PR; rebased onto upstream on sync.
  upstream-main   local mirror of upstream/main (refresh: git fetch upstream &&
                  git branch -f upstream-main upstream/main). Base for ALL PR
                  branches so PR diffs are code-only and never include docs.
  fix/*           security PR branches — branch from upstream-main
  feat/*          feature PR branches — branch from upstream-main
```

**Rule:** every PR branch is cut from `upstream-main` (clean), not from fork `main` (which carries docs). Docs live only on `main`. This guarantees PR diffs contain zero documentation noise.

**PR plan for this design:**

| PR | Branch (from `upstream-main`) | Contents |
|----|-------------------------------|----------|
| 1  | `fix/security-audit-v3.6.0`   | Subject A vulns **1, 2, 3, 4, 5, 7, 8, 9** (all backend/main.py). Atomic commits, one per finding. |
| 2  | `fix/mcp-per-request-auth`    | Subject A vuln **6**. Isolated to `mcp/`. Separate PR because the transport integration is the highest-risk piece and deserves its own review. |
| 3  | `feat/trusted-proxies-x-forwarded` | Subject B.Touches backend/main.py (middleware, audit log, config) — base on `upstream-main`, rebase after PR 1 lands if needed. |

PR 1 and PR 3 both edit `backend/main.py`. Land PR 1 first; PR 3 rebases. PR 2 is independent and can proceed in parallel.

---

## 4. Subject A — Security fixes

Each subsection: the vuln, the fix, the files, and risk notes. Line numbers are from v3.6.0 / current `main`.

### A1. Share-link access control — Vulns 1 & 2 (HIGH, conf 10)

**Vuln 1** `create_share_link` (`main.py:3356`) is gated only by `get_current_user`; no check that the caller can read `req.bucket`. The public resolver (`:3395`) signs a presigned URL with the **server's** S3 creds. Any viewer exfiltrates any object.
**Vuln 2** `list_share_links` (`:3369`) returns the secret `token` column for **all** rows to any user; the sibling DELETE (`:3388`) does enforce ownership — proving the omission is a bug.

**Fix (introduce one shared helper, reuse it):**
- Add `_caller_can_read_bucket(user, bucket, request)` returning bool: admin → True; `AUTH_MODE=local` non-admin → existing `bucket_permissions` lookup (mirror `:196-200`); `AUTH_MODE=s3` → `_s3_user_can_access(_user_creds_ctx.get(), endpoint_id, bucket)` (`:141`).
- `create_share_link`: call it before INSERT; 403 on miss. Also bind the link's `endpoint_id` (schema gap — see §A1.extra).
- `list_share_links`: for non-admins filter `WHERE created_by = user["username"]`; **drop `token` from the SELECT** for all callers (token is only needed once at creation). Admins still see all rows (minus the token) for oversight.

**Extra (correctness, same PR):** `share_links` has no `endpoint_id` column; the resolver always uses `_endpoint_ctx="default"`, so a link created via `/api/e/ep1/share-links` resolves against the wrong endpoint. Add `endpoint_id` column (default `'default'`) and resolve against the stored endpoint.

**Files:** `backend/main.py` (~3356-3430, ~567-580 schema, ~141 helper, ~196-200 lookup), `backend/test_main.py` (add viewer-negative tests).

### A2. Session & token revocation — Vulns 3 & 8 (HIGH conf 9 / MEDIUM conf 8)

**Vuln 3** `auth_refresh` (`:2992`) re-signs `user["role"]` straight from the presented JWT — never opens `users`. Demoted/deleted admins self-renew forever. Rotating `JWT_SECRET` is the only kill-switch and it bricks Fernet at-rest creds (key derived at `:361`).
**Vuln 8** `auth_delete_user` (`:3037`) deletes `users` + `bucket_permissions` but not `api_tokens`; `_verify_api_token` (`:696`) trusts `api_tokens.role` without joining `users`. A deleted user's admin token keeps working (and `expires_at` can be NULL).

**Fix (minimal, sufficient, low-risk):**
- `auth_refresh`: look the user up in `users`; if missing → 401; use the **DB** `role` in the new JWT. (One DB hit per refresh.)
- `auth_update_user` (`:3051`): after `UPDATE users …`, also `UPDATE api_tokens SET role=? WHERE username=?` so demotions propagate to tokens.
- `auth_delete_user`: add `DELETE FROM api_tokens WHERE username=?`.
- Defense-in-depth: `_verify_api_token` JOINs `users` and rejects if the owner row is gone.

**Out of scope (flagged as follow-up, not in this PR):** opaque rotating refresh tokens + a `jti` denylist + short access-token TTL. The minimal fix above closes the exploit; the stronger design is a separate, larger change.

**Files:** `backend/main.py` (~696-741, ~2992-3003, ~3037-3064), `backend/test_main.py`.

### A3. `AUTH_MODE=s3` privilege escalation — Vuln 4 (HIGH, conf 9)

`auth_login_s3` (`:2928`) mints `role:"admin"` for any key pair that passes `list_buckets`. `_extract_s3_session` (`:118`) only reads the **cookie**, so a Bearer (API-token) session has no `_user_creds_ctx` → `bucket_permission_middleware` admin-bypasses (`:192`) → all S3 calls use the **server's** root creds. A read-only IAM user mints an admin token and escapes IAM entirely.

**Fix (chose the conservative shape, not the "bind keys to token" shape):**
- `create_token` (`:3316`): reject callers whose JWT `sub` starts with `s3:` (i.e. s3-mode sessions cannot mint API tokens at all). Real local/LDAP/OAuth/OIDC admins are unaffected.
- `_verify_api_token` (`:696`) / `get_current_user` (`:718`): when `AUTH_MODE=="s3"`, refuse Bearer auth entirely — s3-mode sessions must use the cookie so `_user_creds_ctx` stays bound to the user's IAM keys.
- Update the misleading comment at `:117` to match.

This keeps s3-mode users IAM-scoped (the whole point of the mode) and removes the server-cred-escape hatch. The alternative (store encrypted user keys on the token row, rehydrate `_user_creds_ctx` on Bearer) is more flexible but a bigger change — **deferred**.

**Files:** `backend/main.py` (~114-133, ~696-741, ~3316-3333), `backend/test_main.py`.

### A4. `AUTH_MODE=s3` index metadata leak — Vuln 9 (MEDIUM, conf 8)

`_check_compat_bucket_read` (`:6780`) admin-short-circuits; every s3 session is admin (`:2929`). The compat read routes (`/api/list`, `/api/search`, `/api/folder-size`, `/api/storage-breakdown`, `/api/crawl-status`) read the **local index** (built with server creds) without a `head_bucket`-with-user-keys check — leaking object names/sizes/timestamps of buckets the user's IAM denies.

**Fix:** rewrite `_check_compat_bucket_read(user)` to reuse the same gate as the middleware: when `_user_creds_ctx` is populated, call `_s3_user_can_access(creds, endpoint_id, _DEFAULT_BUCKET)` and 403 on miss — instead of the blanket admin short-circuit. One chokepoint closes all compat routes.

**Files:** `backend/main.py` (~141, ~6780-6870).

### A5. OAuth login CSRF — Vuln 5 (HIGH, conf 9)

`oauth_start`/`oauth_callback` (`:3653/3678`) omit `state`, nonce, and PKCE; the OIDC path (`:3884`) does all three. Login CSRF: victim lands logged in as the attacker.

**Fix:** mirror the OIDC pattern at the OAuth path — generate `state` (+ PKCE `verifier`/`challenge`), stash in a short-lived signed `samesite=lax` cookie scoped to `/api/auth/oauth` (reuse the existing `_sign_state_cookie` / `_verify_state_cookie` helpers the OIDC path already uses — factor them out of the OIDC branch if they are inline), include in the authorize URL, and `secrets.compare_digest` in the callback. PKCE is free; add it.

**Files:** `backend/main.py` (~3640-3745, plus factor state-cookie helpers from ~3884-3942).

### A6. GitHub allowed-domains fail-open — Vuln 7 (MEDIUM, conf 9)

GitHub branch domain check (`:3735`) is `if OAUTH_ALLOWED_DOMAINS and domain and domain not in …:` — the `and domain` short-circuits when email is empty (default for GitHub users with no public email). `/user/emails` is never called despite the `user:email` scope. The Google branch (`:3708`) correctly omits `and domain`.

**Fix:** drop `and domain` (match Google's fail-closed shape). Additionally, when `gh_user.get("email")` is falsy, call `GET /user/emails` and pick the primary verified address (the scope is already requested).

**Files:** `backend/main.py` (~3726-3736).

### A7. MCP per-request authentication — Vuln 6 (HIGH, conf 8) → PR 2

`mcp/server.py:142` (`lifespan`) authenticates **once** at startup with `SAIRO_API_TOKEN` and stores a single shared `UserSession` in `lifespan_context["session"]`; every tool (`mcp/tools/*.py`) reuses it. No HTTP-level auth on the `/mcp` streamable-HTTP route (only `/metrics` has it). The documented Docker Quick Setup binds `0.0.0.0:8100`. Anyone reaching the port inherits admin.

**Fix:**
1. Add a Starlette middleware on the FastMCP ASGI app that validates `Authorization: Bearer <token>` on **every** request against the Sairo `_verify_api_token` equivalent (HTTP 401 on miss/empty). Reach the app via `mcp.streamable_http_app()` (or whatever FastMCP exposes) and `app.add_middleware(...)`.
2. Build a **per-request** `UserSession` from the validated token and stash it in `request.state`; change `_ctx_session(ctx)` in every tool to read from `request.state` instead of the shared lifespan dict. Audit attribution now points at the real caller.
3. `MCP_DEV_MODE=true` admin fallback: restrict to loopback bind (`MCP_BIND_HOST=127.0.0.1`) only; refuse to mint the admin session when bound on a non-loopback interface.
4. **Fail closed when `SAIRO_API_TOKEN` is unset and `MCP_DEV_MODE=false`.** Currently `server.py:191-200` silently mints a `username="mcp-anonymous", role="viewer"` session in that case, which (combined with the lack of per-request auth) lets any client reach the `/mcp` route as a viewer. Replace the viewer fallback with `raise RuntimeError(...)` / `sys.exit(1)` at startup so a misconfigured production deploy fails loud and fast instead of running degraded.
5. **Fix `SairoClient.get_user_permissions` to forward the caller's token.** Currently `sairo_client.py:101-103` calls `self._request(...)` with no `user_token` parameter, so the lookup runs under the server's own service token. Harmless under today's single-session model but **becomes a real authorization bypass** the moment fix #2 lands: per-user permission checks would all evaluate against the server's authority rather than the caller's. Add a `user_token: Optional[str] = None` parameter (mirror `preview_object` at `sairo_client.py:122-130`) and forward it from every caller in `mcp/auth.py` and `mcp/tools/*.py` that performs a permission lookup.
6. Resources (`mcp/resources/providers.py`) currently can't see the session (no `Context`) and **perform no auth/authz of any kind** — they enumerate every per-bucket DB on disk and return bucket names / object counts / sizes / growth history. Two-layer fix: (a) apply the same Bearer middleware from fix #1 so unauthenticated clients can't reach them at all; (b) switch to FastMCP's context-aware resource handler form, thread the per-request identity, and enforce `require_bucket_read` per bucket inside each handler (for `storage_overview`, filter `bucket_dbs` through `session.can_read_bucket(bucket)` exactly as `tools/discovery.py:61-62` does). Until (b) lands, the minimum-risk mitigation is to disable both resources when the resolved session is non-admin.
7. Fix the docs (`website/src/content/docs/features/mcp.mdx`) that falsely claim "every tool call is gated by authentication" and instruct operators to mint an **admin**-role token (should be least-privilege viewer by default) — but **docs go on fork `main`, not this PR branch**. Coordinate: code in PR 2, doc correction on `main`.

**Risk flag (resolved — implementation path confirmed):** FastMCP's `streamable_http_app() -> Starlette` is the intended seam (confirmed by reading `mcp/server/fastmcp/server.py` in MCP SDK v1.9.0). It returns a fully-wired Starlette app with the `/mcp` mount, custom routes, and session manager already in place. The clean integration path is to **bypass `mcp.run(transport="streamable-http")`** (which calls `streamable_http_app()` internally and runs uvicorn itself, leaving no seam to inject middleware) and instead in `mcp/server.py:main()`:

```python
# Build the Starlette app ourselves, attach the Bearer middleware, run uvicorn
app = mcp.streamable_http_app()
app.add_middleware(SairoBearerAuthMiddleware)   # new — validates per-request Bearer
import uvicorn
uvicorn.run(app, host=MCP_HOST, port=MCP_PORT)
```

The SDK also has a first-class OAuth provider hook (`OAuthAuthorizationServerProvider` + `BearerAuthBackend` + `RequireAuthMiddleware`) at `mcp.server.auth.middleware.*`, but it's OAuth-shaped (token validation + scopes + client IDs) and overkill for Sairo's "validate a single static Bearer against the backend" model. A custom Starlette middleware is simpler and decouples us from SDK auth reshuffles.

**Per-request session propagation:** tools already receive a FastMCP `Context` (see `_ctx_session(ctx)` usage in every `mcp/tools/*.py`). The context exposes `request_context.meta` and the underlying Starlette `Request` via `request_context.request`. The middleware should stash the validated `UserSession` in `request.state.sairo_session`; `_ctx_session(ctx)` then reads from there instead of the lifespan dict. Resources need to switch to the context-aware signature form (`def handler(ctx: Context)` instead of `def handler()`) — the SDK supports both.

**Files:** `mcp/server.py`, `mcp/auth.py`, `mcp/tools/*.py`, `mcp/resources/providers.py`, `mcp/tests/`.

---

## 5. Subject B — `X-Forwarded-*` & `TRUSTED_PROXIES`

### B1. Threat model & goals

- **Goal:** when Sairo runs behind the operator's reverse proxy, the app sees the **real client IP** (for the audit log and rate limiters) and the **real host/scheme** (so SSO redirect URIs are correct).
- **Threat:** `X-Forwarded-For` is spoofable by any client. Blindly honoring it lets an attacker bypass per-IP rate limits and poison audit logs. Therefore trust must be **gated on the direct TCP peer being a configured proxy**.
- **Default:** `TRUSTED_PROXIES` empty → current behavior preserved (XFF ignored). Fail-closed.

### B2. `TrustedProxyMiddleware` design

New file `backend/trusted_proxy.py` (or inline in `main.py` if a single file is preferred for consistency — **recommend a new module** since `main.py` is already 6.9k lines). Registered as the **outermost** middleware (runs first) so all downstream code sees the rewritten scope.

```python
# pseudocode — the contract, not the implementation
class TrustedProxyMiddleware:
    def __init__(self, app, trusted_proxies: set[ip_network]):
        self.app = app; self.trusted = trusted_proxies

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.trusted:
            return await self.app(scope, receive, send)
        peer = scope.get("client", (None, None))[0]
        if peer is None or ip_address(peer) not in any(self.trusted):
            # direct client is NOT a trusted proxy → ignore forwarded headers
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])  # bytes
        # X-Forwarded-For: client, proxy1, proxy2 → walk right-to-left,
        # skip entries that are themselves trusted proxies; first untrusted = real client
        xff = headers.get(b"x-forwarded-for", b"").decode().strip()
        real_ip = _rightmost_untrusted(xff, self.trusted, fallback=peer)
        # X-Forwarded-Proto → scheme (http/https) — only if present
        xfp = headers.get(b"x-forwarded-proto")
        # X-Forwarded-Host → Host header — only if present
        xfh = headers.get(b"x-forwarded-host")
        new_scope = dict(scope)
        new_scope["client"] = (real_ip, scope["client"][1])
        if xfp: new_scope["scheme"] = xfp.decode().strip()
        if xfh: new_scope["headers"] = _with_host(scope["headers"], xfh)
        return await self.app(new_scope, receive, send)
```

**Parsing rules (specify precisely so tests are unambiguous):**
- `TRUSTED_PROXIES` is a comma-separated list of **IPs or CIDRs** (e.g. `10.0.0.0/8,172.16.0.0/12,169.254.0.0/16`). Parsed once at startup with `ipaddress.ip_network(..., strict=False)`. Invalid entries → fail-fast at boot (log + refuse to start) rather than silently widening trust.
- **IP resolution from XFF:** parse the comma-separated list, trim whitespace, **walk from the rightmost entry leftward**, skipping any entry whose IP is inside `TRUSTED_PROXIES` or equals the peer; the first non-trusted entry is the real client. If all entries are trusted, fall back to the **leftmost** entry. (Standard "trusted-proxy" interpretation, robust to multi-hop chains.)
- Also accept **`X-Real-IP`** (single IP, used by nginx) — honored only when the direct peer is trusted and XFF is absent.
- **RFC 7239 `Forwarded:` header** — support is a **stretch goal**, not required for v1. X-Forwarded-{For,Proto,Host} cover >99% of deployments (nginx, Caddy, Traefik, Cloudflare, AWS ALB). Note in docs that `Forwarded:` is not yet parsed.
- Proto/Host are applied **only when the peer is trusted**; never applied on a direct (untrusted) connection.
- All headers are **case-insensitive** (ASGI lowercases them, so read lowercase keys).

**Why not uvicorn `--proxy-headers` / `--forwarded-allow-ips`:** those are launch-time CLI flags on the uvicorn CMD. Sairo's model is "one container, configure via env". Driving this from `TRUSTED_PROXIES` (an env var the app reads) means operators don't override `CMD`. Also, uvicorn's flags don't cover `X-Forwarded-Host` (needed for SSO `base_url`). The middleware is the right layer.

### B3. Consumers (what changes once `request.client` is correct)

1. **Audit log** — add `client_ip TEXT` column. Schema migration (`main.py:539`, additive `ALTER TABLE` via the existing migration block) + capture resolved IP in the INSERT at `:821` and SELECT at `:4093` + surface in the audit-log API response and (optionally) the UI. Existing rows get NULL (backfill not needed).
2. **Login rate limiter** — `_check_login_rate(request.client.host)` (`:2874/2909/3549`) now automatically receives the resolved IP because the middleware rewrote `scope["client"]`. No code change at call sites; just verify.
3. **slowapi Limiter** (`:36/62`) — replace `key_func=get_remote_address` with `key_func=lambda req: req.client.host` (or keep `get_remote_address`; once scope is rewritten it returns the resolved IP). **Verify slowapi's `get_remote_address` behavior first** — if it still reads `X-Forwarded-For` directly it would double-apply; in that case use a custom `key_func` that reads only `request.client.host`.
4. **SSO redirect URIs** (`:2962, 3656, 3682, 3894, 3949`) — automatically correct once `scope["scheme"]` + Host are rewritten (`request.base_url` reads them). No code change; add a regression test.

### B4. Config & docs

- `.env.example` `# Deployment` section: add
  ```
  # Comma-separated IPs/CIDRs of trusted reverse proxies. When set, the app honors
  # X-Forwarded-For / X-Forwarded-Proto / X-Forwarded-Host ONLY from these peers
  # (fail-closed otherwise). Required for correct client IPs in the audit log and
  # rate limiters, and for correct SSO redirect URIs, when behind a proxy.
  # Example: 10.0.0.0/8,172.16.0.0/12
  # TRUSTED_PROXIES=
  ```
- `docs/` operator guide (on fork `main`, not the PR) — short "Running behind a reverse proxy" page with nginx/Caddy snippets.
- README deployment section: one-liner pointer.

---

## 6. Implementation sequence (task breakdown for project-manager)

Ordered by dependency. Each item maps to one or more atomic commits.

1. **Branch setup** (PM): refresh `upstream-main`; cut `fix/security-audit-v3.6.0` from it.
2. **A2 session/token revocation** (self-contained, no schema change beyond a row delete/update) — land first, lowest risk.
3. **A6 GitHub domains** (one-liner) and **A1 share-link access control** (helper + 2 routes + schema `endpoint_id`) — A1 needs the shared `_caller_can_read_bucket` helper.
4. **A4 s3 compat leak** (reuses A1's helper conceptually) and **A3 s3 token priv-esc**.
5. **A5 OAuth state/PKCE** (factor state-cookie helpers out of OIDC path first).
6. Backend test pass → open **PR 1**.
7. **PR 2 (parallel):** spike FastMCP transport seam → A7 MCP per-request auth → tests → open PR. **Pause for user decision** if the transport can't be secured cleanly.
8. **PR 3:** branch `feat/trusted-proxies-x-forwarded` from `upstream-main` (rebase after PR 1 lands) → `TrustedProxyMiddleware` + audit_log `client_ip` migration + slowapi verification + `.env.example` + tests → open PR.
9. **Docs (on `main`, not in any PR):** operator reverse-proxy guide, MCP security correction, AGENTS.md updates, this architecture doc updates if design shifts.

---

## 7. Testing strategy

- **Backend (`pytest backend/`):** for every fix, add a positive **and** negative test (e.g. viewer cannot create share-link for foreign bucket → 403; deleted user's refresh → 401; s3-mode token creation → 403; GitHub empty-email with allowed-domains → rejected). The audit's "Verified-OK" list (parameterized SQL, Fernet, OIDC) is the regression baseline — don't break it.
- **TrustedProxyMiddleware unit tests:** trusted peer + XFF → resolved IP; untrusted peer + XFF → ignored (peer used); multi-hop chain (rightmost-untrusted walk); X-Forwarded-Proto/Host rewrite; invalid `TRUSTED_PROXIES` → boot failure; CIDR matching.
- **Integration:** behind a fake proxy header in TestClient, assert audit-log row carries the resolved IP and SSO redirect_uri uses the forwarded host/scheme.
- **MCP (`pytest mcp/`):** request with no Bearer → 401; valid Bearer → per-request session with caller's identity/role; admin-only tool with viewer token → 403.

## 8. Risks & open questions (flagged for the user)

1. **MCP transport seam (highest risk).** If FastMCP's streamable-HTTP app can't host a per-request auth middleware, the MCP threat model changes (loopback-only or reverse-proxy-gated). **Decision needed** before PR 2 lands. Default recommendation if blocked: enforce `MCP_BIND_HOST=127.0.0.1` and document a public-exposure path.
2. **Session-revocation depth.** Minimal fix (DB lookup in refresh + cascade deletes) closes the exploit. Full design (opaque refresh tokens + `jti` denylist) is deferred — confirm the user is OK with the minimal scope for this round.
3. **`TRUSTED_PROXIES` semantics.** Confirm CIDR list (recommended) vs hostname list (rejected — DNS-spoofable). Default empty = current behavior.
4. **Docs vs. code split.** This design and AGENTS.md live on fork `main` only. The PM must cut PR branches from `upstream-main`, never from `main`. Verify before each PR that `git diff upstream-main...<branch>` contains no `docs/` or `AGENTS.md` changes.
5. **Git rights.** Local branch/commit/push-to-origin are permitted by current tool rules; **opening PRs upstream via `gh`** and any force-push/rebase-on-shared-branch may need additional rights — flag when PR 1 is ready.
6. **Depth of A8 fix (decision needed before PR 4 lands).** The `require_local_admin` chokepoint in §9.2 closes the exploit by breaking the chain at step 2 (`auth_create_user`). It does **not** address two deeper structural gaps that operators may or may not consider in-scope:
   - `auth_login` (`main.py:2964`) is reachable in `AUTH_MODE=s3` — local login is always available. Combined with the always-seeded default admin (`main.py:697-708`), anyone who knows `ADMIN_PASS` can bypass S3/IAM entirely.
   - `_init_users_db` (`main.py:697-708`) seeds the default local admin even in `AUTH_MODE=s3`.

   **Default recommendation:** leave both as-is (the chokepoint is sufficient; emergency local admin access is a legitimate operator workflow). **Stricter option (flag for user):** gate `auth_login` on `AUTH_MODE != "s3"` AND skip default-admin seeding in S3 mode. This is reversible but changes operator expectations — do **not** include in PR 4 unless the user explicitly approves.

---

## 9. Post-v3.6.0 follow-up audit (A8 / A9)

A full-project audit run after PRs 1 + 3 landed on `main` surfaced two additional issues in `backend/main.py`. Both are scoped to backend auth — no other audit area (SQL, path traversal, OIDC, crypto, frontend, Dockerfile, trusted-proxy) produced findings ≥ conf 7.

> **Baseline drift note (housekeeping).** Line numbers and structural references in §9.2–§9.5 were authored against fork `main` (which carries v3.6.0 + trusted-proxy + audit-log-`client_ip` changes). PR 4 is cut from `upstream-main` (the v3.6.0 rollback), where line numbers are ~80–170 lower and two structures §9.5 referenced do **not** exist: (a) the inline `s3:` guard at `main.py:3422` (A3 was rolled back in v3.6.0 → nothing to delete; the chokepoint is the sole guard), and (b) `TestS3TokenPrivilegeEscalation` in `backend/test_main.py:1361-1440` (didn't exist on `upstream-main` → PM created it fresh at `test_main.py:864`). The PM identified all targets by name and applied the spec correctly; only the line numbers / "extend" wording were stale.

### 9.1 Context

| Ref | Title | Severity | Confidence | Status |
|-----|-------|----------|------------|--------|
| A8 | `AUTH_MODE=s3` session can mint a non-IAM-scoped local admin via `auth_create_user` → `auth_login` → `create_token` chain | HIGH | 9/10 | **Bypass of A3.** The v3.6.0 fix added the `s3:` guard only at `create_token` (`main.py:3422`); every other admin mutation route was missed. |
| A9 | User / auth-provider enumeration via 500 on federated usernames (uncaught `bcrypt.verify` `ValueError`) | MEDIUM | 9/10 | **New.** Affects `auth_login`, `twofa_disable`, `auth_change_password`. |

These ship together on one new PR (PR 4 below) because they are small, backend-only, and A9 is naturally co-located with A8's auth routes.

### 9.2 A8 — S3-mode priv-esc bypass (HIGH, conf 9)

**The bypass.** The A3 fix used a **syntactic guard** — `if user["username"].startswith("s3:"): raise 403` — applied at exactly one chokepoint (`create_token` at `main.py:3422`). Every other admin mutation route still passes `require_admin` and trusts the JWT's `role:"admin"`. The full chain:

1. `POST /api/auth/login-s3` (`main.py:2997`, **not gated on `AUTH_MODE=="s3"`**) → admin cookie with `sub:"s3:AKIA…"` for any key pair that passes `list_buckets()` (including read-only IAM users).
2. `POST /api/auth/users {"username":"backdoor","password":"Password123","role":"admin"}` (`main.py:3123`, `require_admin` only, **no `s3:` guard`) → local user row inserted.
3. `POST /api/auth/login {"username":"backdoor",...}` (`main.py:2964`, **not gated on `AUTH_MODE`**) → new admin cookie with `sub:"backdoor"` (no `s3:` prefix).
4. `POST /api/auth/tokens {"role":"admin"}` (`main.py:3420`) → passes the existing `s3:` guard because `sub="backdoor"` → returns a `sairo_…` admin API token.
5. Attacker now holds a **persistent admin token not bound to the original IAM keys** and survives their revocation. Side attacks in the same chain: demote the operator's real admin (`PUT /api/auth/users/admin {"role":"viewer"}`) or delete legitimate users.

**Root cause.** "Whack-a-mole" — applying a syntactic guard per-route is fragile; every future admin route has to remember it. The deeper issue is that `AUTH_MODE=s3` sessions carry `role:"admin"` (because the rest of the code uses `role=="admin"` as the sole capability check), so the role claim alone cannot distinguish "IAM-scoped admin" from "non-IAM-scoped admin." The `sub` prefix is the only signal.

**Fix — introduce one structural chokepoint, not nine syntactic ones:**

Add a new FastAPI dependency `require_local_admin` directly below `require_admin` (`main.py:822`):

```python
def require_local_admin(request: Request, user: dict = Depends(require_admin)):
    """Admin routes that mutate non-IAM-scoped state (local users, API tokens,
    endpoints, bucket grants, 2FA resets). In AUTH_MODE=s3, the session's
    `role:"admin"` only reflects IAM capability (cached via list_buckets) —
    it MUST NOT authorize changes to state outside the user's IAM scope."""
    if AUTH_MODE == "s3" and user["username"].startswith("s3:"):
        raise HTTPException(
            403,
            "S3-mode sessions cannot perform this action; "
            "ask an admin with local/LDAP/OAuth/OIDC credentials.",
        )
    return user
```

Switch every admin mutation route that writes non-IAM-scoped state from `Depends(require_admin)` to `Depends(require_local_admin)`:

| Route | Line | What it mutates |
|-------|------|-----------------|
| `auth_create_user` | 3123 | local user row (the chain's step 2) |
| `auth_update_user` | 3154 | user role (privilege) |
| `auth_delete_user` | 3139 | user row + cascade |
| `twofa_admin_reset` | 3236 | another user's 2FA state |
| `set_user_permissions` | 3356 | bucket grant row |
| `delete_user_permission` | 3377 | bucket grant row |
| `create_endpoint` | 4570 | endpoint row (encrypted server creds) |
| `update_endpoint` | 4610 | endpoint row (encrypted server creds) |
| `delete_endpoint` | 4632 | endpoint row |
| `create_token` | 3420 | API token row — **refactor**: drop the inline `s3:` check at 3422, switch the route to `require_local_admin` for consistency |

Routes that stay on `require_admin` (they operate on S3 state via the user's IAM scope — that's the entire point of `AUTH_MODE=s3`):

- All bucket routes (`create_bucket`, `delete_bucket`, versioning, lifecycle, CORS, policy, ACL, tagging, multipart, copy/rename, crawl)
- All object routes (`delete_objects`, `delete_folder`, `create_folder`, `purge_versions`, `version_*`)
- Read-only admin routes (`auth_list_users`, `get_user_permissions`, `list_tokens`, `list_endpoints`, `s3_health_*`, `health_detail`, `audit_log`) — these don't enable persistence; deeper tightening is a follow-up.

**Out of scope (flagged in §8 risk #6 above):** gating `auth_login` on `AUTH_MODE != "s3"` and/or skipping default-admin seeding in S3 mode. Both are deeper structural changes that may break operator workflows (emergency local access); the chokepoint above is sufficient to close the exploit without touching them.

**Files:** `backend/main.py` (one new ~10-line dependency, ten `Depends(...)` swaps, one inline check deleted at 3422), `backend/test_main.py` (positive + negative tests per swapped route).

### 9.3 A9 — Federated user enumeration via uncaught `bcrypt.verify` `ValueError` (MEDIUM, conf 9)

**The bug.** Federated users (LDAP/OAuth/OIDC) created by `_sync_federated_user` (`main.py:836`) store an **unusable** placeholder password hash of the form `LDAP:<hex>` / `OAUTH:<hex>` / `OIDC:<hex>` (`main.py:873`). passlib's `bcrypt.verify(pw, hash)` raises `ValueError: not a valid bcrypt hash` for any non-bcrypt input — verified:

```
$ python3 -c "from passlib.hash import bcrypt; bcrypt.verify('test', 'LDAP:abc123')"
ValueError: not a valid bcrypt hash
```

The verify calls are not wrapped, so FastAPI returns **500** for federated usernames and **401** for non-existent / local usernames. That oracle fingerprints both existence and which IdP the user authenticates against — exactly the targeting data an attacker needs for phishing.

**Three affected sites:**

| Route | Line | Reach | Current behavior |
|-------|------|-------|------------------|
| `auth_login` | 2971 | unauthenticated | 500 on federated username → enumeration oracle |
| `twofa_disable` | 3225-3227 | self (auth'd) | has the `("LDAP:", "OAUTH:")` prefix-skip but **omits `"OIDC:"`** → 500 on OIDC users |
| `auth_change_password` | 3395 | self (auth'd) | same unwrapped pattern |

**Fix — defensive wrap returning 401 (matches the "Invalid username or password" branch):**

```python
# auth_login (main.py:2971)
if not row:
    raise HTTPException(401, "Invalid username or password")
try:
    pw_ok = bcrypt.verify(req.password, row["password_hash"])
except (ValueError, TypeError):
    pw_ok = False  # federated placeholder hash — same response as bad password
if not pw_ok:
    raise HTTPException(401, "Invalid username or password")
```

Plus:
- `twofa_disable` (`main.py:3225`): add `"OIDC:"` to the prefix tuple (`("LDAP:", "OAUTH:", "OIDC:")`) so the existing skip works for all three providers, AND wrap the `bcrypt.verify` defensively for forward safety (a future `auth_source` value would otherwise reintroduce the crash).
- `auth_change_password` (`main.py:3395`): same try/except wrap → 401 on malformed hash.

**Files:** `backend/main.py` (~2971, ~3225, ~3395), `backend/test_main.py` (one test per site: federated username + any password → 401, not 500).

### 9.4 Branch & PR strategy

| PR | Branch (from `upstream-main`) | Contents |
|----|-------------------------------|----------|
| 4  | `fix/s3-mode-priv-esc-bypass` | A8 (`require_local_admin` chokepoint + 10 route swaps) **and** A9 (bcrypt wrap at 3 sites + `OIDC:` prefix) **and** the §9.7 test-isolation cherry-pick. All three are small, backend-only, and ride together so a reviewer can validate the security changes without the cross-run flake noise. |

Branch from `upstream-main` (clean), never from `main`. Docs (this section) live only on `main`. Before opening PR 4 verify `git diff upstream-main...fix/s3-mode-priv-esc-bypass` contains **no** `docs/`, `AGENTS.md`, or `*.md` changes.

PR 2 (`fix/mcp-per-request-auth`, A7 with the §4 augmentation above) proceeds independently — it touches only `mcp/` and is unchanged by A8/A9.

### 9.5 Implementation sequence (for project-manager)

Ordered by dependency. Each item maps to one atomic commit.

1. **Branch setup:** refresh `upstream-main` (`git fetch upstream && git branch -f upstream-main upstream/main`); cut `fix/s3-mode-priv-esc-bypass` from it.
2. **A8 chokepoint** (highest leverage, smallest change): add `require_local_admin` below `require_admin`; swap the 10 routes in §9.2's table; delete the now-redundant inline check at `main.py:3422`. Run `pytest backend/` — existing tests should still pass (they use local/LDAP/OAuth/OIDC auth, not S3 sessions).
3. **A8 negative tests:** for each swapped route, add a test that creates an S3-mode session (cookie with `sub:"s3:..."`) and asserts 403. Extend the existing `TestS3TokenPrivilegeEscalation` class in `backend/test_main.py:1361-1440`.
4. **A9 fix:** wrap `bcrypt.verify` at the three sites; add `"OIDC:"` to the `twofa_disable` prefix tuple.
5. **A9 tests:** one positive test per site — login as a federated user (any password) → 401, not 500; `twofa_disable` for an OIDC user → succeeds (skip path) instead of 500; `auth_change_password` for a federated user → 401.
6. **§9.7 test-isolation cherry-pick** (see below): cherry-pick `539f6c7` onto this branch; apply the two belt-and-suspenders test edits. Run `pytest backend/` repeatedly (≥3×) to confirm zero flakes.
7. **Backend test pass → open PR 4.**

Estimated effort: 1–2 hours code + tests, plus review.

### 9.6 Testing strategy

- **A8:** for every route swapped to `require_local_admin`, an S3-mode session (cookie JWT `sub:"s3:AKIA..."`) gets 403; a local/LDAP/OAuth/OIDC admin gets the normal 2xx/4xx response. The full chain in §9.2 must fail at step 2 (`auth_create_user`) — add an end-to-end regression test asserting the chain is broken.
- **A9:** `auth_login` with username `"oidc-user"` (placeholder hash `"OIDC:abc"`) returns 401 for any password, not 500. Same for `"ldap-user"` and `"oauth-user"`. `twofa_disable` for an OIDC user with `password=""` succeeds (skip path). Verify the timing oracle is closed (responses are byte-identical 401s — manual check, not a hard test requirement).

### 9.7 Test-isolation fix (cherry-pick `539f6c7` into PR 4)

**Why this is in scope.** While validating PR 4 the PM noticed a "test-scaling flake" — `test_scaling.py::TestPrefixChildrenRebuild::test_root_level_files_excluded` and `test_scaling.py::TestFullIntegration::test_storage_history_uses_latest_not_max` failed on the 2nd consecutive `pytest backend/` run. The user authorized fixing it even if the cause originated upstream.

**Root cause (fully root-caused, not probabilistic — confidence 10/10):**

1. **`DB_DIR` `setdefault` race.** `backend/test_main.py:28` does `os.environ.setdefault("DB_DIR", "/tmp/sairo-test")` and `backend/test_scaling.py:25-26` does `os.environ.setdefault("DB_DIR", <tempfile.mkdtemp>)`. `main.py:322` reads `DB_DIR` exactly once at import. Pytest collects alphabetically by default (`test_main` < `test_scaling`, no `pytest-randomly`, no `pyproject.toml`/`pytest.ini` to change order), so `test_main.py` wins the race → `DB_DIR=/tmp/sairo-test` (persistent) for the whole session. `test_scaling.py`'s `setdefault` is a no-op.
2. **Two non-idempotent `INSERT`s in `test_scaling.py`.** `_init_db()` uses `CREATE TABLE IF NOT EXISTS` (so existing rows survive a 2nd run). Most tests use `INSERT OR REPLACE` (idempotent on PK), but two use plain `INSERT`:
   - `test_scaling.py:429-440` — `INSERT INTO objects` with deterministic keys `root_file_0.txt`…`root_file_9.txt` → `sqlite3.IntegrityError: UNIQUE constraint failed: objects.key` on run 2.
   - `test_scaling.py:647, 652` — `INSERT INTO storage_history` (no PK) → rows accumulate forever → `assert len(apr12) == 1` fails with `2 == 1` on run 2.

**Reproduction (deterministic, 100%):**
```bash
cd backend
rm -rf /tmp/sairo-test && pytest .           # Run 1: 115 passed
pytest .                                      # Run 2: 2 failed, 113 passed
```
Does NOT reproduce when `test_scaling.py` runs alone (its `setdefault` wins and it gets a fresh tempdir).

**Prior art — `539f6c7` (`fix/test-isolation-conftest`, already on fork `main` as `ff188e2`):** adds `backend/conftest.py` (23 lines) that wipes `/tmp/sairo-test/` at session start:
```python
import os, shutil
_TEST_DB_DIR = "/tmp/sairo-test"
if os.environ.get("DB_DIR", _TEST_DB_DIR) == _TEST_DB_DIR:
    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)
os.makedirs(_TEST_DB_DIR, exist_ok=True)
```
Verified by the investigator: **5/5 consecutive full-suite runs pass (115/115 each)** with this conftest. Session-start scope is correct — function-scoped cleanup would break `test_main.py`'s module-scoped `app`/`client`/`admin_cookies`/`viewer_cookies` fixtures.

**Upstream impact.** `git diff upstream/main HEAD -- backend/test_scaling.py` is empty (byte-identical) and `upstream/main` has no `backend/conftest.py`. The bug exists upstream and the fix should be sent there too — folding the cherry-pick into PR 4 achieves that.

**Fix (two parts):**

1. **Cherry-pick the existing conftest fix onto PR 4:**
   ```bash
   git cherry-pick 539f6c7
   ```
   This adds `backend/conftest.py` verbatim. Single commit, no source code changes. PR 4 reviewer sees three commits: A8, A9, test-isolation.

2. **Belt-and-suspenders hardening of the two non-idempotent tests** (defense-in-depth so the flake cannot resurface if the conftest is ever removed):
   - `backend/test_scaling.py:429, 437` — change `INSERT INTO objects` → `INSERT OR REPLACE INTO objects`.
   - `backend/test_scaling.py:647, 652` — add `DELETE FROM storage_history` (or scope the assertion query to rows inserted this run via a per-run run_id column).

**Out of scope (follow-up, not in PR 4):** the investigator noted that `test_scaling.py:25` calls `tempfile.mkdtemp(prefix="sairo-scaling-test-")` which is never cleaned up (118 orphaned dirs were found on the dev machine). A `tmp_path_factory`-based fixture or `atexit` cleanup would fix it but is not user-visible and not the cause of this flake.

**Acceptance:**
- `pytest backend/` passes 3/3 consecutive runs from a cold start.
- `pytest backend/` passes 3/3 consecutive runs from a warm `/tmp/sairo-test/`.

---
