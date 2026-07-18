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
4. Resources (`mcp/resources/providers.py`) currently can't see the session (no `Context`) — at minimum enforce that resources are admin-only via the same middleware, or thread the per-request identity into them.
5. Fix the docs (`website/src/content/docs/features/mcp.mdx`) that falsely claim "every tool call is gated by authentication" — but **docs go on fork `main`, not this PR branch**. Coordinate: code in PR 2, doc correction on `main`.

**Risk flag (highest-risk item in the whole plan):** FastMCP's streamable-HTTP transport may not expose a clean middleware/seam; the PM must spike `mcp.streamable_http_app()` first. If FastMCP can't be secured at the transport level, the fallback is to run the MCP server behind a sidecar that injects auth, or to gate by `MCP_BIND_HOST=127.0.0.1` only + document that public exposure requires an auth-aware reverse proxy in front. This decision is **flagged for the user** because it shapes the MCP threat model.

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
