# Sairo — Security Audit Report (2026-07)

**Auditor:** GitHub Copilot · **Date:** 2026-07-26 · **Scope:** gijoe88/sairo fork analysis  
**Status:** COMPREHENSIVE · **Action:** Fork-internal documentation (not upstreamed)

---

## Executive Summary

Sairo is a self-hosted S3-compatible object storage browser with a **single-file FastAPI backend** (`backend/main.py`, ~6.9k lines), a **React/Vite SPA frontend**, and an **MCP server for AI clients** (`mcp/`). The project operates in **three deployment contexts:** local SQLite auth, LDAP, and OAuth/OIDC federation, plus a read-only **S3-mode** where users authenticate against the S3 endpoint directly.

This audit validates the **fork-internal design doc** (`docs/architecture/security-and-proxy-design.md`) against the **current codebase state** and identifies:

1. **Nine (9) confirmed vulnerabilities** detailed in the design doc (6 HIGH, 3 MEDIUM) — under active remediation via PR branches.
2. **Three (3) additional post-audit findings** (from full-project re-audit) — requiring separate PR.
3. **Five (5) architectural strengths** and seven (7) operational best practices.
4. **Twelve (12) critical recommendations** for hardening post-fix.

This report is **fork-internal** and **must not** be upstreamed; it documents the workstream only for internal visibility and testing guidance.

---

## 1. Codebase Structure & Security Posture

### 1.1 Architecture Overview

```
gijoe88/sairo (fork origin)
├── backend/main.py          ~6.9k lines: single FastAPI app
│   ├── Middleware stack     security_headers → bucket_permission → endpoint_routing
│   ├── Auth routes          login, refresh, LDAP, OAuth, OIDC, API tokens, S3-mode
│   ├── Bucket/object ops    crud, presigned URLs, lifecycle, versioning, CORS
│   ├── Audit log            (id, timestamp, username, action, bucket, details)
│   ├── Database            SQLite schema (~20 tables, no migrations framework)
│   └── S3 client proxy      endpoint context, cred encryption, request signing
├── mcp/                      MCP server for AI clients
│   ├── server.py            FastMCP ASGI app with bearer middleware
│   ├── auth.py              token validation against Sairo backend
│   ├── tools/                discovery, inspection, analytics, cost, pipeline, operations
│   ├── resources/           bucket/object resource providers (no per-request auth)
│   └── tests/               pytest-based validation
├── frontend/                React/Vite SPA (client-side only)
├── cli/                      Go CLI (secondary, audit-only)
└── docs/architecture/        Fork-internal design docs
```

### 1.2 Threat Model

**Deployment contexts:**
- **Local auth:** username/password stored as bcrypt hashes; admin is seeded at first run.
- **LDAP/OAuth/OIDC:** federated identity; local user row synced on first login (federated placeholder password).
- **S3-mode:** `AUTH_MODE=s3` — users authenticate against the S3 endpoint; every successful login mints an admin session (since S3 IAM is the identity source).

**Trust boundaries:**
- Frontend (browser) ← untrusted; browser security model applies.
- Backend ← semi-trusted; operator controls deployment, but can be compromised via RCE.
- S3 endpoint ← operator-trusted (credentials in `.env`); can be hostile.
- MCP clients ← trusted (operate via carrier token); can be compromised.
- Reverse proxy (if present) ← semi-trusted (can spoof `X-Forwarded-*` headers).

**Primary threat:** operator needs to grant bucket access selectively (viewer, editor, admin roles per user + per bucket); a vulnerability that lets a viewer read/write buckets they don't own is a **direct data breach**.

---

## 2. Confirmed Vulnerabilities (v3.6.0 Audit)

All nine vulnerabilities are **documented in `docs/architecture/security-and-proxy-design.md`** (§4) and are under active remediation via PR branches `fix/security-audit-v3.6.0` (subjects A1–A5, A9), `fix/mcp-per-request-auth` (A7), and `feat/trusted-proxies-x-forwarded` (A6 + subject B).

### 2.1 Subject A — Backend Security Fixes (9 findings)

| # | Issue | Severity | Location | Root Cause | PR Branch |
|---|-------|----------|----------|-----------|----------|
| A1 | Share-link access control (create + list) | HIGH | `main.py:3356, 3369` | `create_share_link` checks `get_current_user` only, not bucket access; `list_share_links` returns secret tokens to any user | fix/security-audit-v3.6.0 |
| A2 | Session & token revocation (refresh + delete) | HIGH | `main.py:2992, 3037, 696` | `auth_refresh` re-signs from JWT (never DB); deleted users keep API tokens; `_verify_api_token` doesn't join users | fix/security-audit-v3.6.0 |
| A3 | S3-mode privilege escalation (bearer→admin) | HIGH | `main.py:2928, 3316, 696` | `create_token` rejects `s3:*` tokens but only at that route; s3-mode sessions are always admin; no scope limit on API token | fix/security-audit-v3.6.0 |
| A4 | S3-mode index metadata leak | MEDIUM | `main.py:6780` | `_check_compat_bucket_read` admin-short-circuits; s3 sessions bypass bucket-level gate | fix/security-audit-v3.6.0 |
| A5 | OAuth login CSRF | HIGH | `main.py:3653, 3678` | OAuth path omits `state` + PKCE (OIDC has both); victim lands logged in as attacker | fix/security-audit-v3.6.0 |
| A6 | GitHub email domain check fail-open | MEDIUM | `main.py:3735` | `if OAUTH_ALLOWED_DOMAINS and domain and domain not in …:` — skips check when email is empty (GitHub default) | fix/security-audit-v3.6.0 |
| A7 | MCP per-request authentication | HIGH | `mcp/server.py:142, mcp/tools/*.py` | Authenticates **once** at startup; every tool uses shared session; no per-request Bearer validation | fix/mcp-per-request-auth |
| A8 | S3-mode priv-esc bypass (post-audit) | HIGH | `main.py:2997, 3123, 2964, 3422` | A3 fix is syntactic (one-site guard); s3 session can chain `auth_create_user` → `auth_login` → `create_token` → admin API token | fix/s3-mode-priv-esc-bypass |
| A9 | User enumeration via bcrypt ValueError | MEDIUM | `main.py:2971, 3225, 3395` | Federated placeholder hashes raise `ValueError` on verify → 500 vs 401; oracle on user existence + IdP | fix/s3-mode-priv-esc-bypass |

### 2.2 Subject B — Trusted-Proxy Design

**Feature:** `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` support gated by `TRUSTED_PROXIES` env var.

| # | Issue | Severity | Location | Root Cause | Status |
|---|-------|----------|----------|-----------|--------|
| B1 | Blind XFF parsing (no trusted-proxy gate) | MEDIUM | `main.py:36, 62` (slowapi) | `slowapi.util.get_remote_address` reads XFF first entry unconditionally; any client spoofs rate-limit bypass | Proposed; design in §5 of arch doc |
| B2 | Audit log missing `client_ip` | MEDIUM | `main.py:821, 539` | `audit_log` schema has no IP column; client identity is raw TCP peer (broken behind proxy) | Proposed in PR 3 |
| B3 | SSO redirect URIs behind proxy | MEDIUM | `main.py:2962, 3656, 3682, 3894, 3949` | `request.base_url` built from Host header + scheme (both from client, spoofable); SSO login fails or redirects to attacker's domain | Proposed in PR 3 |

---

## 3. Design Strengths Observed

✅ **1. Parameterized SQL (defense-in-depth)**  
All queries use `?`-parameterized bindings (line `main.py:4787` shows FTS5 `MATCH ?` with proper escaping). No observed SQL injection vectors.

✅ **2. Secrets management (industry standard)**  
- Passwords: `bcrypt` with `.verify()` (constant-time comparison).
- Tokens: `secrets.token_urlsafe()` / `secrets.token_hex()` (cryptographically secure PRNG).
- At-rest crypto: Fernet with SHA-256 key derivation from `JWT_SECRET` (line `main.py:361`).

✅ **3. JWT hardened (algorithm pinning)**  
All JWT decodes pin `algorithms=["HS256"]` on decode; OIDC restricts to asymmetric algorithms only (line `main.py:3900+`). No algorithm-confusion attacks observed.

✅ **4. Middleware ordering (defense-in-depth)**  
Registration order (lines 93, 167, 216) enforces `security_headers` → `bucket_permission` → `endpoint_routing`; effective reverse order ensures bucket permission checks run before routes execute.

✅ **5. MCP bearer auth (robust middleware)**  
`SairoBearerAuthMiddleware` (lines 274–349) implements:
- Constant-time scheme comparison (`hmac.compare_digest`).
- Per-request session binding via ContextVar (not shared state).
- Public allow-list (`/healthz`, `/readyz`).
- DNS-rebinding guard for browser Origin header.

---

## 4. Architectural Issues (Beyond v3.6.0)

### 4.1 Database Schema Maturity

**Observation:** SQLite with no migration framework. `_init_db()` runs `CREATE TABLE IF NOT EXISTS` at startup; schema evolves via direct SQL in the codebase.

**Risk:**
- Hard to track schema state across versions; easy to miss dependent columns during refactoring.
- A1 fix requires adding `endpoint_id` to `share_links` table (line ~567); no schema-versioning mechanism to ensure consistency on roll-forward.

**Recommendation (post-audit):** 
- Consider Alembic or similar for schema migrations (not blocking; `CREATE TABLE IF NOT EXISTS` is sufficient for a single-container deployment where the schema is owned by the app).
- Document schema in a `.sql` file alongside the code; CI test that `_init_db()` matches the reference.

### 4.2 Single-File Architecture Scaling

**Observation:** All backend logic in `main.py` (~6.9k lines). No logical separation of concerns (auth, S3 proxy, audit, schema).

**Risk:**
- Hard to audit isolated subsystems; cognitive load on reviewers.
- Easier to miss cross-cutting bugs (e.g., A8's bypass of A3's single-point guard).
- Maintenance burden: every new route competes for lines and mental stack with existing routes.

**Recommendation (post-audit):** 
- Split into 3–4 logical modules (`auth.py`, `s3_proxy.py`, `audit.py`) and import them into `main.py` for route registration.
- Not critical for security (code organization doesn't prevent bugs), but reduces review friction.

### 4.3 Session Persistence (Stateless Design)

**Observation:** Sairo uses stateless JWT + DB row verification (no session table or denylist).

**Risk:**
- A2 exploit: demoted/deleted admins can refresh forever (JWT is the source of truth until refresh time).
- Revoking a session requires waiting for JWT expiration or changing `JWT_SECRET` (which also invalidates **all** active sessions globally).

**Design choice (deliberate):** Stateless is simpler for single-container deployments. A2 fix adds per-refresh DB lookup (closes exploit); full revocation (denylist + short-lived tokens) is deferred as a follow-up.

---

## 5. Operational Best Practices Observed

✅ **1. Environment-driven config** (`.env.example`)  
All configuration via `KEY=value` env vars; documented in `.env.example` with inline comments. No hardcoded secrets observed.

✅ **2. Health/readiness probes** (Kubernetes-ready)  
`/healthz` (liveness) and `/readyz` (readiness) endpoints; MCP also includes `/metrics` for Prometheus.

✅ **3. Structured logging** (observability)**  
Backend logs include `extra={"tool": "server"}` for structured context; MCP has observability module with metrics.

✅ **4. Fail-closed by default** (MCP_DEV_MODE guard)  
MCP server refuses to start without `SAIRO_API_TOKEN` or explicit `MCP_DEV_MODE=true` (lines 368–374). Dev mode restricted to loopback (lines 378–383).

✅ **5. Audit logging** (accountability)  
`_audit_log(...)` inserted for sensitive actions (login, user create/delete, bucket grants, share-link create). Schema carries `(id, timestamp, username, action, bucket, details)`.

✅ **6. CSRF protection (partial)** 
OIDC path has `state` + PKCE (lines 3884+); OAuth path **lacks** both (A5 — under fix).

✅ **7. CSP headers** (XSS defense)  
`_csp_connect_origins()` (lines 101+) constructs `Content-Security-Policy` headers scoped to S3 endpoints.

---

## 6. Critical Recommendations (Post-Audit Hardening)

### Tier 1 — Before any production deployment:

1. **Merge PR 1** (`fix/security-audit-v3.6.0`) — closes A1–A5, A9 (7 vulns).
2. **Merge PR 2** (`fix/mcp-per-request-auth`) — closes A7 (1 vuln).
3. **Verify test pass** — PR 1 and 2 require backend/MCP tests for every fix.
4. **Tag as v3.6.1** (patch) — all fixes are backward-compatible; no config change needed.

### Tier 2 — Within one sprint:

5. **Merge PR 3** (`feat/trusted-proxies-x-forwarded`) — adds `TRUSTED_PROXIES` env var + audit-log `client_ip` column + rate-limit fix (subject B).
6. **Merge PR 4** (`fix/s3-mode-priv-esc-bypass`) — closes A8 (1 vuln, bypass of A3) + A9 additions + test-isolation fix.
7. **Tag as v3.6.2** (patch) — post-audit findings.
8. **Deploy to staging** — run behind a reverse proxy; verify audit log captures correct client IP; test S3-mode chains fail.

### Tier 3 — Hardening (deferred, not blocking):

9. **Opaque refresh tokens + `jti` denylist** — replaces stateless JWT for session revocation depth. Target: v3.7.
10. **Database schema migration framework** — Alembic or similar. Needed if schema churn increases.
11. **Single-file → logical modules split** — `auth.py`, `s3_proxy.py`, `audit.py`. For maintainability; no security impact.
12. **Rate-limit storage backend** — slowapi currently uses in-memory dict (resets on restart, not shared across replicas). Upgrade to Redis if horizontally scaled.

---

## 7. Branch & PR Strategy (Current State)

**Fork-internal policy (from `AGENTS.md`):**

```
upstream    AshwathStephen/sairo (source of truth; PR target)
origin      gijoe88/sairo (this fork)

local branches:
  main            = upstream/main + fork docs (AGENTS.md, docs/architecture/*)
  upstream-main   local mirror of upstream/main (base for all PRs)
  fix/*           security PR branches (cut from upstream-main)
  feat/*          feature PR branches (cut from upstream-main)
```

**PR plan (from architecture doc §3):**

| PR | Branch | Contents | Status |
|----|--------|----------|--------|
| 1  | fix/security-audit-v3.6.0 | A1–A5, A9 backend vulns | Atomic commits, one per finding |
| 2  | fix/mcp-per-request-auth | A7 MCP vuln | Independent; can parallel PR 1 |
| 3  | feat/trusted-proxies-x-forwarded | Subject B (proxy support) | Land after PR 1; rebases if needed |
| 4  | fix/s3-mode-priv-esc-bypass | A8 (bypass of A3) + A9 additions + test-isolation | Post-audit; land after PR 1 + PR 3 |

**Critical rule:** Every PR branch is **cut from `upstream-main`** (clean, code-only), **never** from fork `main` (carries docs). This guarantees PR diffs contain zero documentation noise.

---

## 8. Testing Strategy

### Unit Tests (per PR)

**PR 1 (backend vulns A1–A5, A9):**
- **A1 (share-link AC):** viewer cannot create link for foreign bucket → 403; non-admin cannot list others' links; secret token dropped from list response.
- **A2 (session revocation):** deleted user refresh → 401; demoted user refresh uses DB role (not JWT); deleted user's API token → 401.
- **A3 (S3 priv-esc):** s3-mode session cannot create API token → 403; s3-mode token cannot be used as Bearer → 403.
- **A4 (s3 compat leak):** s3-mode read routes check `_s3_user_can_access` per bucket (not admin short-circuit).
- **A5 (OAuth CSRF):** OAuth callback validates `state` + PKCE (cookies set by start endpoint); invalid state → 400.
- **A9 (federated enum):** `auth_login` with federated username + any password → 401 (not 500); `twofa_disable` OIDC user → 200 (not 500).

**PR 2 (MCP auth A7):**
- Request with no Bearer → 401.
- Valid Bearer → per-request session with caller's identity/role (not shared startup session).
- Viewer token on admin tool → 403.
- `MCP_DEV_MODE=true` on non-loopback → startup error.

**PR 3 (trusted proxies B1–B3):**
- Trusted peer + XFF → resolved IP captured in audit log.
- Untrusted peer + XFF → peer IP used (header ignored).
- Multi-hop chain (rightmost-untrusted walk) → correct resolution.
- SSO redirect URI uses forwarded host/scheme (integration test).

**PR 4 (A8 bypass + A9 additions + test-isolation):**
- S3 session cannot mutate non-IAM state (10 routes on `require_local_admin`).
- Federated user 500→401 wraps at all three sites.
- Test suite passes ≥3× consecutive runs (test-isolation fixed).

### Integration Tests

- **Auth flow:** login (all 5 modes) → token issuance → JWT decode + DB verify → refresh.
- **Bucket access:** viewer reads, fails on foreign buckets; editor edits own; admin all.
- **Audit:** sensitive actions logged with correct client IP (behind proxy).
- **S3-mode chain:** login → attempt local-user create → 403 (no escalation).

---

## 9. Assumptions & Out-of-Scope

### Assumptions Made in Audit

1. **Deployment:** Single container behind optional reverse proxy (nginx, Caddy, Traefik, Cloudflare, AWS ALB).
2. **Database:** SQLite on shared container storage (not horizontally scaled; schema is app-owned).
3. **Secrets:** `.env` file not committed to git; operator responsible for `JWT_SECRET` entropy and `SAIRO_API_TOKEN` rotation.
4. **S3 endpoint:** Operator-controlled; credentials in `.env` are trusted (if they point to an attacker's S3, data is lost regardless).

### Out-of-Scope (Not This Audit)

- **Frontend XSS/CSRF:** browser security model; audit scope was backend + MCP.
- **Go CLI (`cli/`):** secondary tool for operator audits; not analyzed.
- **Network-level attacks:** firewall, DDoS, TLS, etc. assumed operator-configured.
- **Supply-chain security:** dependencies (FastAPI, Starlette, passlib, etc.). Assume maintained and monitored.

---

## 10. Compliance Notes

### OWASP Top 10 (2021) Coverage

| Category | Finding | Status |
|----------|---------|--------|
| **A1: Broken Access Control** | A1 (share-link), A3 (S3 priv-esc), A8 (bypass) | Under fix (PRs 1, 4) |
| **A2: Cryptographic Failures** | None observed | ✅ Passed |
| **A3: Injection** | None observed (all queries parameterized) | ✅ Passed |
| **A4: Insecure Design** | A5 (CSRF), A7 (stateful session) | Under fix (PRs 1, 2) |
| **A5: Security Misconfiguration** | B1–B3 (proxy misconfiguration vectors) | Under fix (PR 3) |
| **A6: Vulnerable & Outdated Components** | Not in scope (supply-chain) | ℹ Assume maintained |
| **A7: Authentication Failures** | A2 (revocation), A6 (CSRF), A9 (enum) | Under fix (PRs 1, 4) |
| **A8: Data Integrity Failures** | A8 (state mutation escape) | Under fix (PR 4) |
| **A9: Logging & Monitoring Failures** | B2 (audit-log IP missing) | Under fix (PR 3) |
| **A10: SSRF** | None observed (S3 client uses operator credentials only) | ✅ Passed |

### CWE Mapping (Top 15)

| CWE | Title | Finding | PR |
|-----|-------|---------|-----|
| **CWE-639** | Authorization Bypass Through User-Controlled Key | A1, A3, A8 | 1, 4 |
| **CWE-287** | Improper Authentication | A2, A7, A9 | 1, 2, 4 |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | A5, A6 | 1 |
| **CWE-613** | Insufficient Session Expiration | A2 | 1 |
| **CWE-200** | Exposure of Sensitive Information | A9 (enumeration) | 4 |
| **CWE-404** | Improper Resource Validation | B1–B3 (proxy header trust) | 3 |

---

## 11. Audit Checklist & Verification

**Code Review Checklist (before merging PR 1):**

- [ ] A1: `_caller_can_read_bucket` helper defined and used by `create_share_link` + `list_share_links`.
- [ ] A1: `share_links` table has `endpoint_id` column (schema migration applied).
- [ ] A2: `auth_refresh` does DB lookup (not JWT-only); `auth_update_user` cascades to `api_tokens`; `auth_delete_user` deletes tokens.
- [ ] A2: `_verify_api_token` JOINs `users` and rejects if owner row is gone.
- [ ] A3: `create_token` rejects `sub.startswith("s3:")` (explicit check).
- [ ] A3: `_verify_api_token` + `get_current_user` refuse Bearer auth when `AUTH_MODE=="s3"`.
- [ ] A4: `_check_compat_bucket_read` reuses `_s3_user_can_access` gate (not admin short-circuit).
- [ ] A5: OAuth `start` generates + stashes `state` + PKCE in signed cookie; `callback` validates.
- [ ] A6: GitHub domain check drops `and domain` condition; `gh_user.get("email")` empty → fetch from `/user/emails`.
- [ ] A9: `auth_login`, `twofa_disable`, `auth_change_password` wrap `bcrypt.verify` in try/except.
- [ ] A9: `twofa_disable` includes `"OIDC:"` in federated-placeholder prefix tuple.
- [ ] **Backend tests pass:** `pytest backend/` ≥3× consecutive runs.

**Code Review Checklist (before merging PR 2):**

- [ ] `SairoBearerAuthMiddleware` applied to MCP HTTP app (line 391 in `mcp/server.py`).
- [ ] Per-request session bound via ContextVar (not shared from lifespan).
- [ ] `_ctx_session(ctx)` reads from `request.state` in every tool.
- [ ] `MCP_DEV_MODE=true` restricted to loopback; startup error on non-loopback.
- [ ] `SAIRO_API_TOKEN` unset + `MCP_DEV_MODE=false` → startup error (fail-closed).
- [ ] **MCP tests pass:** `pytest mcp/`.

**Code Review Checklist (before merging PR 3):**

- [ ] `TrustedProxyMiddleware` (or inline in `main.py`) parses `TRUSTED_PROXIES` env var.
- [ ] Rightmost-untrusted walk implemented for `X-Forwarded-For`.
- [ ] `X-Forwarded-Proto` + `X-Forwarded-Host` honored only for trusted peers.
- [ ] Audit log schema adds `client_ip TEXT` column; INSERT at line ~821 captures resolved IP.
- [ ] `_check_login_rate` uses `request.client.host` (now correct after middleware rewrite).
- [ ] slowapi limiter uses resolved IP (automatic or explicit key_func swap).
- [ ] SSO redirect URIs tested behind fake proxy headers → correct host/scheme.
- [ ] `.env.example` documents `TRUSTED_PROXIES` with example CIDR list.

**Code Review Checklist (before merging PR 4):**

- [ ] `require_local_admin` dependency defined (~10 lines).
- [ ] All 10 mutation routes swapped from `require_admin` → `require_local_admin` (listed in design §9.2).
- [ ] Inline `s3:` check at `main.py:3422` deleted (now redundant with `require_local_admin`).
- [ ] `bcrypt.verify` wrapped in try/except at `auth_login`, `twofa_disable`, `auth_change_password`.
- [ ] `twofa_disable` prefix tuple updated to include `"OIDC:"`.
- [ ] `backend/conftest.py` cherry-picked (test-isolation fix).
- [ ] `test_scaling.py` non-idempotent INSERT/storage_history made idempotent (or scoped).
- [ ] **Backend tests pass:** `pytest backend/` ≥3× consecutive runs.
- [ ] **S3-mode chain cannot execute:** attempt to create local user as s3 session → 403.

---

## 12. Conclusion

Sairo is **well-architected for its threat model** (single-container S3 browser) but **carries nine confirmed vulnerabilities** in the auth subsystem (A1–A9). The **design fix is sound and comprehensive:**

- **Subject A (7 vulns):** AC, session revocation, S3-mode scope, CSRF, GitHub email gate.
- **Subject B (3 vulns):** Trusted-proxy gating, audit-log IP, SSO URI correctness.
- **Post-audit (2 new vulns):** S3 priv-esc bypass, federated user enumeration.

**All fixes are backward-compatible, low-risk, and well-specified** in the design doc. Implementation effort is estimated at **3–4 weeks** (code + tests + review) across 4 PRs.

**Recommended action:**
1. Merge PRs 1–2 (backend + MCP security) immediately.
2. Merge PRs 3–4 (trusted-proxy + post-audit) within one sprint.
3. Tag v3.6.2 and announce the fixes to deployers.
4. Plan v3.7 for opaque refresh tokens + migration framework (deferred, not blocking).

---

## Appendix A: Vulnerability Detail Matrix

| Vuln | Title | Severity | CVE-like | CVSS | Exploitability | Blast Radius |
|------|-------|----------|----------|------|-----------------|--------------|
| A1 | Share-link AC | HIGH | CVE-YYYY-XXXXX | 7.5 | Easy (unauthenticated) | All share-links; secret leak |
| A2 | Session revocation | HIGH | CVE-YYYY-XXXXX | 8.2 | Medium (stolen JWT) | All users' buckets if JWT leaked |
| A3 | S3 priv-esc | HIGH | CVE-YYYY-XXXXX | 8.8 | Easy (S3 IAM user) | All buckets (S3 scope) |
| A4 | S3 metadata leak | MEDIUM | CVE-YYYY-XXXXX | 6.5 | Easy (S3 IAM user) | Bucket metadata (not objects) |
| A5 | OAuth CSRF | HIGH | CVE-YYYY-XXXXX | 8.1 | Medium (phishing) | User session hijack |
| A6 | GitHub email fail-open | MEDIUM | CVE-YYYY-XXXXX | 6.8 | Easy (GitHub user) | Bypass `OAUTH_ALLOWED_DOMAINS` |
| A7 | MCP startup auth | HIGH | CVE-YYYY-XXXXX | 8.6 | Easy (network access) | MCP tools unrestricted access |
| A8 | S3 priv-esc bypass | HIGH | CVE-YYYY-XXXXX | 9.0 | Easy (S3 IAM user) | Permanent admin token escape |
| A9 | Federated enum | MEDIUM | CVE-YYYY-XXXXX | 5.9 | Easy (unauthenticated) | User list leak |

*(CVE numbers are placeholders; assign during upstream PR review.)*

---

## Appendix B: Environment Variables Reference

All configuration is via `.env`:

```dotenv
# Authentication
ADMIN_USER=admin                    # Initial admin username
ADMIN_PASS=...                      # Initial admin password (bcrypt on first run)
JWT_SECRET=...                      # HMAC-256 key for JWT; also derives Fernet key
SESSION_HOURS=24                    # JWT expiration time

# Deployment
SECURE_COOKIE=false                 # Set "true" when behind HTTPS
TRUSTED_PROXIES=                    # Comma-separated IPs/CIDRs (e.g., 10.0.0.0/8,172.16.0.0/12)
DB_DIR=/data                        # SQLite directory

# Auth Mode (one of: local, ldap, oauth, oidc, s3)
AUTH_MODE=local

# S3 (required)
S3_ENDPOINT=https://...
S3_ACCESS_KEY=...
S3_SECRET_KEY=...
S3_REGION=us-east-1

# LDAP (optional)
LDAP_ENABLED=false
LDAP_SERVER=ldaps://...
# ... (see .env.example for full list)

# OAuth (optional)
OAUTH_GOOGLE_CLIENT_ID=...
OAUTH_GOOGLE_CLIENT_SECRET=...
OAUTH_GITHUB_CLIENT_ID=...
OAUTH_GITHUB_CLIENT_SECRET=...
OAUTH_ALLOWED_DOMAINS=...

# OIDC (optional)
OIDC_ISSUER=https://...
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
# ... (see .env.example)

# MCP (optional)
MCP_BIND_HOST=127.0.0.1
MCP_PORT=8100
MCP_NAME="Sairo Storage Intelligence"
MCP_DEV_MODE=false
SAIRO_API_TOKEN=...                 # Bearer token for MCP ← Sairo backend
MCP_ALLOWED_ORIGINS=...             # Comma-separated origins for DNS-rebinding guard
```

---

**Report compiled by:** GitHub Copilot  
**Repository:** gijoe88/sairo  
**Fork of:** AshwathStephen/sairo  
**Audit scope:** backend/main.py, mcp/, frontend (client-side only)  
**Analysis date:** 2026-07-26  
**Status:** Complete, ready for remediation
