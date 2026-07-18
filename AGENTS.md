# AGENTS.md — Sairo (fork: gijoe88/sairo)

Fork-internal guidance for opencode agents. **This file is not upstreamed.** It lives only on fork `main`.

## Project

Sairo is a self-hosted, S3-compatible object storage browser. Single Python FastAPI backend (`backend/main.py`, ~6.9k lines) + React/Vite SPA (`frontend/`) + a Model Context Protocol server (`mcp/`) for AI clients. Deployed as one container.

Upstream: `AshwathStephen/sairo`. This fork: `gijoe88/sairo` (set as `origin`).

## Branch policy (read before any commit)

```
upstream-main   local mirror of upstream/main — base for ALL PR branches
main            origin/main = upstream/main + fork-only docs (AGENTS.md, docs/architecture/*)
fix/*, feat/*   PR branches — cut from upstream-main, CODE ONLY
```

**Rules:**
1. Cut every PR branch from `upstream-main` (clean), never from `main`. `main` carries fork docs that must not appear in PR diffs.
2. Documentation (this file, `docs/architecture/*`, operator guides) lives **only on `main`**. Never commit docs to a `fix/*` or `feat/*` branch.
3. Before opening a PR, verify `git diff upstream-main...<branch>` contains **no** `docs/`, `AGENTS.md`, or `*.md` changes.
4. Keep `main` rebased onto `upstream/main` on sync; re-resolve doc conflicts by hand.

Refresh the mirror:
```bash
git fetch upstream && git branch -f upstream-main upstream/main
```

## Where things live

- `backend/main.py` — the entire backend. Middleware stack, all routes, DB, auth, S3 client proxy.
- `backend/pricing.py`, `backend/test_main.py`, `backend/test_scaling.py`.
- `mcp/` — MCP server (`server.py`, `auth.py`, `security.py`, `sairo_client.py`, `tools/`, `resources/`).
- `frontend/src/` — React SPA; client-side only (don't add server authz there).
- `cli/` — Go CLI (secondary for backend audits).
- `docs/architecture/` — fork-internal design docs. Start here for context: `security-and-proxy-design.md`.

## Conventions (match these; do not reinvent)

- **SQL:** always `?`-parameterized (including FTS5 `MATCH ?` — see `main.py:4787` for the escape pattern).
- **Secrets/tokens:** `secrets.token_urlsafe(...)` / `secrets.token_hex(...)`; never `random.*`.
- **Passwords:** passlib `bcrypt` with `.verify()` (constant-time).
- **At-rest crypto:** Fernet; key derived from `JWT_SECRET` via SHA-256 (`main.py:361`). Rotating `JWT_SECRET` invalidates both sessions **and** decryptable S3 creds — treat as a high-cost operation.
- **JWT:** `HS256` with `algorithms=["HS256"]` pinned on every decode. OIDC ID-token validation restricts to asymmetric algs only.
- **Middleware order:** registration is `security_headers` → `bucket_permission` → `endpoint_routing`; effective request order is the reverse. `bucket_permission_middleware` only enforces `/api/buckets/...`; everything else is the route's responsibility.
- **Config:** flat `KEY=value` env vars, documented in `.env.example`. Optional vars commented out. Add new env vars there.

## Test & run

```bash
# Backend tests
pytest backend/

# MCP tests
pytest mcp/        # see mcp/pytest.ini

# Frontend
cd frontend && npm install && npm run build

# Run backend locally (single container is the prod shape)
uvicorn main:app --host 0.0.0.0 --port 8000    # from backend/
```

## Active workstreams

See `docs/architecture/security-and-proxy-design.md` for the full design. Summary:
- **Subject A** — fix the 9 v3.6.0 audit findings (6 HIGH, 3 MEDIUM). PR branches `fix/security-audit-v3.6.0` and `fix/mcp-per-request-auth`.
- **Subject B** — `X-Forwarded-*` support gated by `TRUSTED_PROXIES` (audit-log client IP, rate-limiter correctness, SSO redirect URIs behind a proxy). PR branch `feat/trusted-proxies-x-forwarded`.

## Things to never do

- Don't commit docs (`*.md`) on a `fix/*` or `feat/*` branch.
- Don't cut PR branches from `main` — always from `upstream-main`.
- Don't trust `X-Forwarded-*` without checking the peer against `TRUSTED_PROXIES`.
- Don't add `subprocess`/`eval`/`pickle`/`yaml.load` to the backend.
- Don't introduce a new runtime dependency without justification in the design doc.
