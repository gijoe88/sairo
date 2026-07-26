# Architecture: CSP `wasm-unsafe-eval` for the duckdb-wasm SQL tab

Status: **Accepted** · Author: architect · Targets: `upstream/main` (code) + this doc on `main`
Related: `docs/architecture/parquet-content-preview.md` (the feature this unblocks)

> Fork-internal design doc. Must **not** be included in any PR branch (see
> `AGENTS.md`). The code change itself is upstream code and is PR'd from
> `upstream-main`.

---

## 1. Problem

Opening the **SQL** tab on a Parquet file hangs forever on a spinning loader.
DevTools shows:

- Network: `…/assets/duckdb-eh-*.wasm` → **200 OK** (bytes download fine).
- Console: `CompileError: call to WebAssembly.instantiateStreaming() blocked
  by CSP  duckdb-browser-eh.worker-*.js:1:…`

The WASM *file* is fetched under `connect-src 'self'` (same-origin, allowed);
it is the **compilation** that CSP gates separately under `script-src`.

## 2. Root cause (verified)

`backend/main.py` `security_headers_middleware` — the **sole** CSP source for
the app (no nginx/meta tag exists) — emits:

```python
"script-src 'self'; "
```

Since Chrome 93 / Firefox 101 / Safari 16.4, `script-src 'self'` is **no
longer sufficient** to compile WebAssembly. `WebAssembly.instantiateStreaming()`
/ `WebAssembly.compile()` are treated like `eval` and require the explicit
**`'wasm-unsafe-eval'`** keyword. Without it the compile throws inside the
duckdb worker, `db.instantiate(wasmUrl)` (`frontend/src/lib/duckdb.js:73`)
never resolves, and `ParquetSqlConsole.jsx` never leaves its loading phase.

**Timeline (why this regressed):** the CSP was authored with `script-src 'self'`
in `243b35f` and last touched in `3616587` (v3.4.0, `connect-src` only). The
duckdb-wasm SQL tab landed later in `988f03b` ("feat: Parquet content preview
— row Data tab + duckdb-wasm SQL console"). The CSP was never reconciled to
permit WASM. **The CSP block is byte-identical between `upstream-main`
(`64bdb2f`) and `main`** — `git diff -G "script-src|Content-Security" upstream-main..main
-- backend/main.py` shows no CSP hunk — so this is cleanly an upstream bug.

## 3. Decision

Add `'wasm-unsafe-eval'` to `script-src`:

```python
"script-src 'self' 'wasm-unsafe-eval'; "
```

`'wasm-unsafe-eval'` is the W3C (CSP3) keyword purpose-built for this case. It
permits **only** WebAssembly compile/execute — it does **not** re-enable JS
`eval()`, `Function()`, or `setTimeout("string")` (those need `'unsafe-eval'`,
which we deliberately do **not** add).

### Why this over alternatives

| Option | Verdict |
|---|---|
| `'unsafe-eval'` | **Rejected** — overly broad; re-enables JS string eval, which the project explicitly avoids. |
| WASM hash / per-file nonce | **Rejected** — CSP3 has no hash mechanism for `WebAssembly.instantiateStreaming()` of a dynamically-located module. duckdb-wasm resolves the WASM URL at runtime; there is no static digest to pin. `'wasm-unsafe-eval'` is the only standard opt-in. |
| Serve WASM from a 2nd origin w/ its own relaxed CSP | **Rejected** — over-engineering; adds CORS/origin complexity for zero security gain (the bytes are already trusted). |
| Env-gate (`ENABLE_WASM_CSP=1`) | **Rejected** — over-engineering + footgun. The SQL tab is a core shipped feature, not optional. An env gate creates a hidden failure mode where a deploy without the flag silently reintroduces this exact bug. The existing CSP is **entirely** hardcoded (no env var drives any directive); gating only this one would be inconsistent. |
| Explicit `worker-src 'self'` | **Not now** (optional future hardening). The worker JS is same-origin (`/assets/duckdb-browser-eh.worker-*.js`) and already loads under the `script-src` fallback; the bug is compile, not worker-load. Adding `worker-src` expands the diff without fixing anything. Note for later if a cross-origin worker is ever introduced. |

### Security posture

Adding `wasm-unsafe-eval` is a **narrow, documented** relaxation:

- The app already ships and trusts a WASM binary (duckdb). It is not widening
  the set of *vendors* it trusts, only permitting the compile step for code it
  already serves.
- duckdb-wasm is client-side sandboxed: no network, no host filesystem (only
  explicitly-registered buffers), and the SQL surface is read-only against a
  parquet-backed view (`parquet-content-preview.md` §7).
- No conflict with the active v3.6.0 audit workstream
  (`security-and-proxy-design.md`) — none of the 9 findings touch `script-src`.

## 4. Exact change

### 4.1 Backend (the fix) — `backend/main.py`

In `security_headers_middleware`, one line:

```diff
     response.headers["Content-Security-Policy"] = (
         "default-src 'self'; "
-        "script-src 'self'; "
+        "script-src 'self' 'wasm-unsafe-eval'; "
         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
         "font-src 'self' https://fonts.gstatic.com; "
         "img-src 'self' blob: data:; "
         f"{connect_src}; "
         "frame-src blob:;"
     )
```

### 4.2 Backend unit test — `backend/test_main.py`

`TestSecurityHeaders.test_csp_header_present` currently asserts the substring
`"script-src 'self'"` (line 714) — it will still pass, but it will **not
catch a regression** that drops the keyword. Add a dedicated assertion so the
unit suite fails fast (no browser needed) if someone removes it:

```python
        assert "script-src 'self'" in csp
        # Required for the duckdb-wasm SQL tab: without 'wasm-unsafe-eval' the
        # browser blocks WebAssembly.instantiateStreaming() and the SQL tab
        # hangs forever on its loading spinner.
        assert "'wasm-unsafe-eval'" in csp
```

### 4.3 E2E test — `e2e/tests/26-security-hardening.spec.ts`

Test `26.1` (line 17) uses `toContain("script-src 'self'")` — still passes.
Add a matching assertion so the security-hardening suite also pins the
keyword:

```typescript
      expect(csp).toContain("script-src 'self'");
      expect(csp).toContain("'wasm-unsafe-eval'");
```

### 4.4 No frontend change

`frontend/src/lib/duckdb.js`, `ParquetSqlConsole.jsx`, the Vite `?url` asset
imports — all unchanged. The fix is server-side only.

### 4.5 Existing e2e `4.12` is the real regression net

`e2e/tests/04-file-operations.spec.ts:239` ("4.12 runs ad-hoc SQL against
Parquet via duckdb-wasm") is the **only** e2e that exercises real WASM. Its
`await expect(runBtn).toBeEnabled({ timeout: 60_000 })` (line 258) **hard-fails**
on this bug: the Run button stays disabled until `phase === "ready"`, which
never happens when the compile is blocked. Confirm it goes green after the
fix. (Its early-return skip only fires when the SQL *tab* is absent or
`sample.parquet` is missing — not when WASM compile is blocked.)

## 5. Implementation sequence

Ordered, with dependencies. Small enough to be one PR.

1. **Cut branch** `fix/csp-wasm-unsafe-eval` from `upstream-main` (clean, per
   `AGENTS.md` rule #1). Do **not** cut from `main` — `main` carries fork
   docs and fork-only feature code that must not appear in the PR diff.
2. **Apply 4.1** — the one-line CSP change.
3. **Apply 4.2** — backend test assertion.
4. **Apply 4.3** — e2e assertion (same branch; it's test code, not docs).
5. **Verify**:
   - `pytest backend/` — `TestSecurityHeaders` green, incl. the new assertion.
   - `cd frontend && npm run build` — confirms no asset breakage (sanity; no
     frontend file changed).
   - `cd e2e && npx playwright test tests/26-security-hardening.spec.ts` —
     `26.1` green with the new assertion.
   - If `sample.parquet` is seeded in the e2e env: `npx playwright test
     tests/04-file-operations.spec.ts -g "4.12"` — real WASM round-trip green.
6. **Diff hygiene check** before opening the PR:
   `git diff upstream-main...fix/csp-wasm-unsafe-eval` must contain **only**
   `backend/main.py`, `backend/test_main.py`, `e2e/tests/26-security-hardening.spec.ts`.
   **No** `docs/`, `AGENTS.md`, or `*.md` changes.
7. **Open PR** against upstream with a standalone justification (the CSP must
   permit WASM compile for any current/future in-browser WASM feature; it is
   not framed as fork-specific).

## 6. Rollout / migration

- **Single-container redeploy.** No DB migration, no config/env change, no
  schema change. The CSP only becomes *more* permissive (one keyword added);
  nothing that currently works breaks.
- **To fix the deployed fork** (`s3-console-dev.xreveillon.eu`): once the PR is
  green, merge the branch into `main` (which carries the parquet feature) and
  redeploy the fork container. The fix reaches the deployed SQL tab only after
  `main` is redeployed.
- **Rollback:** revert the single line in `backend/main.py` and redeploy.

## 7. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `'wasm-unsafe-eval'` weakens CSP in a way an audit flags | Low | Low | Documented, scoped (WASM-only, not JS eval); duckdb is already a trusted binary. Audit workstream reviewed — no conflict. |
| Upstream rejects / delays the PR | Medium | Medium (fork deploy stays broken) | The change is a clean one-liner on upstream code. If upstream is slow, the branch can still be merged into `main` to fix the fork deploy without waiting; the upstream PR remains the record. |
| A future duckdb-wasm upgrade needs `worker-src`/module-worker changes | Low | Low | `frontend/src/lib/duckdb.js` already documents the worker-format MUST-FIX notes; revisit CSP then if a cross-origin or module worker appears. |

## 8. Files touched

| File | Change | Branch |
|---|---|---|
| `backend/main.py` | 1 line — add `'wasm-unsafe-eval'` to `script-src` | `fix/csp-wasm-unsafe-eval` (code) |
| `backend/test_main.py` | +1 assertion in `test_csp_header_present` | same branch |
| `e2e/tests/26-security-hardening.spec.ts` | +1 `toContain` in test `26.1` | same branch |
| `docs/architecture/parquet-content-preview.md` | +cross-ref to this doc | `main` (docs only) |
| `docs/architecture/csp-wasm-instantiation.md` | this doc | `main` (docs only) |
