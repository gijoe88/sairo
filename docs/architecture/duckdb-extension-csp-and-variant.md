# Architecture: duckdb-wasm SQL tab — extension-CDN CSP + MVP variant

> Companion to `csp-wasm-instantiation.md` (which covered `script-src 'wasm-unsafe-eval'`
> for the **compile** step). This doc covers the **fetch** step: allowing the duckdb
> extension CDN in `connect-src`, and switching the duckdb-wasm variant from `eh` to `mvp`.
> Code lives on `fix/duckdb-extension-csp-and-variant` (cut from `upstream-main`, CODE ONLY);
> this doc is fork-only and stays on `main`.

## Context

The Tier-2 SQL tab (`ParquetSqlConsole`) runs ad-hoc SQL over a fetched parquet file fully
client-side via `@duckdb/duckdb-wasm`. After `wasm-unsafe-eval` unblocked wasm **compilation**,
a second failure surfaced on the sairo-dev tier:

```
Couldn't load the file for SQL: Failed to register parquet for "t": indirect call signature mismatch
  at _duckdb_web_query_run_buffer  …/duckdb-browser-eh.worker-*.js
```

### Root cause (confirmed by HAR)

duckdb-wasm **1.32.0 does not statically link the parquet reader**. On first parquet scan it
dynamically loads the parquet extension from the duckdb extension CDN:

```
GET https://extensions.duckdb.org/v1.4.3/wasm_eh/parquet.duckdb_extension.wasm
  Origin: https://s3-console-dev.xreveillon.eu
  → status 0, 0 headers, bodySize -1, time 0   ← CSP pre-block (Firefox 153)
```

Sairo's CSP `connect-src` allows only `'self'` and the S3 origins — `extensions.duckdb.org`
is absent, so the browser blocks the fetch. The extension never registers in the wasm function
table, and the subsequent `call_indirect` into the parquet reader mismatches → the runtime error
above (a symptom, not the cause).

The CDN itself is healthy (server-side curl returns `200`, `content-type: application/wasm`,
`access-control-allow-origin: *`, Cloudflare-fronted). The block is purely the application CSP.

## Decisions

### D1 — Add `extensions.duckdb.org` to `connect-src`  (load-bearing fix)

**What:** Allow the duckdb extension CDN in the page CSP `connect-src`.

**Why:** Without this the SQL tab cannot work under *any* duckdb-wasm variant — the parquet
extension fetch is blocked regardless. This is the fix that resolves the reported bug. Once the
fetch is allowed, the extension compiles fine because `script-src 'wasm-unsafe-eval'` is already
present (D0 / `csp-wasm-instantiation.md`).

**Where:** `backend/main.py`, `security_headers_middleware`. Add a module-level constant and
append it to the `connect-src` string. Keeping `_csp_connect_origins()` (which is semantically
"configured S3 endpoints") untouched, and listing the CDN as a separate named constant,
mirrors how `style-src` already hardcodes `https://fonts.googleapis.com`.

```python
# The default duckdb-wasm extension repository. duckdb-wasm 1.32.0 dynamically
# loads the parquet reader (and other extensions) from this CDN at first use
# rather than statically linking them; CSP connect-src must allow it or the
# fetch is silently blocked and the SQL tab fails with a wasm signature
# mismatch. If the extension repository is ever reconfigured (self-hosted,
# mirrored, or a future duckdb-wasm default change), update this to match.
_DUCKDB_EXTENSION_REPO = "https://extensions.duckdb.org"
```

```python
connect_src = (
    "connect-src 'self' "
    + _DUCKDB_EXTENSION_REPO + " "
    + _csp_connect_origins()
).rstrip()
```

### D2 — Switch duckdb-wasm variant `eh` → `mvp`  (defensive hardening)

**What:** In `frontend/src/lib/duckdb.js`, import the `mvp` worker + wasm instead of `eh`.

**Why:** The `eh` variant is compiled with Emscripten `-fwasm-exceptions` (the WebAssembly
Exception-Handling proposal). That proposal's encoding is in flux across browser versions: the
legacy `try` instruction is being deprecated in favor of `try_table`, and the SQL tab emitted
the deprecation warning during the incident. The `eh` build was never the *cause* of this bug
(the CSP block was), but it is a source of unrelated fragility — `mvp` removes that entire class
of risk. The original rationale ("EH for best Parquet support", in the existing code comment) is
stale: Parquet support is identical across variants.

**Trade-off:** `mvp` (~39 MB) is ~5 MB larger than `eh` (~34 MB). For a single-user object
browser this is negligible, and it buys browser-independence. Worth it.

**Why the switch alone does NOT fix the bug:** the `mvp` variant fetches its extension from
`extensions.duckdb.org/v1.4.3/wasm_mvp/parquet.duckdb_extension.wasm` — same CDN host, so the
same CSP `connect-src` would block it. **D1 is mandatory under either variant.** Do not let a
merge message claim "switched to MVP, fixed the tab" — D1 is the fix; D2 is cleanup.

**Worker construction is unchanged:** `duckdb-browser-mvp.worker.js` is, like the `eh` worker, a
predigested **classic** IIFE bundle in 1.32.0 (`"use strict";var duckdb=(()=>{…`, zero
top-level `import`/`export`). So `new Worker(workerUrl)` stays WITHOUT `{type:"module"}` — the
"MUST-FIX 1" reasoning in the existing comment remains valid, just retargeted to the mvp file.

## Change set (code — on `fix/duckdb-extension-csp-and-variant`, from `upstream-main`)

| File | Change |
|---|---|
| `backend/main.py` (~L93) | Add `_DUCKDB_EXTENSION_REPO` constant. |
| `backend/main.py` (~L116) | Append the constant to the `connect-src` string. |
| `frontend/src/lib/duckdb.js` (L9-11) | Update the code-splitting comment: rationale for `mvp` (was "EH for best Parquet support"). |
| `frontend/src/lib/duckdb.js` (L23-39) | Retarget the "MUST-FIX 1" classic-worker note from `eh` to `mvp` (same conclusion). |
| `frontend/src/lib/duckdb.js` (L40-41) | `duckdb-browser-eh.worker.js` → `duckdb-browser-mvp.worker.js`; `duckdb-eh.wasm` → `duckdb-mvp.wasm`. |
| `backend/test_main.py` (`test_csp_header_present`, ~L718) | Add `assert "extensions.duckdb.org" in csp` (+ comment why). |
| `frontend/src/test/duckdb.test.js` (L43-48) | Update the two `vi.mock("@duckdb/duckdb-wasm/dist/duckdb-browser-eh.…")` paths to `mvp`. |
| `e2e/tests/26-security-hardening.spec.ts` (test 26.1, ~L18) | Add `expect(csp).toContain("extensions.duckdb.org");`. |

No `package.json` / lockfile change — both variants ship in the already-pinned
`@duckdb/duckdb-wasm@1.32.0`. No seaweedfs-side change — the sairo-dev tier picks up the
rebuilt image via `--pull always` on next deploy.

## Implementation sequence

1. Cut `fix/duckdb-extension-csp-and-variant` from `upstream-main` (clean; CODE ONLY).
2. D1 — backend CSP constant + `connect-src` wiring.
3. D1 test — `backend/test_main.py` CSP assertion.
4. D2 — frontend `lib/duckdb.js` import swap + comment updates.
5. D2 test — `frontend/src/test/duckdb.test.js` mock paths.
6. E2E — `26-security-hardening.spec.ts` CSP assertion.
7. Verify locally: `pytest backend/`; `cd frontend && npm run build && npm test`.
8. Gate: `git diff upstream-main...fix/duckdb-extension-csp-and-variant` must contain **no**
   `docs/`, `AGENTS.md`, or `*.md` (branch policy).
9. Merge `fix/duckdb-extension-csp-and-variant` → `main`.
10. Commit this design doc on `main` (fork-only docs; separate from the code branch).
11. Rebuild the sairo dev image; redeploy the sairo-dev tier.
12. Manual verify on `s3-console-dev.xreveillon.eu`: SQL tab runs a query, DevTools shows the
    `parquet.duckdb_extension.wasm` response is `200` (not status 0), no `connect-src` CSP
    violation, no `indirect call signature mismatch`, and no `try` deprecation warning.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| CSP now allows a third-party CDN | Low | Low | `extensions.duckdb.org` is duckdb-controlled, TLS, Cloudflare-fronted, CORS `*`. Alternative if tightening is later desired: self-host the extension binary and drop the CDN from CSP (out of scope here). |
| `mvp` wasm is ~5 MB larger | Certain | Negligible | Acceptable for single-user console; it is lazily loaded only when the SQL tab is opened. |
| duckdb-wasm changes its default extension repo URL upstream | Low | Medium | Constant is centralized (`_DUCKDB_EXTENSION_REPO`); comment flags the coupling. Pinned to `1.32.0`. |
| Future duckdb-wasm drops `mvp` or reshuffles dist filenames | Low | Medium | Pinned to `1.32.0`; revisit on next bump (only `-dev` builds exist above 1.32.0 today). |
| Reviewer misattributes the fix to the variant switch | Medium | Low (comms) | Doc + merge message explicitly state D1 is the fix, D2 is hardening. |

## Verification

- **Unit:** `pytest backend/` (CSP test green); `cd frontend && npm test` (duckdb.test.js mocks
  resolve against the mvp paths); `cd frontend && npm run build` (mvp imports resolve at build
  time — confirms both files exist in the pinned package).
- **E2E:** `26-security-hardening.spec.ts` 26.1 asserts the extension CDN in CSP.
- **Manual (dev tier):** HAR / DevTools network shows
  `extensions.duckdb.org/.../parquet.duckdb_extension.wasm` → `200`; console is free of CSP
  violations, `indirect call signature mismatch`, and the `try`-deprecation warning; a query
  returns rows.
