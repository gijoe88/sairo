# Architecture: Parquet Content Preview (actual rows + SQL)

Status: **Proposed**
Branch context: `fix/mcp-per-request-auth`
Owner: architect

## 1. Problem

The web preview for `.parquet` (and `.orc`/`.avro`) files currently shows only
**metadata** — row count, column schema, row groups, compression. It does **not**
show actual row data. See `frontend/src/components/FilePreview.jsx` →
`SchemaPreview`, backed by `GET /api/buckets/{bucket}/file-metadata`, whose
parquet path (`_read_parquet_metadata` in `backend/main.py`) reads **only the
footer + 4-byte header** via S3 range GETs and never decodes any data pages.

Goal: let users see the **actual content** of a Parquet file in the browser, and
optionually run ad-hoc SQL against it. The user suggested `duckdb-wasm`.

## 2. Constraints discovered in the codebase

These shape every design decision below.

1. **Single container, same origin.** FastAPI serves the React SPA as static
   files (`backend/main.py` → `app.mount("/assets", …)` + `serve_spa`). Every
   `/api/...` call is **same-origin** → no CORS for the Sairo API itself.
2. **Direct browser→S3 is cross-origin.** Presigned GET URLs
   (`get_presigned_url`) point at the S3 endpoint, not Sairo. `<img>`/`<iframe>`
   display is not CORS-restricted, which is why image/PDF preview works today.
   But `fetch()` with `Range` headers **is** CORS-restricted.
3. **CORS auto-config already exists for uploads** (`_ensure_upload_cors`) and
   only runs when Sairo has permission to `PutBucketCors`. Many users connect
   read-only to third-party buckets (Leaseweb, R2, existing AWS buckets) where
   Sairo **cannot** write CORS rules. → We cannot rely on client-side
   direct-to-S3 reads being universally available.
4. **Petabyte scale; files can be huge.** The README/CLI examples show
   ~892 MB Parquet files. Downloading a whole file to the browser to feed
   duckdb-wasm is impractical above tens of MB.
5. **Server load is already bounded.** `_metadata_semaphore = threading.Semaphore(4)`
   caps concurrent metadata/preview ops. Any new server work must reuse this
   gate (or document why a new one is needed).
   - **Recorded divergence (T5a `parquet-stream`):** the Tier 2 proxy uses a
     dedicated `_stream_semaphore(2)`, not the shared metadata gate. Streaming
     is duration-bound I/O (a ≤128MB download can hold a slot for
     seconds–minutes; `iter_chunks(64KB)` keeps only ~64KB × concurrency
     resident regardless of the cap), so routing it through the memory-sized
     metadata gate would let a SQL-tab user 429-starve the Tier 1 core path
     (`parquet-rows`/`file-metadata`/`preview`) for the whole download window.
     A dedicated gate isolates that latency; worst case 2 × 128MB throughput is
     trivial. Tier 1 endpoints continue to use `_metadata_semaphore` only.
6. **`pyarrow` is already a backend dependency** (`import pyarrow.parquet as pq`).
   The frontend deps are intentionally minimal (React, react-virtual,
   lucide-react, qrcode.react) — no data grid, no state lib.
7. **duckdb-wasm is heavy.** Current npm publish is `1.33.1-dev57.0` (dev);
   a stable `@latest` tag exists — **pin to the latest stable at install time**,
   do not ship a `-dev` build. The WASM bundle is ~10 MB (gzip) across MVP + EH
   variants. It must **never** be in the initial bundle.

## 3. Design decision: two layered tiers

We do **not** bet purely on duckdb-wasm direct-to-S3, because of constraint #3
(CORS) and #4 (file size). Instead we layer:

```
                       Parquet file opened in preview modal
                                     │
                      ┌──────────────┴──────────────┐
                      ▼                             ▼
            TIER 1 — Data tab (always)     TIER 2 — SQL tab (optional)
            backend pyarrow row sample     duckdb-wasm in browser
            works for EVERY file           small/medium files only
            (any size, any CORS)           lazy-loaded WASM chunk
```

### Tier 1 — Backend row sampling (universal, low-risk) — **the core fix**

New endpoint `GET /api/buckets/{bucket}/parquet-rows` returns actual rows.
Uses `pyarrow` (already a dep). Works for **every** bucket and **every** size
because the server decides how many bytes to read.

```
Browser: ParquetDataTable
   │  GET /api/buckets/{b}/parquet-rows?key=…&limit=100&offset=0&columns=a,b
   ▼
FastAPI  (acquire one _metadata_semaphore slot — reuse existing gate)
   │
   ├─ head_object                       → file_size
   ├─ read footer (existing path)       → column chunk offsets, row groups
   ├─ size branch:
   │     • file_size ≤ SMALL_FILE (32 MB):
   │           range-GET whole object → BytesIO
   │     • file_size  > SMALL_FILE:
   │           range-GET only the first row group(s) needed to cover limit,
   │           projecting to requested columns (offsets from footer)
   ├─ pq.ParquetFile(buf).read(columns=…) → Table → slice(offset, limit)
   └─ JSON: { columns, rows, total_rows, offset, limit, truncated, next_offset }
```

**Why this shape:**
- Reuses the footer-reading logic already in `_read_parquet_metadata`.
- Reuses `_metadata_semaphore` so worst case = 4 × ~32 MB ≈ 128 MB resident.
- Column projection + row-group pruning keep large-file reads bounded (a 1 GB
  file previews its first 100 rows by reading ~1–10 MB, not 1 GB).
- v1 may ship the small-file path only and return a friendly “file too large to
  preview rows — showing schema only” message above the cap; the large-file
  targeted-range path is a fast-follow, fully optional. **Recommended: ship
  small-file in v1, large-file targeted ranges in v1.1.**

### Tier 2 — duckdb-wasm SQL console (enhanced UX, gated)

A **SQL** tab appears for qualifying files. Power users get full ad-hoc SQL
(`WHERE`, `GROUP BY`, aggregations) running entirely client-side.

```
Browser: ParquetSqlConsole  (React.lazy → separate Vite chunk)
   │  1. dynamic import('./lib/duckdb') → instantiate Worker + WASM once (cached)
   │  2. GET /api/buckets/{b}/parquet-stream?key=…   ← SAME-ORIGIN proxy
   ▼
Uint8Array  →  db.registerFileBuffer('t.parquet', buf)
   │  CREATE OR REPLACE VIEW t AS SELECT * FROM 't.parquet'
   │  user SQL  →  Arrow result  →  results table
```

**Critical decision: route the WASM path through Sairo, not direct to S3.**
This sidesteps CORS entirely (constraint #3). The proxy endpoint streams the
object bytes same-origin and is hard size-capped (e.g. 128 MB) + guarded by the
metadata semaphore. Above the cap the SQL tab is hidden; Tier 1 still works.

A future **Tier 3** optimization (out of scope for v1): when Sairo **can** write
CORS (`_ensure_read_cors`, modelled on `_ensure_upload_cors` but allowing
`GET` + `Range` + `ExposeHeaders: Content-Range, Accept-Ranges, ETag`), point
duckdb-wasm `httpfs` at the presigned URL so it range-reads large files without
proxying. This is additive and can land later without changing Tier 1/2 UX.

### Why not pure duckdb-wasm direct-to-S3 as v1?

- Fails on every CORS-locked bucket (common for read-only / third-party).
- Loads ~10 MB WASM even for a quick “peek at the rows”.
- No good story for large files without CORS.
Tier 1 gives a guaranteed win with zero new deps; Tier 2 layers duckdb-wasm on
top exactly where it shines (interactive SQL on manageable files).

## 4. Component & file organization

### Backend
- **New module `backend/parquet_reader.py`** — pure, testable functions:
  - `read_parquet_rows(client, bucket, key, *, limit, offset, columns) -> dict`
  - `assemble_row_group_buffer(client, bucket, key, footer_meta, row_groups, columns) -> bytes`
    (the large-file targeted-range assembler)
  - `stream_object(client, bucket, key) -> Iterator[bytes]` (Tier 2 proxy source)
  - Factor the existing `_read_parquet_metadata` footer logic into a shared
    `read_footer(client, bucket, key) -> (ParquetMetaData, file_size)` helper
    reused by both metadata and row endpoints. Keep endpoints in `main.py` to
    match the existing pattern; only the logic moves.
- **`backend/main.py`** — thin endpoints (auth + semaphore + delegate):
  - `GET /api/buckets/{bucket}/parquet-rows` (Tier 1)
  - `GET /api/buckets/{bucket}/parquet-stream` (Tier 2, size-capped,
    `StreamingResponse`). Reuse `get_current_user` + `_metadata_semaphore`.
- Constants: `PARQUET_PREVIEW_SMALL_FILE = 32 * 1024 * 1024`,
  `PARQUET_STREAM_CAP = 128 * 1024 * 1024`, `PARQUET_ROW_LIMIT_MAX = 1000`.

### Frontend
- **`frontend/src/api.js`** — add:
  - `fetchParquetRows(bucket, key, { limit, offset, columns })`
  - `streamParquetBytes(bucket, key)` (returns `Response` for `arrayBuffer()`)
- **`frontend/src/lib/duckdb.js`** *(new, lazy)* — singleton manager:
  - instantiates `AsyncDuckDB` from a Vite `?url`-imported Worker + WASM bundle
    (see the duckdb-wasm Vite recipe), caches the instance for the session,
  - exposes `runSql(parquetBuffer, sql)` and `registerView(parquetBuffer)`.
- **`frontend/src/components/ParquetDataTable.jsx`** *(new)* — paginated,
  column-aware table (header types from schema), uses Tier 1 endpoint,
  virtualized with `@tanstack/react-virtual` (already a dep) for wide/long
  results. Reuse `.preview-csv-table` styling tokens.
- **`frontend/src/components/ParquetSqlConsole.jsx`** *(new, lazy)* — textarea
  editor + Run button + results table + per-query error display. Read-only
  mindset (no DML; wrap in a transaction/view).
- **`frontend/src/components/FilePreview.jsx`** — for `type === "schema"`:
  - keep `SchemaPreview` as the **Schema** tab,
  - add **Data** tab (`ParquetDataTable`),
  - add **SQL** tab (`React.lazy(() => import('./ParquetSqlConsole'))`) shown
    only when `file_size <= PARQUET_STREAM_CAP`.
  - Add a lightweight tab bar in `.preview-header`.

### Tests
- `frontend/src/test/components.test.jsx` — add Data-tab render + pagination
  tests; extend the existing parquet-category coverage.
- `backend/test_main.py` — add `parquet-rows` tests: small file happy path,
  column projection, limit/offset, large-file message, 401/404.
- `e2e/tests/04-file-operations.spec.ts` — extend `4.10 previews Parquet file`
  to assert the Data tab shows rows; add a SQL-tab smoke test.

### Docs
- `website/src/content/docs/features/file-preview.mdx` — update the “Analytics”
  row (“Schema + **row preview** + optional SQL”) and the Parquet section.
- `CHANGELOG.md` — entry under the next release.

## 5. Key abstractions / data models

```ts
// Tier 1 response — GET /parquet-rows
interface ParquetRows {
  columns: { name: string; type: string }[];
  rows: any[][];            // column-major not needed; row arrays are fine for ≤1000 rows
  total_rows: number;
  offset: number;
  limit: number;
  truncated: boolean;       // true when offset+limit < total_rows
  next_offset: number | null;
  read_mode: "full" | "first_row_groups";  // for UI transparency
}

// Tier 2 — duckdb.js singleton
interface DuckDBHandle {
  register(buffer: Uint8Array, name: string): Promise<void>;
  query(sql: string): Promise<{ columns: string[]; rows: any[][] }>;
  reset(): Promise<void>;   // drop registered views when modal closes
}
```

Notes:
- `parquet-rows` reads `limit` then slices in-process for `offset` only for the
  small-file path; for the large-file path, `offset` beyond the first row groups
  is not supported in v1 (return `truncated: true`, UI disables “next page”).
- Backend row serialization: convert pyarrow `Table` → Python via `.to_pylist()`
  / `.to_pandas().values.tolist()`; cap cell size (e.g. truncate strings/blobs
  > 4 KB) and serialize `datetime`/`decimal`/`bytes` explicitly to JSON.

## 6. Technology choices & trade-offs

| Choice | Decision | Rationale |
|---|---|---|
| Row decoding | **pyarrow (backend)** | Already a dep; random-access + column projection; no client weight |
| SQL engine | **@duckdb/duckdb-wasm**, latest **stable** tag | Best-in-class in-browser SQL on Parquet; pin stable, never `-dev` |
| WASM transport | **Backend same-origin proxy** (v1) | Eliminates the CORS failure mode; size-capped |
| Direct-to-S3 (httpfs) | **Deferred (Tier 3)** | Needs bucket CORS write perms; additive, not blocking |
| Table render | **@tanstack/react-virtual** (existing) | No new dep; handles wide/long results |
| Code splitting | **`React.lazy` + Vite `?url`** | Keeps WASM (~10 MB) out of initial bundle |
| Auth/security | **Reuse `get_current_user` + semaphore** | Consistent with existing endpoints; per-request auth already on this branch |

## 7. Security & cost considerations

- **Auth:** both new endpoints use `Depends(get_current_user)` and existing
  per-bucket permission checks (mirror `preview`/`file-metadata`).
- **Server memory:** bounded by `_metadata_semaphore(4)` × caps. Large-file
  targeted reads must cap total bytes fetched per request (e.g. ≤ 32 MB) even
  when projecting columns.
- **Abuse:** hard-clamp `limit ≤ 1000`, `offset ≥ 0`, allowlist `columns`
  against the schema (reject unknown names), cap proxy stream at
  `PARQUET_STREAM_CAP`. Reuse any existing rate limiting (slowapi).
- **SQL tab:** register a read-only **view**, not the raw file path, and prefix
  the user SQL so DML/DROP is a no-op against a view; this is a soft guard, not
  a security boundary (data is local to the browser anyway).
- **PII:** rows may contain sensitive data; no telemetry on cell contents (the
  project’s telemetry is already aggregate-only).

## 8. Risks & open questions (flagged)

1. **[HIGH / IRREVERSIBLE-ISH] WASM bundle weight.** ~10 MB first time a user
   opens the SQL tab. Mitigation: lazy chunk + `stale-while-revalidate` cache
   headers on the WASM asset; only load on explicit tab open. **Decision point
   for the user:** is the SQL tab worth ~10 MB? If not, ship Tier 1 only.
2. **[MEDIUM] Large-file targeted-range assembler correctness.** Building a
   valid partial Parquet buffer from selected column chunks is fiddly. v1 ships
   the small-file path; large-file is gated behind v1.1 with its own tests.
3. **[LOW] Complex/nested Parquet types** (lists, structs, maps). Serialize to
   JSON strings; tests must cover at least one nested-type fixture.
4. **[LOW] ORC/Avro content** — out of scope for this design; Tier 1 footer
   readers already exist, content rows could reuse the same UI later.

## 9. Implementation sequence (dependencies)

1. **Backend refactor (no behavior change):** extract `read_footer()` and
   `_read_parquet_metadata` into `backend/parquet_reader.py`; move only logic.
   Tests still pass. *(unblocks 2 & 3)*
2. **Tier 1 endpoint + small-file row read:** `parquet-rows` + `read_parquet_rows`
   (small-file path), serialization, caps, auth, semaphore. Backend tests.
   *(this alone satisfies the core request)*
3. **Frontend Data tab:** `ParquetDataTable` + tabs in `FilePreview.jsx` +
   `fetchParquetRows`. Frontend tests + e2e.
4. **Docs + CHANGELOG** for Tier 1. → **Shippable v1.**
5. **Tier 2: duckdb-wasm lazy singleton + `parquet-stream` proxy endpoint.**
6. **Tier 2: `ParquetSqlConsole`** + SQL tab gating on size cap. Tests/e2e.
7. *(Optional v1.1)* Large-file targeted-range reader for Tier 1.
8. *(Optional Tier 3)* `_ensure_read_cors` + duckdb-wasm `httpfs` direct path.

Each step is independently reviewable; step 4 is a clean release boundary.

## 10. Migration / compatibility

- Pure additive: new endpoints, new tabs, new lazy chunk. No existing endpoint
  changes; `SchemaPreview` is preserved verbatim as the Schema tab.
- `pyarrow` and `@tanstack/react-virtual` are already dependencies. Only
  **new** dependency is `@duckdb/duckdb-wasm` (Tier 2).
- Docker build: the duckdb-wasm `.wasm`/worker assets are emitted by Vite into
  `frontend/dist/assets` and served by the existing `StaticFiles` mount — no
  Dockerfile change beyond the standard `npm ci && npm run build`.
