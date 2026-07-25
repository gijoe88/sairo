// Lazy singleton around @duckdb/duckdb-wasm powering the Tier 2 SQL tab.
//
// IMPORTANT — code splitting:
//   This module pulls in the ~10MB DuckDB WASM bundle. It MUST only be loaded
//   through a dynamic `import('../lib/duckdb')` (e.g. from a React.lazy SQL
//   console). Never add a static top-level import of this module from app code
//   that lives in the initial bundle, or the WASM will leak into index-*.js.
//   The Worker + WASM binaries below are imported via Vite's `?url` suffix so
//   Vite emits them as separate hashed asset files (official duckdb-wasm Vite
//   recipe). The EH (exception-handling) variant is used for best Parquet
//   support.
//
// Lifecycle:
//   getDuckDB()  → instantiates AsyncDuckDB + a long-lived connection once,
//                  cached for the browser session.
//   register()   → registerFileBuffer + CREATE OR REPLACE VIEW so user SQL can
//                  reference the parquet by a friendly name.
//   query()      → runs SQL, returns a row-major { columns, rows } result set.
//   reset()      → drops registered views/files when the preview modal closes.
//                  The WASM instance stays alive for reuse on the next file.

import { AsyncDuckDB, ConsoleLogger } from "@duckdb/duckdb-wasm";
// Worker file format note (MUST-FIX 1, verified empirically against
// @duckdb/duckdb-wasm@1.32.0):
//   The imported file `dist/duckdb-browser-eh.worker.js` is a PREDIGESTED
//   CLASSIC worker bundle, NOT an ES module. Evidence:
//     - `head -c 800 .../duckdb-browser-eh.worker.js` begins with
//       `"use strict";var duckdb=(()=>{...` (IIFE, no top-level import/export).
//     - `grep -c '^import\|^export'` over the file returns 0; the only
//       occurrences of the words "import"/"export" are inside string literals
//       (`"unhandled export type for..."`, `"bad export type for..."`).
//     - There is NO `.mjs` worker variant shipped in v1.32.0 (only `.worker.js`
//       for browser, `.worker.cjs` for node), so the ESM `{type:"module"}` path
//       recommended by upstream is unavailable here.
//   Therefore the Worker is constructed WITHOUT a `type` option. Passing
//   `{type:"module"}` to a classic worker throws `SyntaxError` at runtime, and
//   keeping the default (classic) is the only correct combination for this file.
//   If a future duckdb-wasm release ships `duckdb-browser-eh.worker.mjs`,
//   switch the import and add `{ type: "module" }`.
import workerUrl from "@duckdb/duckdb-wasm/dist/duckdb-browser-eh.worker.js?url";
import wasmUrl from "@duckdb/duckdb-wasm/dist/duckdb-eh.wasm?url";

// Module-level singleton state. `_db`/`_conn` are reused for the session;
// `_registered` tracks view names so reset() can clean them up.
let _db = null;
let _conn = null;
let _pending = null;
const _registered = new Set();

/**
 * Lazily instantiate the AsyncDuckDB singleton and a long-lived connection.
 * On first call this spawns the Worker, instantiates the WASM bundle, and opens
 * a connection; subsequent calls return the cached instances. Throws a
 * descriptive Error if instantiation fails.
 *
 * Concurrent calls are de-duplicated via `_pending`: two callers racing the
 * first instantiation (e.g. React 18 StrictMode double-invoke, or getDuckDB()
 * racing an immediate register()) share the same in-flight promise instead of
 * each spawning their own Worker + WASM. On failure `_pending` is cleared so a
 * retry can attempt a fresh instantiation, and the partially-constructed Worker
 * is terminated to avoid orphaning it.
 *
 * @returns {Promise<{ db: AsyncDuckDB, conn: AsyncDuckDBConnection }>}
 */
export function getDuckDB() {
  if (_db) return Promise.resolve({ db: _db, conn: _conn });
  if (_pending) return _pending;
  _pending = (async () => {
    let db;
    try {
      // Classic worker — see the import comment above for why no `type` option.
      db = new AsyncDuckDB(new ConsoleLogger(), new Worker(workerUrl));
      await db.instantiate(wasmUrl);
      const conn = await db.connect();
      _db = db;
      _conn = conn;
      return { db, conn };
    } catch (err) {
      // Clear the guard first so a retry isn't blocked by the rejected promise.
      _pending = null;
      // If the Worker was already spawned (AsyncDuckDB constructed) but a later
      // step (instantiate/connect) threw, terminate it so a retry doesn't leak
      // a second orphaned Worker. Wrap cleanup so its errors don't mask the
      // original cause. Keep `_db`/`_conn` null so the next call rebuilds.
      if (db) {
        try { await db.terminate(); } catch { /* ignore cleanup errors */ }
      }
      throw new Error(`Failed to initialize DuckDB: ${err?.message || err}`);
    }
  })();
  return _pending;
}

/**
 * Register a Parquet byte buffer as a view named `name` (default "t") so user
 * SQL can reference it as `SELECT ... FROM t`. Re-registering the same name
 * replaces the view. The underlying file is registered as `<name>.parquet`.
 *
 * @param {Uint8Array} parquetBuffer - raw parquet bytes (from streamParquetBytes)
 * @param {string} [name='t'] - view/table name to expose to user SQL
 */
export async function register(parquetBuffer, name = "t") {
  // `name` is interpolated raw into DDL (CREATE/DROP VIEW, file path), so guard
  // it against SQL/identifier injection. App-controlled and sandboxed, but the
  // one-liner matches the read-only Tier 2 mindset (arch §7).
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`Invalid view name: ${name}`);
  }
  const { db, conn } = await getDuckDB();
  const file = `${name}.parquet`;
  try {
    await db.registerFileBuffer(file, parquetBuffer);
    // Track eagerly so reset() always drops the backing file even if the
    // CREATE VIEW below throws — otherwise the (up to 128 MB) buffer would
    // stay registered in DuckDB but untracked, leaking across files.
    _registered.add(name);
    await conn.query(`CREATE OR REPLACE VIEW ${name} AS SELECT * FROM '${file}'`);
  } catch (err) {
    throw new Error(`Failed to register parquet for "${name}": ${err?.message || err}`);
  }
}

/**
 * Run SQL against the registered views and return a row-major result set.
 *
 * @param {string} sql - SQL text; references the view name passed to register()
 * @returns {Promise<{ columns: string[], rows: any[][] }>}
 */
export async function query(sql) {
  const { conn } = await getDuckDB();
  try {
    const table = await conn.query(sql);
    const columns = table.schema.fields.map((f) => f.name);
    const rows = [];
    for (let i = 0; i < table.numRows; i++) {
      const row = table.get(i);
      rows.push(columns.map((c) => row[c]));
    }
    return { columns, rows };
  } catch (err) {
    throw new Error(`DuckDB query failed: ${err?.message || err}`);
  }
}

/**
 * Drop all registered views and their backing parquet files. Called when the
 * preview modal closes so stale data does not leak between files. The DuckDB
 * instance and connection are kept alive for reuse; only the per-file views are
 * torn down. Safe to call before anything was registered.
 */
export async function reset() {
  if (!_db || !_conn) return;
  try {
    for (const name of _registered) {
      try { await _conn.query(`DROP VIEW IF EXISTS ${name}`); } catch { /* view may not exist */ }
      try { await _db.dropFile(`${name}.parquet`); } catch { /* file may not exist */ }
    }
  } finally {
    _registered.clear();
  }
}
