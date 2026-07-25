import React, { useState, useEffect, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { streamParquetBytes, PARQUET_STREAM_CAP } from "../api";
import { getDuckDB, register, query, reset } from "../lib/duckdb";

// Default editor text — a safe read-only sample over the registered view `t`.
// `t` is the FIXED view name (never derived from user input); see lib/duckdb.js.
const DEFAULT_SQL = "SELECT * FROM t LIMIT 100;";

// Estimated row height for virtualization; matches the .preview-csv-table td
// padding (5px 10px) + one line of 12px content (same as ParquetDataTable).
const ROW_HEIGHT = 32;

// Fixed view name exposed to user SQL. Hard-coded on purpose: deriving it from
// user input would be an identifier-injection vector (arch §7). The duckdb
// singleton validates this against ^[A-Za-z_][A-Za-z0-9_]*$.
const VIEW_NAME = "t";

/**
 * Read-only soft guard (arch §7). Strips SQL comments, then rejects statements
 * that begin with a DML/DDL keyword. This is NOT a security boundary — the data
 * is local to the browser and duckdb rejects DML against a parquet-backed view
 * anyway — it just gives a friendlier error than the engine's.
 */
function stripSqlComments(sql) {
  return sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, "");
}
// Known gap: CTE-led writes (`WITH … DELETE …`) start with WITH and slip past this start anchor; acceptable for a soft guard (data is local, DuckDB rejects DML on parquet-backed views anyway).
const WRITE_STMT_RE = /^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b/i;
function isWriteStatement(sql) {
  return WRITE_STMT_RE.test(stripSqlComments(sql));
}

// Cell rendering — mirrors ParquetDataTable: NULL/undefined → muted "NULL",
// booleans → lowercase string, everything else → String(cell). Arrow may hand
// back BigInt for large ints; String() serializes those fine.
function renderCell(cell) {
  if (cell === null || cell === undefined) return <span className="muted">NULL</span>;
  if (cell === true) return "true";
  if (cell === false) return "false";
  return String(cell);
}
function cellTitle(cell) {
  return typeof cell === "string" ? cell : "";
}
function isJsonLikeString(v) {
  return typeof v === "string" && v.length > 0 && (v[0] === "[" || v[0] === "{");
}

/**
 * ParquetSqlConsole — Tier 2 ad-hoc SQL over a Parquet file's bytes, entirely
 * client-side via duckdb-wasm.
 *
 * Props:
 *   bucket     — S3 bucket name
 *   objectKey  — S3 object key of the parquet file (named objectKey, not `key`,
 *                because React reserves the `key` prop; matches ParquetDataTable)
 *   fileSize   — object size in bytes; used to defensively re-enforce the proxy
 *                cap (the parent hides the SQL tab above it already)
 *
 * Lifecycle (on mount, i.e. first SQL-tab activation):
 *   1. "Fetching file…"        — streamParquetBytes() → Uint8Array
 *   2. "Starting SQL engine…"  — getDuckDB() (singleton; instant after first
 *      load) → register(buffer, 't') (CREATE OR REPLACE VIEW)
 *   3. ready — editor + Run + virtualized results table
 *
 * On unmount (modal close or tab switch away), reset() drops the per-file view
 * so stale bytes never leak between files; the duckdb instance stays alive for
 * reuse. The WASM (~34MB) is only pulled in because THIS module is loaded via
 * React.lazy from FilePreview — never import it statically from app entry.
 */
export default function ParquetSqlConsole({ bucket, objectKey, fileSize }) {
  // phase: "idle" | "fetching" | "starting-engine" | "ready"
  const [phase, setPhase] = useState("idle");
  const [loadError, setLoadError] = useState(null);

  const [sql, setSql] = useState(DEFAULT_SQL);
  const [results, setResults] = useState(null); // { columns, rows } from last successful query
  const [queryError, setQueryError] = useState(null);
  const [running, setRunning] = useState(false);

  const scrollRef = useRef(null);

  // Defensive cap: parent hides the tab above PARQUET_STREAM_CAP, but don't
  // trust the caller — never fetch if over the limit.
  const overCap = typeof fileSize === "number" && fileSize > PARQUET_STREAM_CAP;

  // Boot the engine + register the parquet bytes as view `t`. Re-runs only if
  // the target file changes (parent mounts with key={objectKey}, so in practice
  // this runs once per mount).
  useEffect(() => {
    if (overCap) return;
    let cancelled = false;
    const initPromise = (async () => {
      setPhase("fetching");
      // Same-origin proxy → Uint8Array (no CORS, hard-capped server-side).
      const res = await streamParquetBytes(bucket, objectKey);
      if (cancelled) return;
      const buf = new Uint8Array(await res.arrayBuffer());
      if (cancelled) return;
      // First load instantiates the Worker + WASM (slow); later loads hit the
      // cached singleton and this phase resolves immediately.
      setPhase("starting-engine");
      await getDuckDB();
      await register(buf, VIEW_NAME);
      if (cancelled) return;
      setPhase("ready");
    })().catch((e) => {
      if (cancelled) return;
      setLoadError(e?.message || String(e));
      setPhase("idle");
    });

    return () => {
      cancelled = true;
      // Wait for init to settle before dropping, so a late register() can't
      // re-create the view after reset() already ran. Fire-and-forget — reset()
      // is safe to call even if nothing was ever registered.
      initPromise.finally(() => { reset(); });
    };
  }, [bucket, objectKey, fileSize, overCap]);

  const rows = results?.rows ?? [];
  const columns = results?.columns ?? [];

  // Virtualize the result body so large result sets don't lag. Mirrors the
  // padding-spacer <tr> technique from ParquetDataTable so thead/tbody column
  // widths stay aligned in normal table flow.
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 16,
  });
  const virtualItems = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();
  const paddingTop = virtualItems.length > 0 ? virtualItems[0].start : 0;
  const paddingBottom =
    virtualItems.length > 0 ? totalSize - virtualItems[virtualItems.length - 1].end : 0;

  async function onRun() {
    const trimmed = sql.trim();
    if (!trimmed || phase !== "ready") return;
    // Soft read-only guard (arch §7) — friendly message, no engine round-trip.
    if (isWriteStatement(trimmed)) {
      setQueryError("Only read-only SELECT queries are supported.");
      return;
    }
    setRunning(true);
    setQueryError(null);
    try {
      const res = await query(trimmed);
      setResults(res);
    } catch (e) {
      // Show inline; keep the last successful results (or empty) so the user
      // can iterate on the query without losing context.
      setQueryError(e?.message || String(e));
    } finally {
      setRunning(false);
    }
  }

  // ── Render: guard states first ──────────────────────────────────────────
  if (overCap) {
    return (
      <div className="empty">
        SQL preview is only available for files up to 128 MB. This file is larger — use the Data tab instead.
      </div>
    );
  }
  if (loadError) {
    return (
      <div className="empty" style={{ color: "var(--danger)" }}>
        Couldn’t load the file for SQL: {loadError}
      </div>
    );
  }
  if (phase === "fetching") {
    return <div className="empty"><div className="spinner" /> Fetching file…</div>;
  }
  if (phase === "starting-engine") {
    return <div className="empty"><div className="spinner" /> Starting SQL engine…</div>;
  }
  if (phase !== "ready") {
    return <div className="empty"><div className="spinner" /> Preparing…</div>;
  }

  // ── Render: ready (editor + results) ────────────────────────────────────
  return (
    <div className="parquet-sql-console">
      <div className="parquet-sql-editor">
        <textarea
          aria-label="SQL editor"
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          spellCheck={false}
          rows={4}
          className="sql-editor-input"
          // Monospace + block styling comes from index.css (.sql-editor-input).
        />
        <button
          type="button"
          className="btn-primary"
          onClick={onRun}
          disabled={running || phase !== "ready"}
        >
          {running ? "Running…" : "Run"}
        </button>
      </div>

      {queryError && (
        <div className="sql-query-error" role="alert">{queryError}</div>
      )}

      {results && (
        <div className="parquet-data-scroll" ref={scrollRef}>
          {rows.length === 0 ? (
            <div className="empty">Query returned no rows.</div>
          ) : (
            <table className="preview-csv-table">
              <thead>
                <tr>
                  {columns.map((c, i) => (
                    <th key={i}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paddingTop > 0 && (
                  <tr aria-hidden="true" style={{ height: paddingTop }}>
                    <td colSpan={columns.length} style={{ padding: 0, border: "none" }} />
                  </tr>
                )}
                {virtualItems.map((vr) => {
                  const row = rows[vr.index];
                  return (
                    <tr key={vr.key} style={{ height: vr.size }}>
                      {row.map((cell, j) => (
                        <td
                          key={j}
                          className={isJsonLikeString(cell) ? "mono" : undefined}
                          title={cellTitle(cell)}
                        >
                          {renderCell(cell)}
                        </td>
                      ))}
                    </tr>
                  );
                })}
                {paddingBottom > 0 && (
                  <tr aria-hidden="true" style={{ height: paddingBottom }}>
                    <td colSpan={columns.length} style={{ padding: 0, border: "none" }} />
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
