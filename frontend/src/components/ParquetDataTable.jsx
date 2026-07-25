import React, { useState, useEffect, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { fetchParquetRows } from "../api";

// Page size for the Tier 1 parquet-rows endpoint. The backend hard-clamps limit
// at 1000; 100 keeps responses small and pagination granular.
const PAGE_SIZE = 100;
// Estimated row height for virtualization; matches the .preview-csv-table td
// padding (5px 10px) + one line of 12px content.
const ROW_HEIGHT = 32;

// Cells arrive from the backend as JSON values. Simple scalars (int/float/str/
// bool/null) render as text. Complex Parquet types (list/struct/map) arrive as
// JSON-encoded STRINGS (e.g. '["x","y"]') — render them verbatim so we never
// crash trying to treat them as objects. The .preview-csv-table td already
// truncates with ellipsis; the `title` carries the full value on hover.
function isJsonLikeString(v) {
  return typeof v === "string" && v.length > 0 && (v[0] === "[" || v[0] === "{");
}

function renderCell(cell) {
  if (cell === null || cell === undefined) return <span className="muted">NULL</span>;
  if (cell === true) return "true";
  if (cell === false) return "false";
  // numbers + plain strings + JSON-encoded complex-type strings → render as-is
  return String(cell);
}

function cellTitle(cell) {
  if (typeof cell === "string") return cell;
  return "";
}

/**
 * ParquetDataTable — paginated, virtualized preview of actual Parquet rows.
 *
 * Props:
 *   bucket     — S3 bucket name
 *   objectKey  — S3 object key of the parquet file
 *
 * Fetches its own data from GET /api/buckets/{bucket}/parquet-rows and manages
 * pagination/loading/error state. When the backend reports `read_mode ===
 * "too_large"` (file > 32 MB), it renders a friendly message instead of a table
 * and disables pagination.
 *
 * Note: the parent passes `key={fileKey}` so this component fully remounts on
 * file change, which resets all internal state (no stale rows from a previous
 * file). The bucket/objectKey props are therefore stable for a component's life.
 */
export default function ParquetDataTable({ bucket, objectKey }) {
  const [data, setData] = useState(null); // full response payload
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [offset, setOffset] = useState(0);
  const scrollRef = useRef(null);

  // Fetch a page whenever the paging offset changes. bucket/objectKey are stable
  // for this mount (parent uses key={objectKey}); the reset-on-file-change
  // requirement is satisfied by remounting.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetchParquetRows(bucket, objectKey, { limit: PAGE_SIZE, offset })
      .then((res) => {
        if (cancelled) return;
        setData(res);
        setLoading(false);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e.message || String(e));
        setLoading(false);
      });
    return () => { cancelled = true; };
  }, [bucket, objectKey, offset]);

  const rows = data?.rows ?? [];
  const columns = data?.columns ?? [];

  // Virtualize the body so wide/long pages don't lag. Mirrors the pattern used
  // in ObjectTable.jsx (useVirtualizer over a scroll container ref).
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 16,
  });

  const virtualItems = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();
  // Padding spacers keep the <table> in normal flow (so thead/tbody column
  // widths stay aligned) while only the visible slice of rows is rendered.
  const paddingTop = virtualItems.length > 0 ? virtualItems[0].start : 0;
  const paddingBottom =
    virtualItems.length > 0 ? totalSize - virtualItems[virtualItems.length - 1].end : 0;

  // Initial load (no data yet).
  if (loading && !data) {
    return <div className="empty"><div className="spinner" /> Loading rows…</div>;
  }
  if (error) {
    return <div className="empty" style={{ color: "var(--danger)" }}>Error: {error}</div>;
  }
  if (!data) return null;

  // File too large for the server to decode rows → friendly message, no table,
  // no pagination (Schema tab still works).
  if (data.read_mode === "too_large") {
    return (
      <div className="empty">
        File is too large to preview rows — showing schema only.
      </div>
    );
  }

  const canPrev = offset > 0;
  const canNext = data.truncated !== false && data.next_offset != null;

  return (
    <div className="parquet-data-table">
      <div className="parquet-data-toolbar">
        <span className="muted" style={{ fontSize: 12 }}>
          {rows.length > 0
            ? `rows ${offset + 1}–${offset + rows.length} of ${data.total_rows != null ? data.total_rows.toLocaleString() : "…"}`
            : "no rows"}
        </span>
        <div className="log-mode-toggle" role="group" aria-label="Row pagination">
          <button
            type="button"
            className="log-mode-btn"
            disabled={loading || !canPrev}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            aria-label="Previous page"
          >
            Prev
          </button>
          <button
            type="button"
            className="log-mode-btn"
            disabled={loading || !canNext}
            onClick={() => setOffset(data.next_offset)}
            aria-label="Next page"
          >
            Next
          </button>
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="empty">This file has no rows.</div>
      ) : (
        <div ref={scrollRef} className="parquet-data-scroll">
          <table className="preview-csv-table">
            <thead>
              <tr>
                {columns.map((c, i) => (
                  <th key={i} title={`${c.name}: ${c.type || "unknown"}`}>
                    <div>{c.name}</div>
                    {c.type && <div className="preview-col-type">{c.type}</div>}
                  </th>
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
        </div>
      )}
    </div>
  );
}
