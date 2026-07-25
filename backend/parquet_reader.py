"""Pure, unit-testable helpers for reading Parquet metadata over S3 range GETs.

This module is intentionally free of any FastAPI app/request-state coupling so
that it can be exercised directly from unit tests with a fake S3 client.

The footer-reading logic here was lifted verbatim from the former inline
implementation in ``backend/main.py::_read_parquet_metadata`` (now a thin
caller). The byte-range layout, magic checks, sparse-buffer assembly, the
``MAX_PADDING = 1MB`` branch and every error message string are preserved
exactly — this is a pure refactor with no behavior change.
"""

import datetime
import decimal
import io
import json
import struct

import pyarrow.parquet as pq
from botocore.exceptions import ClientError
from fastapi import HTTPException

# Keep this aligned with the original inline constant. When the gap between the
# 4-byte header and the footer is larger than this, we build a *sparse* buffer
# (seek-based) instead of allocating a giant zero-run, so that pyarrow sees the
# correct column-chunk offsets without blowing up memory on large files.
_MAX_PADDING = 1 * 1024 * 1024  # 1MB max padding


def read_footer(client, bucket, key, file_size=None):
    """Read a Parquet footer via S3 range GETs.

    Parameters
    ----------
    client : object
        Anything exposing ``get_object(Bucket=..., Key=..., Range=...)`` (and
        ``head_object`` when ``file_size`` is not supplied) — typically the
        module-level ``s3`` :class:`_S3ClientProxy` in ``main.py``.
    bucket, key : str
        S3 location of the Parquet object.
    file_size : int, optional
        Object size in bytes. If omitted, it is resolved via ``head_object``.

    Returns
    -------
    (pyarrow.parquet.ParquetMetaData, int)
        The parsed footer metadata and the object's byte size.

    Raises
    ------
    fastapi.HTTPException
        ``400`` for any malformed/undecodable Parquet, ``404`` when the object
        does not exist and ``file_size`` had to be resolved here. Messages are
        identical to the former inline implementation.
    """
    # If the caller already knows the size (the file-metadata path does, via its
    # own head_object), reuse it to avoid a redundant call.
    if file_size is None:
        # Narrow to S3 ClientError so the 404 string-mapping only applies to
        # real S3 errors and unrelated bugs (e.g. AttributeError from a misused
        # client) propagate instead of being masked. Mirrors
        # ``_file_metadata_inner`` in ``main.py``.
        try:
            head = client.head_object(Bucket=bucket, Key=key)
        except ClientError as e:
            if "NoSuchKey" in str(e) or "NotFound" in str(e):
                raise HTTPException(404, "Object not found")
            raise
        file_size = head.get("ContentLength", 0)

    # Parquet footer: last 8 bytes = 4-byte footer length + 4-byte magic "PAR1"
    # Then read the footer itself from (file_size - 8 - footer_length) to (file_size - 8)
    if file_size < 12:
        raise HTTPException(400, "File too small to be a valid Parquet file")

    # Read the last 8 bytes to get footer length
    tail_resp = client.get_object(Bucket=bucket, Key=key, Range=f"bytes={file_size - 8}-{file_size - 1}")
    tail = tail_resp["Body"].read()
    if tail[4:8] != b"PAR1":
        raise HTTPException(400, "Not a valid Parquet file (missing PAR1 magic)")
    footer_len = struct.unpack("<I", tail[0:4])[0]

    # Sanity check: footer shouldn't exceed 256MB
    if footer_len > 256 * 1024 * 1024:
        raise HTTPException(400, f"Parquet footer too large ({footer_len} bytes), likely corrupted")

    # Read footer + magic for pyarrow
    footer_start = file_size - 8 - footer_len
    if footer_start < 4:
        raise HTTPException(400, "Invalid Parquet footer length")
    range_resp = client.get_object(Bucket=bucket, Key=key, Range=f"bytes={footer_start}-{file_size - 1}")
    footer_bytes = range_resp["Body"].read()

    # Also need the first 4 bytes (PAR1 magic) for a valid parquet buffer
    header_resp = client.get_object(Bucket=bucket, Key=key, Range="bytes=0-3")
    header_bytes = header_resp["Body"].read()
    if header_bytes != b"PAR1":
        raise HTTPException(400, "Not a valid Parquet file (missing header magic)")

    # Build a minimal buffer: header (4) + padding + footer
    # Cap padding to avoid OOM on large files (pyarrow only needs offsets to match)
    padding_size = footer_start - 4
    if padding_size > _MAX_PADDING:
        # Use a sparse approach: seek instead of allocating giant buffer
        buf = io.BytesIO()
        buf.write(header_bytes)
        buf.seek(footer_start)
        buf.write(footer_bytes)
        buf.seek(0)
    else:
        buf = io.BytesIO(header_bytes + b"\x00" * padding_size + footer_bytes)
    try:
        meta = pq.read_metadata(buf)
    except Exception as e:
        raise HTTPException(400, f"Failed to read Parquet metadata: {e}")

    return meta, file_size


# ── Tier 1: actual row content ──────────────────────────────────────────────
# These caps are defined here (in the pure helper module that branches on them)
# and re-imported into ``main.py`` so there is a single source of truth for both
# the read path and the FastAPI ``Query`` validators. ``main.py`` exposes them
# as module-level names near ``_metadata_semaphore``.

# Files at or below this size are read in full (single range GET) and decoded
# with pyarrow. Above this, ``read_parquet_rows`` returns a schema-only
# "too_large" response — the targeted-range reader for large files is v1.1.
# Worst-case resident memory = ``_metadata_semaphore(4)`` × this cap ≈ 128 MB.
PARQUET_PREVIEW_SMALL_FILE = 32 * 1024 * 1024

# Hard clamp on how many rows a single request may decode. The endpoint's
# ``Query(le=PARQUET_ROW_LIMIT_MAX)`` enforces this at the HTTP layer (422 on
# overflow); the clamp inside ``read_parquet_rows`` is purely defensive.
PARQUET_ROW_LIMIT_MAX = 1000

# Tier 2 (parquet-stream proxy): hard size cap above which a Parquet object is
# refused for same-origin streaming. Bounds server memory/bandwidth — a user
# must never be able to pipe a 100 GB file through Sairo. Enforced by the
# endpoint in ``main.py`` against ``head_object``'s ContentLength before any
# bytes are streamed; above the cap the SQL tab is hidden and the user is sent
# to the Tier 1 Data tab for row preview.
PARQUET_STREAM_CAP = 128 * 1024 * 1024

# ``bytes`` / ``bytearray`` cells larger than this are not inlined into the JSON
# response as a decoded string — a short placeholder is returned instead, so a
# single binary blob can't dominate a row payload.
_BINARY_CELL_INLINE_LIMIT = 4096


def _json_default(o):
    """Fallback serializer for ``json.dumps`` of nested cells.

    pyarrow's ``to_pylist`` may embed temporal / decimal / bytes values inside
    list/struct/map cells; without this default those would raise
    ``TypeError`` under ``json.dumps``.
    """
    if isinstance(o, (datetime.datetime, datetime.date, datetime.time)):
        return o.isoformat()
    if isinstance(o, decimal.Decimal):
        return str(o)
    if isinstance(o, (bytes, bytearray)):
        n = len(o)
        if n <= _BINARY_CELL_INLINE_LIMIT:
            try:
                return o.decode("utf-8")
            except UnicodeDecodeError:
                return f"<binary {n} bytes>"
        return f"<{n} bytes>"
    if isinstance(o, tuple):  # pyarrow maps decode to list-of-tuples
        return list(o)
    return str(o)


def _serialize_cell(cell):
    """Convert one pyarrow-decoded Python value into JSON-safe form (§8 risk #3).

    Temporal types → ISO 8601 string; ``Decimal`` → its string repr; bytes are
    utf-8 decoded (or replaced by a short placeholder when large/non-utf-8);
    nested types (list/struct/map/large_list, which decode to list/tuple/dict)
    are flattened to a JSON string so the row array stays a flat list of
    primitives/strings. Every other value (int/float/str/bool/None) is returned
    unchanged.
    """
    # datetime is a subclass of date — check it first so timestamps don't lose
    # their time component by hitting the date branch.
    if isinstance(cell, datetime.datetime):
        return cell.isoformat()
    if isinstance(cell, datetime.date):
        return cell.isoformat()
    if isinstance(cell, datetime.time):
        return cell.isoformat()
    if isinstance(cell, decimal.Decimal):
        return str(cell)
    if isinstance(cell, (bytes, bytearray)):
        n = len(cell)
        if n > _BINARY_CELL_INLINE_LIMIT:
            return f"<{n} bytes>"
        try:
            return cell.decode("utf-8")
        except UnicodeDecodeError:
            return f"<binary {n} bytes>"
    # list (incl. large_list), tuple (map entries), dict (struct) → JSON string.
    if isinstance(cell, (list, tuple, dict)):
        return json.dumps(cell, default=_json_default, ensure_ascii=False)
    return cell


def read_parquet_rows(client, bucket, key, *, limit, offset, columns=None):
    """Decode up to ``limit`` rows of a Parquet object on S3.

    Returns the Tier 1 / T2 response dict::

        {columns, rows, total_rows, offset, limit, truncated, next_offset, read_mode}

    * ``columns``: list of ``{"name", "type"}`` projected in the requested
      order (or the full schema when ``columns`` is None).
    * ``rows``: row-major arrays whose column order matches ``columns``.
    * ``read_mode``: ``"full"`` when the file was small enough to decode (≤
      ``PARQUET_PREVIEW_SMALL_FILE``); ``"too_large"`` otherwise — in that case
      ``rows`` is empty, ``truncated`` is True and ``next_offset`` is None, but
      ``columns`` and ``total_rows`` are still accurate (parsed from the
      footer) so the frontend can render a "showing schema only" message.

    Parameters
    ----------
    client : object
        Anything exposing ``get_object(Bucket, Key, Range)`` and
        ``head_object(Bucket, Key)`` — typically the module-level ``s3``
        :class:`_S3ClientProxy` in ``main.py``.
    bucket, key : str
        S3 location of the Parquet object.
    limit, offset : int
        Pagination. The endpoint validates these (``1 ≤ limit ≤
        PARQUET_ROW_LIMIT_MAX``, ``offset ≥ 0``); they are defensively clamped
        here too.
    columns : list[str] | None
        Optional projection allowlist. Unknown names raise
        :class:`fastapi.HTTPException` (400).

    Notes
    -----
    For v1 ``offset`` is applied in-process by slicing the decoded table
    (``table.slice(offset, limit)``); this is correct for the small-file path
    but means large-file offset beyond the first row groups is unsupported
    (deferred to v1.1 along with the targeted-range reader).
    """
    # Defensive clamps — the FastAPI Query validators already enforce bounds;
    # this guards direct callers (unit tests, future reuse).
    limit = max(0, min(int(limit), PARQUET_ROW_LIMIT_MAX))
    offset = max(0, int(offset))

    # read_footer is standalone: it does its own head_object (mapping NoSuchKey
    # → 404) and returns the parsed FileMetaData + the object's byte size.
    meta, file_size = read_footer(client, bucket, key)

    arrow_schema = meta.schema.to_arrow_schema()
    all_names = [arrow_schema.field(i).name for i in range(len(arrow_schema))]
    name_set = set(all_names)

    # Column projection allowlist — reject unknown names before any row decoding
    # so we never read a column the caller can't legitimately name.
    requested = list(columns) if columns else list(all_names)
    for name in requested:
        if name not in name_set:
            raise HTTPException(400, f"Unknown column: {name}")

    # The output ``columns`` list follows the requested order so the frontend
    # can zip(rows[i], columns) directly.
    columns_out = [
        {"name": name, "type": str(arrow_schema.field(name).type)}
        for name in requested
    ]

    total_rows = meta.num_rows
    truncated = (offset + limit) < total_rows
    next_offset = (offset + limit) if truncated else None

    # Large-file branch: do NOT download the object body. Return the schema +
    # accurate totals so the UI can render the "showing schema only" state. The
    # targeted-range reader that would actually decode rows up here is v1.1.
    if file_size > PARQUET_PREVIEW_SMALL_FILE:
        return {
            "columns": columns_out,
            "rows": [],
            "total_rows": total_rows,
            "offset": offset,
            "limit": limit,
            "truncated": True,
            "next_offset": None,
            "read_mode": "too_large",
        }

    # Small-file path: a single full-object range GET, then pyarrow decode.
    # Bounded by PARQUET_PREVIEW_SMALL_FILE (≤ 32 MB) → worst case across the
    # four metadata-semaphore slots is ~128 MB resident.
    range_resp = client.get_object(
        Bucket=bucket, Key=key, Range=f"bytes=0-{file_size - 1}"
    )
    raw = range_resp["Body"].read()
    buf = io.BytesIO(raw)
    try:
        table = pq.ParquetFile(buf).read(columns=requested)
    except Exception as e:
        raise HTTPException(400, f"Failed to read Parquet rows: {e}")

    # v1 applies offset in-process. pyarrow's Table.slice clamps gracefully
    # when offset ≥ num_rows (returns an empty table).
    table = table.slice(offset, limit)
    records = table.to_pylist()

    rows = [
        [_serialize_cell(rec[name]) for name in requested]
        for rec in records
    ]

    return {
        "columns": columns_out,
        "rows": rows,
        "total_rows": total_rows,
        "offset": offset,
        "limit": limit,
        "truncated": truncated,
        "next_offset": next_offset,
        "read_mode": "full",
    }


# ── Tier 2: same-origin object streaming (duckdb-wasm proxy source) ────────

def stream_object(client, bucket, key, *, chunk_size=64 * 1024):
    """Yield an object's bytes in chunks from S3 (generator).

    Thin wrapper over ``client.get_object(...)["Body"].iter_chunks(...)``; the
    caller controls iteration (and therefore backpressure / cancellation). This
    is the byte source for the Tier 2 ``GET /parquet-stream`` proxy endpoint:
    routing the bytes same-origin through Sairo sidesteps the cross-origin /
    CORS failure mode that ``fetch()`` with ``Range`` hits on read-only /
    third-party buckets (arch §3 "Critical decision").

    Pure generator — does NOT acquire the metadata semaphore. The endpoint owns
    the slot lifecycle: it acquires before calling and releases in a ``finally``
    around this generator so the permit is freed on both normal completion and a
    client disconnect (``GeneratorExit``). The hard size cap
    (``PARQUET_STREAM_CAP``) is also enforced by the endpoint via
    ``head_object`` before this is ever called, so a too-large object never
    starts streaming.

    Parameters
    ----------
    client : object
        Anything exposing ``get_object(Bucket, Key)`` — typically the
        module-level ``s3`` :class:`_S3ClientProxy` in ``main.py``.
    bucket, key : str
        S3 location of the object.
    chunk_size : int
        Bytes per yielded chunk. Defaults to 64 KB (a sane default for piping
        into an HTTP chunked/streaming response).

    Raises
    ------
    botocore.exceptions.ClientError
        Propagated upward unchanged (e.g. 404 / access-denied) so the endpoint
        / global exception handler can map it to an HTTP status.
    """
    resp = client.get_object(Bucket=bucket, Key=key)
    for chunk in resp["Body"].iter_chunks(chunk_size):
        yield chunk
