"""Unit tests for the pure ``backend/parquet_reader.py`` helper.

These tests do NOT spin up the FastAPI app and do NOT use moto. They build a
real Parquet file in memory with pyarrow and serve its bytes through a tiny fake
S3 client that implements ``get_object(Bucket, Key, Range)`` + ``head_object``,
matching the contract ``read_footer`` expects (same style as the MagicMock-based
fakes used elsewhere in this repo's test suite).
"""
import io
import re
import struct

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException

# parquet_reader is a sibling module — import it the same way the app fixture in
# test_main.py imports main (works whether pytest runs from repo root or backend/).
try:
    from backend.parquet_reader import (
        read_footer,
        read_parquet_rows,
        stream_object,
        _MAX_PADDING,
        PARQUET_PREVIEW_SMALL_FILE,
        PARQUET_ROW_LIMIT_MAX,
        PARQUET_STREAM_CAP,
    )
except ModuleNotFoundError:
    from parquet_reader import (
        read_footer,
        read_parquet_rows,
        stream_object,
        _MAX_PADDING,
        PARQUET_PREVIEW_SMALL_FILE,
        PARQUET_ROW_LIMIT_MAX,
        PARQUET_STREAM_CAP,
    )


BUCKET = "test-bucket"
KEY = "data/test.parquet"


class _FakeS3:
    """Minimal S3 client that serves byte-range GETs from an in-memory buffer.

    Mirrors the subset of the boto3 S3 client API that ``read_footer`` uses:
    ``get_object(Bucket, Key, Range)`` returns ``{"Body": <file-like>}`` and
    ``head_object(Bucket, Key)`` returns ``{"ContentLength": int}``.
    """

    def __init__(self, data: bytes):
        self._data = data
        self.get_calls = []  # recorded (start, end) ranges, handy for assertions
        self.head_calls = 0  # number of head_object invocations

    def head_object(self, *, Bucket, Key):
        self.head_calls += 1
        return {"ContentLength": len(self._data)}

    def get_object(self, *, Bucket, Key, Range):
        m = re.match(r"bytes=(\d+)-(\d+)", Range)
        assert m, f"unexpected Range header: {Range!r}"
        start, end = int(m.group(1)), int(m.group(2))
        self.get_calls.append((start, end))
        # S3 Range responses are inclusive on both ends.
        return {"Body": io.BytesIO(self._data[start : end + 1])}


@pytest.fixture
def parquet_buf():
    """A small real Parquet file: 2 columns, 10 rows, 1 row group."""
    schema = pa.schema(
        [
            pa.field("id", pa.int64()),
            pa.field("name", pa.string()),
        ]
    )
    table = pa.table(
        {
            "id": pa.array(list(range(10)), pa.int64()),
            "name": pa.array([f"row{i}" for i in range(10)], pa.string()),
        },
        schema=schema,
    )
    buf = io.BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()


@pytest.fixture
def fake_s3(parquet_buf):
    return _FakeS3(parquet_buf)


class TestReadFooter:
    def test_read_footer_with_explicit_file_size(self, fake_s3, parquet_buf):
        """When file_size is supplied, head_object must NOT be called."""
        meta, file_size = read_footer(fake_s3, BUCKET, KEY, len(parquet_buf))
        assert file_size == len(parquet_buf)
        assert meta.num_rows == 10
        assert meta.num_columns == 2
        assert meta.num_row_groups == 1
        # head_object must not be needed when file_size is passed in. This is a
        # real counter (not the former tautological `hasattr` check, which could
        # never fail because _FakeS3 always defines head_object).
        assert fake_s3.head_calls == 0

    def test_read_footer_standalone_resolves_size_via_head(self, fake_s3, parquet_buf):
        """When file_size is omitted, read_footer resolves it via head_object."""
        meta, file_size = read_footer(fake_s3, BUCKET, KEY)
        assert file_size == len(parquet_buf)
        assert meta.num_rows == 10
        assert meta.num_columns == 2
        assert meta.num_row_groups == 1
        # Exactly one head_object call to resolve the size.
        assert fake_s3.head_calls == 1

    def test_read_footer_schema_matches_written_columns(self, fake_s3):
        """The arrow schema reconstructed from the footer matches the source table."""
        meta, _ = read_footer(fake_s3, BUCKET, KEY, fake_s3.head_object(Bucket=BUCKET, Key=KEY)["ContentLength"])
        arrow_schema = meta.schema.to_arrow_schema()
        assert len(arrow_schema) == 2
        assert arrow_schema.field(0).name == "id"
        assert str(arrow_schema.field(0).type) == "int64"
        assert arrow_schema.field(1).name == "name"
        assert str(arrow_schema.field(1).type) == "string"

    def test_read_footer_uses_range_gets_not_full_download(self, fake_s3, parquet_buf):
        """read_footer must only range-GET small slices, never the whole object."""
        fake_s3.get_calls = []
        read_footer(fake_s3, BUCKET, KEY, len(parquet_buf))
        # Three range GETs: tail (8B), footer, header (4B). None should fetch the
        # whole file.
        assert len(fake_s3.get_calls) == 3
        for start, end in fake_s3.get_calls:
            chunk_len = end - start + 1
            assert chunk_len < len(parquet_buf), "read_footer fetched the whole object!"

    def test_read_footer_returns_valid_parquet_metadata(self, fake_s3, parquet_buf):
        """The returned metadata is the real pyarrow FileMetaData produced by pq.read_metadata."""
        import pyarrow._parquet as _pq

        meta, file_size = read_footer(fake_s3, BUCKET, KEY, len(parquet_buf))
        # pq.read_metadata() returns a pyarrow._parquet.FileMetaData instance.
        assert isinstance(meta, _pq.FileMetaData)
        assert file_size == len(parquet_buf)

    def test_read_footer_sparse_buffer_branch(self, parquet_buf):
        """Force the ``padding_size > _MAX_PADDING`` large-file code path.

        The default ~1KB fixture always takes the single-alloc ``else`` branch.
        Here we synthesize a Parquet object whose footer starts well beyond
        ``4 + _MAX_PADDING`` by splicing ``2 * _MAX_PADDING`` zero bytes between
        the 4-byte header and the rest of a real (small) Parquet file. The
        footer bytes themselves are untouched, so ``read_metadata`` still sees a
        valid FileMetaData — only the column-chunk offsets shift into the gap,
        which ``pq.read_metadata`` does not dereference.

        This is the load-bearing path for large real-world Parquet files (T2
        ``parquet-rows`` / T5 ``parquet-stream`` will hit it), and it must NOT
        allocate a multi-MB zero-buffer: the bytes fetched via range GETs must
        stay tiny relative to the padded object size.
        """
        # footer_len of the small source file, as stored in its trailing 8 bytes.
        footer_len = struct.unpack("<I", parquet_buf[-8:-4])[0]
        footer_start_small = len(parquet_buf) - 8 - footer_len
        assert footer_start_small >= 4  # sanity: header present

        # Splice a 2MB gap right after the 4-byte header magic. The footer (and
        # its trailing magic/length) is preserved verbatim, so the resulting
        # object is still a structurally valid Parquet file from the footer's
        # perspective.
        pad = 2 * _MAX_PADDING
        large_data = parquet_buf[0:4] + b"\x00" * pad + parquet_buf[4:]
        # The footer now sits at footer_start_small + pad, so
        # padding_size = footer_start_small + pad - 4 > _MAX_PADDING. Assert it
        # explicitly so this test is guaranteed to exercise the sparse
        # (seek-based) branch rather than silently regressing to the
        # single-alloc path.
        padding_size = (footer_start_small + pad) - 4
        assert padding_size > _MAX_PADDING, (
            "test setup broken: padding_size must exceed _MAX_PADDING to hit "
            "the sparse-buffer branch"
        )
        fake_s3 = _FakeS3(large_data)
        fake_s3.get_calls = []

        meta, file_size = read_footer(fake_s3, BUCKET, KEY, len(large_data))

        # Footer parsed correctly despite the giant gap.
        assert file_size == len(large_data)
        assert meta.num_rows == 10
        assert meta.num_columns == 2
        assert meta.num_row_groups == 1
        # The sparse branch must NOT materialize the ~2MB zero-run: total bytes
        # fetched via range GETs (tail + footer + header) is on the order of the
        # *small* footer size, i.e. orders of magnitude smaller than the padded
        # object. A single-alloc path would still only fetch via range GETs, so
        # the decisive check is that we did NOT pull the 2MB gap across the wire.
        bytes_fetched = sum(end - start + 1 for start, end in fake_s3.get_calls)
        assert bytes_fetched < _MAX_PADDING, (
            f"read_footer fetched {bytes_fetched}B; sparse branch should fetch "
            f"only the footer, not the {_MAX_PADDING}B+ gap"
        )
        # Three range GETs as always: tail (8B), footer, header (4B).
        assert len(fake_s3.get_calls) == 3


class TestReadFooterErrors:
    """Error messages must match the original inline implementation exactly."""

    def test_file_too_small(self):
        from unittest.mock import MagicMock

        with pytest.raises(HTTPException) as exc:
            read_footer(MagicMock(), BUCKET, KEY, 5)
        assert exc.value.status_code == 400
        assert exc.value.detail == "File too small to be a valid Parquet file"

    def test_missing_tail_magic(self):
        """Last 8 bytes without the trailing PAR1 magic → 400."""

        class BadTail:
            def get_object(self, *, Bucket, Key, Range):
                # 8 bytes: 4 length + bad magic
                return {"Body": io.BytesIO(b"\x00\x00\x00\x00XXXX")}

        with pytest.raises(HTTPException) as exc:
            read_footer(BadTail(), BUCKET, KEY, 20)
        assert exc.value.status_code == 400
        assert exc.value.detail == "Not a valid Parquet file (missing PAR1 magic)"

    def test_missing_header_magic(self):
        """Footer magic present but header magic missing → 400."""
        # Build a buffer whose tail is a valid PAR1 but whose header is not.
        # Easiest: take a real parquet file and corrupt its first 4 bytes, then
        # confirm read_footer rejects it on the header check.
        schema = pa.schema([pa.field("x", pa.int64())])
        tbl = pa.table({"x": pa.array([1, 2, 3], pa.int64())}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(tbl, buf)
        data = bytearray(buf.getvalue())
        data[0:4] = b"XXXX"  # corrupt header magic
        fake = _FakeS3(bytes(data))
        with pytest.raises(HTTPException) as exc:
            read_footer(fake, BUCKET, KEY, len(data))
        assert exc.value.status_code == 400
        assert exc.value.detail == "Not a valid Parquet file (missing header magic)"

    def test_footer_too_large_rejected(self):
        """A footer length > 256MB → 400 with the exact "too large" message.

        T2 (``parquet-rows``) will call ``read_footer`` standalone and depends on
        this guard firing before any giant allocation is attempted. We craft a
        tail whose first 4 bytes unpack to a value just over the 256MB cap; the
        magic is valid so we reach the size check.
        """
        huge_len = 256 * 1024 * 1024 + 1  # one byte over the 256MB cap
        # Tail = 4-byte little-endian length + 4-byte PAR1 magic.
        tail = struct.pack("<I", huge_len) + b"PAR1"
        # file_size just needs to be large enough to look plausible (>= 12); the
        # size check fires before the footer range GET is interpreted.
        file_size = 4096

        class HugeFooter:
            def get_object(self, *, Bucket, Key, Range):
                # read_footer's first range GET is always the 8-byte tail.
                return {"Body": io.BytesIO(tail)}

        with pytest.raises(HTTPException) as exc:
            read_footer(HugeFooter(), BUCKET, KEY, file_size)
        assert exc.value.status_code == 400
        assert exc.value.detail == f"Parquet footer too large ({huge_len} bytes), likely corrupted"

    def test_head_object_not_found_maps_to_404(self):
        """When ``file_size`` is omitted and head_object 404s, map to HTTP 404.

        Mirrors ``_file_metadata_inner`` in ``main.py``. T2/T5 call
        ``read_footer`` standalone (no pre-resolved size), so the NoSuchKey →
        "Object not found" mapping must hold for real botocore ClientErrors.
        """
        not_found = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}},
            "HeadObject",
        )

        class MissingObject:
            def head_object(self, *, Bucket, Key):
                raise not_found

            def get_object(self, *, Bucket, Key, Range):  # pragma: no cover - never reached
                raise AssertionError("get_object should not be called when head_object 404s")

        with pytest.raises(HTTPException) as exc:
            read_footer(MissingObject(), BUCKET, KEY)
        assert exc.value.status_code == 404
        assert exc.value.detail == "Object not found"


# ── Tier 1: read_parquet_rows ──────────────────────────────────────────────

class _RowsFakeS3:
    """Fake S3 serving a real in-memory Parquet buffer.

    Same shape as the ``read_footer`` fake above, kept separate so these tests
    can record both ``head_object`` and full-object ``get_object`` calls
    independently.
    """

    def __init__(self, data: bytes):
        self._data = data
        self.get_calls = []  # list of (start, end) ranges
        self.head_calls = 0

    def head_object(self, *, Bucket, Key):
        self.head_calls += 1
        return {"ContentLength": len(self._data)}

    def get_object(self, *, Bucket, Key, Range):
        m = re.match(r"bytes=(\d+)-(\d+)", Range)
        assert m, f"unexpected Range header: {Range!r}"
        start, end = int(m.group(1)), int(m.group(2))
        self.get_calls.append((start, end))
        return {"Body": io.BytesIO(self._data[start : end + 1])}


class _LargeFakeS3:
    """Fake S3 that presents a *virtual* Parquet object larger than
    ``PARQUET_PREVIEW_SMALL_FILE`` without materializing a 32 MB+ buffer.

    Layout: ``[0:4] = small[0:4]`` (PAR1 header), ``[4 : 4+pad] = 0`` bytes,
    ``[4+pad : total] = small[4:]``. The real footer bytes are preserved at the
    tail, so ``read_footer`` parses correctly; only the column-chunk offsets
    shift into the gap, which footer parsing does not dereference. Only the
    requested byte range is ever built, so the test stays cheap.
    """

    def __init__(self, small: bytes, total: int):
        assert total > len(small) > 12
        self.small = small
        self.total = total
        self.pad = total - len(small)
        self.get_calls = []

    def head_object(self, *, Bucket, Key):
        return {"ContentLength": self.total}

    def _byte(self, i):
        if i < 4:
            return self.small[i]
        if i < 4 + self.pad:
            return 0
        return self.small[4 + (i - (4 + self.pad))]

    def get_object(self, *, Bucket, Key, Range):
        m = re.match(r"bytes=(\d+)-(\d+)", Range)
        assert m, f"unexpected Range header: {Range!r}"
        start, end = int(m.group(1)), int(m.group(2))
        self.get_calls.append((start, end))
        return {"Body": io.BytesIO(bytes(self._byte(i) for i in range(start, end + 1)))}


@pytest.fixture
def parquet_500():
    """A real Parquet file: 2 columns × 500 rows."""
    schema = pa.schema(
        [
            pa.field("a", pa.int64()),
            pa.field("b", pa.string()),
        ]
    )
    table = pa.table(
        {
            "a": pa.array(list(range(500)), pa.int64()),
            "b": pa.array([f"row{i}" for i in range(500)], pa.string()),
        },
        schema=schema,
    )
    buf = io.BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()


class TestReadParquetRows:
    """Lock the Tier 1 ``read_parquet_rows`` contract (frozen for T3 frontend)."""

    def test_happy_path_small_file(self, parquet_500):
        """Small file: rows decoded, pagination fields correct, read_mode=='full'."""
        fake = _RowsFakeS3(parquet_500)
        out = read_parquet_rows(fake, BUCKET, KEY, limit=100, offset=0)

        # Exact key set and order — T3 zips rows against columns by position.
        assert list(out.keys()) == [
            "columns", "rows", "total_rows", "offset", "limit",
            "truncated", "next_offset", "read_mode",
        ]
        assert out["read_mode"] == "full"
        assert out["total_rows"] == 500
        assert out["offset"] == 0
        assert out["limit"] == 100
        assert out["truncated"] is True
        assert out["next_offset"] == 100

        # rows are row-major arrays; column order matches `columns`.
        assert len(out["rows"]) == 100
        assert out["rows"][0] == [0, "row0"]
        assert out["rows"][99] == [99, "row99"]
        assert out["columns"] == [
            {"name": "a", "type": "int64"},
            {"name": "b", "type": "string"},
        ]

    def test_offset_advances_window(self, parquet_500):
        """offset slices the decoded table; next_offset advances accordingly."""
        fake = _RowsFakeS3(parquet_500)
        out = read_parquet_rows(fake, BUCKET, KEY, limit=10, offset=490)
        assert out["read_mode"] == "full"
        assert len(out["rows"]) == 10
        assert out["rows"][0] == [490, "row490"]
        assert out["truncated"] is False  # 490 + 10 == 500 → not truncated
        assert out["next_offset"] is None

    def test_column_projection(self, parquet_500):
        """Requesting a subset of columns projects both `columns` and each row."""
        fake = _RowsFakeS3(parquet_500)
        out = read_parquet_rows(fake, BUCKET, KEY, limit=5, offset=0, columns=["b"])
        assert [c["name"] for c in out["columns"]] == ["b"]
        # Each row contains only the projected column, in requested order.
        assert all(len(row) == 1 for row in out["rows"])
        assert out["rows"][0] == ["row0"]
        # pyarrow projection must not be a full-object read of every column:
        # the body GET still fetches the whole small file (small-file path),
        # but the decoded table has exactly one column.
        assert out["read_mode"] == "full"

    def test_unknown_column_raises_400(self, parquet_500):
        """Unknown column names are rejected before any row decoding."""
        fake = _RowsFakeS3(parquet_500)
        with pytest.raises(HTTPException) as exc:
            read_parquet_rows(fake, BUCKET, KEY, limit=5, offset=0, columns=["nope"])
        assert exc.value.status_code == 400
        assert exc.value.detail == "Unknown column: nope"
        # Decoding was skipped: only read_footer's range GETs happened, no body GET.
        assert all((e - s + 1) < len(parquet_500) for s, e in fake.get_calls)

    def test_limit_clamped_to_max(self, parquet_500):
        """The helper clamps limit defensively to PARQUET_ROW_LIMIT_MAX."""
        fake = _RowsFakeS3(parquet_500)
        out = read_parquet_rows(fake, BUCKET, KEY, limit=10_000, offset=0)
        # Only 500 rows actually exist; clamp + slice yields all 500.
        assert out["limit"] == PARQUET_ROW_LIMIT_MAX
        assert len(out["rows"]) == 500
        assert out["truncated"] is False
        assert out["next_offset"] is None

    def test_large_file_returns_schema_only(self, parquet_500):
        """Files > PARQUET_PREVIEW_SMALL_FILE return read_mode=='too_large'."""
        total = PARQUET_PREVIEW_SMALL_FILE + 1024  # just over 32 MB
        fake = _LargeFakeS3(parquet_500, total)
        out = read_parquet_rows(fake, BUCKET, KEY, limit=100, offset=0)

        assert out["read_mode"] == "too_large"
        assert out["rows"] == []
        assert out["truncated"] is True
        assert out["next_offset"] is None
        # Schema + totals still accurate from the footer.
        assert out["total_rows"] == 500
        assert out["columns"] == [{"name": "a", "type": "int64"},
                                  {"name": "b", "type": "string"}]
        # No full-object body GET: only read_footer's small range GETs happened.
        for start, end in fake.get_calls:
            assert (end - start + 1) < PARQUET_PREVIEW_SMALL_FILE, (
                "too_large branch must not fetch the object body"
            )

    def test_nested_types_serialize_to_json_strings(self):
        """§8 risk #3: list/struct/map/temporal/decimal/binary cells don't crash."""
        import datetime
        import decimal

        schema = pa.schema(
            [
                pa.field("id", pa.int64()),
                pa.field("tags", pa.list_(pa.string())),
                pa.field("meta", pa.struct([
                    pa.field("a", pa.int32()),
                    pa.field("b", pa.string()),
                ])),
                pa.field("m", pa.map_(pa.string(), pa.int64())),
                pa.field("amt", pa.decimal128(10, 2)),
                pa.field("ts", pa.timestamp("us")),
                pa.field("blob", pa.binary()),
            ]
        )
        table = pa.table(
            {
                "id": [1],
                "tags": [["x", "y"]],
                "meta": [{"a": 1, "b": "foo"}],
                "m": [{"k": 1}],
                "amt": [decimal.Decimal("1.50")],
                "ts": [datetime.datetime(2024, 1, 1, 12, 0, 0)],
                "blob": [b"hello"],
            },
            schema=schema,
        )
        buf = io.BytesIO()
        pq.write_table(table, buf)
        fake = _RowsFakeS3(buf.getvalue())

        out = read_parquet_rows(fake, BUCKET, KEY, limit=10, offset=0)
        assert out["read_mode"] == "full"
        assert len(out["rows"]) == 1
        row = out["rows"][0]

        # Primitive columns pass through unchanged.
        assert row[0] == 1  # id

        # Nested types are flattened to JSON strings (parseable, no crash).
        import json as _json
        assert row[1] == '["x", "y"]'                                  # list
        assert _json.loads(row[1]) == ["x", "y"]
        assert _json.loads(row[2]) == {"a": 1, "b": "foo"}             # struct
        # map decodes to a list of [k, v] pairs (JSON array of arrays).
        assert row[3] == '[["k", 1]]'

        # Temporal/decimal become ISO/str.
        assert row[4] == "1.50"                                        # decimal
        assert row[5] == "2024-01-01T12:00:00"                         # timestamp
        # Short utf-8 bytes are decoded.
        assert row[6] == "hello"                                       # binary

    def test_large_binary_cell_truncated(self):
        """bytes > 4 KB are replaced by a '<{n} bytes>' placeholder."""
        schema = pa.schema([pa.field("blob", pa.binary())])
        big = b"\x00" * 5000
        table = pa.table({"blob": [big]}, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf)
        fake = _RowsFakeS3(buf.getvalue())

        out = read_parquet_rows(fake, BUCKET, KEY, limit=1, offset=0)
        assert out["rows"][0] == ["<5000 bytes>"]

    def test_404_propagates_when_object_missing(self):
        """read_parquet_rows reuses read_footer, so a missing object maps to 404."""
        not_found = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}},
            "HeadObject",
        )

        class MissingObject:
            def head_object(self, *, Bucket, Key):
                raise not_found

            def get_object(self, *, Bucket, Key, Range):  # pragma: no cover
                raise AssertionError("body GET must not happen on a missing object")

        with pytest.raises(HTTPException) as exc:
            read_parquet_rows(MissingObject(), BUCKET, KEY, limit=10, offset=0)
        assert exc.value.status_code == 404
        assert exc.value.detail == "Object not found"


class TestReadParquetRowsTemporalOverflow:
    """Out-of-range temporal values must not crash the preview with a bare 500.

    Regression guard: before the fix, ``table.to_pylist()`` raised
    ``OverflowError`` when a timestamp/date/time/duration column held a value
    outside Python's ``datetime`` range (e.g. year > 9999), surfacing as an
    HTTP 500 from FastAPI. The fix catches that and falls back to casting the
    temporal columns to string so the row is still returned.
    """

    def test_out_of_range_timestamp_returns_row_not_500(self):
        """A timestamp(us) value beyond datetime.max is recovered, not dropped.

        10**18 microseconds ≈ year 33688, well past ``datetime.max`` (~year
        9999 ≈ 2.53e17 us). It fits in int64 so Parquet stores it fine, but
        materializing it to a Python datetime overflows the OLD ``to_pylist()``
        path (OverflowError "date value out of range" -> bare HTTP 500).

        Fallback engaged: for this value ``pc.cast(col, pa.string())``
        SUCCEEDS (pyarrow renders the placeholder
        '<value out of range: 1000000000000000000>'), so the int64 fallback
        does NOT fire here. The cell is therefore a ``str``, not an ``int``.
        """
        # 10**18 us ≈ year 33688 — beyond datetime.max. Built via int64 then
        # cast to timestamp(us) so the value is genuinely stored out of range.
        arr = pa.array([10**18], pa.int64()).cast(pa.timestamp("us"))
        tbl = pa.table(
            {"ts": arr},
            schema=pa.schema([pa.field("ts", pa.timestamp("us"))]),
        )
        buf = io.BytesIO()
        pq.write_table(tbl, buf)
        fake = _RowsFakeS3(buf.getvalue())

        # Must not raise (the old code raised OverflowError -> 500 here).
        out = read_parquet_rows(fake, BUCKET, KEY, limit=10, offset=0)

        # The row is present (NOT dropped) and the preview still completes.
        assert out["read_mode"] == "full"
        assert len(out["rows"]) == 1

        # String cast path fired: the cell is a str holding pyarrow's
        # out-of-range placeholder (which includes the raw micros value).
        cell = out["rows"][0][0]
        assert isinstance(cell, str)
        assert cell == "<value out of range: 1000000000000000000>"

    def test_in_range_timestamp_preserves_iso_format(self):
        """A normal timestamp(us) takes the fast path: ISO 8601 format unchanged.

        Locks the backward-compat requirement: the try-then-cast-fallback must
        NOT alter the frontend-visible format for in-range files. The fast path
        materializes a real ``datetime`` and ``_serialize_cell`` renders it as
        '2024-01-01T12:00:00' ('T' separator, no fractionals). Casting upfront
        would instead yield pyarrow's '2024-01-01 12:00:00.000000' (space +
        trailing fractionals) — a regression this test pins out.
        """
        import datetime

        tbl = pa.table(
            {"ts": pa.array(
                [datetime.datetime(2024, 1, 1, 12, 0, 0)],
                pa.timestamp("us"),
            )},
            schema=pa.schema([pa.field("ts", pa.timestamp("us"))]),
        )
        buf = io.BytesIO()
        pq.write_table(tbl, buf)
        fake = _RowsFakeS3(buf.getvalue())

        out = read_parquet_rows(fake, BUCKET, KEY, limit=10, offset=0)

        assert out["read_mode"] == "full"
        assert out["rows"][0][0] == "2024-01-01T12:00:00"

    def test_mixed_in_range_and_out_of_range_columns_per_column_resolution(self):
        """The regression the per-column fallback exists to prevent.

        When a single table has BOTH an in-range timestamp column AND an
        out-of-range timestamp column, the OLD whole-table cast fallback would
        cast EVERY temporal column to string — re-rendering the in-range column
        as pyarrow's '2024-01-01 00:00:00.000000' (space separator + trailing
        fractionals) instead of the required ISO '2024-01-01T00:00:00'.

        The per-column fix resolves each column independently: the in-range
        column keeps its datetime → _serialize_cell → ISO path (byte-identical
        to the fast path), and only the overflowing column gets cast to string.

        This test MUST fail against a whole-table-cast implementation and pass
        against the per-column implementation.
        """
        import datetime

        # One row, two timestamp("us") columns: one in-range, one out-of-range.
        # The out-of-range value is built via int64 → timestamp cast so it is
        # genuinely stored beyond datetime.max (10**18 us ≈ year 33688).
        in_range = pa.array(
            [datetime.datetime(2024, 1, 1, 12, 0, 0)], pa.timestamp("us")
        )
        out_of_range = pa.array([10**18], pa.int64()).cast(pa.timestamp("us"))
        tbl = pa.table(
            {"good": in_range, "bad": out_of_range},
            schema=pa.schema([
                pa.field("good", pa.timestamp("us")),
                pa.field("bad", pa.timestamp("us")),
            ]),
        )
        buf = io.BytesIO()
        pq.write_table(tbl, buf)
        fake = _RowsFakeS3(buf.getvalue())

        out = read_parquet_rows(fake, BUCKET, KEY, limit=10, offset=0)

        # The row is present and the preview completes — no exception, no drop.
        assert out["read_mode"] == "full"
        assert len(out["rows"]) == 1

        good_cell, bad_cell = out["rows"][0]

        # THE REGRESSION GUARD: the in-range column keeps ISO format even though
        # a sibling column overflowed. A whole-table cast would yield
        # '2024-01-01 12:00:00.000000' here instead.
        assert good_cell == "2024-01-01T12:00:00"

        # The out-of-range column is still present (not dropped) and rendered as
        # pyarrow's '<value out of range: N>' string placeholder.
        assert isinstance(bad_cell, str)
        assert bad_cell == "<value out of range: 1000000000000000000>"

    def test_nested_temporal_overflow_returns_structured_400_not_500(self):
        """A struct column holding an out-of-range timestamp degrades to 400.

        The per-column string/int64 fallback only handles TOP-LEVEL temporal
        columns; nested temporal (inside struct/list/map) can't be recovered by
        a column cast. Such a file must NOT crash the preview as a bare 500 — it
        must surface as a structured HTTPException(400) starting with the
        'Failed to decode Parquet rows' prefix.

        Construction note: building a struct whose child ts field holds an
        out-of-range value is fiddly via ``pa.array`` (it rejects raw ints for a
        timestamp field). The reliable path is to build the child timestamp
        array from int64 (``pa.array([10**18], pa.int64()).cast(timestamp)``)
        and assemble the struct with ``StructArray.from_arrays``.
        """
        # Child timestamp("us") array holding a genuinely out-of-range value
        # (10**18 us ≈ year 33688, beyond datetime.max).
        child = pa.array([10**18], pa.int64()).cast(pa.timestamp("us"))
        struct_arr = pa.StructArray.from_arrays(
            [child], fields=[pa.field("ts", pa.timestamp("us"))]
        )
        schema = pa.schema([
            pa.field("s", pa.struct([pa.field("ts", pa.timestamp("us"))])),
        ])
        tbl = pa.table([struct_arr], schema=schema)
        buf = io.BytesIO()
        pq.write_table(tbl, buf)
        fake = _RowsFakeS3(buf.getvalue())

        # Trace under the fix: table.to_pylist() raises OverflowError (fast path
        # miss) → per-column path runs table.column("s").to_pylist(), which also
        # raises OverflowError → pc.cast(struct, string) raises
        # ArrowNotImplementedError → caught → pc.cast(struct, int64) raises
        # ArrowNotImplementedError, which is NOT caught by the inner string-cast
        # handler → propagates to the outer `except Exception` → 400.
        with pytest.raises(HTTPException) as exc:
            read_parquet_rows(fake, BUCKET, KEY, limit=10, offset=0)

        # Structured 400, NOT a bare OverflowError / 500.
        assert exc.value.status_code == 400
        assert exc.value.detail.startswith("Failed to decode Parquet rows")


# ── Tier 2: stream_object (pure proxy source) ──────────────────────────────


class TestStreamObject:
    """Unit tests for the pure ``stream_object`` generator (Tier 2 proxy source).

    The generator is the byte source for ``GET /parquet-stream``. These tests
    lock its contract in isolation from the FastAPI endpoint: chunking, full
    byte-fidelity, and that S3 ``ClientError`` propagates unchanged (the endpoint
    / global exception handler is responsible for status mapping). The endpoint
    lifecycle (semaphore acquire/release) is exercised in ``test_main.py``.
    """

    @staticmethod
    def _chunked_body_fake(data):
        """Fake S3 whose ``get_object`` body exposes ``iter_chunks`` (boto3 shape)."""

        class _Body:
            def __init__(self, payload):
                self._payload = payload
                # number of chunks the consumer requested — handy for assertions
                self.chunk_sizes = []

            def iter_chunks(self, chunk_size):
                self.chunk_sizes.append(chunk_size)
                for i in range(0, len(self._payload), chunk_size):
                    yield self._payload[i:i + chunk_size]

        body = _Body(data)

        class _FakeS3:
            get_calls = 0

            def get_object(self_, *, Bucket, Key, Range=None):
                self_.get_calls += 1
                return {"Body": body}

        return _FakeS3(), body

    def test_yields_full_object_bytes_in_order(self):
        """Concatenating all yielded chunks reproduces the original bytes."""
        data = b"PAR1" + bytes(range(256)) * 4 + b"PAR1"
        fake, _body = self._chunked_body_fake(data)

        out = b"".join(stream_object(fake, BUCKET, KEY))

        assert out == data
        assert fake.get_calls == 1  # exactly one get_object, no buffering loop

    def test_chunk_size_is_forwarded_to_iter_chunks(self):
        """The caller controls the chunk granularity (backpressure)."""
        data = bytes(range(256)) * 4  # 1024 bytes
        fake, body = self._chunked_body_fake(data)

        chunks = list(stream_object(fake, BUCKET, KEY, chunk_size=100))

        # 1024 bytes / 100 → 11 chunks (10×100 + 1×24).
        assert len(chunks) == 11
        assert [len(c) for c in chunks[:-1]] == [100] * 10
        assert len(chunks[-1]) == 24
        assert body.chunk_sizes == [100]  # forwarded verbatim

    def test_clienterror_propagates_unchanged(self):
        """A 404 / access-denied from get_object surfaces as ClientError (the
        endpoint owns status mapping — the pure helper must not swallow it)."""

        class _ErrS3:
            def get_object(self, *, Bucket, Key, Range=None):
                raise ClientError(
                    {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}},
                    "GetObject",
                )

        with pytest.raises(ClientError) as exc:
            # collect() forces the generator to run
            list(stream_object(_ErrS3(), BUCKET, KEY))
        assert exc.value.response["Error"]["Code"] == "NoSuchKey"

    def test_default_chunk_size_is_64kb(self):
        """The default chunk_size matches the docstring (64 KiB)."""
        data = b"x" * (64 * 1024 + 10)
        fake, body = self._chunked_body_fake(data)

        chunks = list(stream_object(fake, BUCKET, KEY))

        assert body.chunk_sizes == [64 * 1024]
        # Two chunks: one full 64 KiB + a 10-byte tail.
        assert len(chunks) == 2
        assert len(chunks[0]) == 64 * 1024
        assert chunks[1] == b"x" * 10

    def test_parquet_stream_cap_value(self):
        """Lock the cap value the endpoint branches on (128 MiB)."""
        assert PARQUET_STREAM_CAP == 128 * 1024 * 1024
