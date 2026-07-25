/**
 * Tests for api.js utility functions.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { formatSize, formatDate, streamParquetBytes } from "../api";

describe("formatSize", () => {
  it("formats 0 bytes", () => {
    expect(formatSize(0)).toBe("0 B");
  });

  it("formats null as 0 B", () => {
    expect(formatSize(null)).toBe("0 B");
  });

  it("formats bytes", () => {
    expect(formatSize(512)).toBe("512 B");
  });

  it("formats KB", () => {
    expect(formatSize(1024)).toBe("1.0 KB");
    expect(formatSize(1536)).toBe("1.5 KB");
  });

  it("formats MB", () => {
    expect(formatSize(1048576)).toBe("1.0 MB");
  });

  it("formats GB", () => {
    expect(formatSize(1073741824)).toBe("1.0 GB");
  });

  it("formats TB", () => {
    expect(formatSize(1099511627776)).toBe("1.0 TB");
  });
});

describe("formatDate", () => {
  it("formats null as dash", () => {
    expect(formatDate(null)).toBe("—");
  });

  it("formats empty string as dash", () => {
    expect(formatDate("")).toBe("—");
  });

  it("formats ISO date string", () => {
    const result = formatDate("2024-01-15T10:30:00Z");
    expect(result).toBeTruthy();
    expect(result).not.toBe("—");
  });
});

describe("streamParquetBytes", () => {
  beforeEach(() => {
    global.fetch = vi.fn();
  });

  it("hits /parquet-stream?key=… and returns the Response", async () => {
    const fakeRes = { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(4) };
    global.fetch.mockResolvedValueOnce(fakeRes);

    const res = await streamParquetBytes("mybucket", "path/to/file.parquet");

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url] = global.fetch.mock.calls[0];
    // Same-origin, bucket-scoped, key round-trips through URLSearchParams.
    expect(url).toBe("/api/buckets/mybucket/parquet-stream?key=path%2Fto%2Ffile.parquet");
    // The raw Response is handed back so the caller can arrayBuffer() it.
    expect(res).toBe(fakeRes);
  });

  it("throws when the stream fails (non-ok status)", async () => {
    // apiFetch throws for non-ok responses before streamParquetBytes ever sees
    // the Response, so the rejection propagates with the status in the message.
    global.fetch.mockResolvedValueOnce({
      ok: false,
      status: 413,
      clone: () => ({ json: async () => ({}) }),
    });
    await expect(streamParquetBytes("b", "k")).rejects.toThrow(/413/);
  });
});
