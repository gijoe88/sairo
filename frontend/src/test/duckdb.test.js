/**
 * Tests for the lazy DuckDB singleton (lib/duckdb.js).
 *
 * Real WASM cannot instantiate under jsdom, so @duckdb/duckdb-wasm and the
 * Vite `?url` asset imports are mocked. These tests exercise the singleton
 * lifecycle and result shaping without touching real WASM. A live WASM smoke
 * test belongs to e2e (T6), not here.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
// Imported from the mocked module (below) so we can assert on the constructor
// itself in the concurrent-singleton test.
import { AsyncDuckDB } from "@duckdb/duckdb-wasm";

// Track calls to the connection so we can assert on query/drop sequences.
const connQuery = vi.fn();
const dbRegisterFileBuffer = vi.fn();
const dbDropFile = vi.fn();
const dbInstantiate = vi.fn();
const dbConnect = vi.fn();
const dbTerminate = vi.fn();

// Minimal arrow.Table-shaped object returned by the mocked connection.query().
function fakeArrowTable(fields, rowObjs) {
  return {
    schema: { fields: fields.map((name) => ({ name })) },
    numRows: rowObjs.length,
    get: (i) => rowObjs[i],
  };
}

// Mock the duckdb-wasm package + the Vite ?url asset imports BEFORE importing
// the module under test. The `?url` suffix imports resolve to plain strings.
vi.mock("@duckdb/duckdb-wasm", () => ({
  AsyncDuckDB: vi.fn().mockImplementation(() => ({
    instantiate: dbInstantiate.mockResolvedValue(null),
    connect: dbConnect.mockResolvedValue({ query: connQuery }),
    registerFileBuffer: dbRegisterFileBuffer.mockResolvedValue(null),
    dropFile: dbDropFile.mockResolvedValue(null),
    terminate: dbTerminate.mockResolvedValue(null),
  })),
  ConsoleLogger: vi.fn(),
}));
vi.mock("@duckdb/duckdb-wasm/dist/duckdb-browser-mvp.worker.js?url", () => ({
  default: "/fake-duckdb-mvp.worker.js",
}));
vi.mock("@duckdb/duckdb-wasm/dist/duckdb-mvp.wasm?url", () => ({
  default: "/fake-duckdb-mvp.wasm",
}));

// jsdom has no Worker global; getDuckDB() calls `new Worker(workerUrl)`. Provide
// a no-op stub so the singleton can construct the (mocked) AsyncDuckDB.
global.Worker = class {
  postMessage() {}
  terminate() {}
  addEventListener() {}
  removeEventListener() {}
};

// Import AFTER mocks are registered. Reset module state between tests.
let duckdb;
beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();
  duckdb = await import("../lib/duckdb");
});

describe("duckdb singleton", () => {
  it("getDuckDB returns the same instance on repeated calls (singleton)", async () => {
    const a = await duckdb.getDuckDB();
    const b = await duckdb.getDuckDB();
    // AsyncDuckDB constructor should fire exactly once.
    expect(a.db).toBe(b.db);
    expect(a.conn).toBe(b.conn);
    // instantiate + connect also exactly once.
    expect(dbInstantiate).toHaveBeenCalledTimes(1);
    expect(dbConnect).toHaveBeenCalledTimes(1);
  });

  it("getDuckDB instantiates once under concurrent calls (pending guard)", async () => {
    // Two getDuckDB() calls racing in the same tick must share the single
    // in-flight instantiation promise instead of each spawning their own
    // Worker + WASM. Fails if the `_pending` guard is removed.
    const [a, b] = await Promise.all([duckdb.getDuckDB(), duckdb.getDuckDB()]);
    expect(a.db).toBe(b.db);
    expect(a.conn).toBe(b.conn);
    // The mock AsyncDuckDB constructor ran exactly once.
    expect(AsyncDuckDB).toHaveBeenCalledTimes(1);
    expect(dbInstantiate).toHaveBeenCalledTimes(1);
    expect(dbConnect).toHaveBeenCalledTimes(1);
  });

  it("query returns a { columns, rows } row-major result set", async () => {
    connQuery.mockResolvedValueOnce(
      fakeArrowTable(["id", "name"], [{ id: 1, name: "a" }, { id: 2, name: "b" }])
    );
    const result = await duckdb.query("SELECT * FROM t");
    expect(result.columns).toEqual(["id", "name"]);
    expect(result.rows).toEqual([[1, "a"], [2, "b"]]);
  });

  it("register registers the buffer and creates the view, then reset drops it", async () => {
    connQuery.mockResolvedValue(fakeArrowTable([], [])); // CREATE VIEW + DROP VIEW
    const buf = new Uint8Array([1, 2, 3]);
    await duckdb.register(buf, "t");

    expect(dbRegisterFileBuffer).toHaveBeenCalledTimes(1);
    // file name is <view>.parquet
    expect(dbRegisterFileBuffer).toHaveBeenCalledWith("t.parquet", buf);
    // CREATE OR REPLACE VIEW was issued
    const createSql = connQuery.mock.calls[0][0];
    expect(createSql).toContain("CREATE OR REPLACE VIEW t");

    await duckdb.reset();
    // reset drops the view and the backing file
    const dropSql = connQuery.mock.calls
      .map((c) => c[0])
      .find((sql) => sql.startsWith("DROP VIEW IF EXISTS t"));
    expect(dropSql).toBe("DROP VIEW IF EXISTS t");
    expect(dbDropFile).toHaveBeenCalledWith("t.parquet");
  });

  it("register tracks the buffer before CREATE VIEW so a failed view is still droppable via reset()", async () => {
    // registerFileBuffer succeeds, but the subsequent CREATE OR REPLACE VIEW
    // throws. Before the eager-track fix, _registered never recorded `name`, so
    // reset() would skip it and leak the (up to 128 MB) registered buffer.
    dbRegisterFileBuffer.mockResolvedValueOnce(null);
    connQuery.mockRejectedValueOnce(new Error("view DDL failed"));
    await expect(duckdb.register(new Uint8Array([1, 2, 3]), "t"))
      .rejects.toThrow(/Failed to register parquet/);

    // registerFileBuffer ran, so the backing file exists in DuckDB...
    expect(dbRegisterFileBuffer).toHaveBeenCalledWith("t.parquet", expect.any(Uint8Array));
    // ...but CREATE VIEW failed and propagated; it was the only conn.query so far.
    expect(connQuery).toHaveBeenCalledTimes(1);
    expect(connQuery.mock.calls[0][0]).toContain("CREATE OR REPLACE VIEW t");

    // reset() must still drop the orphaned buffer (this is the regression).
    await duckdb.reset();
    expect(dbDropFile).toHaveBeenCalledWith("t.parquet");
  });

  it("reset is a no-op before anything is registered", async () => {
    // Touch the singleton so _db is set, but register nothing.
    await duckdb.getDuckDB();
    await expect(duckdb.reset()).resolves.toBeUndefined();
    expect(dbDropFile).not.toHaveBeenCalled();
  });

  it("query wraps failures in a descriptive Error", async () => {
    connQuery.mockRejectedValueOnce(new Error("syntax error near 'FROMM'"));
    await expect(duckdb.query("SELECT 1 FROMM t")).rejects.toThrow(/DuckDB query failed/);
  });

  it("register wraps failures in a descriptive Error", async () => {
    dbRegisterFileBuffer.mockRejectedValueOnce(new Error("buffer too small"));
    await expect(duckdb.register(new Uint8Array(0), "t")).rejects.toThrow(/Failed to register parquet/);
  });
});
