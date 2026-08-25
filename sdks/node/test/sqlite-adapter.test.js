import assert from "node:assert/strict";
import { setImmediate as nextTurn } from "node:timers/promises";
import { createRequire } from "node:module";
import test from "node:test";

import {
  createManagedEngineProjectForTest,
  runOperation,
} from "../src/engine-operation.js";
import {
  acquireRuntimeObservationAdapters,
  runtimeObservationAdapterStateForTest,
} from "../src/runtime-observation-adapters.js";

const require = createRequire(import.meta.url);
const sqliteModule = require("node:sqlite");
const workerThreads = require("node:worker_threads");

class SqliteBridge {
  abandoned = 0;
  requests = [];
  responses = [];
  unowned = [];
  #action;
  #currentResponse = null;
  #nextHandle = 4;
  #offset = 0;
  #replayResponses;

  constructor(action, replayResponses = []) {
    this.#action = action;
    this.#replayResponses = replayResponses;
  }

  operationBegin() {
    return { operationHandle: 2, operationId: "op_sqlite" };
  }

  operationInput() {}

  dependencyOpen(_operationHandle, request) {
    this.requests.push(request);
    const dependencyHandle = this.#nextHandle;
    this.#nextHandle += 1;
    if (this.#action === "replay") {
      this.#currentResponse = this.#replayResponses.shift();
      this.#offset = 0;
    }
    return { action: this.#action, dependencyHandle };
  }

  observationRead() {
    const bytes = responseRecord(this.#currentResponse);
    const end = Math.min(this.#offset + 97, bytes.length);
    const chunk = bytes.subarray(this.#offset, end);
    this.#offset = end;
    return { chunk, eof: end === bytes.length };
  }

  dependencyFinish(_dependencyHandle, response) {
    if (response !== null) {
      this.responses.push(response);
      return response.outcome;
    }
    return this.#currentResponse?.outcome ?? null;
  }

  operationUnowned(_operationHandle, observationClass, evidence) {
    this.unowned.push({ evidence: Buffer.from(evidence), observationClass });
  }

  operationSucceed() {}

  operationAbandon() {
    this.abandoned += 1;
  }

  engineClose() {}
}

test("the runtime lease installs SQLite once and restores it after the last lease", () => {
  const originalExec = sqliteModule.DatabaseSync.prototype.exec;
  const firstRelease = acquireRuntimeObservationAdapters();
  const installedExec = sqliteModule.DatabaseSync.prototype.exec;
  const secondRelease = acquireRuntimeObservationAdapters();
  try {
    assert.notEqual(installedExec, originalExec);
    assert.equal(sqliteModule.DatabaseSync.prototype.exec, installedExec);
    assert.equal(
      runtimeObservationAdapterStateForTest().classes.filter(
        (value) => value === "database",
      ).length,
      1,
    );
    firstRelease();
    assert.equal(sqliteModule.DatabaseSync.prototype.exec, installedExec);
  } finally {
    firstRelease();
    secondRelease();
  }
  assert.equal(sqliteModule.DatabaseSync.prototype.exec, originalExec);
});

test("a missing required hook restores partial hooks and skips registration", () => {
  const runDescriptor = Object.getOwnPropertyDescriptor(
    sqliteModule.StatementSync.prototype,
    "run",
  );
  const originalExec = sqliteModule.DatabaseSync.prototype.exec;
  Object.defineProperty(sqliteModule.StatementSync.prototype, "run", {
    ...runDescriptor,
    value: null,
  });
  let release;
  try {
    release = acquireRuntimeObservationAdapters();
    assert.equal(
      runtimeObservationAdapterStateForTest().classes.includes("database"),
      false,
    );
    assert.equal(sqliteModule.DatabaseSync.prototype.exec, originalExec);
  } finally {
    release?.();
    Object.defineProperty(
      sqliteModule.StatementSync.prototype,
      "run",
      runDescriptor,
    );
  }
});

test("exec, prepare, get, all, and run replay without live SQLite", () => {
  const capture = withAdapters(() => {
    const database = new sqliteModule.DatabaseSync(":memory:");
    const bridge = new SqliteBridge("capture");
    try {
      const value = run(bridge, () => {
        database.exec("CREATE TABLE records (id INTEGER, body BLOB)");
        const insert = database.prepare(
          "INSERT INTO records (id, body) VALUES (?, ?)",
        );
        const runResult = insert.run(7n, new Uint8Array([1, 2, 255]));
        const select = database.prepare(
          "SELECT id, body FROM records WHERE id = ?",
        );
        assert.equal(select instanceof sqliteModule.StatementSync, true);
        assert.equal(select.sourceSQL, "SELECT id, body FROM records WHERE id = ?");
        return {
          all: select.all(7),
          get: select.get(7),
          run: runResult,
        };
      });
      return { bridge, value };
    } finally {
      database.close();
    }
  });

  assert.equal(capture.bridge.requests.length, 6);
  assert.deepEqual(
    capture.bridge.requests.map((request) => requestPayload(request)[1]),
    ["exec", "prepare", "run", "prepare", "all", "get"],
  );
  assert.equal(capture.bridge.responses.length, 6);
  const runRequest = requestPayload(capture.bridge.requests[2]);
  assert.deepEqual(runRequest.slice(1, 5), [
    "run",
    "database-1",
    1,
    "INSERT INTO records (id, body) VALUES (?, ?)",
  ]);
  assert.deepEqual(runRequest[5], [
    ["value", ["bigint", "7"]],
    ["value", ["blob", "AQL_"]],
  ]);

  const replay = withAdapters(() => {
    const database = new sqliteModule.DatabaseSync(":memory:");
    database.close();
    const bridge = new SqliteBridge("replay", [...capture.bridge.responses]);
    const value = run(bridge, () => {
      database.exec("CREATE TABLE records (id INTEGER, body BLOB)");
      const insert = database.prepare(
        "INSERT INTO records (id, body) VALUES (?, ?)",
      );
      const runResult = insert.run(7n, new Uint8Array([1, 2, 255]));
      const select = database.prepare(
        "SELECT id, body FROM records WHERE id = ?",
      );
      assert.equal(select instanceof sqliteModule.StatementSync, true);
      assert.equal(select.sourceSQL, "SELECT id, body FROM records WHERE id = ?");
      return {
        all: select.all(7),
        get: select.get(7),
        run: runResult,
      };
    });
    return { bridge, value };
  });
  assert.deepEqual(replay.value, capture.value);
  assert.deepEqual(
    replay.bridge.requests.map((request) => requestPayload(request)),
    capture.bridge.requests.map((request) => requestPayload(request)),
  );
});

test("capture preserves exact results and exceptions", () => {
  const descriptor = Object.getOwnPropertyDescriptor(
    sqliteModule.StatementSync.prototype,
    "get",
  );
  const sentinelResult = Object.assign(Object.create(null), { value: 41n });
  const sentinelError = new Error("application sentinel");
  Object.defineProperty(sqliteModule.StatementSync.prototype, "get", {
    ...descriptor,
    value(argument) {
      if (argument === "throw") throw sentinelError;
      return sentinelResult;
    },
  });
  try {
    withAdapters(() => {
      const database = new sqliteModule.DatabaseSync(":memory:");
      const statement = database.prepare("SELECT ? AS value");
      try {
        const resultBridge = new SqliteBridge("capture");
        assert.equal(run(resultBridge, () => statement.get("result")), sentinelResult);
        const errorBridge = new SqliteBridge("capture");
        assert.throws(
          () => run(errorBridge, () => statement.get("throw")),
          (error) => error === sentinelError,
        );
        assert.equal(errorBridge.abandoned, 1);
      } finally {
        database.close();
      }
    });
  } finally {
    Object.defineProperty(sqliteModule.StatementSync.prototype, "get", descriptor);
  }
});

test("BigInt, blobs, named bindings, rows, and arrays keep their shapes", () => {
  const capture = withAdapters(() => {
    const database = new sqliteModule.DatabaseSync(":memory:");
    const objectStatement = database.prepare(
      "SELECT $big AS big, $blob AS blob",
    );
    objectStatement.setReadBigInts(true);
    const arrayStatement = database.prepare("SELECT ? AS value");
    arrayStatement.setReturnArrays(true);
    try {
      const bridge = new SqliteBridge("capture");
      const value = run(bridge, () => ({
        array: arrayStatement.get(9),
        object: objectStatement.get({
          $big: 9_007_199_254_740_991n,
          $blob: new Uint8Array([0, 128, 255]),
        }),
      }));
      return { bridge, value };
    } finally {
      database.close();
    }
  });
  assert.equal(Object.getPrototypeOf(capture.value.object), null);
  assert.equal(capture.value.object.big, 9_007_199_254_740_991n);
  assert.deepEqual(capture.value.object.blob, new Uint8Array([0, 128, 255]));
  assert.deepEqual(capture.value.array, [9]);
  const namedRequest = requestPayload(capture.bridge.requests[1]);
  assert.deepEqual(namedRequest[5][0][0], "named");
  assert.deepEqual(
    namedRequest[5][0][1][1].map((field) => field[0]),
    ["$big", "$blob"],
  );
});

test("unsupported and over-bound operations become unowned", () => {
  withAdapters(() => {
    const database = new sqliteModule.DatabaseSync(":memory:");
    const statement = database.prepare("SELECT length(?) AS length");
    try {
      const bridge = new SqliteBridge("capture");
      const value = run(bridge, () => statement.get("x".repeat(16 * 1_024 + 1)));
      assert.equal(value.length, 16 * 1_024 + 1);
      assert.equal(bridge.requests.length, 0);
      assert.deepEqual(bridge.unowned.map((entry) => entry.observationClass), [
        "database",
      ]);

      const unsupportedBridge = new SqliteBridge("capture");
      run(unsupportedBridge, () => [...statement.iterate("value")]);
      run(unsupportedBridge, () => database.serialize());
      assert.throws(() => run(
        unsupportedBridge,
        () => Reflect.apply(process.dlopen, null, [{}, ""]),
      ));
      assert.throws(() => run(
        unsupportedBridge,
        () => Reflect.apply(workerThreads.Worker, null, []),
      ));
      assert.equal(
        unsupportedBridge.unowned.every(
          (entry) => entry.observationClass === "database",
        ),
        true,
      );
      assert.equal(unsupportedBridge.unowned.length, 4);
    } finally {
      database.close();
    }
  });
});

test("unsupported replay getters stop without live SQLite", () => {
  const capture = withAdapters(() => {
    const database = new sqliteModule.DatabaseSync(":memory:");
    const bridge = new SqliteBridge("capture");
    try {
      run(bridge, () => database.prepare("SELECT 1"));
      return bridge.responses;
    } finally {
      database.close();
    }
  });
  withAdapters(() => {
    const database = new sqliteModule.DatabaseSync(":memory:");
    database.close();
    const bridge = new SqliteBridge("replay", [...capture]);
    assert.throws(
      () => run(bridge, () => database.prepare("SELECT 1").expandedSQL),
      { code: "ERR_REPROIT_SQLITE_REPLAY" },
    );
    assert.deepEqual(bridge.unowned.map((entry) => entry.observationClass), [
      "database",
    ]);
  });
});

test("parallel operation contexts keep dependency ordering separate", async () => {
  await withAdapters(async () => {
    const database = new sqliteModule.DatabaseSync(":memory:");
    const statement = database.prepare("SELECT ? AS value");
    const firstBridge = new SqliteBridge("capture");
    const secondBridge = new SqliteBridge("capture");
    try {
      const [first, second] = await Promise.all([
        runAsync(firstBridge, async () => {
          await nextTurn();
          return statement.get(1);
        }),
        runAsync(secondBridge, async () => {
          await nextTurn();
          return statement.get(2);
        }),
      ]);
      assert.equal(first.value, 1);
      assert.equal(second.value, 2);
      assert.equal(requestPayload(firstBridge.requests[0])[5][0][1][1], "1");
      assert.equal(requestPayload(secondBridge.requests[0])[5][0][1][1], "2");
    } finally {
      database.close();
    }
  });
});

function responseRecord(value) {
  if (value === undefined) return Buffer.from("null");
  return Buffer.from(JSON.stringify({
    error_code: value.errorCode,
    error_number: value.errorNumber,
    metadata: value.metadata.map((field) => ({
      name: Buffer.from(field.name).toString("base64url"),
      value: field.value.toString("base64url"),
    })),
    outcome: value.outcome,
    payload: value.payload === null ? null : value.payload.toString("base64url"),
    status: value.status,
    status_code: value.statusCode,
  }));
}

function requestPayload(request) {
  return JSON.parse(Buffer.from(request.payload, "base64url").toString("utf8"));
}

function run(bridge, operation) {
  const project = createManagedEngineProjectForTest(bridge, 1, () => "unused");
  return runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    operation,
    () => null,
  );
}

function runAsync(bridge, operation) {
  return Promise.resolve(run(bridge, operation));
}

function withAdapters(action) {
  const release = acquireRuntimeObservationAdapters();
  let result;
  try {
    result = action();
  } catch (error) {
    release();
    throw error;
  }
  if (result !== null && typeof result?.then === "function") {
    return Promise.resolve(result).finally(release);
  }
  release();
  return result;
}
