import assert from "node:assert/strict";
import test from "node:test";

import {
  createManagedEngineProjectForTest,
  runOperation,
} from "../src/engine-operation.js";
import {
  dependencyRequest,
  dependencyResponse,
  runDependency,
} from "../src/semantic-dependency.js";

function request(changes = {}) {
  return dependencyRequest({
    encoding: "http-1.1-message",
    metadata: [
      { name: "x-tag", value: Buffer.from("first") },
      { name: "x-tag", value: Buffer.from("second") },
    ],
    method: "POST",
    observationClass: "outbound-http",
    operation: "outbound-http-request",
    payload: Buffer.from("request"),
    protocol: "http-1.1",
    target: "https://inventory.example/item",
    ...changes,
  });
}

function response(changes = {}) {
  return dependencyResponse({
    metadata: [
      { name: "x-tag", value: Buffer.from("first") },
      { name: "x-tag", value: Buffer.from("second") },
    ],
    outcome: "response",
    payload: Buffer.from("response"),
    statusCode: 200,
    ...changes,
  });
}

function responseRecord(value) {
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

class DependencyBridge {
  calls = [];
  failFinish = false;
  failOpen = false;
  failRead = false;
  #action;
  #offset = 0;
  #readBytes;
  #response;

  constructor(action, responseBytes = Buffer.alloc(0), readBytes = 17) {
    this.#action = action;
    this.#readBytes = readBytes;
    this.#response = responseBytes;
  }

  operationBegin() {
    return { operationHandle: 2, operationId: "op_dependency" };
  }

  operationInput() {}

  dependencyOpen(handle, dependencyRequestValue, parent) {
    if (this.failOpen) throw new Error("private bridge failure");
    this.calls.push(["dependency-open", handle, dependencyRequestValue, parent]);
    return { action: this.#action, dependencyHandle: 4 };
  }

  observationRead(handle) {
    if (this.failRead) throw new Error("private bridge failure");
    const end = Math.min(this.#offset + this.#readBytes, this.#response.length);
    const chunk = this.#response.subarray(this.#offset, end);
    this.#offset = end;
    this.calls.push(["observation-read", handle, chunk.length]);
    return { chunk, eof: this.#offset === this.#response.length };
  }

  dependencyFinish(handle, dependencyResponseValue) {
    if (this.failFinish) throw new Error("private bridge failure");
    this.calls.push(["dependency-finish", handle, dependencyResponseValue]);
    return dependencyResponseValue?.outcome ?? "response";
  }

  operationSucceed() {}

  operationAbandon(handle) {
    this.calls.push(["operation-abandon", handle]);
  }

  engineClose() {}
}

test("capture uses the exact native call shape for response and error", () => {
  for (const captured of [
    response(),
    response({
      errorCode: "not-found",
      errorNumber: 2,
      metadata: [],
      outcome: "error",
      payload: null,
      statusCode: null,
    }),
  ]) {
    const bridge = new DependencyBridge("capture");
    assert.equal(run(bridge, () => captured), captured);
    const [open, finish] = bridge.calls;
    assert.deepEqual(open.slice(0, 2), ["dependency-open", 2]);
    assert.equal(open[2].payload, "cmVxdWVzdA");
    assert.deepEqual(open[2].metadata, [
      { name: "eC10YWc", value: "Zmlyc3Q" },
      { name: "eC10YWc", value: "c2Vjb25k" },
    ]);
    assert.deepEqual(finish.slice(0, 2), ["dependency-finish", 4]);
    assert.equal(finish[2].outcome, captured.outcome);
  }
});

test("replay reads chunks, finishes validation, then reconstructs", () => {
  const expected = response();
  const bridge = new DependencyBridge("replay", responseRecord(expected), 7);
  let calls = 0;
  const actual = run(bridge, () => {
    calls += 1;
    return expected;
  });
  assert.deepEqual(actual, expected);
  assert.equal(calls, 0);
  assert.deepEqual(bridge.calls.at(-1), ["dependency-finish", 4, null]);
});

test("capture failures preserve one exact result or exception", () => {
  for (const mode of ["conversion", "open", "finish"]) {
    const selected = mode === "conversion"
      ? request({ payload: Buffer.alloc(65_537) })
      : request();
    const resultBridge = new DependencyBridge("capture");
    resultBridge.failOpen = mode === "open";
    resultBridge.failFinish = mode === "finish";
    const expected = response();
    let resultCalls = 0;
    const actual = run(resultBridge, () => {
      resultCalls += 1;
      return expected;
    }, selected);
    assert.equal(actual, expected, `${mode} result identity`);
    assert.equal(resultCalls, 1, `${mode} result calls`);

    const errorBridge = new DependencyBridge("capture");
    errorBridge.failOpen = mode === "open";
    errorBridge.failFinish = mode === "finish";
    const sentinel = new Error("application sentinel");
    let errorCalls = 0;
    assert.throws(() => run(errorBridge, () => {
      errorCalls += 1;
      throw sentinel;
    }, selected), (error) => error === sentinel);
    assert.equal(errorCalls, 1, `${mode} error calls`);
  }
});

test("async capture preserves the exact result", async () => {
  const bridge = new DependencyBridge("capture");
  const expected = response();
  assert.equal(await run(bridge, async () => expected), expected);
});

test("metadata conversion is bounded before engine open", () => {
  const bridge = new DependencyBridge("capture");
  const expected = response();
  const selected = request({
    metadata: [{ name: "name", value: Buffer.alloc(65_537) }],
  });
  assert.equal(run(bridge, () => expected, selected), expected);
  assert.equal(bridge.calls.some((call) => call[0] === "dependency-open"), false);
});

test("replay failures never call the live dependency", () => {
  for (const mode of ["read", "finish", "record"]) {
    const bridge = new DependencyBridge("replay", Buffer.from("not-json"));
    bridge.failRead = mode === "read";
    bridge.failFinish = mode === "finish";
    let calls = 0;
    assert.throws(() => run(bridge, () => {
      calls += 1;
      return response();
    }), { code: "ERR_REPROIT_SEMANTIC_DEPENDENCY" });
    assert.equal(calls, 0);
  }
});

function run(bridge, live, selected = request()) {
  const project = createManagedEngineProjectForTest(bridge, 1, () => "unused");
  return runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    () => runDependency(selected, live),
    () => null,
  );
}
