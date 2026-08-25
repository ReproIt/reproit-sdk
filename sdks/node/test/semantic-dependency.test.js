import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  createManagedEngineProjectForTest,
  runOperation,
} from "../src/engine-operation.js";
import {
  decodeDependencyRequest,
  decodeDependencyResponse,
  dependencyResponse,
  encodeDependencyRequest,
  encodeDependencyResponse,
  runDependency,
} from "../src/semantic-dependency.js";

const vectorPath = path.resolve(
  import.meta.dirname,
  "../../../.core/specs/v1/protocol-vectors.json",
);
const vectors = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
const positive = vectors.positive;

class DependencyBridge {
  calls = [];
  failDispatch = false;
  failFinish = false;
  failOpen = false;
  failRequestWrite = false;
  failResponseWrite = false;
  requestChunks = [];
  responseChunks = [];
  #action;
  #offset = 0;
  #response;

  constructor(action, response = null) {
    this.#action = action;
    this.#response = response === null
      ? Buffer.alloc(0)
      : Buffer.from(JSON.stringify(response), "utf8");
  }

  operationBegin() {
    return { operationHandle: 2, operationId: "op_dependency_fixture" };
  }

  operationInput() {}

  observationOpen(handle, observationClass, parent) {
    if (this.failOpen) throw new Error("private bridge failure");
    this.calls.push(["observation-open", handle, observationClass, parent]);
    return { observationHandle: 4, sessionPosition: 0 };
  }

  observationWrite(handle, stream, chunk) {
    if (
      (stream === "request" && this.failRequestWrite) ||
      (stream === "response" && this.failResponseWrite)
    ) {
      throw new Error("private bridge failure");
    }
    this.calls.push(["observation-write", handle, stream, chunk.length]);
    const destination = stream === "request"
      ? this.requestChunks
      : this.responseChunks;
    destination.push(Buffer.from(chunk));
  }

  observationDispatch() {
    if (this.failDispatch) throw new Error("private bridge failure");
    return this.#action;
  }

  observationRead() {
    const end = Math.min(this.#offset + 8_192, this.#response.length);
    const chunk = this.#response.subarray(this.#offset, end);
    this.#offset = end;
    return { chunk, eof: this.#offset === this.#response.length };
  }

  observationFinish(handle, outcome, position) {
    if (this.failFinish) throw new Error("private bridge failure");
    this.calls.push(["observation-finish", handle, outcome, position]);
  }

  observationAbandon(handle) {
    this.calls.push(["observation-abandon", handle]);
  }

  operationUnowned(handle, observationClass, evidence) {
    this.calls.push(["operation-unowned", handle, observationClass, evidence]);
  }

  operationSucceed() {}

  operationAbandon(handle) {
    this.calls.push(["operation-abandon", handle]);
  }

  engineClose() {}
}

test("all positive Core dependency vectors round trip exactly", () => {
  for (const suffix of ["database", "outbound_http", "queue"]) {
    const requestValue = positive[`semantic_dependency_request_${suffix}`].value;
    const responseValue = positive[`semantic_dependency_response_${suffix}`].value;
    const requestRecord = canonicalBytes(requestValue);
    const responseRecord = canonicalBytes(responseValue);
    const request = decodeDependencyRequest(requestRecord);
    const response = decodeDependencyResponse(requestRecord, responseRecord);
    assert.deepEqual(encodeDependencyRequest(request), requestRecord);
    assert.deepEqual(
      encodeDependencyResponse(requestRecord, response),
      responseRecord,
    );
  }
  const http = decodeDependencyRequest(canonicalBytes(
    positive.semantic_dependency_request_outbound_http.value,
  ));
  assert.deepEqual(
    http.metadata.map((field) => [field.name, field.value.toString("utf8")]),
    [["x-tag", "capture"], ["x-tag", "second"]],
  );
});

test("all negative Core dependency vectors are rejected", () => {
  const negatives = vectors.negative.filter((vector) =>
    vector.name.startsWith("semantic-dependency-"));
  assert.equal(negatives.length, 9);
  for (const vector of negatives) {
    const mutated = structuredClone(positive[vector.base].value);
    applyVectorChange(mutated, vector);
    const record = canonicalBytes(mutated);
    assert.throws(() => {
      if (vector.schema === "semantic_dependency_request") {
        decodeDependencyRequest(record);
        return;
      }
      const suffix = vector.base.replace("semantic_dependency_response_", "");
      const request = canonicalBytes(
        positive[`semantic_dependency_request_${suffix}`].value,
      );
      decodeDependencyResponse(request, record);
    }, { code: "ERR_REPROIT_SEMANTIC_DEPENDENCY" }, vector.name);
  }
});

test("capture and replay use only the generic observation session", async () => {
  const requestRecord = canonicalBytes(
    positive.semantic_dependency_request_outbound_http.value,
  );
  const responseRecord = canonicalBytes(
    positive.semantic_dependency_response_outbound_http.value,
  );
  const request = decodeDependencyRequest(requestRecord);
  const response = decodeDependencyResponse(requestRecord, responseRecord);

  const captureBridge = new DependencyBridge("capture");
  const captured = await run(captureBridge, () =>
    runDependency(request, async () => response));
  assert.deepEqual(captured, response);
  assert.deepEqual(Buffer.concat(captureBridge.requestChunks), requestRecord);
  assert.deepEqual(Buffer.concat(captureBridge.responseChunks), responseRecord);
  assert.deepEqual(captureBridge.calls.at(-1), [
    "observation-finish", 4, "response", 0,
  ]);

  const replayBridge = new DependencyBridge(
    "replay",
    positive.semantic_dependency_response_outbound_http.value,
  );
  const replayed = run(replayBridge, () => runDependency(request, () => {
    throw new Error("Replay called the live dependency.");
  }));
  assert.deepEqual(replayed, response);
});

test("bounds apply before a session and corrupt replay has no live fallback", () => {
  const invalid = {
    encoding: "postgresql-wire-v3",
    metadata: [],
    method: null,
    observationClass: "database",
    operation: "database-execute",
    payload: Buffer.alloc(24 * 1_024 + 1),
    protocol: "postgresql",
    target: "primary",
  };
  const boundBridge = new DependencyBridge("capture");
  const sentinel = dependencyResponse({
    metadata: [],
    outcome: "response",
    payload: Buffer.alloc(0),
    status: "complete",
  });
  assert.equal(
    run(boundBridge, () => runDependency(invalid, () => sentinel)),
    sentinel,
  );
  assert.equal(
    boundBridge.calls.some((call) => call[0] === "observation-open"),
    false,
  );
  assert.equal(
    boundBridge.calls.some((call) => call[0] === "operation-unowned"),
    true,
  );

  const request = decodeDependencyRequest(canonicalBytes(
    positive.semantic_dependency_request_outbound_http.value,
  ));
  const replayBridge = new DependencyBridge("replay", {});
  assert.throws(
    () => run(replayBridge, () => runDependency(request, () => {
      throw new Error("Replay called the live dependency.");
    })),
    { code: "ERR_REPROIT_SEMANTIC_DEPENDENCY" },
  );
  assert.equal(
    replayBridge.calls.some((call) => call[0] === "observation-abandon"),
    true,
  );
});

test("request infrastructure failures preserve one exact live result or error", () => {
  const request = decodeDependencyRequest(canonicalBytes(
    positive.semantic_dependency_request_outbound_http.value,
  ));
  const response = decodeDependencyResponse(
    encodeDependencyRequest(request),
    canonicalBytes(positive.semantic_dependency_response_outbound_http.value),
  );
  for (const mode of [
    "invalid", "open", "write", "dispatch", "action", "live",
  ]) {
    const selected = mode === "invalid"
      ? { ...request, payload: Buffer.alloc(24 * 1_024 + 1) }
      : request;
    const resultBridge = failedRequestBridge(mode);
    let resultCalls = 0;
    const result = run(resultBridge, () => runDependency(selected, () => {
      resultCalls += 1;
      return response;
    }));
    assert.equal(result, response, `${mode} result identity`);
    assert.equal(resultCalls, 1, `${mode} result calls`);

    const errorBridge = failedRequestBridge(mode);
    const sentinel = new Error("application sentinel");
    let errorCalls = 0;
    let raised;
    try {
      run(errorBridge, () => runDependency(selected, () => {
        errorCalls += 1;
        throw sentinel;
      }));
    } catch (error) {
      raised = error;
    }
    assert.equal(raised, sentinel, `${mode} error identity`);
    assert.equal(errorCalls, 1, `${mode} error calls`);
  }
});

test("response infrastructure failures preserve the exact live result", () => {
  const request = decodeDependencyRequest(canonicalBytes(
    positive.semantic_dependency_request_outbound_http.value,
  ));
  const response = decodeDependencyResponse(
    encodeDependencyRequest(request),
    canonicalBytes(positive.semantic_dependency_response_outbound_http.value),
  );
  for (const mode of ["encode", "write", "finish"]) {
    const bridge = new DependencyBridge("capture");
    bridge.failResponseWrite = mode === "write";
    bridge.failFinish = mode === "finish";
    const sentinel = mode === "encode" ? { application: "result" } : response;
    let calls = 0;
    const result = run(bridge, () => runDependency(request, () => {
      calls += 1;
      return sentinel;
    }));
    assert.equal(result, sentinel, `${mode} result identity`);
    assert.equal(calls, 1, `${mode} result calls`);
  }
});

function run(bridge, call) {
  const project = createManagedEngineProjectForTest(bridge, 1, () => "unused");
  return runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    call,
    () => null,
  );
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function failedRequestBridge(mode) {
  const bridge = new DependencyBridge(mode === "action" ? "unknown" : "capture");
  bridge.failOpen = mode === "open";
  bridge.failRequestWrite = mode === "write";
  bridge.failDispatch = mode === "dispatch";
  return bridge;
}

function applyVectorChange(value, vector) {
  const parts = vector.path.replace(/^\//u, "").split("/");
  let parent = value;
  for (const part of parts.slice(0, -1)) {
    parent = Array.isArray(parent) ? parent[Number(part)] : parent[part];
  }
  const key = parts.at(-1);
  if (Array.isArray(parent)) parent[Number(key)] = vector.value;
  else parent[key] = vector.value;
}
