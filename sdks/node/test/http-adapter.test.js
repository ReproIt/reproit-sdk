import assert from "node:assert/strict";
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
const httpModule = require("node:http");
const httpsModule = require("node:https");

class HttpBridge {
  requests = [];
  responses = [];
  unowned = [];
  #action;
  #offset = 0;
  #replay;

  constructor(action, replay = null) {
    this.#action = action;
    this.#replay = replay;
  }

  operationBegin() {
    return { operationHandle: 2, operationId: "op_http" };
  }

  operationInput() {}

  dependencyOpen(_handle, request) {
    this.requests.push(request);
    return { action: this.#action, dependencyHandle: 4 };
  }

  dependencyFinish(_handle, response) {
    if (response !== null) {
      this.responses.push(response);
      return response.outcome;
    }
    return this.#replay.outcome;
  }

  observationRead() {
    const bytes = responseRecord(this.#replay);
    const end = Math.min(this.#offset + 31, bytes.length);
    const chunk = bytes.subarray(this.#offset, end);
    this.#offset = end;
    return { chunk, eof: end === bytes.length };
  }

  operationUnowned(_handle, observationClass) {
    this.unowned.push(observationClass);
  }

  operationSucceed() {}
  operationAbandon() {}
  engineClose() {}
}

test("the runtime lease installs and conditionally restores HTTP hooks", () => {
  const originalGet = httpModule.get;
  const originalRequest = httpsModule.request;
  const releaseFirst = acquireRuntimeObservationAdapters();
  const installedGet = httpModule.get;
  const releaseSecond = acquireRuntimeObservationAdapters();
  try {
    assert.notEqual(installedGet, originalGet);
    assert.equal(httpModule.get, installedGet);
    assert.notEqual(httpsModule.request, originalRequest);
    assert.equal(
      runtimeObservationAdapterStateForTest().classes.includes("outbound-http"),
      true,
    );
    releaseFirst();
    assert.equal(httpModule.get, installedGet);
  } finally {
    releaseFirst();
    releaseSecond();
  }
  assert.equal(httpModule.get, originalGet);
  assert.equal(httpsModule.request, originalRequest);
});

test("HTTP capture keeps live objects and replay performs no live request", async () => {
  const server = httpModule.createServer((_request, response) => {
    response.setHeader("X-Tag", ["first", "second"]);
    response.writeHead(204);
    response.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const target = `http://127.0.0.1:${address.port}/empty?value=1`;
  const captureBridge = new HttpBridge("capture");
  let captureRequest;
  let captureResponse;
  try {
    await withAdapters(() => run(captureBridge, () => new Promise((resolve, reject) => {
      captureRequest = httpModule.get(target, { headers: { "X-Order": ["a", "b"] } },
        (response) => {
          captureResponse = response;
          resolve();
        });
      captureRequest.once("error", reject);
    })));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  assert.equal(captureRequest instanceof httpModule.ClientRequest, true);
  assert.equal(captureResponse instanceof httpModule.IncomingMessage, true);
  assert.equal(captureBridge.requests.length, 1);
  assert.equal(captureBridge.responses.length, 1);
  assert.equal(captureBridge.requests[0].protocol, "http");
  assert.equal(captureBridge.responses[0].status_code, 204);
  assert.deepEqual(
    captureBridge.requests[0].metadata.map((field) => field.value),
    ["YQ", "Yg"],
  );

  const replayBridge = new HttpBridge("replay", captureBridge.responses[0]);
  let replayRequest;
  let replayResponse;
  await withAdapters(() => run(replayBridge, () => new Promise((resolve, reject) => {
    replayRequest = httpModule.get(target, { headers: { "X-Order": ["a", "b"] } },
      (response) => {
        replayResponse = response;
        resolve();
      });
    replayRequest.once("error", reject);
  })));
  assert.equal(replayResponse.statusCode, 204);
  assert.equal(replayResponse.statusMessage, captureResponse.statusMessage);
  assert.equal(replayRequest instanceof httpModule.ClientRequest, true);
  assert.equal(replayResponse instanceof httpModule.IncomingMessage, true);
  assert.equal(replayRequest.finished, true);
  assert.equal(replayBridge.responses.length, 0);
});

test("unsupported streaming, credentials, agents, and request API become unowned", async () => {
  const server = httpModule.createServer((_request, response) => {
    response.writeHead(200, { "Content-Length": "1" });
    response.end("x");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const target = `http://127.0.0.1:${address.port}/stream`;
  try {
    for (const action of [
      () => httpModule.get(target, { agent: false }),
      () => httpModule.get(target, { headers: { Authorization: "not-recorded" } }),
      () => httpModule.get(target, { timeout: 1 }),
      () => httpModule.request(target).end(),
      () => httpModule.get(target),
    ]) {
      const bridge = new HttpBridge("capture");
      await withAdapters(() => run(bridge, () => new Promise((resolve) => {
        const request = action();
        request.once("error", resolve);
        request.once("response", (response) => {
          response.resume();
          response.once("end", resolve);
        });
      })));
      assert.equal(bridge.unowned.includes("outbound-http"), true);
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("noncanonical replay bytes stop without a live request", async () => {
  const payload = Buffer.from(JSON.stringify({
    format: "reproit.node-http-empty-response.v1",
    http_version: "1.1",
    status_code: 204,
    status_message: "No Content",
  }));
  const replay = {
    error_code: null,
    error_number: null,
    metadata: [],
    outcome: "response",
    payload: Buffer.concat([Buffer.from(" "), payload]).toString("base64url"),
    status: null,
    status_code: 204,
  };
  const bridge = new HttpBridge("replay", replay);
  await withAdapters(() => run(bridge, () => new Promise((resolve, reject) => {
    const request = httpModule.get("http://127.0.0.1:1/no-live-request");
    request.once("response", () => reject(new Error("Replay used a response.")));
    request.once("error", (error) => {
      assert.equal(error.code, "ERR_REPROIT_HTTP_REPLAY");
      resolve();
    });
  })));
});

function run(bridge, operation) {
  const project = createManagedEngineProjectForTest(bridge, 1, () => "unused");
  return runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    operation,
    () => null,
  );
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
  return Promise.resolve(result).finally(release);
}

function responseRecord(value) {
  return Buffer.from(JSON.stringify(value));
}
