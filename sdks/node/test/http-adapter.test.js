import assert from "node:assert/strict";
import { EventEmitter, errorMonitor } from "node:events";
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
  abandons = 0;
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
  operationAbandon() {
    this.abandons += 1;
  }
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

test("HTTP capture streams a body and replay performs no live request", async () => {
  const server = httpModule.createServer((_request, response) => {
    response.setHeader("X-Tag", ["first", "second"]);
    response.setHeader("Trailer", "X-Checksum");
    response.writeHead(200);
    response.addTrailers({ "X-Checksum": "abc123" });
    response.end("response body");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const target = `http://127.0.0.1:${address.port}/empty?value=1`;
  const captureBridge = new HttpBridge("capture");
  let captureRequest;
  let captureResponse;
  const captureChunks = [];
  try {
    await withAdapters(() => run(captureBridge, () => new Promise((resolve, reject) => {
      captureRequest = httpModule.get(target, { headers: { "X-Order": ["a", "b"] } },
        (response) => {
          captureResponse = response;
          response.on("data", (chunk) => captureChunks.push(chunk));
          response.once("end", resolve);
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
  assert.equal(captureBridge.responses[0].status_code, 200);
  assert.equal(Buffer.concat(captureChunks).toString(), "response body");
  assert.equal(captureResponse.trailers["x-checksum"], "abc123");
  assert.equal(responsePayload(captureBridge.responses[0]).body, "response body");
  assert.deepEqual(captureBridge.unowned, []);
  assert.deepEqual(
    captureBridge.requests[0].metadata.map((field) => field.value),
    ["YQ", "Yg"],
  );

  const replayBridge = new HttpBridge("replay", captureBridge.responses[0]);
  let replayRequest;
  let replayResponse;
  const replayChunks = [];
  await withAdapters(() => run(replayBridge, () => new Promise((resolve, reject) => {
    replayRequest = httpModule.get(target, { headers: { "X-Order": ["a", "b"] } },
      (response) => {
        replayResponse = response;
        response.on("data", (chunk) => replayChunks.push(chunk));
        response.once("end", resolve);
      });
    replayRequest.once("error", reject);
  })));
  assert.equal(replayResponse.statusCode, 200);
  assert.equal(replayResponse.statusMessage, captureResponse.statusMessage);
  assert.equal(Buffer.concat(replayChunks).toString(), "response body");
  assert.equal(replayResponse.trailers["x-checksum"], "abc123");
  assert.equal(replayRequest instanceof httpModule.ClientRequest, true);
  assert.equal(replayResponse instanceof httpModule.IncomingMessage, true);
  assert.equal(replayRequest.finished, true);
  assert.equal(replayBridge.responses.length, 0);
});

test("a built-in HTTP error keeps its live identity and stays local", async () => {
  const target = await closedLocalTarget();
  const bridge = new HttpBridge("capture");
  let monitoredError;
  let deliveredError;
  await withAdapters(() => run(bridge, () => new Promise((resolve) => {
    const request = httpModule.get(target);
    request.once(errorMonitor, (error) => {
      monitoredError = error;
    });
    request.once("error", (error) => {
      deliveredError = error;
      resolve();
    });
  })));

  assert.equal(deliveredError, monitoredError);
  assert.equal(deliveredError instanceof Error, true);
  assert.equal(bridge.requests.length, 1);
  assert.equal(bridge.responses.length, 0);
  assert.equal(bridge.unowned.includes("outbound-http"), true);
  assert.equal(bridge.abandons, 1);
});

test("an HTTPS error keeps the exact built-in error object and stays local", async () => {
  const sourceError = await builtInConnectionError();
  const { bridge, deliveredError } = await captureSyntheticError(
    sourceError,
    httpsModule,
    "https://127.0.0.1:1/synthetic-error",
  );
  assert.equal(deliveredError, sourceError);
  assert.equal(bridge.requests.length, 1);
  assert.equal(bridge.responses.length, 0);
  assert.equal(bridge.unowned.includes("outbound-http"), true);
  assert.equal(bridge.abandons, 1);
});

test("subclasses, added fields, and oversized HTTP errors stay local", async () => {
  const addedField = new Error("added field");
  addedField.code = "ECUSTOM";
  for (const error of [
    new TypeError("subclass"),
    addedField,
    new Error("x".repeat(16 * 1_024 + 1)),
  ]) {
    const { bridge, deliveredError, sourceError } = await captureSyntheticError(error);
    assert.equal(deliveredError, sourceError);
    assert.equal(bridge.responses.length, 0);
    assert.equal(bridge.unowned.includes("outbound-http"), true);
    assert.equal(bridge.abandons, 1);
  }
});

test("unsupported credentials, agents, options, and request API become unowned", async () => {
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

test("partial, oversized, and sensitive HTTP responses stay local", async () => {
  for (const serve of [
    (_request, response) => {
      response.writeHead(200, { Connection: "close", "Content-Length": "5" });
      response.end("x");
    },
    (_request, response) => {
      response.writeHead(200, { Connection: "close" });
      response.end(Buffer.alloc(16 * 1024 + 1));
    },
    (_request, response) => {
      response.writeHead(200, { Connection: "close", "Set-Cookie": "private=value" });
      response.end("x");
    },
  ]) {
    const server = httpModule.createServer(serve);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const target = `http://127.0.0.1:${server.address().port}/unsafe`;
    const bridge = new HttpBridge("capture");
    try {
      await withAdapters(() => run(bridge, () => new Promise((resolve) => {
        const request = httpModule.get(target, (response) => {
          response.resume();
          response.once("aborted", resolve);
          response.once("end", resolve);
          response.once("close", resolve);
        });
        request.once("error", resolve);
      })));
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    assert.equal(bridge.unowned.includes("outbound-http"), true);
    assert.equal(bridge.responses.length, 0);
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

test("corrupt streamed HTTP replay stops without a live request", async () => {
  const replay = {
    error_code: null,
    error_number: null,
    metadata: [],
    outcome: "response",
    payload: Buffer.from(JSON.stringify({
      body: "*",
      format: "reproit.node-http-response.v1",
      http_version: "1.1",
      raw_trailers: [],
      status_code: 200,
      status_message: "OK",
    })).toString("base64url"),
    status: null,
    status_code: 200,
  };
  const bridge = new HttpBridge("replay", replay);
  await withAdapters(() => run(bridge, () => new Promise((resolve, reject) => {
    const request = httpModule.get("http://127.0.0.1:1/no-live-stream");
    request.once("response", () => reject(new Error("Replay used a response.")));
    request.once("error", (error) => {
      assert.equal(error.code, "ERR_REPROIT_HTTP_REPLAY");
      resolve();
    });
  })));
});

test("recorded HTTP errors are rejected without a live request", async () => {
  const replay = {
    error_code: "other",
    error_number: null,
    metadata: [],
    outcome: "error",
    payload: Buffer.from(JSON.stringify({
      format: "reproit.node-http-empty-response.v1",
      message: "not replayable",
    })).toString("base64url"),
    status: null,
    status_code: null,
  };
  let liveCalls = 0;
  await withFakeModuleGet(httpModule, () => {
    liveCalls += 1;
    throw new Error("A live HTTP request was attempted.");
  }, async () => {
    const bridge = new HttpBridge("replay", replay);
    await withAdapters(() => run(bridge, () => new Promise((resolve, reject) => {
      const request = httpModule.get("http://127.0.0.1:1/no-live-error-request");
      request.once("response", () => reject(new Error("Replay used a response.")));
      request.once("error", (error) => {
        assert.equal(error.code, "ERR_REPROIT_HTTP_REPLAY");
        resolve();
      });
    })));
  });
  assert.equal(liveCalls, 0);
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

async function closedLocalTarget() {
  const server = httpModule.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return `http://127.0.0.1:${port}/closed`;
}

async function builtInConnectionError() {
  const target = await closedLocalTarget();
  return new Promise((resolve) => {
    httpModule.get(target).once("error", resolve);
  });
}

async function captureSyntheticError(
  sourceError,
  module = httpModule,
  target = "http://127.0.0.1:1/synthetic-error",
) {
  let deliveredError;
  const bridge = new HttpBridge("capture");
  await withFakeModuleGet(module, () => {
    const request = new EventEmitter();
    process.nextTick(() => request.emit("error", sourceError));
    return request;
  }, () => withAdapters(() => run(bridge, () => new Promise((resolve) => {
    const request = module.get(target);
    request.once("error", (error) => {
      deliveredError = error;
      resolve();
    });
  }))));
  return { bridge, deliveredError, sourceError };
}

async function withFakeModuleGet(module, replacement, action) {
  const descriptor = Object.getOwnPropertyDescriptor(module, "get");
  Object.defineProperty(module, "get", { ...descriptor, value: replacement });
  try {
    return await action();
  } finally {
    Object.defineProperty(module, "get", descriptor);
  }
}

function responseRecord(value) {
  return Buffer.from(JSON.stringify(value));
}

function responsePayload(value) {
  const payload = JSON.parse(Buffer.from(value.payload, "base64url").toString("utf8"));
  return {
    ...payload,
    body: Buffer.from(payload.body, "base64url").toString("utf8"),
  };
}
