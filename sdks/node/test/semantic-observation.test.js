import assert from "node:assert/strict";
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createManagedEngineProjectForTest,
  runOperation,
} from "../src/engine-operation.js";
import { installedObservationAdapters } from "../src/observation-adapters.js";
import {
  acquireRuntimeObservationAdapters,
  runtimeObservationAdapterStateForTest,
} from "../src/runtime-observation-adapters.js";
import {
  encodedTarget,
  semanticRequest,
  SEMANTIC_OPERATIONS,
} from "../src/semantic-observation.js";

const require = createRequire(import.meta.url);
const cryptoModule = require("node:crypto");
const fsModule = require("node:fs");
const coreRoot = process.env.REPROIT_CORE_ROOT ??
  path.resolve(import.meta.dirname, "../../../.core");
const vectors = JSON.parse(fs.readFileSync(
  path.join(coreRoot, "specs/v1/semantic-observation-vector.json"),
  "utf8",
));
const positive = Object.fromEntries(
  vectors.positive.map((vector) => [vector.name, vector]),
);
const negative = Object.fromEntries(
  vectors.negative.map((vector) => [vector.name, vector]),
);

class SemanticBridge {
  calls = [];
  requestChunks = [];
  responseChunks = [];
  #action;
  #readOffset = 0;
  #replayBytes;

  constructor(action, response = null) {
    this.#action = action;
    this.#replayBytes = response === null
      ? Buffer.alloc(0)
      : Buffer.from(JSON.stringify(response), "utf8");
  }

  operationBegin() {
    return { operationHandle: 2, operationId: "op_semantic_fixture" };
  }

  operationInput() {}

  observationOpen(handle, observationClass, parent) {
    this.calls.push(["observation-open", handle, observationClass, parent]);
    return { observationHandle: 4, sessionPosition: 0 };
  }

  observationWrite(handle, stream, chunk) {
    this.calls.push(["observation-write", handle, stream, chunk.length]);
    const destination = stream === "request"
      ? this.requestChunks
      : this.responseChunks;
    destination.push(Buffer.from(chunk));
  }

  observationDispatch() {
    this.calls.push(["observation-dispatch"]);
    return this.#action;
  }

  observationRead() {
    const end = Math.min(this.#readOffset + 1_024, this.#replayBytes.length);
    const chunk = this.#replayBytes.subarray(this.#readOffset, end);
    this.#readOffset = end;
    return { chunk, eof: end === this.#replayBytes.length };
  }

  observationFinish(handle, outcome, position) {
    this.calls.push(["observation-finish", handle, outcome, position]);
  }

  observationAbandon(handle) {
    this.calls.push(["observation-abandon", handle]);
  }

  operationUnowned(handle, observationClass, evidence, parent) {
    this.calls.push([
      "operation-unowned",
      handle,
      observationClass,
      Buffer.from(evidence),
      parent,
    ]);
  }

  operationCloseWorld() {}

  operationSucceed() {
    this.calls.push(["operation-succeed"]);
  }

  operationAbandon() {
    this.calls.push(["operation-abandon"]);
  }

  operationFail() {
    return 8;
  }

  sinkWait() {
    return true;
  }

  engineClose() {}

  request() {
    return JSON.parse(Buffer.concat(this.requestChunks));
  }

  response() {
    return JSON.parse(Buffer.concat(this.responseChunks));
  }
}

test("the first project lease installs one adapter group and the last restores it", () => {
  const original = {
    date: Date,
    randomBytes: cryptoModule.randomBytes,
    readFileSync: fsModule.readFileSync,
  };
  const releaseFirst = acquireRuntimeObservationAdapters();
  const releaseSecond = acquireRuntimeObservationAdapters();
  try {
    assert.deepEqual(runtimeObservationAdapterStateForTest(), {
      classes: ["clock", "database", "environment", "filesystem", "randomness"],
      leases: 2,
    });
    assert.deepEqual(
      installedObservationAdapters().map((value) => value.class),
      ["clock", "database", "environment", "filesystem", "randomness"],
    );
    assert.notEqual(Date, original.date);
    assert.notEqual(cryptoModule.randomBytes, original.randomBytes);
    assert.notEqual(fsModule.readFileSync, original.readFileSync);
    releaseFirst();
    assert.equal(runtimeObservationAdapterStateForTest().leases, 1);
    assert.notEqual(Date, original.date);
  } finally {
    releaseFirst();
    releaseSecond();
  }
  assert.deepEqual(runtimeObservationAdapterStateForTest(), {
    classes: [],
    leases: 0,
  });
  assert.deepEqual(installedObservationAdapters(), []);
  assert.equal(Date, original.date);
  assert.equal(cryptoModule.randomBytes, original.randomBytes);
  assert.equal(fsModule.readFileSync, original.readFileSync);
});

test("canonical replay returns only the four stored runtime observations", () => {
  withRuntime(() => {
    const clock = replay(positive["clock-wall-time"], () => Date.now());
    const clockBytes = Buffer.from(positive["clock-wall-time"].response.value, "base64url");
    assert.equal(clock.value, Number(clockBytes.readBigInt64BE()) / 1_000_000);

    const environment = replay(
      positive["environment-read"],
      () => process.env.REGION,
    );
    assert.equal(environment.value, "us-west");

    const missing = replay(
      positive["environment-missing"],
      () => process.env.REGION,
    );
    assert.equal(missing.value, undefined);

    const filesystem = replay(
      positive["filesystem-read"],
      () => fsModule.readFileSync("/data/input"),
    );
    assert.deepEqual(filesystem.value, Buffer.from("fixture"));

    const randomness = replay(
      positive["random-bytes"],
      () => cryptoModule.randomBytes(32),
    );
    assert.deepEqual(randomness.value, Buffer.from(
      positive["random-bytes"].response.value,
      "base64url",
    ));
  });
});

test("callback and promise adapters replay without live dependency calls", async () => {
  await withRuntime(async () => {
    const filesystemBridge = new SemanticBridge(
      "replay",
      positive["filesystem-read"].response,
    );
    const fileValue = await run(
      filesystemBridge,
      () => fsModule.promises.readFile("/data/input"),
    );
    assert.deepEqual(fileValue, Buffer.from("fixture"));
    assert.deepEqual(
      filesystemBridge.request(),
      positive["filesystem-read"].request,
    );

    const randomBridge = new SemanticBridge(
      "replay",
      positive["random-bytes"].response,
    );
    const randomValue = await run(
      randomBridge,
      () => new Promise((resolve, reject) => {
        cryptoModule.randomBytes(32, (error, value) => {
          if (error !== null) reject(error);
          else resolve(value);
        });
      }),
    );
    assert.deepEqual(randomValue, Buffer.from(
      positive["random-bytes"].response.value,
      "base64url",
    ));
    assert.deepEqual(randomBridge.request(), positive["random-bytes"].request);
  });
});

test("capture writes canonical request and response records", () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-semantic-"));
  const file = path.join(temporaryRoot, "fixture.bin");
  const fixedEnvironmentName = "REPROIT_FIXED_ENVIRONMENT_FIXTURE";
  const fixedEnvironmentValue = "redacted-fixture";
  fs.writeFileSync(file, Buffer.from("filesystem-fixture"));
  process.env[fixedEnvironmentName] = fixedEnvironmentValue;
  try {
    withRuntime(() => {
      const cases = [
        {
          call: () => Date.now(),
          operation: SEMANTIC_OPERATIONS.clock,
        },
        {
          call: () => process.env[fixedEnvironmentName],
          operation: SEMANTIC_OPERATIONS.environment,
        },
        {
          call: () => fsModule.readFileSync(file),
          operation: SEMANTIC_OPERATIONS.filesystem,
        },
        {
          call: () => cryptoModule.randomBytes(32),
          operation: SEMANTIC_OPERATIONS.randomness,
        },
      ];
      for (const fixture of cases) {
        const bridge = new SemanticBridge("capture");
        const value = run(bridge, fixture.call);
        const request = bridge.request();
        const response = bridge.response();
        assert.equal(request.operation, fixture.operation);
        assert.equal(response.operation, fixture.operation);
        assert.equal(response.outcome, "response");
        assert.equal(response.error_code, null);
        assert.equal(response.error_number, null);
        assert.equal(response.value, captureValue(value));
        assert.match(response.request_digest, /^sha256:[0-9a-f]{64}$/u);
        assert.deepEqual(bridge.calls.at(-2), [
          "observation-finish",
          4,
          "response",
          0,
        ]);
      }
    });
  } finally {
    delete process.env[fixedEnvironmentName];
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

test("invalid canonical replay records fail without a live fallback", () => {
  withRuntime(() => {
    const fixtures = [
      {
        call: () => cryptoModule.randomBytes(32),
        vector: negative["random-length-mismatch"],
      },
      {
        call: () => process.env.REGION,
        vector: negative["response-request-mismatch"],
      },
      {
        call: () => fsModule.readFileSync("/data/input"),
        vector: negative["error-carries-value"],
      },
    ];
    for (const fixture of fixtures) {
      const bridge = new SemanticBridge("replay", fixture.vector.response);
      assert.throws(
        () => run(bridge, fixture.call),
        (error) => error?.code === "ERR_REPROIT_REPLAY_OBSERVATION",
      );
      assert.equal(
        bridge.calls.some((call) => call[0] === "observation-abandon"),
        true,
      );
    }
  });
});

test("one byte over a semantic bound makes the operation unowned or incomplete", () => {
  assert.throws(
    () => semanticRequest(
      SEMANTIC_OPERATIONS.filesystem,
      encodedTarget("/data/input"),
      0,
      32_769,
    ),
    TypeError,
  );

  withRuntime(() => {
    const randomBridge = new SemanticBridge("capture");
    const random = run(randomBridge, () => cryptoModule.randomBytes(32_769));
    assert.equal(random.length, 32_769);
    assert.equal(randomBridge.requestChunks.length, 0);
    assert.equal(
      randomBridge.calls.some(
        (call) => call[0] === "operation-unowned" && call[2] === "randomness",
      ),
      true,
    );

    const temporaryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "reproit-node-one-over-"),
    );
    const file = path.join(temporaryRoot, "one-over.bin");
    fs.writeFileSync(file, Buffer.alloc(32_769, 7));
    try {
      const filesystemBridge = new SemanticBridge("capture");
      const value = run(filesystemBridge, () => fsModule.readFileSync(file));
      assert.equal(value.length, 32_769);
      assert.equal(
        filesystemBridge.calls.some(
          (call) => call[0] === "observation-abandon",
        ),
        true,
      );
      assert.equal(
        filesystemBridge.calls.some((call) => call[0] === "operation-abandon"),
        true,
      );
    } finally {
      fs.rmSync(temporaryRoot, { force: true, recursive: true });
    }
  });
});

test("accessible unsupported clock and filesystem calls mark the operation unowned", () => {
  withRuntime(() => {
    const clockBridge = new SemanticBridge("capture");
    run(clockBridge, () => performance.now());
    assert.equal(
      clockBridge.calls.some(
        (call) => call[0] === "operation-unowned" && call[2] === "clock",
      ),
      true,
    );
    const timeOriginBridge = new SemanticBridge("capture");
    run(timeOriginBridge, () => performance.timeOrigin);
    assert.equal(
      timeOriginBridge.calls.some(
        (call) => call[0] === "operation-unowned" && call[2] === "clock",
      ),
      true,
    );
    const highResolutionBridge = new SemanticBridge("capture");
    run(highResolutionBridge, () => process.hrtime.bigint());
    assert.equal(
      highResolutionBridge.calls.some(
        (call) => call[0] === "operation-unowned" && call[2] === "clock",
      ),
      true,
    );

    const filesystemBridge = new SemanticBridge("capture");
    run(filesystemBridge, () => fsModule.statSync(import.meta.filename));
    assert.equal(
      filesystemBridge.calls.some(
        (call) => call[0] === "operation-unowned" && call[2] === "filesystem",
      ),
      true,
    );
  });
});

function replay(vector, call) {
  const bridge = new SemanticBridge("replay", vector.response);
  const value = run(bridge, call);
  assert.deepEqual(bridge.request(), vector.request);
  assert.deepEqual(bridge.calls.at(-2), [
    "observation-finish",
    4,
    vector.response.outcome,
    0,
  ]);
  return { bridge, value };
}

function run(bridge, call) {
  const project = createManagedEngineProjectForTest(bridge, 1, () => "fixed-test-token");
  return runOperation(
    project,
    { begin: {}, completion: "return", inputs: [] },
    call,
    () => null,
  );
}

function withRuntime(action) {
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

function captureValue(value) {
  if (typeof value === "number") {
    const bytes = Buffer.alloc(8);
    bytes.writeBigInt64BE(BigInt(value) * 1_000_000n);
    return bytes.toString("base64url");
  }
  if (typeof value === "string") return Buffer.from(value, "utf8").toString("base64url");
  return Buffer.from(value).toString("base64url");
}
