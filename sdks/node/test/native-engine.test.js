import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  NativeEngineBridge,
  NativeEngineCallError,
  NativeEngineError,
  loadNativeEngine,
  NATIVE_ENGINE_ABI_VERSION,
  NATIVE_ENGINE_RESPONSE_CAPACITY,
  NATIVE_ENGINE_ABI_CONTRACT_DIGEST,
  validateArtifactManifest,
} from "../src/native-engine.js";

const ABI_PATH = path.resolve(
  import.meta.dirname,
  "../../../crates/reproit-sdk-engine/sdk-engine-abi.json",
);
const ABI_CONTRACT = JSON.parse(fs.readFileSync(ABI_PATH, "utf8"));
const SUCCESS = Buffer.from(
  JSON.stringify({
    error_code: null,
    format: "reproit.sdk-engine-response.v1",
    ok: true,
    result: ABI_CONTRACT,
  }),
  "utf8",
);

function binding(response = SUCCESS, abiVersion = NATIVE_ENGINE_ABI_VERSION) {
  const requests = [];
  return {
    requests,
    abiVersion: () => abiVersion,
    call(request, outputCapacity) {
      assert.equal(outputCapacity, NATIVE_ENGINE_RESPONSE_CAPACITY);
      const parsed = JSON.parse(request);
      requests.push(parsed);
      return typeof response === "function" ? response(parsed) : response;
    },
  };
}

function engineResponse(result, errorCode = null) {
  return Buffer.from(JSON.stringify({
    error_code: errorCode,
    format: "reproit.sdk-engine-response.v1",
    ok: errorCode === null,
    result,
  }));
}

function artifactManifest(files) {
  return {
    abi_contract_digest: NATIVE_ENGINE_ABI_CONTRACT_DIGEST,
    artifacts: [
      artifact("engine", files.engine.file, files.engine.content),
      artifact("node-loader", files.loader.file, files.loader.content),
    ],
    format: "reproit.sdk-engine-artifacts.v1",
    target: "macos-arm64",
  };
}

function artifact(role, file, content) {
  return {
    digest: `sha256:${createHash("sha256").update(content).digest("hex")}`,
    file,
    role,
    size: content.length,
  };
}

function artifactFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "reproit-engine-artifacts-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const files = {
    engine: {
      content: Buffer.from("exact engine bytes"),
      file: "libreproit_sdk_engine.dylib",
    },
    loader: {
      content: Buffer.from("exact loader bytes"),
      file: "reproit_sdk_engine_loader.node",
    },
  };
  for (const value of Object.values(files)) {
    fs.writeFileSync(path.join(root, value.file), value.content);
  }
  return { files, root };
}

test("contract uses ABI version one and the exact JSON call", () => {
  const native = binding();
  const response = new NativeEngineBridge(native).contract();
  assert.deepEqual(response.result, ABI_CONTRACT);
  assert.deepEqual(native.requests, [
    { format: "reproit.sdk-engine-call.v1", operation: "contract" },
  ]);
});

test("real engine returns the full contract when an addon is available", (t) => {
  const addonPath = process.env.REPROIT_NODE_ENGINE_ADDON;
  if (addonPath === undefined) {
    t.skip("A native Node SDK engine addon was not supplied.");
    return;
  }
  const require = createRequire(import.meta.url);
  const bridge = new NativeEngineBridge(require(addonPath));
  assert.deepEqual(bridge.contract().result, ABI_CONTRACT);
});

test("ABI version mismatch is rejected", () => {
  assert.throws(
    () => new NativeEngineBridge(binding(SUCCESS, 2)).contract(),
    NativeEngineError,
  );
});

test("contract rejects changed observation rules", () => {
  const invalidContracts = [];
  const missingOperation = structuredClone(ABI_CONTRACT);
  missingOperation.operations = missingOperation.operations.filter(
    (operation) => operation !== "observation-read",
  );
  invalidContracts.push(missingOperation);
  invalidContracts.push({
    ...structuredClone(ABI_CONTRACT),
    limits: {
      ...ABI_CONTRACT.limits,
      observation_response_read_bytes: 8_193,
    },
  });
  invalidContracts.push({
    ...structuredClone(ABI_CONTRACT),
    observation_actions: ["capture", "unknown"],
  });
  const wrongFields = structuredClone(ABI_CONTRACT);
  wrongFields.observation_contract.read_result_fields = ["chunk"];
  invalidContracts.push(wrongFields);
  const wrongErrorBehavior = structuredClone(ABI_CONTRACT);
  wrongErrorBehavior.error_behavior.json_error.includes_request = true;
  invalidContracts.push(wrongErrorBehavior);

  for (const contract of invalidContracts) {
    assert.throws(
      () => new NativeEngineBridge(
        binding(engineResponse(contract)),
      ).contract(),
      NativeEngineError,
    );
  }
});

test("missing packaged library has a fixed error", () => {
  assert.throws(
    () => loadNativeEngine(),
    (error) => {
      assert.equal(error.constructor, NativeEngineError);
      assert.equal(
        error.message,
        "The packaged shared SDK engine is unavailable.",
      );
      return true;
    },
  );
});

test("malformed response is rejected without echo", () => {
  const secret = "do-not-echo-this-secret";
  assert.throws(
    () => new NativeEngineBridge(binding(Buffer.from(secret))).contract(),
    (error) => {
      assert.equal(error.constructor, NativeEngineError);
      assert.equal(error.message, "The shared SDK engine response is invalid.");
      assert.equal(error.message.includes(secret), false);
      return true;
    },
  );
});

test("response one byte over the bound is rejected", () => {
  const oversized = Buffer.alloc(NATIVE_ENGINE_RESPONSE_CAPACITY + 1);
  assert.throws(
    () => new NativeEngineBridge(binding(oversized)).contract(),
    (error) => {
      assert.equal(error.constructor, NativeEngineError);
      assert.equal(error.message, "The shared SDK engine response is invalid.");
      return true;
    },
  );
});

test("native failure does not echo request values", () => {
  const secret = "local-project-token-value";
  const bridge = new NativeEngineBridge({
    abiVersion: () => NATIVE_ENGINE_ABI_VERSION,
    call() {
      throw new Error(secret);
    },
  });
  assert.throws(
    () => bridge.call({
      format: "reproit.sdk-engine-call.v1",
      operation: "unknown",
      project_token: secret,
    }),
    (error) => {
      assert.equal(error.constructor, NativeEngineError);
      assert.equal(
        error.message,
        "The packaged shared SDK engine is unavailable.",
      );
      assert.equal(error.message.includes(secret), false);
      return true;
    },
  );
});

test("typed calls cover the shared engine lifecycle", () => {
  const results = {
    "dependency-open": { action: "capture", dependency_handle: 15 },
    "dependency-finish": { outcome: "response" },
    "engine-open": { engine_handle: 11 },
    "engine-close": {},
    "observation-open": {
      observation_handle: 14,
      session_position: 0,
    },
    "observation-write": {},
    "observation-dispatch": { action: "replay" },
    "observation-read": { chunk: "", eof: true },
    "observation-finish": {},
    "observation-abandon": {},
    "operation-begin": {
      operation_handle: 12,
      operation_id: "operation-id",
    },
    "operation-input": {},
    "operation-unowned": {},
    "operation-close-world": {},
    "operation-succeed": {},
    "operation-abandon": {},
    "operation-fail": { sink_handle: 13 },
    "sink-wait": { idle: true },
  };
  const native = binding((request) => engineResponse(results[request.operation]));
  const bridge = new NativeEngineBridge(native);

  const engine = bridge.engineOpen({
    buildRepositoryId: "repository",
    projectToml: "format = 1",
    sourceRevision: "revision",
    subjectManifest: { format: "reproit.subject-closure.v1" },
    subjectObjects: [{ digest: "sha256:00", path: "subject", size: 1 }],
  });
  const operation = bridge.operationBegin(engine, {
    format: "reproit.operation-begin.v1",
  });
  bridge.operationInput(operation.operationHandle, {
    format: "reproit.operation-input.v1",
  });
  const dependency = bridge.dependencyOpen(
    operation.operationHandle,
    { observation_class: "database" },
    "dependency-parent",
  );
  assert.equal(
    bridge.dependencyFinish(dependency.dependencyHandle, { outcome: "response" }),
    "response",
  );
  const observation = bridge.observationOpen(
    operation.operationHandle,
    "outbound-http",
    "parent-id",
  );
  bridge.observationWrite(
    observation.observationHandle,
    "request",
    Buffer.from("request"),
  );
  assert.equal(bridge.observationDispatch(observation.observationHandle), "replay");
  assert.deepEqual(bridge.observationRead(observation.observationHandle), {
    chunk: Buffer.alloc(0),
    eof: true,
  });
  bridge.observationFinish(
    observation.observationHandle,
    "response",
    observation.sessionPosition,
  );
  bridge.observationAbandon(observation.observationHandle);
  bridge.operationUnowned(
    operation.operationHandle,
    "filesystem",
    Buffer.from("unowned evidence"),
  );
  bridge.operationCloseWorld(operation.operationHandle, "return");
  bridge.operationSucceed(operation.operationHandle);
  bridge.operationAbandon(operation.operationHandle);
  const sink = bridge.operationFail(
    operation.operationHandle,
    { schema: "failure" },
    "project-token",
  );
  assert.equal(bridge.sinkWait(sink, 250), true);
  bridge.engineClose(engine);

  assert.equal(engine, 11);
  assert.deepEqual(operation, {
    operationHandle: 12,
    operationId: "operation-id",
  });
  assert.deepEqual(dependency, { action: "capture", dependencyHandle: 15 });
  assert.deepEqual(observation, {
    observationHandle: 14,
    sessionPosition: 0,
  });
  assert.equal(sink, 13);
  assert.deepEqual(native.requests[0], {
    build_repository_id: "repository",
    format: "reproit.sdk-engine-call.v1",
    observation_adapters: [],
    operation: "engine-open",
    project_toml: "format = 1",
    sdk: "nodejs",
    source_revision: "revision",
    subject_manifest: { format: "reproit.subject-closure.v1" },
    subject_objects: [{ digest: "sha256:00", path: "subject", size: 1 }],
  });
  assert.deepEqual(native.requests[3], {
    causal_parent_id: "dependency-parent",
    format: "reproit.sdk-engine-call.v1",
    operation: "dependency-open",
    operation_handle: 12,
    request: { observation_class: "database" },
  });
  assert.deepEqual(native.requests[4], {
    dependency_handle: 15,
    format: "reproit.sdk-engine-call.v1",
    operation: "dependency-finish",
    response: { outcome: "response" },
  });
  assert.deepEqual(native.requests[5], {
    causal_parent_id: "parent-id",
    class: "outbound-http",
    format: "reproit.sdk-engine-call.v1",
    operation: "observation-open",
    operation_handle: 12,
  });
  assert.deepEqual(native.requests[6], {
    chunk: Buffer.from("request").toString("base64url"),
    format: "reproit.sdk-engine-call.v1",
    observation_handle: 14,
    operation: "observation-write",
    stream: "request",
  });
  assert.deepEqual(native.requests[9], {
    format: "reproit.sdk-engine-call.v1",
    observation_handle: 14,
    operation: "observation-finish",
    outcome: "response",
    session_position: 0,
  });
  assert.deepEqual(
    native.requests.map((request) => request.operation),
    [
      "engine-open",
      "operation-begin",
      "operation-input",
      "dependency-open",
      "dependency-finish",
      "observation-open",
      "observation-write",
      "observation-dispatch",
      "observation-read",
      "observation-finish",
      "observation-abandon",
      "operation-unowned",
      "operation-close-world",
      "operation-succeed",
      "operation-abandon",
      "operation-fail",
      "sink-wait",
      "engine-close",
    ],
  );
});

test("engine rejection is typed and does not echo the token", () => {
  const secret = "do-not-echo-project-token";
  const bridge = new NativeEngineBridge(
    binding(engineResponse({}, "SCHEMA_INVALID")),
  );
  assert.throws(
    () => bridge.operationFail(1, { schema: "failure" }, secret),
    (error) => {
      assert.equal(error.constructor, NativeEngineCallError);
      assert.equal(error.errorCode, "SCHEMA_INVALID");
      assert.equal(
        error.message,
        "The shared SDK engine rejected the operation.",
      );
      assert.equal(error.message.includes(secret), false);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
});

test("typed calls reject invalid results and handles", () => {
  const native = binding(engineResponse({ engine_handle: true }));
  const bridge = new NativeEngineBridge(native);
  assert.throws(
    () => bridge.engineOpen({
      buildRepositoryId: "repository",
      projectToml: "format = 1",
      sourceRevision: "revision",
      subjectManifest: {},
      subjectObjects: [],
    }),
    NativeEngineError,
  );
  assert.throws(
    () => bridge.engineClose(0),
    (error) => {
      assert.equal(error.constructor, NativeEngineError);
      assert.equal(error.message, "The shared SDK engine request is invalid.");
      return true;
    },
  );
  const requestCount = native.requests.length;
  assert.throws(
    () => bridge.observationWrite(1, "request", Buffer.alloc(32_769)),
    NativeEngineError,
  );
  assert.equal(native.requests.length, requestCount);
});

test("observation chunk bound and replay EOF are exact", () => {
  const results = { "observation-write": {} };
  const native = binding((request) => engineResponse(results[request.operation]));
  const bridge = new NativeEngineBridge(native);
  bridge.observationWrite(1, "request", Buffer.alloc(32_768));
  const requestCount = native.requests.length;
  assert.throws(
    () => bridge.observationWrite(1, "request", Buffer.alloc(32_769)),
    NativeEngineError,
  );
  assert.equal(native.requests.length, requestCount);

  const readAtLimit = Buffer.alloc(8_192, "r");
  const replay = new NativeEngineBridge(
    binding(engineResponse({ chunk: readAtLimit.toString("base64url"), eof: false })),
  );
  assert.deepEqual(replay.observationRead(1), {
    chunk: readAtLimit,
    eof: false,
  });
  const eof = new NativeEngineBridge(
    binding(engineResponse({ chunk: "", eof: true })),
  );
  assert.deepEqual(eof.observationRead(1), {
    chunk: Buffer.alloc(0),
    eof: true,
  });
  const readOneOver = Buffer.alloc(8_193, "r").toString("base64url");
  assert.throws(
    () => new NativeEngineBridge(
      binding(engineResponse({ chunk: readOneOver, eof: false })),
    ).observationRead(1),
    NativeEngineError,
  );
});

test("invalid replay chunk does not echo secret bytes", () => {
  const secret = "local-observation-secret";
  const bridge = new NativeEngineBridge(
    binding(engineResponse({ chunk: `${secret}=`, eof: false })),
  );
  assert.throws(
    () => bridge.observationRead(1),
    (error) => {
      assert.equal(error.constructor, NativeEngineError);
      assert.equal(error.message, "The shared SDK engine response is invalid.");
      assert.equal(error.message.includes(secret), false);
      return true;
    },
  );
});

test("malformed engine error code is rejected without echo", () => {
  const secret = "secret-error-value";
  const bridge = new NativeEngineBridge(
    binding(engineResponse({}, secret)),
  );
  assert.throws(
    () => bridge.engineClose(1),
    (error) => {
      assert.equal(error.constructor, NativeEngineError);
      assert.equal(error.message, "The shared SDK engine response is invalid.");
      assert.equal(error.message.includes(secret), false);
      return true;
    },
  );
});

test("artifact manifest accepts the exact engine and loader", (t) => {
  const { files, root } = artifactFixture(t);
  fs.writeFileSync(
    path.join(root, "sdk-engine-artifacts.json"),
    JSON.stringify(artifactManifest(files)),
  );
  validateArtifactManifest(root, "macos-arm64", {
    engine: files.engine.file,
    "node-loader": files.loader.file,
  });
});

test("artifact manifest rejects invalid or linked artifacts", (t) => {
  const { files, root } = artifactFixture(t);
  const valid = artifactManifest(files);
  const invalid = [];
  invalid.push({ ...structuredClone(valid), target: "linux-arm64" });
  const wrongDigest = structuredClone(valid);
  wrongDigest.artifacts[0].digest = `sha256:${"0".repeat(64)}`;
  invalid.push(wrongDigest);
  const wrongSize = structuredClone(valid);
  wrongSize.artifacts[0].size += 1;
  invalid.push(wrongSize);
  invalid.push({ ...structuredClone(valid), unexpected: true });
  const pathEscape = structuredClone(valid);
  pathEscape.artifacts[0].file = `../${files.engine.file}`;
  invalid.push(pathEscape);
  const unsorted = structuredClone(valid);
  unsorted.artifacts.reverse();
  invalid.push(unsorted);
  const missingRole = structuredClone(valid);
  missingRole.artifacts.pop();
  invalid.push(missingRole);
  const extraArtifact = structuredClone(valid);
  extraArtifact.artifacts.push(structuredClone(extraArtifact.artifacts[0]));
  invalid.push(extraArtifact);
  const oversizedArtifact = structuredClone(valid);
  oversizedArtifact.artifacts[0].size = 256 * 1024 * 1024 + 1;
  invalid.push(oversizedArtifact);

  for (const manifest of invalid) {
    fs.writeFileSync(
      path.join(root, "sdk-engine-artifacts.json"),
      JSON.stringify(manifest),
    );
    assert.throws(
      () => validateArtifactManifest(root, "macos-arm64", {
        engine: files.engine.file,
        "node-loader": files.loader.file,
      }),
      (error) => {
        assert.equal(error.constructor, NativeEngineError);
        assert.equal(
          error.message,
          "The packaged shared SDK engine is unavailable.",
        );
        assert.equal(error.cause, undefined);
        return true;
      },
    );
  }

  fs.writeFileSync(
    path.join(root, "sdk-engine-artifacts.json"),
    JSON.stringify(valid),
  );
  fs.rmSync(path.join(root, files.engine.file));
  fs.symlinkSync("engine-target", path.join(root, files.engine.file));
  fs.writeFileSync(path.join(root, "engine-target"), files.engine.content);
  assert.throws(
    () => validateArtifactManifest(root, "macos-arm64", {
      engine: files.engine.file,
      "node-loader": files.loader.file,
    }),
    NativeEngineError,
  );

  fs.rmSync(path.join(root, files.engine.file));
  fs.mkdirSync(path.join(root, files.engine.file));
  assert.throws(
    () => validateArtifactManifest(root, "macos-arm64", {
      engine: files.engine.file,
      "node-loader": files.loader.file,
    }),
    NativeEngineError,
  );

  fs.writeFileSync(
    path.join(root, "sdk-engine-artifacts.json"),
    Buffer.alloc(16_385),
  );
  assert.throws(
    () => validateArtifactManifest(root, "macos-arm64", {
      engine: files.engine.file,
      "node-loader": files.loader.file,
    }),
    NativeEngineError,
  );
});
