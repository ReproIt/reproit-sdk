import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseStrictJson } from "./managed-json.js";
import { installedObservationAdapters } from "./observation-adapters.js";

export const NATIVE_ENGINE_ABI_VERSION = 1;
export const NATIVE_ENGINE_RESPONSE_CAPACITY = 16_384;
export const NATIVE_ENGINE_CALL_FORMAT = "reproit.sdk-engine-call.v1";
export const NATIVE_ENGINE_RESPONSE_FORMAT = "reproit.sdk-engine-response.v1";
export const NATIVE_ENGINE_MAX_CALL_BYTES = 1_048_576;
export const NATIVE_ENGINE_MAX_EVIDENCE_BYTES = 785_408;
export const NATIVE_ENGINE_MAX_OBSERVATION_ADAPTERS = 7;
export const NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES = 32_768;
export const NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES = 8_192;
export const NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS = 1_024;
export const NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS_PER_OPERATION = 64;
export const NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES = 65_536;
export const NATIVE_ENGINE_MAX_SINK_WAIT_MS = 1_800_000;
export const NATIVE_ENGINE_MAX_SINK_WAITERS = 16;
export const NATIVE_ENGINE_ABI_CONTRACT_DIGEST =
  "sha256:b44f8f670ee31066c81a37876543b6fbce70215e69ed2b0aa6a4aa1ae1b4de47";
export const NATIVE_ENGINE_LIBRARIES = Object.freeze({
  "linux-arm64": "libreproit_sdk_engine.so",
  "linux-x86_64": "libreproit_sdk_engine.so",
  "macos-arm64": "libreproit_sdk_engine.dylib",
  "windows-x86_64": "reproit_sdk_engine.dll",
});
export const NATIVE_ENGINE_SYMBOLS = Object.freeze({
  abi_version: "reproit_sdk_engine_abi_version",
  call: "reproit_sdk_engine_call",
  capture_probe: "reproit_sdk_engine_capture_probe",
});
const ENGINE_OPERATION = Object.freeze({
  CONTRACT: "contract",
  DEPENDENCY_FINISH: "dependency-finish",
  DEPENDENCY_OPEN: "dependency-open",
  ENGINE_CLOSE: "engine-close",
  ENGINE_OPEN: "engine-open",
  OBSERVATION_ABANDON: "observation-abandon",
  OBSERVATION_DISPATCH: "observation-dispatch",
  OBSERVATION_FINISH: "observation-finish",
  OBSERVATION_OPEN: "observation-open",
  OBSERVATION_READ: "observation-read",
  OBSERVATION_WRITE: "observation-write",
  OPERATION_ABANDON: "operation-abandon",
  OPERATION_BEGIN: "operation-begin",
  OPERATION_CLOSE_WORLD: "operation-close-world",
  OPERATION_FAIL: "operation-fail",
  OPERATION_INPUT: "operation-input",
  OPERATION_SUCCEED: "operation-succeed",
  OPERATION_UNOWNED: "operation-unowned",
  SINK_WAIT: "sink-wait",
});
export const NATIVE_ENGINE_OPERATIONS = Object.freeze(
  Object.values(ENGINE_OPERATION),
);
export const NATIVE_ENGINE_OBSERVATION_ACTIONS = Object.freeze([
  "capture",
  "replay",
]);
export const NATIVE_ENGINE_REQUIRED_OBSERVATION_CLASSES = Object.freeze([
  "clock",
  "database",
  "environment",
  "filesystem",
  "outbound-http",
  "queue",
  "randomness",
]);
export const NATIVE_ENGINE_DEPENDENCY_CONTRACT = Object.freeze({
  finish_fields: ["dependency_handle", "response"],
  finish_result_fields: ["outcome"],
  open_fields: ["causal_parent_id", "operation_handle", "request"],
  open_result_fields: ["action", "dependency_handle"],
  replay_read_operation: "observation-read",
  request_fields: [
    "encoding",
    "metadata",
    "method",
    "observation_class",
    "operation",
    "payload",
    "protocol",
    "target",
  ],
  response_fields: [
    "error_code",
    "error_number",
    "metadata",
    "outcome",
    "payload",
    "status",
    "status_code",
  ],
});
export const NATIVE_ENGINE_ERROR_BEHAVIOR = Object.freeze({
  json_error: {
    error_code_source: "reproit-core-v1",
    includes_message: false,
    includes_request: false,
    maximum_bytes: 256,
    result: {},
  },
  native_failures: [
    {
      code: -4,
      condition: "response-length-overflow",
      output_written: false,
    },
    {
      code: -3,
      condition: "output-capacity-exceeded",
      output_written: false,
    },
    { code: -2, condition: "engine-panic", output_written: false },
    {
      code: -1,
      condition: "invalid-call-boundary",
      output_written: false,
    },
  ],
  success: "response-byte-count",
});
export const NATIVE_ENGINE_OBSERVATION_CONTRACT = Object.freeze({
  adapter_implementation_binding: ["subject-module-digest"],
  adapter_registration_fields: [
    "adapter_id",
    "adapter_version",
    "class",
    "implementation_digest",
  ],
  finish_fields: ["observation_handle", "outcome", "session_position"],
  open_fields: ["causal_parent_id", "class", "operation_handle"],
  open_result_fields: ["observation_handle", "session_position"],
  read_result_fields: ["chunk", "eof"],
  write_fields: ["chunk", "observation_handle", "stream"],
});
const MAX_LIBRARY_BYTES = 256 * 1024 * 1024;
const MAX_ARTIFACT_MANIFEST_BYTES = 16_384;
const ARTIFACT_MANIFEST_FORMAT = "reproit.sdk-engine-artifacts.v1";
const ARTIFACT_MANIFEST_NAME = "sdk-engine-artifacts.json";
const CONTRACT_REQUEST = Buffer.from(
  `{"format":"${NATIVE_ENGINE_CALL_FORMAT}",` +
    `"operation":"${ENGINE_OPERATION.CONTRACT}"}`,
  "utf8",
);
const RESPONSE_KEYS = ["error_code", "format", "ok", "result"];
const require = createRequire(import.meta.url);

export class NativeEngineError extends Error {}

export class NativeEngineCallError extends NativeEngineError {
  constructor(errorCode) {
    super("The shared SDK engine rejected the operation.");
    this.errorCode = errorCode;
  }
}

export class NativeEngineBridge {
  #binding;

  constructor(binding) {
    if (
      binding === null ||
      typeof binding !== "object" ||
      typeof binding.abiVersion !== "function" ||
      typeof binding.call !== "function"
    ) {
      throw engineUnavailable();
    }
    this.#binding = binding;
  }

  static load() {
    const { addonPath } = packagedPaths();
    let binding;
    try {
      binding = require(addonPath);
    } catch {
      throw engineUnavailable();
    }
    return new NativeEngineBridge(binding);
  }

  contract() {
    let version;
    try {
      version = this.#binding.abiVersion();
    } catch {
      throw engineUnavailable();
    }
    if (version !== NATIVE_ENGINE_ABI_VERSION) {
      throw engineUnavailable();
    }
    const response = this.#callBytes(CONTRACT_REQUEST);
    if (
      response.ok !== true ||
      response.error_code !== null ||
      !validContract(response.result)
    ) {
      throw responseInvalid();
    }
    return response;
  }

  call(operation) {
    let request;
    try {
      request = Buffer.from(JSON.stringify(operation), "utf8");
    } catch {
      throw requestInvalid();
    }
    return this.#callBytes(request);
  }

  engineOpen(options) {
    if (!isObject(options)) throw requestInvalid();
    let request;
    try {
      request = {
        build_repository_id: options.buildRepositoryId,
        format: NATIVE_ENGINE_CALL_FORMAT,
        observation_adapters: installedObservationAdapters(),
        operation: ENGINE_OPERATION.ENGINE_OPEN,
        project_toml: options.projectToml,
        sdk: "nodejs",
        source_revision: options.sourceRevision,
        subject_manifest: options.subjectManifest,
        subject_objects: options.subjectObjects,
      };
    } catch {
      throw requestInvalid();
    }
    return resultHandle(this.#callResult(request), "engine_handle");
  }

  engineClose(engineHandle) {
    this.#callEmpty(ENGINE_OPERATION.ENGINE_CLOSE, {
      engine_handle: requestHandle(engineHandle),
    });
  }

  operationBegin(engineHandle, begin) {
    const result = this.#callResult({
      begin,
      engine_handle: requestHandle(engineHandle),
      format: NATIVE_ENGINE_CALL_FORMAT,
      operation: ENGINE_OPERATION.OPERATION_BEGIN,
    });
    if (
      !sameKeys(result, ["operation_handle", "operation_id"]) ||
      typeof result.operation_id !== "string" ||
      result.operation_id.length === 0 ||
      result.operation_id.length > 128
    ) {
      throw responseInvalid();
    }
    return {
      operationHandle: resultHandle(result, "operation_handle", false),
      operationId: result.operation_id,
    };
  }

  operationInput(operationHandle, input) {
    this.#callEmpty(ENGINE_OPERATION.OPERATION_INPUT, {
      input,
      operation_handle: requestHandle(operationHandle),
    });
  }

  dependencyOpen(operationHandle, request, causalParentId = null) {
    const result = this.#callResult({
      causal_parent_id: causalParentId,
      format: NATIVE_ENGINE_CALL_FORMAT,
      operation: ENGINE_OPERATION.DEPENDENCY_OPEN,
      operation_handle: requestHandle(operationHandle),
      request,
    });
    if (
      !sameKeys(result, ["action", "dependency_handle"]) ||
      !NATIVE_ENGINE_OBSERVATION_ACTIONS.includes(result.action)
    ) {
      throw responseInvalid();
    }
    return {
      action: result.action,
      dependencyHandle: resultHandle(result, "dependency_handle", false),
    };
  }

  dependencyFinish(dependencyHandle, response) {
    const result = this.#callResult({
      dependency_handle: requestHandle(dependencyHandle),
      format: NATIVE_ENGINE_CALL_FORMAT,
      operation: ENGINE_OPERATION.DEPENDENCY_FINISH,
      response,
    });
    if (
      !sameKeys(result, ["outcome"]) ||
      !["error", "response"].includes(result.outcome)
    ) {
      throw responseInvalid();
    }
    return result.outcome;
  }

  observationOpen(operationHandle, observationClass, causalParentId = null) {
    const result = this.#callResult({
      causal_parent_id: causalParentId,
      class: observationClass,
      format: NATIVE_ENGINE_CALL_FORMAT,
      operation: ENGINE_OPERATION.OBSERVATION_OPEN,
      operation_handle: requestHandle(operationHandle),
    });
    if (!sameKeys(result, ["observation_handle", "session_position"])) {
      throw responseInvalid();
    }
    return {
      observationHandle: resultHandle(result, "observation_handle", false),
      sessionPosition: resultUnsignedInteger(result, "session_position"),
    };
  }

  observationWrite(observationHandle, stream, chunk) {
    if (
      !(chunk instanceof Uint8Array) ||
      chunk.byteLength === 0 ||
      chunk.byteLength > NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES ||
      !["request", "response"].includes(stream)
    ) {
      throw requestInvalid();
    }
    this.#callEmpty(ENGINE_OPERATION.OBSERVATION_WRITE, {
      chunk: Buffer.from(chunk).toString("base64url"),
      observation_handle: requestHandle(observationHandle),
      stream,
    });
  }

  observationDispatch(observationHandle) {
    const result = this.#callResult({
      format: NATIVE_ENGINE_CALL_FORMAT,
      observation_handle: requestHandle(observationHandle),
      operation: ENGINE_OPERATION.OBSERVATION_DISPATCH,
    });
    if (
      !sameKeys(result, ["action"]) ||
      !NATIVE_ENGINE_OBSERVATION_ACTIONS.includes(result.action)
    ) {
      throw responseInvalid();
    }
    return result.action;
  }

  observationRead(observationHandle) {
    const result = this.#callResult({
      format: NATIVE_ENGINE_CALL_FORMAT,
      observation_handle: requestHandle(observationHandle),
      operation: ENGINE_OPERATION.OBSERVATION_READ,
    });
    if (!sameKeys(result, ["chunk", "eof"]) || typeof result.eof !== "boolean") {
      throw responseInvalid();
    }
    return {
      chunk: decodeObservationChunk(result.chunk, result.eof),
      eof: result.eof,
    };
  }

  observationFinish(observationHandle, outcome, sessionPosition) {
    if (!["error", "response"].includes(outcome)) throw requestInvalid();
    this.#callEmpty(ENGINE_OPERATION.OBSERVATION_FINISH, {
      observation_handle: requestHandle(observationHandle),
      outcome,
      session_position: requestUnsignedInteger(sessionPosition),
    });
  }

  observationAbandon(observationHandle) {
    this.#callEmpty(ENGINE_OPERATION.OBSERVATION_ABANDON, {
      observation_handle: requestHandle(observationHandle),
    });
  }

  operationUnowned(operationHandle, observationClass, evidence, causalParentId = null) {
    this.#operationObservation(
      ENGINE_OPERATION.OPERATION_UNOWNED,
      operationHandle,
      observationClass,
      evidence,
      causalParentId,
    );
  }

  operationCloseWorld(operationHandle, completion) {
    this.#callEmpty(ENGINE_OPERATION.OPERATION_CLOSE_WORLD, {
      completion,
      operation_handle: requestHandle(operationHandle),
    });
  }

  operationSucceed(operationHandle) {
    this.#callEmpty(ENGINE_OPERATION.OPERATION_SUCCEED, {
      operation_handle: requestHandle(operationHandle),
    });
  }

  operationAbandon(operationHandle) {
    this.#callEmpty(ENGINE_OPERATION.OPERATION_ABANDON, {
      operation_handle: requestHandle(operationHandle),
    });
  }

  operationFail(operationHandle, failure, projectToken) {
    const result = this.#callResult({
      failure,
      format: NATIVE_ENGINE_CALL_FORMAT,
      operation: ENGINE_OPERATION.OPERATION_FAIL,
      operation_handle: requestHandle(operationHandle),
      project_token: projectToken,
    });
    return resultHandle(result, "sink_handle");
  }

  sinkWait(sinkHandle, timeoutMilliseconds) {
    const result = this.#callResult({
      format: NATIVE_ENGINE_CALL_FORMAT,
      operation: ENGINE_OPERATION.SINK_WAIT,
      sink_handle: requestHandle(sinkHandle),
      timeout_ms: requestUnsignedInteger(timeoutMilliseconds),
    });
    if (!sameKeys(result, ["idle"]) || typeof result.idle !== "boolean") {
      throw responseInvalid();
    }
    return result.idle;
  }

  #operationObservation(
    operation,
    operationHandle,
    observationClass,
    evidence,
    causalParentId,
  ) {
    if (
      !(evidence instanceof Uint8Array) ||
      evidence.byteLength > NATIVE_ENGINE_MAX_EVIDENCE_BYTES
    ) {
      throw requestInvalid();
    }
    this.#callEmpty(operation, {
      causal_parent_id: causalParentId,
      class: observationClass,
      evidence: Buffer.from(evidence).toString("base64url"),
      operation_handle: requestHandle(operationHandle),
    });
  }

  #callEmpty(operation, fields) {
    const result = this.#callResult({
      format: NATIVE_ENGINE_CALL_FORMAT,
      operation,
      ...fields,
    });
    if (!sameKeys(result, [])) throw responseInvalid();
  }

  #callResult(operation) {
    const response = this.call(operation);
    if (!response.ok) throw new NativeEngineCallError(response.error_code);
    return response.result;
  }

  #callBytes(request) {
    if (
      !Buffer.isBuffer(request) ||
      request.length === 0 ||
      request.length > NATIVE_ENGINE_MAX_CALL_BYTES
    ) {
      throw requestInvalid();
    }
    let response;
    try {
      response = this.#binding.call(request, NATIVE_ENGINE_RESPONSE_CAPACITY);
    } catch {
      throw engineUnavailable();
    }
    if (!(response instanceof Uint8Array)) {
      throw responseInvalid();
    }
    const bytes = Buffer.from(response);
    if (bytes.length === 0 || bytes.length > NATIVE_ENGINE_RESPONSE_CAPACITY) {
      throw responseInvalid();
    }
    let value;
    try {
      value = parseStrictJson(bytes, NATIVE_ENGINE_RESPONSE_CAPACITY);
    } catch {
      throw responseInvalid();
    }
    if (
      !sameKeys(value, RESPONSE_KEYS) ||
      value.format !== NATIVE_ENGINE_RESPONSE_FORMAT ||
      typeof value.ok !== "boolean" ||
      !isObject(value.result) ||
      !validErrorCode(value.error_code) ||
      (value.ok && value.error_code !== null) ||
      (!value.ok && value.error_code === null)
    ) {
      throw responseInvalid();
    }
    return value;
  }
}

function validContract(value) {
  const validLibraries =
    Array.isArray(value?.libraries) &&
    value.libraries.length === Object.keys(NATIVE_ENGINE_LIBRARIES).length &&
    value.libraries.every((entry) => sameKeys(entry, ["name", "platform"]));
  const libraries = validLibraries
    ? Object.fromEntries(
        value.libraries.map((entry) => [entry?.platform, entry?.name]),
      )
    : null;
  return (
    sameKeys(value, [
      "abi_version",
      "dependency_contract",
      "error_behavior",
      "format",
      "libraries",
      "limits",
      "operations",
      "observation_actions",
      "observation_contract",
      "required_observation_classes",
      "request",
      "response",
      "symbols",
    ]) &&
    value.abi_version === NATIVE_ENGINE_ABI_VERSION &&
    JSON.stringify(value.dependency_contract) ===
      JSON.stringify(NATIVE_ENGINE_DEPENDENCY_CONTRACT) &&
    value.format === "reproit.sdk-engine-abi.v1" &&
    JSON.stringify(value.error_behavior) ===
      JSON.stringify(NATIVE_ENGINE_ERROR_BEHAVIOR) &&
    sameRecord(libraries, NATIVE_ENGINE_LIBRARIES) &&
    sameRecord(value.limits, {
      engines: 64,
      evidence_bytes: NATIVE_ENGINE_MAX_EVIDENCE_BYTES,
      observation_adapters: NATIVE_ENGINE_MAX_OBSERVATION_ADAPTERS,
      observation_chunk_bytes: NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES,
      observation_response_read_bytes:
        NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES,
      observation_sessions: NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS,
      observation_sessions_per_operation:
        NATIVE_ENGINE_MAX_OBSERVATION_SESSIONS_PER_OPERATION,
      operations: 512,
      semantic_dependency_record_bytes:
        NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES,
      sink_wait_ms: NATIVE_ENGINE_MAX_SINK_WAIT_MS,
      sinks: NATIVE_ENGINE_MAX_SINK_WAITERS,
    }) &&
    Array.isArray(value.operations) &&
    value.operations.every((operation) => typeof operation === "string") &&
    sameArray(value.operations, NATIVE_ENGINE_OPERATIONS) &&
    sameArray(value.observation_actions, NATIVE_ENGINE_OBSERVATION_ACTIONS) &&
    sameArray(
      value.required_observation_classes,
      NATIVE_ENGINE_REQUIRED_OBSERVATION_CLASSES,
    ) &&
    sameRecordOfArrays(
      value.observation_contract,
      NATIVE_ENGINE_OBSERVATION_CONTRACT,
    ) &&
    sameRecord(value.request, {
      format: NATIVE_ENGINE_CALL_FORMAT,
      maximum_bytes: NATIVE_ENGINE_MAX_CALL_BYTES,
    }) &&
    sameRecord(value.response, {
      format: NATIVE_ENGINE_RESPONSE_FORMAT,
      output_capacity_bytes: NATIVE_ENGINE_RESPONSE_CAPACITY,
    }) &&
    sameRecord(value.symbols, NATIVE_ENGINE_SYMBOLS)
  );
}

export function loadNativeEngine() {
  return NativeEngineBridge.load();
}

function packagedPaths() {
  const target = platformTarget();
  const root = fileURLToPath(new URL(`../native/${target.directory}/`, import.meta.url));
  const addonPath = path.join(root, "reproit_sdk_engine_loader.node");
  const libraryPath = path.join(root, target.libraryName);
  validateArtifactManifest(root, target.directory, {
    engine: target.libraryName,
    "node-loader": path.basename(addonPath),
  });
  return { addonPath, libraryPath };
}

function platformTarget() {
  const key = `${process.platform}-${process.arch}`;
  const targets = {
    "darwin-arm64": {
      directory: "macos-arm64",
      libraryName: NATIVE_ENGINE_LIBRARIES["macos-arm64"],
    },
    "linux-arm64": {
      directory: "linux-arm64",
      libraryName: NATIVE_ENGINE_LIBRARIES["linux-arm64"],
    },
    "linux-x64": {
      directory: "linux-x86_64",
      libraryName: NATIVE_ENGINE_LIBRARIES["linux-x86_64"],
    },
    "win32-x64": {
      directory: "windows-x86_64",
      libraryName: NATIVE_ENGINE_LIBRARIES["windows-x86_64"],
    },
  };
  const target = targets[key];
  if (target === undefined) throw engineUnavailable();
  return target;
}

export function validateArtifactManifest(root, target, required) {
  const manifestPath = path.join(root, ARTIFACT_MANIFEST_NAME);
  const manifestBytes = readRegularFile(
    manifestPath,
    MAX_ARTIFACT_MANIFEST_BYTES,
  );
  let manifest;
  try {
    manifest = parseStrictJson(manifestBytes, MAX_ARTIFACT_MANIFEST_BYTES);
  } catch {
    throw engineUnavailable();
  }
  if (
    !sameKeys(manifest, ["abi_contract_digest", "artifacts", "format", "target"]) ||
    manifest.abi_contract_digest !== NATIVE_ENGINE_ABI_CONTRACT_DIGEST ||
    manifest.format !== ARTIFACT_MANIFEST_FORMAT ||
    manifest.target !== target ||
    !Array.isArray(manifest.artifacts) ||
    manifest.artifacts.length !== Object.keys(required).length
  ) {
    throw engineUnavailable();
  }
  const actual = {};
  let previous = null;
  for (const artifact of manifest.artifacts) {
    if (!sameKeys(artifact, ["digest", "file", "role", "size"])) {
      throw engineUnavailable();
    }
    const current = [artifact.role, artifact.file];
    if (
      typeof artifact.role !== "string" ||
      typeof artifact.file !== "string" ||
      (previous !== null && compareArtifactKeys(current, previous) <= 0) ||
      !Object.hasOwn(required, artifact.role) ||
      required[artifact.role] !== artifact.file ||
      Object.hasOwn(actual, artifact.role) ||
      !validBasename(artifact.file) ||
      typeof artifact.digest !== "string" ||
      !/^sha256:[0-9a-f]{64}$/u.test(artifact.digest) ||
      !Number.isSafeInteger(artifact.size) ||
      artifact.size <= 0 ||
      artifact.size > MAX_LIBRARY_BYTES
    ) {
      throw engineUnavailable();
    }
    const artifactPath = path.join(root, artifact.file);
    if (sha256File(artifactPath, artifact.size) !== artifact.digest) {
      throw engineUnavailable();
    }
    actual[artifact.role] = artifact.file;
    previous = current;
  }
  if (!sameRecord(actual, required)) throw engineUnavailable();
}

function readRegularFile(filePath, maximumBytes) {
  const file = openRegularFile(filePath, maximumBytes);
  const output = Buffer.alloc(file.size);
  let offset = 0;
  let failed = false;
  try {
    while (offset < output.length) {
      const count = readSync(file.descriptor, output, offset, output.length - offset, null);
      if (count === 0) {
        failed = true;
        break;
      }
      offset += count;
    }
  } catch {
    failed = true;
  }
  closeDescriptor(file.descriptor);
  if (failed || offset !== output.length) throw engineUnavailable();
  return output;
}

function sha256File(filePath, expectedSize) {
  const file = openRegularFile(filePath, MAX_LIBRARY_BYTES);
  if (file.size !== expectedSize) {
    closeDescriptor(file.descriptor);
    throw engineUnavailable();
  }
  const digest = createHash("sha256");
  const buffer = Buffer.alloc(Math.min(1_048_576, expectedSize));
  let offset = 0;
  let failed = false;
  try {
    while (offset < expectedSize) {
      const remaining = expectedSize - offset;
      const count = readSync(
        file.descriptor,
        buffer,
        0,
        Math.min(buffer.length, remaining),
        null,
      );
      if (count === 0) {
        failed = true;
        break;
      }
      digest.update(buffer.subarray(0, count));
      offset += count;
    }
  } catch {
    failed = true;
  }
  closeDescriptor(file.descriptor);
  if (failed || offset !== expectedSize) throw engineUnavailable();
  return `sha256:${digest.digest("hex")}`;
}

function openRegularFile(filePath, maximumBytes) {
  let descriptor = null;
  let metadata = null;
  try {
    const pathMetadata = lstatSync(filePath);
    if (pathMetadata.isSymbolicLink()) return invalidFile();
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    descriptor = openSync(filePath, fsConstants.O_RDONLY | noFollow);
    metadata = fstatSync(descriptor);
  } catch {
    if (descriptor !== null) closeDescriptor(descriptor);
    descriptor = null;
  }
  if (
    descriptor === null ||
    metadata === null ||
    !metadata.isFile() ||
    metadata.size <= 0 ||
    metadata.size > maximumBytes
  ) {
    if (descriptor !== null) closeDescriptor(descriptor);
    throw engineUnavailable();
  }
  return { descriptor, size: metadata.size };
}

function closeDescriptor(descriptor) {
  try {
    closeSync(descriptor);
  } catch {
    // A close failure cannot make an invalid artifact valid.
  }
}

function invalidFile() {
  throw engineUnavailable();
}

function validBasename(value) {
  return (
    value !== "" &&
    value !== "." &&
    value !== ".." &&
    !value.includes("/") &&
    !value.includes("\\") &&
    path.basename(value) === value
  );
}

function compareArtifactKeys(left, right) {
  const leftKey = `${left[0]}\0${left[1]}`;
  const rightKey = `${right[0]}\0${right[1]}`;
  if (leftKey < rightKey) return -1;
  if (leftKey > rightKey) return 1;
  return 0;
}

function sameRecord(left, right) {
  return (
    sameKeys(left, Object.keys(right)) &&
    Object.entries(right).every(([key, value]) => left[key] === value)
  );
}

function sameRecordOfArrays(left, right) {
  return (
    sameKeys(left, Object.keys(right)) &&
    Object.entries(right).every(
      ([key, value]) => sameArray(left[key], value),
    )
  );
}

function sameArray(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function sameKeys(value, keys) {
  return (
    isObject(value) &&
    Object.keys(value).sort().join("\0") === [...keys].sort().join("\0")
  );
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validErrorCode(value) {
  return value === null || (
    typeof value === "string" &&
    /^[A-Z][A-Z0-9_]{0,63}$/u.test(value)
  );
}

function requestHandle(value) {
  if (!Number.isSafeInteger(value) || value <= 0) throw requestInvalid();
  return value;
}

function requestUnsignedInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw requestInvalid();
  return value;
}

function decodeObservationChunk(value, allowEmpty) {
  if (typeof value !== "string") throw responseInvalid();
  if (value === "") {
    if (allowEmpty) return Buffer.alloc(0);
    throw responseInvalid();
  }
  const maximumEncodedBytes = Math.floor(
    (NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES + 2) / 3,
  ) * 4;
  if (
    value.length > maximumEncodedBytes ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw responseInvalid();
  }
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.length === 0 ||
    decoded.length > NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES ||
    decoded.toString("base64url") !== value
  ) {
    throw responseInvalid();
  }
  return decoded;
}

function resultHandle(result, key, exact = true) {
  if (
    (exact && !sameKeys(result, [key])) ||
    !Number.isSafeInteger(result[key]) ||
    result[key] <= 0
  ) {
    throw responseInvalid();
  }
  return result[key];
}

function resultUnsignedInteger(result, key) {
  if (!Number.isSafeInteger(result[key]) || result[key] < 0) {
    throw responseInvalid();
  }
  return result[key];
}

function engineUnavailable() {
  return new NativeEngineError("The packaged shared SDK engine is unavailable.");
}

function requestInvalid() {
  return new NativeEngineError("The shared SDK engine request is invalid.");
}

function responseInvalid() {
  return new NativeEngineError("The shared SDK engine response is invalid.");
}
