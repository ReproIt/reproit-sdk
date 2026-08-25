import { createHash } from "node:crypto";

import {
  currentOperationContext,
  openObservation,
} from "./engine-operation.js";
import { parseStrictJson } from "./managed-json.js";
import {
  NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES,
  NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES,
} from "./native-engine.js";

const REQUEST_FORMAT = "reproit.semantic-observation-request.v1";
const RESPONSE_FORMAT = "reproit.semantic-observation-response.v1";
const MAX_TARGET_BYTES = 16 * 1_024;
const MAX_VALUE_BYTES = 32 * 1_024;
const MAX_RESPONSE_BYTES = 64 * 1_024;
const MAX_RESPONSE_READS = 16;
const ERROR_CODES = new Set([
  "interrupted",
  "invalid-input",
  "not-found",
  "other",
  "permission-denied",
  "resource-limit",
  "unsupported",
]);
const RESPONSE_KEYS = [
  "error_code",
  "error_number",
  "format",
  "operation",
  "outcome",
  "request_digest",
  "value",
];

export const SEMANTIC_OPERATIONS = Object.freeze({
  clock: "clock-wall-time",
  environment: "environment-read",
  filesystem: "filesystem-read",
  randomness: "random-bytes",
});

export function semanticRequest(operation, target, offset, length) {
  const request = {
    format: REQUEST_FORMAT,
    length,
    offset,
    operation,
    target,
  };
  validateRequest(request);
  return request;
}

export function encodedTarget(value) {
  if (typeof value !== "string") return null;
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length === 0 || bytes.length > MAX_TARGET_BYTES) return null;
  return bytes.toString("base64url");
}

export function startSemanticObservation(observationClass, request) {
  const context = currentOperationContext();
  if (context === null) return null;
  const session = openObservation(context, observationClass);
  if (session === null) return null;
  const requestBytes = canonicalBytes(request);
  if (!writeChunks(session, "request", requestBytes)) return null;
  const action = session.dispatch();
  if (action === null) return null;
  const digest = `sha256:${createHash("sha256").update(requestBytes).digest("hex")}`;
  if (action === "capture") {
    return new CaptureObservation(session, request, digest);
  }
  if (action !== "replay") {
    session.abandon();
    throw replayUnavailable();
  }
  const response = readReplayResponse(session, request, digest);
  if (!session.finish(response.outcome)) throw replayUnavailable();
  return Object.freeze({ action, response });
}

export function replayValue(response) {
  if (response.outcome === "error") throw replayError(response);
  return response.value === null
    ? null
    : Buffer.from(response.value, "base64url");
}

export function errorResponse(error) {
  return {
    errorCode: semanticErrorCode(error),
    errorNumber: semanticErrorNumber(error),
  };
}

export function replayError(response) {
  const error = new Error("The captured runtime observation returned an error.");
  error.code = nodeErrorCode(response.error_code);
  if (response.error_number !== null) error.errno = -response.error_number;
  return error;
}

export function responseBytes(value) {
  if (value === null) return null;
  const bytes = Buffer.from(value);
  return bytes.length <= MAX_VALUE_BYTES ? bytes : null;
}

class CaptureObservation {
  #digest;
  #request;
  #session;

  constructor(session, request, digest) {
    this.action = "capture";
    this.#digest = digest;
    this.#request = request;
    this.#session = session;
  }

  finishResponse(value) {
    this.#finish("response", value, null, null);
  }

  finishError(error) {
    const mapped = errorResponse(error);
    this.#finish("error", null, mapped.errorCode, mapped.errorNumber);
  }

  abandon() {
    const session = this.#take();
    session?.abandon();
  }

  #finish(outcome, value, errorCode, errorNumber) {
    const session = this.#take();
    if (session === null) return;
    const response = {
      error_code: errorCode,
      error_number: errorNumber,
      format: RESPONSE_FORMAT,
      operation: this.#request.operation,
      outcome,
      request_digest: this.#digest,
      value: value === null ? null : Buffer.from(value).toString("base64url"),
    };
    try {
      validatePair(this.#request, response, this.#digest);
      const bytes = canonicalBytes(response);
      if (!writeChunks(session, "response", bytes)) return;
      session.finish(outcome);
    } catch {
      session.abandon();
    }
  }

  #take() {
    const session = this.#session;
    this.#session = null;
    return session;
  }
}

function readReplayResponse(session, request, digest) {
  const chunks = [];
  let total = 0;
  for (let reads = 0; reads < MAX_RESPONSE_READS; reads += 1) {
    const result = session.readResponse();
    if (
      result === null ||
      !Buffer.isBuffer(result.chunk) ||
      result.chunk.length > NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES
    ) {
      session.abandon();
      throw replayUnavailable();
    }
    total += result.chunk.length;
    if (total > MAX_RESPONSE_BYTES) {
      session.abandon();
      throw replayUnavailable();
    }
    chunks.push(result.chunk);
    if (result.eof) {
      try {
        const response = parseStrictJson(Buffer.concat(chunks), MAX_RESPONSE_BYTES);
        validatePair(request, response, digest);
        return response;
      } catch {
        session.abandon();
        throw replayUnavailable();
      }
    }
  }
  session.abandon();
  throw replayUnavailable();
}

function writeChunks(session, stream, bytes) {
  if (bytes.length === 0) return false;
  for (let offset = 0; offset < bytes.length; offset += NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES) {
    const chunk = bytes.subarray(
      offset,
      Math.min(offset + NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES, bytes.length),
    );
    const written = stream === "request"
      ? session.writeRequest(chunk)
      : session.writeResponse(chunk);
    if (!written) return false;
  }
  return true;
}

function validateRequest(request) {
  if (
    request === null ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    request.format !== REQUEST_FORMAT
  ) {
    throw new TypeError("The semantic observation request is invalid.");
  }
  if (request.operation === SEMANTIC_OPERATIONS.clock) {
    require(request.target === null && request.offset === null && request.length === null);
    return;
  }
  if (request.operation === SEMANTIC_OPERATIONS.environment) {
    require(validTarget(request.target) && request.offset === null && request.length === null);
    return;
  }
  if (request.operation === SEMANTIC_OPERATIONS.filesystem) {
    require(
      validTarget(request.target) &&
      validOffset(request.offset) &&
      validLength(request.length),
    );
    return;
  }
  if (request.operation === SEMANTIC_OPERATIONS.randomness) {
    require(request.target === null && request.offset === null && validLength(request.length));
    return;
  }
  throw new TypeError("The semantic observation request is invalid.");
}

function validatePair(request, response, digest) {
  require(
    response !== null &&
    typeof response === "object" &&
    !Array.isArray(response) &&
    sameKeys(response, RESPONSE_KEYS) &&
    response.format === RESPONSE_FORMAT &&
    response.operation === request.operation &&
    response.request_digest === digest &&
    ["error", "response"].includes(response.outcome),
  );
  if (response.outcome === "error") {
    require(
      ERROR_CODES.has(response.error_code) &&
      validErrorNumber(response.error_number) &&
      response.value === null,
    );
    return;
  }
  require(response.error_code === null && response.error_number === null);
  if (request.operation === SEMANTIC_OPERATIONS.environment && response.value === null) return;
  const value = decodeCanonicalBase64url(response.value);
  require(value !== null && value.length <= MAX_VALUE_BYTES);
  if (request.operation === SEMANTIC_OPERATIONS.clock) require(value.length === 8);
  if (request.operation === SEMANTIC_OPERATIONS.filesystem) {
    require(value.length <= request.length);
  }
  if (request.operation === SEMANTIC_OPERATIONS.randomness) {
    require(value.length === request.length);
  }
}

function decodeCanonicalBase64url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value)) return null;
  try {
    const bytes = Buffer.from(value, "base64url");
    return bytes.toString("base64url") === value ? bytes : null;
  } catch {
    return null;
  }
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function validTarget(value) {
  const bytes = decodeCanonicalBase64url(value);
  return bytes !== null && bytes.length > 0 && bytes.length <= MAX_TARGET_BYTES;
}

function validLength(value) {
  return Number.isSafeInteger(value) && value > 0 && value <= MAX_VALUE_BYTES;
}

function validOffset(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function validErrorNumber(value) {
  return value === null ||
    (Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff);
}

function semanticErrorCode(error) {
  const code = typeof error?.code === "string" ? error.code : null;
  if (code === "EINTR") return "interrupted";
  if (code === "EINVAL") return "invalid-input";
  if (code === "ENOENT") return "not-found";
  if (["EACCES", "EPERM"].includes(code)) return "permission-denied";
  if (["EMFILE", "ENFILE", "ENOMEM", "ENOSPC"].includes(code)) {
    return "resource-limit";
  }
  if (["ENOTSUP", "EOPNOTSUPP"].includes(code)) return "unsupported";
  return "other";
}

function semanticErrorNumber(error) {
  const number = error?.errno;
  if (!Number.isInteger(number)) return null;
  const absolute = Math.abs(number);
  return absolute <= 0xffff_ffff ? absolute : null;
}

function nodeErrorCode(code) {
  return {
    interrupted: "EINTR",
    "invalid-input": "EINVAL",
    "not-found": "ENOENT",
    other: "ERR_REPROIT_CAPTURED_OBSERVATION",
    "permission-denied": "EACCES",
    "resource-limit": "ENOMEM",
    unsupported: "ENOTSUP",
  }[code];
}

function sameKeys(value, keys) {
  return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function require(condition) {
  if (!condition) throw new TypeError("The semantic observation value is invalid.");
}

function replayUnavailable() {
  const error = new Error("The captured runtime observation is unavailable.");
  error.code = "ERR_REPROIT_REPLAY_OBSERVATION";
  return error;
}
