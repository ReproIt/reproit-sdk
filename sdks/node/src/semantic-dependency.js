import { createHash } from "node:crypto";

import {
  currentOperationContext,
  markOperationUnowned,
  openObservation,
} from "./engine-operation.js";
import { parseStrictJson } from "./managed-json.js";
import {
  NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES,
  NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES,
} from "./native-engine.js";

const REQUEST_FORMAT = "reproit.semantic-dependency-request.v1";
const RESPONSE_FORMAT = "reproit.semantic-dependency-response.v1";
const MAX_RECORD_BYTES = 65_536;
const MAX_TARGET_BYTES = 8 * 1_024;
const MAX_PAYLOAD_BYTES = 24 * 1_024;
const MAX_METADATA_ENTRIES = 64;
const MAX_METADATA_BYTES = 8 * 1_024;
const MAX_METADATA_NAME_BYTES = 256;
const MAX_METADATA_VALUE_BYTES = 4 * 1_024;
const COMPONENT = /^[a-z][a-z0-9.-]*$/u;
const METHOD = /^[A-Z][A-Z0-9-]{0,31}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ERROR_CODES = new Set([
  "interrupted",
  "invalid-input",
  "not-found",
  "other",
  "permission-denied",
  "resource-limit",
  "unsupported",
]);
const CLASS_OPERATIONS = Object.freeze({
  database: new Set(["database-execute"]),
  "outbound-http": new Set(["outbound-http-request"]),
  queue: new Set([
    "queue-acknowledge",
    "queue-publish",
    "queue-receive",
    "queue-reject",
  ]),
});
const REQUEST_KEYS = [
  "encoding",
  "format",
  "metadata",
  "method",
  "observation_class",
  "operation",
  "payload",
  "protocol",
  "target",
];
const RESPONSE_KEYS = [
  "error_code",
  "error_number",
  "format",
  "metadata",
  "observation_class",
  "operation",
  "outcome",
  "payload",
  "request_digest",
  "status",
  "status_code",
];

export function dependencyRequest(fields) {
  const request = {
    encoding: fields?.encoding,
    metadata: cloneMetadata(fields?.metadata),
    method: fields?.method,
    observationClass: fields?.observationClass,
    operation: fields?.operation,
    payload: cloneBuffer(fields?.payload),
    protocol: fields?.protocol,
    target: fields?.target,
  };
  validateRequest(request);
  return Object.freeze(request);
}

export function dependencyResponse(fields) {
  const response = {
    errorCode: fields?.errorCode ?? null,
    errorNumber: fields?.errorNumber ?? null,
    metadata: cloneMetadata(fields?.metadata),
    outcome: fields?.outcome,
    payload: fields?.payload === null ? null : cloneBuffer(fields?.payload),
    status: fields?.status ?? null,
    statusCode: fields?.statusCode ?? null,
  };
  return Object.freeze(response);
}

export function encodeDependencyRequest(request) {
  validateRequest(request);
  return boundedRecord({
    encoding: request.encoding,
    format: REQUEST_FORMAT,
    metadata: encodeMetadata(request.metadata),
    method: request.method,
    observation_class: request.observationClass,
    operation: request.operation,
    payload: request.payload.toString("base64url"),
    protocol: request.protocol,
    target: Buffer.from(request.target, "utf8").toString("base64url"),
  });
}

export function decodeDependencyRequest(record) {
  const value = parseRecord(record, REQUEST_KEYS);
  require(value.format === REQUEST_FORMAT);
  const request = dependencyRequest({
    encoding: value.encoding,
    metadata: decodeMetadata(value.metadata),
    method: value.method,
    observationClass: value.observation_class,
    operation: value.operation,
    payload: decodeBase64url(value.payload),
    protocol: value.protocol,
    target: decodeUtf8(value.target),
  });
  return request;
}

export function encodeDependencyResponse(requestRecord, response) {
  const request = decodeDependencyRequest(requestRecord);
  validateResponse(request, response);
  return boundedRecord({
    error_code: response.errorCode,
    error_number: response.errorNumber,
    format: RESPONSE_FORMAT,
    metadata: encodeMetadata(response.metadata),
    observation_class: request.observationClass,
    operation: request.operation,
    outcome: response.outcome,
    payload: response.payload === null
      ? null
      : response.payload.toString("base64url"),
    request_digest: digest(requestRecord),
    status: response.status,
    status_code: response.statusCode,
  });
}

export function decodeDependencyResponse(requestRecord, responseRecord) {
  const request = decodeDependencyRequest(requestRecord);
  const value = parseRecord(responseRecord, RESPONSE_KEYS);
  require(
    value.format === RESPONSE_FORMAT &&
    value.observation_class === request.observationClass &&
    value.operation === request.operation &&
    typeof value.request_digest === "string" &&
    DIGEST.test(value.request_digest) &&
    value.request_digest === digest(requestRecord),
  );
  const response = dependencyResponse({
    errorCode: value.error_code,
    errorNumber: value.error_number,
    metadata: decodeMetadata(value.metadata),
    outcome: value.outcome,
    payload: value.payload === null ? null : decodeBase64url(value.payload),
    status: value.status,
    statusCode: value.status_code,
  });
  validateResponse(request, response);
  return response;
}

export function runDependency(request, capture) {
  const context = currentOperationContext();
  if (context === null) return capture();
  let requestRecord;
  try {
    requestRecord = encodeDependencyRequest(request);
  } catch {
    markInvalidRequest(context, request);
    return capture();
  }
  let session;
  try {
    session = openObservation(context, request.observationClass);
  } catch {
    context.abandon();
    return capture();
  }
  if (session === null) {
    return capture();
  }
  let written;
  try {
    written = writeChunks(session, "request", requestRecord);
  } catch {
    session.abandon();
    return capture();
  }
  if (!written) return capture();
  let action;
  try {
    action = session.dispatch();
  } catch {
    session.abandon();
    return capture();
  }
  if (action === "replay") return replayDependency(session, requestRecord);
  if (action !== "capture") {
    session.abandon();
    return capture();
  }
  let captured;
  try {
    captured = capture();
  } catch (error) {
    session.abandon();
    throw error;
  }
  if (captured !== null && typeof captured?.then === "function") {
    return Promise.resolve(captured).then(
      (response) => finishCapture(session, requestRecord, response),
      (error) => {
        session.abandon();
        throw error;
      },
    );
  }
  return finishCapture(session, requestRecord, captured);
}

function markInvalidRequest(context, request) {
  if (CLASS_OPERATIONS[request?.observationClass] !== undefined) {
    markOperationUnowned(
      context,
      request.observationClass,
      Buffer.from("semantic-dependency-request-invalid", "utf8"),
    );
  } else {
    context.abandon();
  }
}

function finishCapture(session, requestRecord, response) {
  let responseRecord;
  try {
    responseRecord = encodeDependencyResponse(requestRecord, response);
  } catch {
    session.abandon();
    return response;
  }
  if (writeChunks(session, "response", responseRecord)) {
    session.finish(response.outcome);
  }
  return response;
}

function replayDependency(session, requestRecord) {
  try {
    const responseRecord = readResponse(session);
    const response = decodeDependencyResponse(requestRecord, responseRecord);
    if (!session.finish(response.outcome)) throw invalidReplay();
    return response;
  } catch (error) {
    session.abandon();
    if (error?.code === "ERR_REPROIT_SEMANTIC_DEPENDENCY") throw error;
    throw invalidReplay();
  }
}

function validateRequest(request) {
  require(request !== null && typeof request === "object");
  require(
    CLASS_OPERATIONS[request.observationClass]?.has(request.operation) === true &&
    validComponent(request.protocol, 64) &&
    validComponent(request.encoding, 64) &&
    validUtf8(request.target, MAX_TARGET_BYTES) &&
    Buffer.isBuffer(request.payload) &&
    request.payload.length <= MAX_PAYLOAD_BYTES,
  );
  validateMetadata(request.metadata);
  if (request.observationClass === "outbound-http") {
    require(typeof request.method === "string" && METHOD.test(request.method));
  } else {
    require(request.method === null);
  }
}

function validateResponse(request, response) {
  require(response !== null && typeof response === "object");
  if (response.outcome === "error") {
    require(
      ERROR_CODES.has(response.errorCode) &&
      validErrorNumber(response.errorNumber) &&
      response.payload === null &&
      Array.isArray(response.metadata) &&
      response.metadata.length === 0 &&
      response.status === null &&
      response.statusCode === null,
    );
    return;
  }
  require(
    response.outcome === "response" &&
    response.errorCode === null &&
    response.errorNumber === null &&
    Buffer.isBuffer(response.payload) &&
    response.payload.length <= MAX_PAYLOAD_BYTES,
  );
  validateMetadata(response.metadata);
  if (request.observationClass === "outbound-http") {
    require(
      response.status === null &&
      Number.isInteger(response.statusCode) &&
      response.statusCode >= 100 &&
      response.statusCode <= 599,
    );
  } else {
    require(
      response.statusCode === null &&
      (response.status === null || validComponent(response.status, 64)),
    );
  }
}

function validateMetadata(metadata) {
  require(Array.isArray(metadata) && metadata.length <= MAX_METADATA_ENTRIES);
  let total = 0;
  for (const field of metadata) {
    require(
      field !== null &&
      typeof field === "object" &&
      sameKeys(field, ["name", "value"]) &&
      validUtf8(field.name, MAX_METADATA_NAME_BYTES) &&
      Buffer.isBuffer(field.value) &&
      field.value.length <= MAX_METADATA_VALUE_BYTES,
    );
    total += Buffer.byteLength(field.name, "utf8") + field.value.length;
    require(total <= MAX_METADATA_BYTES);
  }
}

function cloneMetadata(metadata) {
  if (!Array.isArray(metadata)) return metadata;
  return metadata.map((field) => ({
    name: field?.name,
    value: cloneBuffer(field?.value),
  }));
}

function encodeMetadata(metadata) {
  return metadata.map((field) => ({
    name: Buffer.from(field.name, "utf8").toString("base64url"),
    value: field.value.toString("base64url"),
  }));
}

function decodeMetadata(value) {
  require(Array.isArray(value));
  const metadata = value.map((field) => {
    require(
      field !== null &&
      typeof field === "object" &&
      !Array.isArray(field) &&
      sameKeys(field, ["name", "value"]),
    );
    return {
      name: decodeUtf8(field.name),
      value: decodeBase64url(field.value),
    };
  });
  validateMetadata(metadata);
  return metadata;
}

function parseRecord(record, keys) {
  require(Buffer.isBuffer(record) && record.length <= MAX_RECORD_BYTES);
  let value;
  try {
    value = parseStrictJson(record, MAX_RECORD_BYTES);
  } catch {
    throw invalidRecord();
  }
  require(
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    sameKeys(value, keys) &&
    Buffer.from(JSON.stringify(value), "utf8").equals(record),
  );
  return value;
}

function boundedRecord(value) {
  let record;
  try {
    record = Buffer.from(JSON.stringify(value), "utf8");
  } catch {
    throw invalidRecord();
  }
  require(record.length <= MAX_RECORD_BYTES);
  return record;
}

function decodeBase64url(value) {
  require(typeof value === "string" && /^[A-Za-z0-9_-]*$/u.test(value));
  let bytes;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    throw invalidRecord();
  }
  require(bytes.toString("base64url") === value);
  return bytes;
}

function decodeUtf8(value) {
  const bytes = decodeBase64url(value);
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw invalidRecord();
  }
  return decoded;
}

function validUtf8(value, maximumBytes) {
  if (typeof value !== "string") return false;
  const bytes = Buffer.from(value, "utf8");
  return bytes.length > 0 &&
    bytes.length <= maximumBytes &&
    bytes.toString("utf8") === value;
}

function validComponent(value, maximumBytes) {
  return typeof value === "string" &&
    value.length <= maximumBytes &&
    COMPONENT.test(value);
}

function validErrorNumber(value) {
  return value === null || (
    Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff
  );
}

function cloneBuffer(value) {
  return Buffer.isBuffer(value) ? Buffer.from(value) : value;
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function writeChunks(session, stream, record) {
  for (
    let offset = 0;
    offset < record.length;
    offset += NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES
  ) {
    const chunk = record.subarray(
      offset,
      Math.min(offset + NATIVE_ENGINE_MAX_OBSERVATION_CHUNK_BYTES, record.length),
    );
    const written = stream === "request"
      ? session.writeRequest(chunk)
      : session.writeResponse(chunk);
    if (!written) return false;
  }
  return true;
}

function readResponse(session) {
  const chunks = [];
  let total = 0;
  for (let reads = 0; reads < 9; reads += 1) {
    const result = session.readResponse();
    if (
      result === null ||
      !Buffer.isBuffer(result.chunk) ||
      result.chunk.length > NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES
    ) {
      throw invalidReplay();
    }
    total += result.chunk.length;
    if (total > MAX_RECORD_BYTES) throw invalidReplay();
    chunks.push(result.chunk);
    if (result.eof) return Buffer.concat(chunks);
  }
  throw invalidReplay();
}

function sameKeys(value, keys) {
  return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function require(condition) {
  if (!condition) throw invalidRecord();
}

function invalidRecord() {
  const error = new TypeError("The semantic dependency record is invalid.");
  error.code = "ERR_REPROIT_SEMANTIC_DEPENDENCY";
  return error;
}

function invalidReplay() {
  const error = new Error("The semantic dependency replay is invalid.");
  error.code = "ERR_REPROIT_SEMANTIC_DEPENDENCY";
  return error;
}
