import {
  currentOperationContext,
  openDependency,
} from "./engine-operation.js";
import {
  NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES,
  NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES,
} from "./native-engine.js";

export function dependencyRequest(fields) {
  return Object.freeze({
    encoding: fields?.encoding,
    metadata: cloneMetadata(fields?.metadata),
    method: fields?.method,
    observationClass: fields?.observationClass,
    operation: fields?.operation,
    payload: cloneBuffer(fields?.payload),
    protocol: fields?.protocol,
    target: fields?.target,
  });
}

export function dependencyResponse(fields) {
  return Object.freeze({
    errorCode: fields?.errorCode ?? null,
    errorNumber: fields?.errorNumber ?? null,
    metadata: cloneMetadata(fields?.metadata),
    outcome: fields?.outcome,
    payload: fields?.payload === null ? null : cloneBuffer(fields?.payload),
    status: fields?.status ?? null,
    statusCode: fields?.statusCode ?? null,
  });
}

export function runDependency(request, capture) {
  const context = currentOperationContext();
  if (context === null) return capture();
  let session;
  try {
    session = openDependency(context, requestInput(request));
  } catch {
    context.abandon();
    return capture();
  }
  if (session === null) return capture();
  if (session.action === "capture") return captureDependency(session, capture);
  if (session.action === "replay") return replayDependency(session);
  session.abandon();
  return capture();
}

// Start one event-driven dependency without changing the shared engine contract.
export function startDependency(request) {
  const context = currentOperationContext();
  if (context === null) return null;
  let session;
  try {
    session = openDependency(context, requestInput(request));
  } catch {
    context.abandon();
    return null;
  }
  if (session === null) return null;
  if (session.action === "replay") {
    return Object.freeze({ action: "replay", response: replayDependency(session) });
  }
  if (session.action !== "capture") {
    session.abandon();
    return null;
  }
  let finished = false;
  return Object.freeze({
    action: "capture",
    abandon() {
      if (finished) return;
      finished = true;
      session.abandon();
    },
    finish(response) {
      if (finished) return null;
      finished = true;
      try {
        return session.finish(responseInput(response));
      } catch {
        session.abandon();
        return null;
      }
    },
  });
}

function captureDependency(session, capture) {
  let captured;
  try {
    captured = capture();
  } catch (error) {
    session.abandon();
    throw error;
  }
  if (captured !== null && typeof captured?.then === "function") {
    return Promise.resolve(captured).then(
      (response) => finishCapture(session, response),
      (error) => {
        session.abandon();
        throw error;
      },
    );
  }
  return finishCapture(session, captured);
}

function finishCapture(session, response) {
  try {
    session.finish(responseInput(response));
  } catch {
    session.abandon();
  }
  return response;
}

function replayDependency(session) {
  try {
    const responseRecord = readResponse(session);
    const outcome = session.finish(null);
    if (outcome === null) throw invalidReplay();
    return responseFromRecord(responseRecord, outcome);
  } catch (error) {
    session.abandon();
    if (error?.code === "ERR_REPROIT_SEMANTIC_DEPENDENCY") throw error;
    throw invalidReplay();
  }
}

function requestInput(request) {
  return {
    encoding: boundedText(request?.encoding),
    metadata: encodeMetadata(request?.metadata),
    method: request?.method === null ? null : boundedText(request?.method),
    observation_class: boundedText(request?.observationClass),
    operation: boundedText(request?.operation),
    payload: boundedBuffer(request?.payload).toString("base64url"),
    protocol: boundedText(request?.protocol),
    target: boundedTextBuffer(request?.target).toString("base64url"),
  };
}

function responseInput(response) {
  return {
    error_code: response?.errorCode,
    error_number: response?.errorNumber,
    metadata: encodeMetadata(response?.metadata),
    outcome: boundedText(response?.outcome),
    payload: response?.payload === null
      ? null
      : boundedBuffer(response?.payload).toString("base64url"),
    status: response?.status === null ? null : boundedText(response?.status),
    status_code: response?.statusCode,
  };
}

function responseFromRecord(record, validatedOutcome) {
  try {
    const value = JSON.parse(record.toString("utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw invalidReplay();
    }
    return dependencyResponse({
      errorCode: value.error_code,
      errorNumber: value.error_number,
      metadata: decodeMetadata(value.metadata),
      outcome: validatedOutcome,
      payload: value.payload === null ? null : decodeBase64url(value.payload),
      status: value.status,
      statusCode: value.status_code,
    });
  } catch (error) {
    if (error?.code === "ERR_REPROIT_SEMANTIC_DEPENDENCY") throw error;
    throw invalidReplay();
  }
}

function encodeMetadata(metadata) {
  if (
    !Array.isArray(metadata) ||
    metadata.length > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
  ) {
    throw invalidValue();
  }
  const encoded = [];
  let totalBytes = 0;
  for (const field of metadata) {
    const name = boundedTextBuffer(field?.name);
    const value = boundedBuffer(field?.value);
    totalBytes += name.length + value.length;
    if (totalBytes > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES) {
      throw invalidValue();
    }
    encoded.push({
      name: name.toString("base64url"),
      value: value.toString("base64url"),
    });
  }
  return encoded;
}

function decodeMetadata(value) {
  if (
    !Array.isArray(value) ||
    value.length > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
  ) {
    throw invalidReplay();
  }
  const metadata = [];
  let totalBytes = 0;
  for (const field of value) {
    const nameBytes = decodeBase64url(field?.name);
    const fieldValue = decodeBase64url(field?.value);
    totalBytes += nameBytes.length + fieldValue.length;
    if (totalBytes > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES) {
      throw invalidReplay();
    }
    metadata.push({
      name: new TextDecoder("utf-8", { fatal: true }).decode(nameBytes),
      value: fieldValue,
    });
  }
  return metadata;
}

function readResponse(session) {
  const chunks = [];
  let totalBytes = 0;
  const maximumReads = NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES;
  for (let reads = 0; reads < maximumReads; reads += 1) {
    const result = session.readResponse();
    if (
      result === null ||
      !Buffer.isBuffer(result.chunk) ||
      result.chunk.length > NATIVE_ENGINE_MAX_OBSERVATION_RESPONSE_READ_BYTES ||
      (result.chunk.length === 0 && !result.eof)
    ) {
      break;
    }
    totalBytes += result.chunk.length;
    if (totalBytes > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES) break;
    chunks.push(result.chunk);
    if (result.eof) {
      const record = Buffer.concat(chunks);
      if (record.length > 0) return record;
      break;
    }
  }
  throw invalidReplay();
}

function cloneMetadata(metadata) {
  if (!Array.isArray(metadata)) return metadata;
  return metadata.map((field) => ({
    name: field?.name,
    value: cloneBuffer(field?.value),
  }));
}

function cloneBuffer(value) {
  return Buffer.isBuffer(value) ? Buffer.from(value) : value;
}

function boundedText(value) {
  boundedTextBuffer(value);
  return value;
}

function boundedTextBuffer(value) {
  if (typeof value !== "string") throw invalidValue();
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES) {
    throw invalidValue();
  }
  return bytes;
}

function boundedBuffer(value) {
  if (
    !Buffer.isBuffer(value) ||
    value.length > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
  ) {
    throw invalidValue();
  }
  return value;
}

function decodeBase64url(value) {
  if (
    typeof value !== "string" ||
    value.length > NATIVE_ENGINE_MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES * 2 ||
    !/^[A-Za-z0-9_-]*$/u.test(value)
  ) {
    throw invalidReplay();
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) throw invalidReplay();
  return bytes;
}

function invalidValue() {
  const error = new TypeError("The semantic dependency value is invalid.");
  error.code = "ERR_REPROIT_SEMANTIC_DEPENDENCY";
  return error;
}

function invalidReplay() {
  const error = new Error("The semantic dependency replay is invalid.");
  error.code = "ERR_REPROIT_SEMANTIC_DEPENDENCY";
  return error;
}
