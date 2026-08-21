import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

const CANDIDATE_KEYS = [
  "capture_id",
  "deployment",
  "failure",
  "format",
  "operation_id",
  "processing_mode",
  "records",
  "world_id",
];
const DEPENDENCY_KEYS = [
  "adapter_id",
  "adapter_version",
  "causal_parent_id",
  "cursor",
  "cursor_digest",
  "format",
];
const TERMINAL_KEYS = ["complete", "event_count", "format"];

export function candidateUsesMode(candidateBytes, modes, canonicalBytes) {
  let candidate;
  try {
    candidate = JSON.parse(Buffer.from(candidateBytes).toString("utf8"));
  } catch {
    return false;
  }
  const modeMatches =
    isObject(candidate) &&
    isObject(candidate.deployment) &&
    Buffer.from(canonicalBytes(candidate)).equals(
      Buffer.from(candidateBytes),
    ) &&
    modes.has(candidate.processing_mode) &&
    candidate.processing_mode === candidate.deployment.processing_mode;
  if (!modeMatches) return false;
  try {
    const failureRecord = candidate.records.find(
      (record) => record.kind === "failure",
    );
    const failure = decodeRecordPayload(failureRecord);
    validateCandidate(candidate, failure, canonicalBytes);
    return true;
  } catch {
    return false;
  }
}

export function validateCandidate(candidate, failure, canonicalBytes) {
  if (
    !isObject(candidate) ||
    !sameKeys(candidate, CANDIDATE_KEYS) ||
    candidate.format !== "reproit.candidate.v1" ||
    !validIdentity(candidate.capture_id, "cap_") ||
    !validIdentity(candidate.operation_id, "op_") ||
    !validDigest(candidate.world_id) ||
    !isObject(candidate.deployment) ||
    candidate.processing_mode !== candidate.deployment.processing_mode ||
    !isObject(candidate.failure) ||
    !Array.isArray(candidate.records) ||
    candidate.records.length < 3 ||
    candidate.records.length > 1_025
  ) {
    throw new Error("The candidate identity is incomplete.");
  }
  const records = candidate.records;
  if (
    records[0]?.kind !== "begin" ||
    records.at(-1)?.kind !== "terminal" ||
    records.some((record, index) => !validRecord(record, index)) ||
    records.filter((record) => record.kind === "begin").length !== 1 ||
    records.filter((record) => record.kind === "failure").length !== 1 ||
    records.filter((record) => record.kind === "terminal").length !== 1
  ) {
    throw new Error("The candidate record sequence is incomplete.");
  }
  const payloads = records.map((record) => decodeRecordPayload(record));
  validatePayloadBindings(
    candidate,
    failure,
    records,
    payloads,
    canonicalBytes,
  );
}

export function decodeRecordPayload(record) {
  if (!isObject(record) || typeof record.payload !== "string") {
    throw new Error("The candidate record payload is invalid.");
  }
  const bytes = decodeBase64url(record.payload);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("The candidate record payload is invalid.");
  }
  if (!isObject(value)) {
    throw new Error("The candidate record payload is invalid.");
  }
  return value;
}

function validatePayloadBindings(
  candidate,
  failure,
  records,
  payloads,
  canonicalBytes,
) {
  const begin = payloads[0];
  const terminal = payloads.at(-1);
  const failureIndex = records.findIndex((record) => record.kind === "failure");
  const failurePayload = payloads[failureIndex];
  const identity = failurePayload?.identity;
  if (
    !isObject(identity) ||
    begin.format !== "reproit.operation-begin.v1" ||
    !["request-response", "stream", "delivered-work"].includes(
      identity.operation_kind,
    ) ||
    begin.operation_kind !== identity.operation_kind ||
    begin.operation_name !== identity.operation_name ||
    !sameValue(failurePayload, failure, canonicalBytes) ||
    !sameValue(failurePayload.failure, candidate.failure, canonicalBytes) ||
    digestValue(identity, canonicalBytes) !== candidate.failure.identity ||
    !sameKeys(terminal, TERMINAL_KEYS) ||
    terminal.complete !== true ||
    terminal.event_count !== records.length - 1 ||
    terminal.format !== "reproit.terminal.v1"
  ) {
    throw new Error("The candidate payload bindings are incomplete.");
  }
  validateOrderedPayloads(records, payloads);
}

function validateOrderedPayloads(records, payloads) {
  let inputIndex = 0;
  for (let index = 0; index < records.length; index += 1) {
    const { kind } = records[index];
    const payload = payloads[index];
    if (kind === "input") {
      if (
        payload.format !== "reproit.operation-input.v1" ||
        !Number.isSafeInteger(payload.input_index) ||
        payload.input_index !== inputIndex ||
        digestBytes(decodeBase64url(payload.value)) !== payload.value_digest
      ) {
        throw new Error("The candidate input binding is invalid.");
      }
      inputIndex += 1;
    } else if (kind === "dependency" && !validDependencyCursor(payload)) {
      throw new Error("The candidate dependency cursor is invalid.");
    } else if (
      !["begin", "dependency", "failure", "input", "terminal"].includes(kind)
    ) {
      throw new Error("The candidate contains an unknown record kind.");
    }
  }
}

function validRecord(record, sequence) {
  return (
    isObject(record) &&
    sameKeys(record, ["kind", "payload", "sequence"]) &&
    Number.isSafeInteger(record.sequence) &&
    record.sequence === sequence &&
    typeof record.kind === "string" &&
    typeof record.payload === "string"
  );
}

function validDependencyCursor(value) {
  return (
    isObject(value) &&
    sameKeys(value, DEPENDENCY_KEYS) &&
    typeof value.adapter_id === "string" &&
    /^[a-z][a-z0-9.-]{0,127}$/u.test(value.adapter_id) &&
    typeof value.adapter_version === "string" &&
    value.adapter_version.length >= 1 &&
    value.adapter_version.length <= 64 &&
    typeof value.cursor === "string" &&
    value.cursor.length >= 1 &&
    value.cursor.length <= 16_384 &&
    /^[A-Za-z0-9_-]+$/u.test(value.cursor) &&
    (value.causal_parent_id === null ||
      validIdentity(value.causal_parent_id, "op_")) &&
    validDigest(value.cursor_digest) &&
    value.format === "reproit.dependency-cursor.v1"
  );
}

function decodeBase64url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new Error("The base64url value is invalid.");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) {
    throw new Error("The base64url value is invalid.");
  }
  return bytes;
}

function validIdentity(value, prefix) {
  return (
    typeof value === "string" &&
    new RegExp(
      `^${prefix}[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
      "u",
    ).test(value)
  );
}

function validDigest(value) {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function digestValue(value, canonicalBytes) {
  return digestBytes(canonicalBytes(value));
}

function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sameKeys(value, keys) {
  return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function sameValue(left, right, canonicalBytes) {
  return (
    isObject(left) &&
    isObject(right) &&
    Buffer.from(canonicalBytes(left)).equals(Buffer.from(canonicalBytes(right)))
  );
}
