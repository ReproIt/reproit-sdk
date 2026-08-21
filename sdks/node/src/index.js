import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { validateCandidate } from "./candidate-validation.js";
import { CaptureError } from "./capture-error.js";
import {
  runDeliveredWork,
  runOperation,
  runPreparedOperation,
  runStreamOperation,
} from "./operation.js";
export {
  CaptureError,
  runDeliveredWork,
  runOperation,
  runPreparedOperation,
  runStreamOperation,
};

// The managed-mode capture client. These modules import canonicalBytes and
// the queue bounds from this module at call time, so the circular imports
// below are safe: nothing in them runs module-level code against this file.
export { ManagedError } from "./managed-protocol.js";
export {
  ManagedWorkloadIdentityState,
  loadOrCreateManagedWorkloadKey,
} from "./managed-identity.js";
export {
  EncryptionResponse,
  ManagedProjectToken,
  ManagedTlsClient,
  ManagedTlsEndpoint,
} from "./managed-transport.js";
export {
  FrozenManagedCaptureClosure,
} from "./managed-closure.js";
export {
  NodeSubjectPackage,
  packageRunningNodeSubject,
  subjectBinding,
} from "./managed-subject.js";
export {
  PreparedManagedCandidate,
  SealedManagedCandidate,
} from "./managed-candidate.js";
export { ManagedCandidateSink } from "./managed-sink.js";
export {
  createOfficialManagedCandidateSink,
  OfficialManagedOperation,
  OfficialManagedProject,
} from "./official-managed.js";
export { captureProcessorCapabilities } from "./processor-capture.js";

export const MAX_GLOBAL_BYTES = 1_048_576;
export const MAX_OPERATION_BYTES = 262_144;
export const MAX_EVENT_BYTES = 65_536;
export const MAX_EVENTS = 1_024;
export const MAX_ACTIVE_OPERATIONS = 512;
export const MAX_QUEUED_CANDIDATES = 16;
export const MAX_FAILURE_STORM_IDENTITIES = 256;
const FAILURE_SUPPRESSION_MS = 60_000;
const FAILURE_TOKEN_CAPACITY = 4;
const FAILURE_TOKENS_PER_MS = 0.002;
const WORLD_TOKEN_BYTES = 65_536;
const COUNTER_MAXIMUM = Number.MAX_SAFE_INTEGER;
const RECALL_KEYS = [
  "candidate_delivery_expired",
  "candidate_durably_accepted",
  "candidate_incomplete",
  "candidate_queue_full",
  "candidate_rejected",
  "eligible_failure_observed",
  "suppressed_exact_storm",
  "suppressed_high_cardinality_storm",
];
export function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(canonicalValue(value)), "utf8");
}

function canonicalValue(value) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new CaptureError("The protocol value contains an invalid number.");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  throw new CaptureError("The protocol value has an unsupported type.");
}

function eventRecord(kind, sequence, value) {
  const encoded = canonicalBytes(value);
  if (encoded.length > MAX_EVENT_BYTES) {
    throw new CaptureError("The SDK capture limit was reached.");
  }
  return {
    kind,
    payload: encoded.toString("base64url"),
    sequence,
  };
}

function recordSize(record) {
  return record.payload.length + 32;
}

export class Sdk {
  #globalBytes = 0;
  #operations = new Map();
  #recall = Object.fromEntries(RECALL_KEYS.map((key) => [key, 0]));
  #sink;
  #stormAdmitted = new Map();
  #stormLastRefill = performance.now();
  #stormTokenRejections = 0n;
  #stormTokens = FAILURE_TOKEN_CAPACITY;

  constructor(sink) {
    this.#sink = sink;
  }

  get activeOperations() {
    return this.#operations.size;
  }

  get recallCounters() {
    const counters = { ...this.#recall };
    const sinkCounters = this.#sink.recallCounters;
    if (sinkCounters) {
      for (const key of RECALL_KEYS) {
        counters[key] = Math.min(
          COUNTER_MAXIMUM,
          counters[key] + sinkCounters[key],
        );
      }
    }
    return counters;
  }

  begin(start, value) {
    const record = eventRecord("begin", 0, value);
    const bytes = recordSize(record);
    if (this.#operations.has(start.operationId)) {
      throw new CaptureError("The operation already has capture state.");
    }
    if (
      this.#operations.size >= MAX_ACTIVE_OPERATIONS ||
      this.#globalBytes + this.#sink.queuedBytes + bytes > MAX_GLOBAL_BYTES
    ) {
      throw new CaptureError("The SDK capture limit was reached.");
    }
    this.#operations.set(start.operationId, {
      bytes,
      records: [record],
      start: structuredClone(start),
    });
    this.#globalBytes += bytes;
  }

  recordInput(operationId, value) {
    this.#append(operationId, "input", value);
  }

  recordDependency(operationId, value) {
    this.#append(operationId, "dependency", value);
  }

  succeed(operationId) {
    this.#delete(operationId);
  }

  cancel(operationId) {
    this.#delete(operationId);
  }

  abandonIncomplete(operationId) {
    if (!this.#operations.has(operationId)) return;
    this.#delete(operationId);
    incrementCounter(this.#recall, "candidate_incomplete");
  }

  fail(operationId, value) {
    incrementCounter(this.#recall, "eligible_failure_observed");
    const operation = this.#operations.get(operationId);
    if (!operation) {
      incrementCounter(this.#recall, "candidate_incomplete");
      throw new CaptureError(
        "The operation does not have complete capture state.",
      );
    }
    let failure;
    try {
      failure = eventRecord("failure", operation.records.length, value);
    } finally {
      this.#delete(operationId);
    }
    const failureSize = recordSize(failure);
    if (!withinOperation(operation, failureSize)) {
      incrementCounter(this.#recall, "candidate_incomplete");
      throw new CaptureError("The SDK capture limit was reached.");
    }
    operation.records.push(failure);
    const terminalValue = {
      complete: true,
      event_count: operation.records.length,
      format: "reproit.terminal.v1",
    };
    const terminal = eventRecord(
      "terminal",
      operation.records.length,
      terminalValue,
    );
    if (
      operation.bytes + failureSize + recordSize(terminal) >
      MAX_OPERATION_BYTES
    ) {
      incrementCounter(this.#recall, "candidate_incomplete");
      throw new CaptureError("The SDK capture limit was reached.");
    }
    operation.records.push(terminal);
    const candidate = {
      capture_id: operation.start.captureId,
      deployment: operation.start.deployment,
      failure: structuredClone(value.failure),
      format: "reproit.candidate.v1",
      operation_id: operationId,
      processing_mode: operation.start.deployment.processing_mode,
      records: operation.records,
      world_id: operation.start.worldId,
    };
    try {
      validateCandidate(candidate, value, canonicalBytes);
    } catch {
      incrementCounter(this.#recall, "candidate_incomplete");
      throw new CaptureError(
        "The operation does not have complete capture state.",
      );
    }
    if (
      !(this.#sink.processingModes instanceof Set) ||
      !this.#sink.processingModes.has(candidate.processing_mode)
    ) {
      incrementCounter(this.#recall, "candidate_incomplete");
      throw new CaptureError(
        "The candidate sink does not support this processing mode.",
      );
    }
    if (!this.#admitFailure(candidate, value)) return;
    const encoded = canonicalBytes(candidate);
    if (
      encoded.length > MAX_OPERATION_BYTES ||
      !this.#sink.trySend(operation.start.captureId, encoded)
    ) {
      incrementCounter(this.#recall, "candidate_queue_full");
      throw new CaptureError("The SDK capture limit was reached.");
    }
  }

  #admitFailure(candidate, value) {
    const identity = value?.identity;
    const failure = value?.failure;
    const deployment = candidate?.deployment;
    if (!identity || !failure || !deployment?.subject) {
      throw new CaptureError(
        "The operation does not have complete capture state.",
      );
    }
    const stable = {
      failure_identity_digest: failure.identity,
      format: "reproit.failure-storm-identity.v1",
      operation_kind: identity.operation_kind,
      operation_name: identity.operation_name,
      service_id: deployment.service_id,
      source_revision: deployment.source_revision,
      subject_artifact_digest: deployment.subject.artifact_digest,
    };
    if (
      Object.values(stable).some(
        (part) => typeof part !== "string" || part.length === 0,
      )
    ) {
      throw new CaptureError(
        "The operation does not have complete capture state.",
      );
    }
    const key = createHash("sha256")
      .update(canonicalBytes(stable))
      .digest("hex");
    const now = performance.now();
    const elapsed = Math.max(0, now - this.#stormLastRefill);
    this.#stormTokens = Math.min(
      FAILURE_TOKEN_CAPACITY,
      this.#stormTokens + elapsed * FAILURE_TOKENS_PER_MS,
    );
    this.#stormLastRefill = now;
    for (const [known, entry] of this.#stormAdmitted) {
      if (now - entry.admitted >= FAILURE_SUPPRESSION_MS)
        this.#stormAdmitted.delete(known);
    }
    const existing = this.#stormAdmitted.get(key);
    if (existing) {
      existing.observed = now;
      existing.suppressed =
        existing.suppressed === 2n ** 64n - 1n
          ? existing.suppressed
          : existing.suppressed + 1n;
      incrementCounter(this.#recall, "suppressed_exact_storm");
      return false;
    }
    if (this.#stormTokens < 1) {
      this.#stormTokenRejections =
        this.#stormTokenRejections === 2n ** 64n - 1n
          ? this.#stormTokenRejections
          : this.#stormTokenRejections + 1n;
      incrementCounter(this.#recall, "suppressed_high_cardinality_storm");
      return false;
    }
    if (this.#stormAdmitted.size >= MAX_FAILURE_STORM_IDENTITIES) {
      const oldest = [...this.#stormAdmitted].sort(
        ([leftKey, left], [rightKey, right]) =>
          left.observed - right.observed || leftKey.localeCompare(rightKey),
      )[0];
      if (oldest) this.#stormAdmitted.delete(oldest[0]);
    }
    this.#stormTokens -= 1;
    this.#stormAdmitted.set(key, {
      admitted: now,
      observed: now,
      suppressed: 0n,
    });
    return true;
  }

  #append(operationId, kind, value) {
    const operation = this.#operations.get(operationId);
    if (!operation) {
      throw new CaptureError(
        "The operation does not have complete capture state.",
      );
    }
    let record;
    try {
      record = eventRecord(kind, operation.records.length, value);
    } catch (error) {
      this.#delete(operationId);
      throw error;
    }
    const bytes = recordSize(record);
    if (
      !withinOperation(operation, bytes) ||
      this.#globalBytes + this.#sink.queuedBytes + bytes > MAX_GLOBAL_BYTES
    ) {
      this.#delete(operationId);
      throw new CaptureError("The SDK capture limit was reached.");
    }
    operation.records.push(record);
    operation.bytes += bytes;
    this.#globalBytes += bytes;
  }

  #delete(operationId) {
    const operation = this.#operations.get(operationId);
    if (operation) {
      this.#operations.delete(operationId);
      this.#globalBytes = Math.max(0, this.#globalBytes - operation.bytes);
    }
  }
}

function incrementCounter(counters, key) {
  counters[key] = Math.min(COUNTER_MAXIMUM, counters[key] + 1);
}

function withinOperation(operation, bytes) {
  return (
    operation.records.length < MAX_EVENTS &&
    operation.bytes + bytes <= MAX_OPERATION_BYTES
  );
}
