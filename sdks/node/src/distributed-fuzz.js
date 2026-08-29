import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, createPublicKey, verify } from "node:crypto";

import { canonicalBytes } from "./encoding.js";

export const FUZZ_CONTEXT_HTTP_HEADER = "ReproIt-Fuzz-Context";
export const FUZZ_PARENT_HTTP_HEADER = "ReproIt-Parent-Operation";
export const FUZZ_CONTEXT_QUEUE_METADATA = "reproit.fuzz.context";
export const FUZZ_PARENT_QUEUE_METADATA = "reproit.parent.operation";

const MAX_CONTEXT_BYTES = 4_096;
const UUID7 = "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const CAMPAIGN_ID = new RegExp(`^fc_${UUID7}$`);
const CASE_ID = new RegExp(`^case_${UUID7}$`);
const PROJECT_ID = new RegExp(`^prj_${UUID7}$`);
const SERVICE_ID = new RegExp(`^svc_${UUID7}$`);
const OPERATION_ID = new RegExp(`^op_${UUID7}$`);
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const CONTEXT_FIELDS = [
  "campaign_id", "case_id", "expires_at", "format", "project_id",
  "service_id", "signature",
];
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ACTIVE_FUZZ_CONTEXT = new AsyncLocalStorage();

export class FuzzContextError extends Error {
  constructor() {
    super("Repro It rejected the fuzz context.");
    this.name = "FuzzContextError";
  }
}

export class FuzzContextValidator {
  #projectId;
  #verificationKey;

  constructor({ projectId, verificationKey }) {
    this.#projectId = projectId;
    this.#verificationKey = verificationKey;
  }

  validate(encoded, now) {
    try {
      if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 5_462) {
        throw new FuzzContextError();
      }
      if (!/^[A-Za-z0-9_-]+$/.test(encoded) || !/^[A-Za-z0-9_-]+$/.test(this.#verificationKey)) {
        throw new FuzzContextError();
      }
      const raw = Buffer.from(encoded, "base64url");
      const key = Buffer.from(this.#verificationKey, "base64url");
      const value = JSON.parse(raw.toString("utf8"));
      const signature = Buffer.from(value.signature, "base64url");
      if (
        raw.length > MAX_CONTEXT_BYTES || key.length !== 32 || signature.length !== 64 ||
        !sameBytes(canonicalBytes(value), raw) || !sameKeys(value, CONTEXT_FIELDS) ||
        value.format !== "reproit.fuzz-context.v1" ||
        !CAMPAIGN_ID.test(value.campaign_id) || !CASE_ID.test(value.case_id) ||
        !PROJECT_ID.test(value.project_id) || !SERVICE_ID.test(value.service_id) ||
        value.project_id !== this.#projectId ||
        !TIMESTAMP.test(now) || !TIMESTAMP.test(value.expires_at) ||
        !Number.isFinite(Date.parse(now)) || !Number.isFinite(Date.parse(value.expires_at)) ||
        Date.parse(now) >= Date.parse(value.expires_at)
      ) {
        throw new FuzzContextError();
      }
      const unsigned = { ...value, signature: "" };
      const publicKey = createPublicKey({
        format: "der",
        key: Buffer.concat([ED25519_SPKI_PREFIX, key]),
        type: "spki",
      });
      if (!verify(null, canonicalBytes(unsigned), publicKey, signature)) {
        throw new FuzzContextError();
      }
      return Object.freeze({
        campaignId: value.campaign_id,
        caseId: value.case_id,
        contextDigest: `sha256:${createHash("sha256").update(raw).digest("hex")}`,
        encoded,
        now,
        parentOperationId: null,
        projectId: value.project_id,
        serviceId: value.service_id,
        verificationKey: this.#verificationKey,
      });
    } catch (error) {
      if (error instanceof FuzzContextError) throw error;
      throw new FuzzContextError();
    }
  }
}

export function extractHttpFuzzContext(headers, validator, now) {
  const encoded = header(headers, FUZZ_CONTEXT_HTTP_HEADER);
  const parent = header(headers, FUZZ_PARENT_HTTP_HEADER);
  if (encoded === null) {
    if (parent !== null) throw new FuzzContextError();
    return null;
  }
  const context = validator.validate(encoded, now);
  return parent === null ? context : withFuzzParent(context, parent);
}

export function extractQueueFuzzContext(metadata, validator, now) {
  return extractHttpFuzzContext({
    [FUZZ_CONTEXT_HTTP_HEADER]: metadata[FUZZ_CONTEXT_QUEUE_METADATA],
    [FUZZ_PARENT_HTTP_HEADER]: metadata[FUZZ_PARENT_QUEUE_METADATA],
  }, validator, now);
}

export function propagateQueueFuzzContext(metadata) {
  const context = currentFuzzContext();
  if (context === null || metadata === null || typeof metadata !== "object") return;
  metadata[FUZZ_CONTEXT_QUEUE_METADATA] = context.encoded;
  if (context.parentOperationId !== null) {
    metadata[FUZZ_PARENT_QUEUE_METADATA] = context.parentOperationId;
  }
}

export function currentFuzzContext() {
  return ACTIVE_FUZZ_CONTEXT.getStore() ?? null;
}

export function runWithFuzzContext(context, operation) {
  return ACTIVE_FUZZ_CONTEXT.run(context, operation);
}

export function withFuzzParent(context, operationId) {
  if (!OPERATION_ID.test(operationId)) throw new FuzzContextError();
  return Object.freeze({ ...context, parentOperationId: operationId });
}

export function fuzzBeginIdentity(context) {
  return {
    campaign_id: context.campaignId,
    case_id: context.caseId,
    context_digest: context.contextDigest,
  };
}

export function nativeFuzzInput(context) {
  return {
    encoded: context.encoded,
    now: context.now,
    project_id: context.projectId,
    service_id: context.serviceId,
    verification_key: context.verificationKey,
  };
}

function header(headers, expectedName) {
  if (headers === null || typeof headers !== "object") throw new FuzzContextError();
  const selected = Object.entries(headers)
    .filter(([name, value]) => name.toLowerCase() === expectedName.toLowerCase() && value !== undefined)
    .map(([, value]) => value);
  if (selected.length === 0) return null;
  if (selected.length !== 1 || typeof selected[0] !== "string" || selected[0].length === 0) {
    throw new FuzzContextError();
  }
  return selected[0];
}

function sameBytes(left, right) {
  return left.length === right.length && left.equals(right);
}

function sameKeys(value, expected) {
  return value !== null && !Array.isArray(value) && typeof value === "object" &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}
