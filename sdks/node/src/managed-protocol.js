// Managed-mode protocol primitives that mirror the Rust reference.
//
// This module is the Node.js mirror of the reproit-core pieces the managed
// capture client depends on: strict base64url and digest helpers, typed
// identifier validation, Ed25519 signing, the AES-256-GCM + HKDF-SHA-256
// candidate seal, and the managed candidate schema validators. The Rust
// implementation in crates/reproit-core is normative. Every rule here has a
// direct counterpart there and in sdks/python/reproit_sdk/managed_protocol.py.

import { Buffer } from "node:buffer";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import { canonicalBytes } from "./index.js";

export const MAX_CHUNK_BYTES = 8 * 1024 * 1024;
export const MAX_CANDIDATE_OBJECTS = 32_767;
export const MAX_CANDIDATE_PLAINTEXT_BYTES = 1_048_576;
export const MAX_CANDIDATE_CIPHERTEXT_BYTES = 1_048_604;
export const MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES = 274_878_824_448;

export const CIPHER_SUITE = "AES-256-GCM+HKDF-SHA-256";
export const CAPTURE_GRANT_FORMAT = "reproit.managed-candidate-capture-grant.v1";
export const CANDIDATE_IDENTITY_FORMAT = "reproit.managed-candidate-identity.v1";
export const CANDIDATE_MANIFEST_FORMAT = "reproit.managed-candidate-manifest.v1";
export const CIPHERTEXT_IDENTITY_FORMAT =
  "reproit.managed-candidate-ciphertext-identity.v1";
export const OBJECT_KEY_CONTEXT_FORMAT = "reproit.object-key-context.v1";
export const CHUNK_KEY_CONTEXT_FORMAT = "reproit.chunk-key-context.v1";
export const CAPTURE_BATCH_FORMAT = "reproit.capture-batch.v1";

export const CANDIDATE_MEDIA_TYPE = "application/vnd.reproit.candidate.v1+json";
export const FAILURE_MEDIA_TYPE = "application/vnd.reproit.failure.v1+json";
export const SUBJECT_MANIFEST_MEDIA_TYPE =
  "application/vnd.reproit.subject-closure.v1+json";
export const TRIGGER_MEDIA_TYPE = "application/vnd.reproit.trigger.v1+json";
export const WORLD_MANIFEST_MEDIA_TYPE =
  "application/vnd.reproit.world-manifest.v1+json";
export const DEPENDENCY_TRANSCRIPT_MEDIA_TYPE =
  "application/vnd.reproit.dependency-transcript.v1+json";

const REQUIRED_ROLES = [
  "candidate",
  "failure",
  "subject",
  "trigger",
  "world-manifest",
];
const ROLE_MEDIA_TYPES = [
  ["candidate", CANDIDATE_MEDIA_TYPE],
  ["failure", FAILURE_MEDIA_TYPE],
  ["subject", SUBJECT_MANIFEST_MEDIA_TYPE],
  ["trigger", TRIGGER_MEDIA_TYPE],
  ["world-manifest", WORLD_MANIFEST_MEDIA_TYPE],
];
const LOGICAL_OBJECT_ROLES = new Set([
  "admission-proof",
  "candidate",
  "debug-symbols",
  "dependency-transcript",
  "failure",
  "replay-capsule-manifest",
  "subject",
  "trigger",
  "world-manifest",
  "world-state",
]);

// Wire values of reproit_core::ErrorCode. The transport rejects a server
// error whose code is not in this closed set.
export const ERROR_CODES = new Set([
  "ADMISSION_PROOF_BINDING",
  "ADMISSION_PROOF_COUNT",
  "ASSIGNEE_NOT_AUTHORIZED",
  "ARTIFACT_NOT_FOUND",
  "ATTESTATION_REVOKED",
  "ATTESTATION_SCOPE",
  "AUTHENTICATION_REQUIRED",
  "AUTHORIZATION_DENIED",
  "CAPTURE_ID_CONFLICT",
  "CONFIG_CONFLICT",
  "CROSS_TENANT_SCOPE",
  "DECRYPTION_AUTHENTICATION",
  "DEPENDENCY_TRANSCRIPT_MISMATCH",
  "DIFFERENT_FAILURE",
  "EVALUATION_ERROR",
  "FORBIDDEN",
  "INCOMPLETE_CANDIDATE",
  "INCOMPLETE_RECORD_SEQUENCE",
  "LIVE_EGRESS_BLOCKED",
  "KEY_PROVIDER_UNAVAILABLE",
  "KEY_UNWRAP_FAILED",
  "KEEP_DESTINATION_UNAVAILABLE",
  "LEGAL_DELETION_CONFLICT",
  "NONCE_REUSE",
  "NOT_FOUND",
  "OBJECT_DIGEST_MISMATCH",
  "PRIORITY_INVALID",
  "RATE_LIMITED",
  "RUNTIME_QUOTA",
  "SCHEMA_INVALID",
  "SERVICE_UNAVAILABLE",
  "SOURCE_ACCESS_DENIED",
  "SOURCE_CHECKOUT_FAILED",
  "SOURCE_DEPENDENCY_MISSING",
  "SOURCE_REVISION_MISSING",
  "STATE_SCOPE_VIOLATION",
  "SUBJECT_DIGEST_MISMATCH",
  "TRIAGE_CONFLICT",
  "UNSUPPORTED",
  "UNSUPPORTED_CAPABILITY_SET",
  "UPLOAD_EXPIRED",
  "UPLOAD_INCOMPLETE",
  "UPLOAD_LIMIT_EXCEEDED",
  "WORLD_NOT_CLOSED",
  "WORLD_POINT_EXPIRED",
  "WORLD_PROVIDER_MISSING",
]);

export const RETRYABLE_CODES = new Set([
  "KEY_PROVIDER_UNAVAILABLE",
  "KEEP_DESTINATION_UNAVAILABLE",
  "RATE_LIMITED",
  "RUNTIME_QUOTA",
  "SERVICE_UNAVAILABLE",
  "SOURCE_CHECKOUT_FAILED",
  "UPLOAD_EXPIRED",
  "UPLOAD_INCOMPLETE",
]);

const ID_PREFIXES = {
  capture_id: "cap_",
  object_id: "obj_",
  operation_id: "op_",
  organization_id: "org_",
  project_id: "prj_",
  service_id: "svc_",
  upload_id: "upl_",
};
const UUID7_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// A managed capture step failed with a stable protocol error code.
export class ManagedError extends Error {
  constructor(code, message, retryable) {
    super(message);
    this.name = "ManagedError";
    this.code = code;
    this.retryable =
      retryable === undefined ? RETRYABLE_CODES.has(code) : retryable;
  }
}

export function schemaInvalid(
  message = "The value does not satisfy the schema.",
) {
  return new ManagedError("SCHEMA_INVALID", message);
}

export function incompleteCandidate() {
  return new ManagedError(
    "INCOMPLETE_CANDIDATE",
    "The managed candidate is incomplete and cannot be uploaded.",
  );
}

export function attestationError() {
  return new ManagedError(
    "ATTESTATION_SCOPE",
    "The signature is invalid for this attestation.",
  );
}

export function objectDigestMismatch() {
  return new ManagedError(
    "OBJECT_DIGEST_MISMATCH",
    "The object bytes do not match the bound digest.",
  );
}

export function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function sameKeys(value, keys) {
  return (
    isObject(value) &&
    Object.keys(value).sort().join("\u0000") ===
      [...keys].sort().join("\u0000")
  );
}

export function encodeBase64url(value) {
  return Buffer.from(value).toString("base64url");
}

// Decode strict unpadded base64url and reject non-canonical encodings.
export function decodeBase64url(value, expectedLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw schemaInvalid();
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw schemaInvalid();
  }
  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    throw schemaInvalid();
  }
  return decoded;
}

export function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function canonicalDigest(value) {
  return digestBytes(canonicalBytes(value));
}

export function validDigest(value) {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

export function validTypedId(value, kind) {
  const prefix = ID_PREFIXES[kind];
  if (typeof value !== "string" || !value.startsWith(prefix)) return false;
  return UUID7_PATTERN.test(value.slice(prefix.length));
}

export function requireTypedId(value, kind) {
  if (!validTypedId(value, kind)) {
    throw schemaInvalid();
  }
  return value;
}

export function idUuidBytes(value, kind) {
  const text = requireTypedId(value, kind).slice(ID_PREFIXES[kind].length);
  return Buffer.from(text.replaceAll("-", ""), "hex");
}

export function newObjectId() {
  const bytes = randomBytes(16);
  const milliseconds = BigInt(Date.now());
  for (let index = 0; index < 6; index += 1) {
    bytes[index] = Number((milliseconds >> BigInt(8 * (5 - index))) & 0xffn);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return (
    `obj_${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}` +
    `-${hex.slice(16, 20)}-${hex.slice(20)}`
  );
}

export function validOpaqueReference(value) {
  if (typeof value !== "string" || value.length !== 43) return false;
  try {
    decodeBase64url(value, 32);
  } catch {
    return false;
  }
  return true;
}

export function validTimestamp(value) {
  if (
    typeof value !== "string" ||
    value.length !== 24 ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)
  ) {
    return false;
  }
  const parsed = Date.parse(value);
  // The round trip rejects rolled-over calendar dates V8 would accept.
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

export function parseTimestampMs(value) {
  if (!validTimestamp(value)) {
    throw schemaInvalid();
  }
  return Date.parse(value);
}

export function nowTimestamp() {
  return new Date().toISOString();
}

// Match the canonical capability shape: ^[a-z][a-z0-9.-]*$ up to 128.
export function validCapability(value) {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    /^[a-z][a-z0-9.-]*$/u.test(value)
  );
}

export function validateCapabilities(values) {
  if (
    !Array.isArray(values) ||
    values.length > 64 ||
    values.some((value) => !validCapability(value)) ||
    values.some((value, index) => index > 0 && values[index - 1] >= value)
  ) {
    throw schemaInvalid();
  }
}

function ed25519PrivateKey(signingKey) {
  if (!(signingKey instanceof Uint8Array) || signingKey.length !== 32) {
    throw schemaInvalid();
  }
  return createPrivateKey({
    format: "der",
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(signingKey)]),
    type: "pkcs8",
  });
}

function ed25519PublicKey(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw attestationError();
  }
  return createPublicKey({
    format: "der",
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]),
    type: "spki",
  });
}

export function signBytes(value, signingKey) {
  return cryptoSign(null, value, ed25519PrivateKey(signingKey)).toString(
    "base64url",
  );
}

export function verificationKey(signingKey) {
  const publicKey = createPublicKey(ed25519PrivateKey(signingKey));
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32));
}

// Verify the detached Ed25519 signature carried in the signature field.
export function verifySignedValue(value, publicKey) {
  const signatureText = value.signature;
  if (typeof signatureText !== "string") {
    throw schemaInvalid();
  }
  const signature = decodeBase64url(signatureText, 64);
  const unsigned = { ...value, signature: "" };
  let valid = false;
  try {
    valid = cryptoVerify(
      null,
      canonicalBytes(unsigned),
      ed25519PublicKey(publicKey),
      signature,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw attestationError();
  }
}

// Reject any nonce reuse within one sealed candidate.
export class NonceRegistry {
  #used = new Set();

  register(nonce) {
    const key = Buffer.from(nonce).toString("hex");
    if (nonce.length !== 12 || this.#used.has(key)) {
      throw new ManagedError(
        "NONCE_REUSE",
        "An occurrence cannot reuse an encryption nonce.",
      );
    }
    this.#used.add(key);
  }
}

export function objectKeyContext(identity, objectId, role) {
  return {
    capture_batch_format: CAPTURE_BATCH_FORMAT,
    capture_id: identity.capture_id,
    format: OBJECT_KEY_CONTEXT_FORMAT,
    object_id: objectId,
    organization_id: identity.organization_id,
    processing_mode: "managed",
    project_id: identity.project_id,
    role,
    service_id: identity.service_id,
  };
}

export function chunkKeyContext(
  objectContextDigest,
  chunkCount,
  chunkIndex,
  plainSize,
) {
  return {
    chunk_count: chunkCount,
    chunk_index: chunkIndex,
    format: CHUNK_KEY_CONTEXT_FORMAT,
    object_context_digest: objectContextDigest,
    plain_size: plainSize,
  };
}

function hkdfExtract(salt, inputKeyMaterial) {
  return createHmac("sha256", salt).update(inputKeyMaterial).digest();
}

function hkdfExpand32(pseudoRandomKey, info) {
  // One SHA-256 block covers the full 32-byte output.
  return createHmac("sha256", pseudoRandomKey)
    .update(Buffer.concat([Buffer.from(info), Buffer.from([0x01])]))
    .digest();
}

// HKDF-SHA-256: extract with the capture UUID salt, expand per object.
export function deriveObjectKey(candidateKey, captureId, objectContext) {
  if (
    candidateKey.length !== 32 ||
    captureId !== objectContext.capture_id
  ) {
    throw schemaInvalid();
  }
  const salt = idUuidBytes(captureId, "capture_id");
  return hkdfExpand32(
    hkdfExtract(salt, candidateKey),
    canonicalBytes(objectContext),
  );
}

export function deriveChunkKey(objectKey, context) {
  if (objectKey.length !== 32) {
    throw schemaInvalid();
  }
  return hkdfExpand32(objectKey, canonicalBytes(context));
}

// AES-256-GCM with the canonical chunk context as associated data.
export function encryptChunk(chunkKey, nonce, plaintext, context) {
  if (
    chunkKey.length !== 32 ||
    nonce.length !== 12 ||
    plaintext.length > MAX_CHUNK_BYTES ||
    context.plain_size !== plaintext.length
  ) {
    throw schemaInvalid();
  }
  const cipher = createCipheriv("aes-256-gcm", chunkKey, nonce);
  cipher.setAAD(canonicalBytes(context));
  return Buffer.concat([
    Buffer.from(nonce),
    cipher.update(Buffer.from(plaintext)),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
}

export function decryptChunk(chunkKey, stored, context) {
  const failure = () =>
    new ManagedError(
      "DECRYPTION_AUTHENTICATION",
      "Ciphertext authentication failed.",
    );
  const plainSize = context.plain_size;
  if (
    chunkKey.length !== 32 ||
    stored.length < 28 ||
    stored.length > MAX_CHUNK_BYTES + 28 ||
    !Number.isSafeInteger(plainSize) ||
    plainSize + 28 !== stored.length
  ) {
    throw failure();
  }
  const buffer = Buffer.from(stored);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    chunkKey,
    buffer.subarray(0, 12),
  );
  decipher.setAAD(canonicalBytes(context));
  decipher.setAuthTag(buffer.subarray(buffer.length - 16));
  try {
    return Buffer.concat([
      decipher.update(buffer.subarray(12, buffer.length - 16)),
      decipher.final(),
    ]);
  } catch {
    throw failure();
  }
}

export function validateLogicalObject(value) {
  if (
    !sameKeys(value, [
      "media_type",
      "object_id",
      "plain_digest",
      "plain_size",
      "role",
    ])
  ) {
    throw schemaInvalid();
  }
  const mediaType = value.media_type;
  const plainSize = value.plain_size;
  if (
    typeof mediaType !== "string" ||
    mediaType.length === 0 ||
    mediaType.length > 128 ||
    !validTypedId(value.object_id, "object_id") ||
    !validDigest(value.plain_digest) ||
    !Number.isSafeInteger(plainSize) ||
    plainSize < 0 ||
    plainSize > MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES ||
    !LOGICAL_OBJECT_ROLES.has(value.role)
  ) {
    throw schemaInvalid();
  }
}

function requireOneManifest(objects, role, mediaType) {
  const matches = objects.filter(
    (value) => value.role === role && value.media_type === mediaType,
  );
  if (matches.length !== 1) {
    throw schemaInvalid();
  }
  return matches[0];
}

// Mirror reproit-core ManagedCandidateIdentity::validate exactly.
export function validateManagedCandidateIdentity(value) {
  if (
    !sameKeys(value, [
      "candidate_digest",
      "capture_id",
      "deployment_digest",
      "format",
      "objects",
      "organization_id",
      "processing_mode",
      "project_id",
      "required_capabilities",
      "service_id",
      "subject_digest",
      "total_plaintext_bytes",
    ])
  ) {
    throw schemaInvalid();
  }
  const objects = value.objects;
  if (
    value.format !== CANDIDATE_IDENTITY_FORMAT ||
    value.processing_mode !== "managed" ||
    !validDigest(value.candidate_digest) ||
    !validDigest(value.deployment_digest) ||
    !validDigest(value.subject_digest) ||
    !validTypedId(value.capture_id, "capture_id") ||
    !validTypedId(value.organization_id, "organization_id") ||
    !validTypedId(value.project_id, "project_id") ||
    !validTypedId(value.service_id, "service_id") ||
    !Array.isArray(objects) ||
    objects.length < 5 ||
    objects.length > MAX_CANDIDATE_OBJECTS
  ) {
    throw schemaInvalid();
  }
  validateCapabilities(value.required_capabilities);
  let totalPlaintextBytes = 0;
  const roles = new Set();
  objects.forEach((entry, index) => {
    validateLogicalObject(entry);
    if (index > 0 && objects[index - 1].object_id >= entry.object_id) {
      throw schemaInvalid();
    }
    roles.add(entry.role);
    totalPlaintextBytes += entry.plain_size;
  });
  if (REQUIRED_ROLES.some((role) => !roles.has(role))) {
    throw schemaInvalid();
  }
  for (const [role, mediaType] of ROLE_MEDIA_TYPES) {
    requireOneManifest(objects, role, mediaType);
  }
  const candidate = requireOneManifest(
    objects,
    "candidate",
    CANDIDATE_MEDIA_TYPE,
  );
  const subject = requireOneManifest(
    objects,
    "subject",
    SUBJECT_MANIFEST_MEDIA_TYPE,
  );
  if (
    candidate.plain_digest !== value.candidate_digest ||
    candidate.plain_size > MAX_CANDIDATE_PLAINTEXT_BYTES ||
    subject.plain_digest !== value.subject_digest ||
    totalPlaintextBytes !== value.total_plaintext_bytes ||
    totalPlaintextBytes > MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES
  ) {
    throw schemaInvalid();
  }
}

function validateChunk(value) {
  if (!sameKeys(value, ["cipher_digest", "cipher_size", "index", "nonce"])) {
    throw schemaInvalid();
  }
  const cipherSize = value.cipher_size;
  if (
    !validDigest(value.cipher_digest) ||
    !Number.isSafeInteger(cipherSize) ||
    cipherSize < 28 ||
    cipherSize > MAX_CHUNK_BYTES + 28 ||
    !Number.isSafeInteger(value.index) ||
    typeof value.nonce !== "string" ||
    value.nonce.length !== 16
  ) {
    throw schemaInvalid();
  }
  decodeBase64url(value.nonce, 12);
}

function validateManifestObject(value) {
  if (
    !sameKeys(value, ["cipher_digest", "cipher_size", "nonce", "object_id"])
  ) {
    throw schemaInvalid();
  }
  const cipherSize = value.cipher_size;
  if (
    !validDigest(value.cipher_digest) ||
    !Number.isSafeInteger(cipherSize) ||
    cipherSize < 28 ||
    cipherSize > MAX_CHUNK_BYTES + 28 ||
    typeof value.nonce !== "string" ||
    value.nonce.length !== 16 ||
    !validTypedId(value.object_id, "object_id")
  ) {
    throw schemaInvalid();
  }
  decodeBase64url(value.nonce, 12);
}

// Mirror ManagedCandidateCiphertextIdentity::validate exactly.
export function validateCiphertextIdentity(value) {
  if (
    !sameKeys(value, [
      "candidate_identity_digest",
      "candidate_key_reference",
      "capture_id",
      "cipher_suite",
      "format",
      "manifest_object",
      "objects",
      "organization_id",
      "processing_mode",
      "project_id",
      "required_capabilities",
      "service_id",
      "total_ciphertext_bytes",
    ])
  ) {
    throw schemaInvalid();
  }
  const objects = value.objects;
  if (
    value.format !== CIPHERTEXT_IDENTITY_FORMAT ||
    value.cipher_suite !== CIPHER_SUITE ||
    value.processing_mode !== "managed" ||
    !validOpaqueReference(value.candidate_key_reference) ||
    !validDigest(value.candidate_identity_digest) ||
    !validTypedId(value.capture_id, "capture_id") ||
    !validTypedId(value.organization_id, "organization_id") ||
    !validTypedId(value.project_id, "project_id") ||
    !validTypedId(value.service_id, "service_id") ||
    !Array.isArray(objects) ||
    objects.length < 5 ||
    objects.length > MAX_CANDIDATE_OBJECTS ||
    !Array.isArray(value.required_capabilities) ||
    value.required_capabilities.length === 0
  ) {
    throw schemaInvalid();
  }
  validateCapabilities(value.required_capabilities);
  validateManifestObject(value.manifest_object);
  const nonces = new Set([value.manifest_object.nonce]);
  let chunkCount = 1;
  let totalCiphertextBytes = value.manifest_object.cipher_size;
  const roles = new Set();
  const descriptors = [];
  objects.forEach((entry, index) => {
    if (!sameKeys(entry, ["chunks", "descriptor"])) {
      throw schemaInvalid();
    }
    validateLogicalObject(entry.descriptor);
    descriptors.push(entry.descriptor);
    if (
      index > 0 &&
      objects[index - 1].descriptor.object_id >= entry.descriptor.object_id
    ) {
      throw schemaInvalid();
    }
    const chunks = entry.chunks;
    if (
      !Array.isArray(chunks) ||
      chunks.length < 1 ||
      chunks.length > MAX_CANDIDATE_OBJECTS
    ) {
      throw schemaInvalid();
    }
    roles.add(entry.descriptor.role);
    chunkCount += chunks.length;
    chunks.forEach((chunk, chunkIndex) => {
      validateChunk(chunk);
      if (chunk.index !== chunkIndex || nonces.has(chunk.nonce)) {
        throw schemaInvalid();
      }
      nonces.add(chunk.nonce);
      totalCiphertextBytes += chunk.cipher_size;
    });
  });
  if (REQUIRED_ROLES.some((role) => !roles.has(role))) {
    throw schemaInvalid();
  }
  for (const [role, mediaType] of ROLE_MEDIA_TYPES) {
    requireOneManifest(descriptors, role, mediaType);
  }
  const candidateChunks = objects
    .filter(
      (entry) =>
        entry.descriptor.role === "candidate" &&
        entry.descriptor.media_type === CANDIDATE_MEDIA_TYPE,
    )
    .map((entry) => entry.chunks);
  if (candidateChunks.length !== 1) {
    throw schemaInvalid();
  }
  const candidateCiphertextBytes = candidateChunks[0].reduce(
    (total, chunk) => total + chunk.cipher_size,
    0,
  );
  if (
    chunkCount > 32_768 ||
    totalCiphertextBytes !== value.total_ciphertext_bytes ||
    totalCiphertextBytes > MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES ||
    candidateCiphertextBytes > MAX_CANDIDATE_CIPHERTEXT_BYTES ||
    objects.some(
      (entry) =>
        entry.descriptor.object_id === value.manifest_object.object_id,
    )
  ) {
    throw schemaInvalid();
  }
}

// Mirror ManagedCandidateCaptureGrant::validate exactly.
export function validateCaptureGrant(value) {
  if (
    !sameKeys(value, [
      "candidate_identity_digest",
      "candidate_key_reference",
      "capture_id",
      "cipher_suite",
      "expires_at",
      "format",
      "grant_id",
      "not_before",
      "operation",
      "organization_id",
      "processing_mode",
      "project_id",
      "service_id",
      "signature",
      "signer_key_id",
    ])
  ) {
    throw schemaInvalid();
  }
  const signerKeyId = value.signer_key_id;
  const signature = value.signature;
  if (
    value.format !== CAPTURE_GRANT_FORMAT ||
    value.cipher_suite !== CIPHER_SUITE ||
    value.operation !== "encrypt-and-upload-candidate" ||
    value.processing_mode !== "managed" ||
    !validOpaqueReference(value.candidate_key_reference) ||
    !validOpaqueReference(value.grant_id) ||
    !validDigest(value.candidate_identity_digest) ||
    !validTypedId(value.capture_id, "capture_id") ||
    !validTypedId(value.organization_id, "organization_id") ||
    !validTypedId(value.project_id, "project_id") ||
    !validTypedId(value.service_id, "service_id") ||
    typeof signerKeyId !== "string" ||
    signerKeyId.length === 0 ||
    signerKeyId.length > 256 ||
    typeof signature !== "string" ||
    signature.length !== 86 ||
    parseTimestampMs(value.not_before) >= parseTimestampMs(value.expires_at)
  ) {
    throw schemaInvalid();
  }
  decodeBase64url(signature, 64);
}

// Mirror verify_managed_candidate_capture_grant exactly.
export function verifyCaptureGrant(grant, expected, now, publicKey) {
  validateCaptureGrant(grant);
  const currentTime = parseTimestampMs(now);
  if (
    grant.candidate_identity_digest !== expected.candidate_identity_digest ||
    grant.candidate_key_reference !== expected.candidate_key_reference ||
    grant.capture_id !== expected.capture_id ||
    grant.organization_id !== expected.organization_id ||
    grant.project_id !== expected.project_id ||
    grant.service_id !== expected.service_id ||
    grant.signer_key_id !== expected.signer_key_id ||
    currentTime < parseTimestampMs(grant.not_before) ||
    currentTime >= parseTimestampMs(grant.expires_at)
  ) {
    throw new ManagedError(
      "ATTESTATION_SCOPE",
      "The managed candidate capture grant does not match this capture.",
    );
  }
  verifySignedValue(grant, publicKey);
}

// Mirror ManagedCandidateUploadRequest::validate exactly.
export function validateUploadRequest(value) {
  if (
    !sameKeys(value, [
      "capture_grant",
      "ciphertext_identity",
      "encrypted_candidate_digest",
    ])
  ) {
    throw schemaInvalid();
  }
  const grant = value.capture_grant;
  const identity = value.ciphertext_identity;
  validateCaptureGrant(grant);
  validateCiphertextIdentity(identity);
  if (
    grant.candidate_identity_digest !== identity.candidate_identity_digest ||
    grant.candidate_key_reference !== identity.candidate_key_reference ||
    grant.capture_id !== identity.capture_id ||
    grant.organization_id !== identity.organization_id ||
    grant.project_id !== identity.project_id ||
    grant.service_id !== identity.service_id ||
    grant.processing_mode !== identity.processing_mode ||
    grant.cipher_suite !== identity.cipher_suite
  ) {
    throw new ManagedError(
      "ATTESTATION_SCOPE",
      "The capture grant does not cover this ciphertext identity.",
    );
  }
  if (canonicalDigest(identity) !== value.encrypted_candidate_digest) {
    throw objectDigestMismatch();
  }
}

export { parseStrictJson } from "./managed-json.js";
