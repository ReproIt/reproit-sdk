// Managed candidate preparation, sealing, and bounded upload.
//
// Mirrors crates/reproit-sdk-rust/src/managed.rs: the SDK proves local
// completeness first, then requests one managed candidate encryption grant,
// seals every object with AES-256-GCM keyed through HKDF-SHA-256, and drives
// the start, missing, object-PUT, commit, and cancel upload session. An
// incomplete candidate stops before any network request.

import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalBytes } from "./index.js";
import { validateCandidate } from "./candidate-validation.js";
import {
  CANDIDATE_IDENTITY_FORMAT,
  CANDIDATE_MANIFEST_FORMAT,
  CANDIDATE_MEDIA_TYPE,
  CIPHER_SUITE,
  CIPHERTEXT_IDENTITY_FORMAT,
  DEPENDENCY_TRANSCRIPT_MEDIA_TYPE,
  FAILURE_MEDIA_TYPE,
  MAX_CHUNK_BYTES,
  ManagedError,
  NonceRegistry,
  SUBJECT_MANIFEST_MEDIA_TYPE,
  TRIGGER_MEDIA_TYPE,
  WORLD_MANIFEST_MEDIA_TYPE,
  canonicalDigest,
  chunkKeyContext,
  decodeBase64url,
  deriveChunkKey,
  deriveObjectKey,
  digestBytes,
  encodeBase64url,
  encryptChunk,
  incompleteCandidate,
  isObject,
  newObjectId,
  objectKeyContext,
  parseStrictJson,
  schemaInvalid,
  signBytes,
  validDigest,
  validTypedId,
  validateCiphertextIdentity,
  validateManagedCandidateIdentity,
  validateUploadRequest,
  verifyCaptureGrant,
} from "./managed-protocol.js";
import {
  FrozenManagedCaptureClosure,
  expectedWorldArtifacts,
  hashFile,
  validateTranscriptBytes,
} from "./managed-closure.js";
import { validateSubjectClosureManifest } from "./managed-subject.js";
import {
  GRANT_TIMEOUT_MS,
  SealedManagedCandidate,
  commitTimeoutMs,
  localStorageError,
} from "./managed-upload.js";

const COMPLETIONS_BY_KIND = {
  "delivered-work": new Set(["acknowledgment", "task-end"]),
  "request-response": new Set(["return"]),
  stream: new Set(["stream-end"]),
};

class PreparedObject {
  constructor(descriptor, content, filePath) {
    this.descriptor = descriptor;
    this.content = content;
    this.path = filePath;
  }

  read() {
    if (this.descriptor.plain_size > MAX_CHUNK_BYTES) {
      throw incompleteCandidate();
    }
    if (this.content !== null) {
      return this.content;
    }
    return readAtMost(this.path, MAX_CHUNK_BYTES + 1);
  }
}

function readAtMost(filePath, maximumBytes) {
  let descriptor;
  try {
    descriptor = openSync(filePath, "r");
  } catch {
    throw incompleteCandidate();
  }
  try {
    const buffer = Buffer.alloc(maximumBytes);
    let total = 0;
    for (;;) {
      const read = readSync(
        descriptor,
        buffer,
        total,
        buffer.length - total,
        null,
      );
      if (read === 0) break;
      total += read;
      if (total >= buffer.length) break;
    }
    return Buffer.from(buffer.subarray(0, total));
  } catch {
    throw incompleteCandidate();
  } finally {
    closeSync(descriptor);
  }
}

// One locally complete candidate whose closure is proved before upload.
export class PreparedManagedCandidate {
  #closure;
  #identity;
  #objects;
  #subject;

  constructor(identity, objects, subject, closure) {
    this.#identity = identity;
    this.#objects = objects;
    this.#subject = subject;
    // The frozen closure owns the artifact spool the objects reference.
    this.#closure = closure;
  }

  static prepareComplete(candidate, subject, closure) {
    if (!(closure instanceof FrozenManagedCaptureClosure)) {
      closure = new FrozenManagedCaptureClosure(closure);
    }
    const frozen = closure.closure;
    validateManagedCandidateRecord(candidate);
    validateSubjectClosureManifest(subject.manifest);
    if (candidate.processing_mode !== "managed") {
      throw schemaInvalid("Managed capture requires a managed deployment.");
    }
    validateSubjectBinding(candidate, subject.manifest);
    if (closure.worldId() !== candidate.world_id) {
      throw incompleteCandidate();
    }

    const objects = [];
    try {
      pushBytes(
        objects,
        newObjectId(),
        "candidate",
        CANDIDATE_MEDIA_TYPE,
        canonicalBytes(candidate),
      );
      pushSubject(objects, subject);
      pushTriggerAndInputs(objects, candidate, frozen.completion);
      pushFailure(objects, candidate);
      pushBytes(
        objects,
        newObjectId(),
        "world-manifest",
        WORLD_MANIFEST_MEDIA_TYPE,
        canonicalBytes(frozen.world),
      );
      pushCaptureArtifacts(objects, candidate, frozen.world, frozen.artifacts);
    } catch (error) {
      if (error instanceof ManagedError) throw error;
      throw incompleteCandidate();
    }
    objects.sort((left, right) =>
      left.descriptor.object_id < right.descriptor.object_id ? -1 : 1,
    );
    verifyLocalClosure(objects);

    const descriptors = objects.map((entry) => ({ ...entry.descriptor }));
    const totalPlaintextBytes = descriptors.reduce(
      (total, entry) => total + entry.plain_size,
      0,
    );
    if (totalPlaintextBytes > 4 * 1024 * 1024 * 1024) {
      throw incompleteCandidate();
    }
    const deployment = candidate.deployment;
    const identity = {
      candidate_digest: canonicalDigest(candidate),
      capture_id: candidate.capture_id,
      deployment_digest: canonicalDigest(deployment),
      format: CANDIDATE_IDENTITY_FORMAT,
      objects: descriptors,
      organization_id: deployment.organization_id,
      processing_mode: "managed",
      project_id: deployment.project_id,
      required_capabilities: [...(deployment.runtime_capabilities ?? [])],
      service_id: deployment.service_id,
      subject_digest: canonicalDigest(subject.manifest),
      total_plaintext_bytes: totalPlaintextBytes,
    };
    validateManagedCandidateIdentity(identity);
    return new PreparedManagedCandidate(identity, objects, subject, closure);
  }

  get identity() {
    return this.#identity;
  }

  async requestEncryptionGrant(delivery, signerKeyId, signingKey) {
    validateManagedCandidateIdentity(this.#identity);
    verifyLocalClosure(this.#objects);
    const request = signedGrantRequest(
      canonicalDigest(this.#identity),
      this.#identity.capture_id,
      this.#identity.deployment_digest,
      this.#identity.organization_id,
      this.#identity.project_id,
      this.#identity.service_id,
      signerKeyId,
      signingKey,
    );
    return delivery.requestEncryptionGrant(request, GRANT_TIMEOUT_MS);
  }

  seal(response, now, captureSignerId, captureSignerPublicKey) {
    const identityDigest = canonicalDigest(this.#identity);
    const keyReference = response.captureGrant.candidate_key_reference;
    verifyCaptureGrant(
      response.captureGrant,
      {
        candidate_identity_digest: identityDigest,
        candidate_key_reference: keyReference,
        capture_id: this.#identity.capture_id,
        organization_id: this.#identity.organization_id,
        project_id: this.#identity.project_id,
        service_id: this.#identity.service_id,
        signer_key_id: captureSignerId,
      },
      now,
      captureSignerPublicKey,
    );
    verifyLocalClosure(this.#objects);

    const spool = mkdtempSync(
      path.join(os.tmpdir(), "reproit-managed-candidate-"),
    );
    try {
      const ciphertext = new Map();
      const nonces = new NonceRegistry();
      const encryptedObjects = this.#objects.map((entry) =>
        encryptObject(
          response.candidateKey,
          this.#identity,
          entry,
          spool,
          ciphertext,
          nonces,
        ),
      );
      const manifest = {
        candidate_identity: this.#identity,
        candidate_identity_digest: identityDigest,
        candidate_key_reference: keyReference,
        cipher_suite: CIPHER_SUITE,
        format: CANDIDATE_MANIFEST_FORMAT,
      };
      const manifestObject = encryptManifest(
        response.candidateKey,
        this.#identity,
        newObjectId(),
        canonicalBytes(manifest),
        spool,
        ciphertext,
        nonces,
      );
      const totalCiphertextBytes =
        manifestObject.cipher_size +
        encryptedObjects.reduce(
          (total, entry) =>
            total +
            entry.chunks.reduce(
              (chunkTotal, chunk) => chunkTotal + chunk.cipher_size,
              0,
            ),
          0,
        );
      const ciphertextIdentity = {
        candidate_identity_digest: identityDigest,
        candidate_key_reference: keyReference,
        capture_id: this.#identity.capture_id,
        cipher_suite: CIPHER_SUITE,
        format: CIPHERTEXT_IDENTITY_FORMAT,
        manifest_object: manifestObject,
        objects: encryptedObjects,
        organization_id: this.#identity.organization_id,
        processing_mode: "managed",
        project_id: this.#identity.project_id,
        required_capabilities: [...this.#identity.required_capabilities],
        service_id: this.#identity.service_id,
        total_ciphertext_bytes: totalCiphertextBytes,
      };
      validateCiphertextIdentity(ciphertextIdentity);
      const request = {
        capture_grant: response.captureGrant,
        ciphertext_identity: ciphertextIdentity,
        encrypted_candidate_digest: canonicalDigest(ciphertextIdentity),
      };
      validateUploadRequest(request);
      return new SealedManagedCandidate(
        request,
        response.candidateKey,
        ciphertext,
        spool,
        this.#identity.deployment_digest,
      );
    } catch (error) {
      rmSync(spool, { force: true, recursive: true });
      throw error;
    }
  }
}

export function signedGrantRequest(
  candidateIdentityDigest,
  captureId,
  deploymentDigest,
  organizationId,
  projectId,
  serviceId,
  signerKeyId,
  signingKey,
) {
  const request = {
      candidate_identity_digest: candidateIdentityDigest,
      capture_id: captureId,
      cipher_suite: CIPHER_SUITE,
      deployment_digest: deploymentDigest,
      organization_id: organizationId,
      processing_mode: "managed",
      project_id: projectId,
      service_id: serviceId,
      signature: "",
      signer_key_id: signerKeyId,
    };
  request.signature = signBytes(canonicalBytes(request), signingKey);
  return request;
}

export function validateSubjectBinding(candidate, manifest) {
  const deployment = candidate.deployment;
  const subject = isObject(deployment) ? deployment.subject : null;
  if (!isObject(subject)) {
    throw incompleteCandidate();
  }
  const manifestDigest = canonicalDigest(manifest);
  const launch = manifest.launch;
  const capabilities = deployment.runtime_capabilities;
  if (
    subject.artifact_digest !== manifestDigest ||
    subject.artifact_media_type !== SUBJECT_MANIFEST_MEDIA_TYPE ||
    subject.architecture !== manifest.architecture ||
    subject.operating_system !== manifest.operating_system ||
    !sameJson(subject.arguments, launch.arguments) ||
    !sameJson(subject.environment_names, launch.environment_names) ||
    subject.executable !== launch.executable ||
    subject.working_directory !== launch.working_directory ||
    !Array.isArray(capabilities) ||
    !capabilities.includes(manifest.architecture) ||
    !capabilities.includes(manifest.operating_system)
  ) {
    throw new ManagedError(
      "SUBJECT_DIGEST_MISMATCH",
      "The managed deployment does not match the running subject package.",
    );
  }
}

function sameJson(left, right) {
  try {
    return Buffer.from(canonicalBytes(left)).equals(
      Buffer.from(canonicalBytes(right)),
    );
  } catch {
    return false;
  }
}

// Prove the candidate record closure locally, mirroring the Rust gate.
function validateManagedCandidateRecord(candidate) {
  if (!isObject(candidate)) {
    throw incompleteCandidate();
  }
  const records = candidate.records;
  const deployment = candidate.deployment;
  if (
    candidate.format !== "reproit.candidate.v1" ||
    !validTypedId(candidate.capture_id, "capture_id") ||
    !validTypedId(candidate.operation_id, "operation_id") ||
    !validDigest(candidate.world_id) ||
    !Array.isArray(records) ||
    !isObject(deployment) ||
    !validTypedId(deployment.organization_id, "organization_id") ||
    !validTypedId(deployment.project_id, "project_id") ||
    !validTypedId(deployment.service_id, "service_id") ||
    candidate.processing_mode !== deployment.processing_mode
  ) {
    throw incompleteCandidate();
  }
  try {
    decodeBase64url(deployment.signature, 64);
  } catch {
    throw incompleteCandidate();
  }
  const failureRecord = records.find(
    (record) => isObject(record) && record.kind === "failure",
  );
  const failurePayload = decodeRecordPayload(failureRecord);
  try {
    validateCandidate(candidate, failurePayload, canonicalBytes);
  } catch {
    throw incompleteCandidate();
  }
}

function decodeRecordPayload(record) {
  if (!isObject(record) || typeof record.payload !== "string") {
    throw incompleteCandidate();
  }
  let value;
  try {
    const decoded = decodeBase64url(record.payload);
    value = parseStrictJson(decoded, MAX_CHUNK_BYTES);
  } catch {
    throw incompleteCandidate();
  }
  if (!isObject(value)) {
    throw incompleteCandidate();
  }
  return value;
}

function pushBytes(objects, objectId, role, mediaType, content) {
  const descriptor = {
    media_type: mediaType,
    object_id: objectId,
    plain_digest: digestBytes(content),
    plain_size: content.length,
    role,
  };
  objects.push(new PreparedObject(descriptor, Buffer.from(content), null));
}

function pushFile(objects, objectId, mediaType, digest, size, filePath, role) {
  const descriptor = {
    media_type: mediaType,
    object_id: objectId,
    plain_digest: digest,
    plain_size: size,
    role,
  };
  objects.push(new PreparedObject(descriptor, null, filePath));
}

function pushSubject(objects, subject) {
  pushBytes(
    objects,
    newObjectId(),
    "subject",
    SUBJECT_MANIFEST_MEDIA_TYPE,
    canonicalBytes(subject.manifest),
  );
  const declared = new Map(
    subject.manifest.objects.map((entry) => [
      entry.digest,
      [entry.media_type, entry.size],
    ]),
  );
  if (declared.size !== subject.objects.length) {
    throw incompleteCandidate();
  }
  for (const packaged of subject.objects) {
    const entry = declared.get(packaged.digest);
    if (entry === undefined || entry[1] !== packaged.size) {
      throw incompleteCandidate();
    }
    pushFile(
      objects,
      newObjectId(),
      entry[0],
      packaged.digest,
      packaged.size,
      packaged.path,
      "subject",
    );
  }
}

function pushTriggerAndInputs(objects, candidate, completion) {
  const records = candidate.records;
  const begin = decodeRecordPayload(records[0]);
  const inputs = [];
  for (const record of records) {
    if (!isObject(record) || record.kind !== "input") continue;
    const payload = decodeRecordPayload(record);
    const content = decodeBase64url(payload.value);
    const objectId = newObjectId();
    inputs.push({
      channel: payload.channel,
      object_id: objectId,
      plain_digest: payload.value_digest,
      sequence: inputs.length,
    });
    pushBytes(objects, objectId, "trigger", payload.content_type, content);
  }
  const operationKind = begin.operation_kind;
  const allowed = COMPLETIONS_BY_KIND[operationKind] ?? new Set();
  const adapterId = begin.adapter_id;
  const adapterVersion = begin.adapter_version;
  const operationName = begin.operation_name;
  const causalParentIds = begin.causal_parent_ids;
  if (
    inputs.length === 0 ||
    inputs.length > 1_024 ||
    !allowed.has(completion) ||
    typeof adapterId !== "string" ||
    adapterId.length < 1 ||
    adapterId.length > 128 ||
    typeof adapterVersion !== "string" ||
    adapterVersion.length < 1 ||
    adapterVersion.length > 64 ||
    typeof operationName !== "string" ||
    operationName.length < 1 ||
    operationName.length > 128 ||
    !Array.isArray(causalParentIds) ||
    causalParentIds.length > 32 ||
    new Set(causalParentIds).size !== causalParentIds.length ||
    causalParentIds.some((parent) => !validTypedId(parent, "operation_id"))
  ) {
    throw incompleteCandidate();
  }
  const trigger = {
    adapter_id: begin.adapter_id,
    adapter_version: begin.adapter_version,
    causal_parent_ids: begin.causal_parent_ids,
    completion,
    format: "reproit.trigger.v1",
    inputs,
    operation_id: candidate.operation_id,
    operation_kind: operationKind,
    operation_name: begin.operation_name,
  };
  pushBytes(
    objects,
    newObjectId(),
    "trigger",
    TRIGGER_MEDIA_TYPE,
    canonicalBytes(trigger),
  );
}

function pushFailure(objects, candidate) {
  const record = candidate.records.find(
    (entry) => isObject(entry) && entry.kind === "failure",
  );
  if (record === undefined) {
    throw incompleteCandidate();
  }
  const payload = decodeRecordPayload(record);
  const failure = payload.failure;
  if (!isObject(failure) || !validTypedId(failure.object_id, "object_id")) {
    throw incompleteCandidate();
  }
  pushBytes(
    objects,
    failure.object_id,
    "failure",
    FAILURE_MEDIA_TYPE,
    canonicalBytes(payload),
  );
}

function pushCaptureArtifacts(objects, candidate, world, artifacts) {
  const dependencyRecords = candidate.records.filter(
    (record) => isObject(record) && record.kind === "dependency",
  );
  const requiresArtifacts =
    expectedWorldArtifacts(world).size > 0 || dependencyRecords.length > 0;
  if (artifacts.length === 0 && requiresArtifacts) {
    throw incompleteCandidate();
  }
  for (const artifact of artifacts) {
    const { size, digest } = hashFile(artifact.path);
    pushFile(
      objects,
      artifact.objectId,
      artifact.mediaType,
      digest,
      size,
      artifact.path,
      artifact.role,
    );
  }
  validateDependencyClosure(candidate, objects, dependencyRecords);
}

function validateDependencyClosure(candidate, objects, dependencyRecords) {
  const cursors = dependencyRecords.map((record) =>
    decodeRecordPayload(record),
  );
  const descriptors = new Map(
    objects.map((entry) => [entry.descriptor.object_id, entry.descriptor]),
  );
  const transcripts = [];
  for (const entry of objects) {
    const descriptor = entry.descriptor;
    if (
      descriptor.role !== "dependency-transcript" ||
      descriptor.media_type !== DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
    ) {
      continue;
    }
    const transcript = validateTranscriptBytes(entry.read());
    for (const interaction of transcript.interactions) {
      if (
        (interaction.operation_id !== candidate.operation_id &&
          interaction.causal_parent_id !== candidate.operation_id) ||
        !(
          descriptorMatches(
            descriptors,
            interaction.request_object_id,
            interaction.request_digest,
          ) &&
          descriptorMatches(
            descriptors,
            interaction.response_object_id,
            interaction.response_digest,
          )
        )
      ) {
        throw incompleteCandidate();
      }
    }
    transcripts.push(transcript);
  }
  if (
    cursors.length !== transcripts.length ||
    cursors.some(
      (cursor) =>
        transcripts.filter(
          (transcript) =>
            transcript.adapter_id === cursor.adapter_id &&
            transcript.adapter_version === cursor.adapter_version,
        ).length !== 1,
    )
  ) {
    throw incompleteCandidate();
  }
}

function descriptorMatches(descriptors, objectId, digest) {
  const descriptor = descriptors.get(objectId);
  return descriptor !== undefined && descriptor.plain_digest === digest;
}

function verifyLocalClosure(objects) {
  if (objects.length < 5 || objects.length > 32_767) {
    throw incompleteCandidate();
  }
  const objectIds = new Set();
  for (const entry of objects) {
    const descriptor = entry.descriptor;
    if (objectIds.has(descriptor.object_id)) {
      throw incompleteCandidate();
    }
    objectIds.add(descriptor.object_id);
    let actualSize;
    let actualDigest;
    if (entry.content !== null) {
      actualSize = entry.content.length;
      actualDigest = digestBytes(entry.content);
    } else {
      const { size, digest } = hashFile(entry.path);
      actualSize = size;
      actualDigest = digest;
    }
    if (
      actualSize !== descriptor.plain_size ||
      actualDigest !== descriptor.plain_digest
    ) {
      throw incompleteCandidate();
    }
  }
}

function encryptObject(
  candidateKey,
  identity,
  entry,
  spoolPath,
  ciphertext,
  nonces,
) {
  const descriptor = entry.descriptor;
  const plainSize = descriptor.plain_size;
  const chunkCount = Math.ceil(Math.max(plainSize, 1) / MAX_CHUNK_BYTES);
  if (chunkCount > 32_767) {
    throw incompleteCandidate();
  }
  const context = objectKeyContext(
    identity,
    descriptor.object_id,
    descriptor.role,
  );
  const contextDigest = canonicalDigest(context);
  const objectKey = deriveObjectKey(candidateKey, identity.capture_id, context);
  const reader = new ObjectReader(entry);
  const plainHasher = createHash("sha256");
  const chunks = [];
  let remaining = plainSize;
  for (let index = 0; index < chunkCount; index += 1) {
    const chunkPlainSize = Math.min(remaining, MAX_CHUNK_BYTES);
    const plaintext = reader.readExact(chunkPlainSize);
    plainHasher.update(plaintext);
    const chunkContext = chunkKeyContext(
      contextDigest,
      chunkCount,
      index,
      chunkPlainSize,
    );
    const chunkKey = deriveChunkKey(objectKey, chunkContext);
    const nonce = randomNonce(nonces);
    const stored = encryptChunk(chunkKey, nonce, plaintext, chunkContext);
    chunks.push(storeCiphertext(spoolPath, ciphertext, index, nonce, stored));
    remaining -= chunkPlainSize;
  }
  if (
    remaining !== 0 ||
    !reader.atEnd() ||
    `sha256:${plainHasher.digest("hex")}` !== descriptor.plain_digest
  ) {
    throw incompleteCandidate();
  }
  return { chunks, descriptor: { ...descriptor } };
}

// Bounded chunked reads over an in-memory or spooled prepared object.
class ObjectReader {
  #content;
  #descriptor;
  #offset;

  constructor(entry) {
    if (entry.content !== null) {
      this.#descriptor = null;
      this.#content = entry.content;
      this.#offset = 0;
    } else {
      try {
        this.#descriptor = openSync(entry.path, "r");
      } catch {
        throw incompleteCandidate();
      }
      this.#content = Buffer.alloc(0);
      this.#offset = 0;
    }
  }

  readExact(size) {
    let value;
    if (this.#descriptor === null) {
      value = this.#content.subarray(this.#offset, this.#offset + size);
      this.#offset += size;
    } else {
      const buffer = Buffer.alloc(size);
      let total = 0;
      try {
        while (total < size) {
          const read = readSync(
            this.#descriptor,
            buffer,
            total,
            size - total,
            null,
          );
          if (read === 0) break;
          total += read;
        }
      } catch {
        this.#close();
        throw incompleteCandidate();
      }
      value = buffer.subarray(0, total);
    }
    if (value.length !== size) {
      this.#close();
      throw incompleteCandidate();
    }
    return Buffer.from(value);
  }

  atEnd() {
    if (this.#descriptor === null) {
      return this.#offset >= this.#content.length;
    }
    try {
      const buffer = Buffer.alloc(1);
      const read = readSync(this.#descriptor, buffer, 0, 1, null);
      return read === 0;
    } catch {
      return false;
    } finally {
      this.#close();
    }
  }

  #close() {
    if (this.#descriptor !== null) {
      closeSync(this.#descriptor);
      this.#descriptor = null;
    }
  }
}

function encryptManifest(
  candidateKey,
  identity,
  objectId,
  plaintext,
  spoolPath,
  ciphertext,
  nonces,
) {
  if (plaintext.length > MAX_CHUNK_BYTES) {
    throw incompleteCandidate();
  }
  const context = objectKeyContext(identity, objectId, "capture-batch-manifest");
  const chunkContext = chunkKeyContext(
    canonicalDigest(context),
    1,
    0,
    plaintext.length,
  );
  const objectKey = deriveObjectKey(candidateKey, identity.capture_id, context);
  const chunkKey = deriveChunkKey(objectKey, chunkContext);
  const nonce = randomNonce(nonces);
  const stored = encryptChunk(chunkKey, nonce, plaintext, chunkContext);
  const chunk = storeCiphertext(spoolPath, ciphertext, 0, nonce, stored);
  return {
    cipher_digest: chunk.cipher_digest,
    cipher_size: chunk.cipher_size,
    nonce: chunk.nonce,
    object_id: objectId,
  };
}

function storeCiphertext(spoolPath, ciphertext, index, nonce, stored) {
  const digest = digestBytes(stored);
  const storedPath = path.join(spoolPath, digest.replace("sha256:", ""));
  try {
    if (!existsSync(storedPath)) {
      writeFileSync(storedPath, stored);
    }
  } catch {
    throw localStorageError();
  }
  const existing = ciphertext.get(digest);
  if (existing !== undefined && existing !== storedPath) {
    throw new ManagedError(
      "OBJECT_DIGEST_MISMATCH",
      "The object bytes do not match the bound digest.",
    );
  }
  ciphertext.set(digest, storedPath);
  return {
    cipher_digest: digest,
    cipher_size: stored.length,
    index,
    nonce: encodeBase64url(nonce),
  };
}

function randomNonce(nonces) {
  const nonce = randomBytes(12);
  nonces.register(nonce);
  return nonce;
}

export {
  GRANT_TIMEOUT_MS,
  SealedManagedCandidate,
  commitTimeoutMs,
} from "./managed-upload.js";
export { FrozenManagedCaptureClosure };
