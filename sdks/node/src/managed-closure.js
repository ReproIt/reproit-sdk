// The static managed capture closure: world binding and frozen artifacts.
//
// Mirrors the closure half of crates/reproit-sdk-rust/src/managed.rs: the
// world checkpoint shape the SDK consumes, the static artifact set proof,
// dependency-transcript validation, and freezing artifact bytes into a
// private spool so they cannot change between proof and upload.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
  unlinkSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { releaseLogical, reserveLogical } from "./process-resources.js";

import { canonicalBytes } from "./index.js";
import {
  DEPENDENCY_TRANSCRIPT_MEDIA_TYPE,
  MAX_CHUNK_BYTES,
  ManagedError,
  canonicalDigest,
  incompleteCandidate,
  isObject,
  newObjectId,
  parseStrictJson,
  sameKeys,
  schemaInvalid,
  validDigest,
  validTimestamp,
  validTypedId,
} from "./managed-protocol.js";

export const MAX_CAPTURE_ARTIFACT_BYTES = 1024 * 1024 * 1024;
export const MAX_WORLD_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024;
export const MAX_WORLD_MANIFEST_BYTES = 262_144;
export const COPY_BUFFER_BYTES = 64 * 1024;

export const ARTIFACT_ROLES = new Set([
  "dependency-transcript",
  "world-state",
]);

// One static capture artifact: { mediaType, objectId, path, role, uri }.
// The plain-object shape mirrors the Python and Rust artifact records.

// A capture closure whose artifact bytes are frozen in a private spool.
export class FrozenManagedCaptureClosure {
  #spool = null;
  #reservedBytes = 0;

  constructor(closure) {
    validateWorldCheckpoint(closure.world);
    validateStaticArtifactSet(closure.world, closure.artifacts);
    this.#reservedBytes = closure.artifacts.reduce((total, artifact) => {
      const size = artifactMetadata(artifact.path).size;
      if (total > MAX_WORLD_ARTIFACT_BYTES - size) {
        throw incompleteCandidate();
      }
      return total + size;
    }, 0);
    if (!reserveLogical(this.#reservedBytes)) throw incompleteCandidate();
    let artifacts = closure.artifacts;
    if (artifacts.length > 0) {
      this.#spool = mkdtempSync(
        path.join(os.tmpdir(), "reproit-managed-world-"),
      );
      try {
        artifacts = closure.artifacts.map((artifact) =>
          freezeArtifact(artifact, this.#spool),
        );
      } catch (error) {
        this.dispose();
        throw error;
      }
    }
    validateStaticArtifactSet(closure.world, artifacts);
    this.closure = {
      artifacts,
      completion: closure.completion,
      world: closure.world,
    };
  }

  worldId() {
    validateWorldCheckpoint(this.closure.world);
    return canonicalDigest(this.closure.world);
  }

  dispose() {
    if (this.#spool !== null) {
      rmSync(this.#spool, { force: true, recursive: true });
      this.#spool = null;
    }
    if (this.#reservedBytes > 0) {
      releaseLogical(this.#reservedBytes);
      this.#reservedBytes = 0;
    }
  }
}

// Validate the bounded world checkpoint shape the SDK consumes.
export function validateWorldCheckpoint(value) {
  if (
    !sameKeys(value, ["created_at", "format", "points"]) ||
    value.format !== "reproit.world-checkpoint.v1" ||
    !validTimestamp(value.created_at) ||
    !Array.isArray(value.points) ||
    value.points.length > 64
  ) {
    throw schemaInvalid();
  }
  const providers = new Set();
  for (const point of value.points) {
    if (
      !isObject(point) ||
      point.format !== "reproit.recoverable-point.v1" ||
      typeof point.provider_id !== "string" ||
      !Array.isArray(point.artifacts) ||
      point.artifacts.length > 32_767 ||
      providers.has(point.provider_id)
    ) {
      throw schemaInvalid();
    }
    providers.add(point.provider_id);
    for (const artifact of point.artifacts) {
      if (
        !isObject(artifact) ||
        !validDigest(artifact.digest) ||
        !Number.isSafeInteger(artifact.size) ||
        artifact.size < 0 ||
        typeof artifact.uri !== "string" ||
        artifact.uri.length === 0 ||
        artifact.uri.length > 2_048 ||
        typeof artifact.media_type !== "string"
      ) {
        throw schemaInvalid();
      }
    }
  }
  if (canonicalBytes(value).length > MAX_WORLD_MANIFEST_BYTES) {
    throw schemaInvalid();
  }
}

export function expectedWorldArtifacts(world) {
  const expected = new Set();
  for (const point of world.points) {
    for (const artifact of point.artifacts) {
      expected.add(
        JSON.stringify([
          artifact.uri,
          artifact.digest,
          artifact.size,
          artifact.media_type,
        ]),
      );
    }
  }
  return expected;
}

export function validateStaticArtifactSet(world, artifacts) {
  if (artifacts.length > 32_767) {
    throw incompleteCandidate();
  }
  const expectedWorld = expectedWorldArtifacts(world);
  const suppliedWorld = new Set(
    artifacts
      .filter((artifact) => artifact.role === "world-state")
      .map((artifact) => artifact.uri),
  );
  const expectedUris = new Set(
    [...expectedWorld].map((entry) => JSON.parse(entry)[0]),
  );
  if (
    expectedUris.size !== suppliedWorld.size ||
    [...expectedUris].some((uri) => !suppliedWorld.has(uri))
  ) {
    throw incompleteCandidate();
  }
  const objectIds = new Set();
  const uris = new Set();
  for (const artifact of artifacts) {
    if (
      !ARTIFACT_ROLES.has(artifact.role) ||
      typeof artifact.uri !== "string" ||
      artifact.uri.length === 0 ||
      artifact.uri.length > 2_048 ||
      typeof artifact.mediaType !== "string" ||
      artifact.mediaType.length === 0 ||
      artifact.mediaType.length > 256 ||
      objectIds.has(artifact.objectId) ||
      uris.has(artifact.uri)
    ) {
      throw incompleteCandidate();
    }
    objectIds.add(artifact.objectId);
    uris.add(artifact.uri);
    const { size, digest } = hashFile(artifact.path);
    if (
      artifact.role === "world-state" &&
      !expectedWorld.has(
        JSON.stringify([artifact.uri, digest, size, artifact.mediaType]),
      )
    ) {
      throw incompleteCandidate();
    }
    if (
      artifact.role === "dependency-transcript" &&
      artifact.mediaType === DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
    ) {
      if (size > MAX_CHUNK_BYTES) {
        throw incompleteCandidate();
      }
      validateTranscriptBytes(readBounded(artifact.path, size));
    }
  }
}

// Mirror the DependencyTranscript strict parse and validation.
export function validateTranscriptBytes(value) {
  const parsed = parseStrictJson(value, MAX_CHUNK_BYTES);
  if (
    !isObject(parsed) ||
    !canonicalBytes(parsed).equals(Buffer.from(value)) ||
    !sameKeys(parsed, [
      "adapter_id",
      "adapter_version",
      "format",
      "interactions",
    ]) ||
    parsed.format !== "reproit.dependency-transcript.v1"
  ) {
    throw schemaInvalid();
  }
  const adapterId = parsed.adapter_id;
  const adapterVersion = parsed.adapter_version;
  const interactions = parsed.interactions;
  if (
    typeof adapterId !== "string" ||
    adapterId.length === 0 ||
    adapterId.length > 128 ||
    typeof adapterVersion !== "string" ||
    adapterVersion.length === 0 ||
    adapterVersion.length > 64 ||
    !Array.isArray(interactions) ||
    interactions.length < 1 ||
    interactions.length > 1_024
  ) {
    throw schemaInvalid();
  }
  interactions.forEach((interaction, index) => {
    validateInteraction(interaction, index);
  });
  return parsed;
}

function validateInteraction(interaction, index) {
  if (
    !sameKeys(interaction, [
      "causal_parent_id",
      "operation_id",
      "outcome",
      "request_digest",
      "request_object_id",
      "response_digest",
      "response_object_id",
      "sequence",
      "session_position",
    ]) ||
    interaction.sequence !== index ||
    !validTypedId(interaction.operation_id, "operation_id") ||
    !(
      interaction.causal_parent_id === null ||
      validTypedId(interaction.causal_parent_id, "operation_id")
    ) ||
    !validDigest(interaction.request_digest) ||
    !validDigest(interaction.response_digest) ||
    !validTypedId(interaction.request_object_id, "object_id") ||
    !validTypedId(interaction.response_object_id, "object_id") ||
    !Number.isSafeInteger(interaction.session_position) ||
    interaction.session_position < 0
  ) {
    throw schemaInvalid();
  }
}

function freezeArtifact(artifact, spoolPath) {
  const metadata = artifactMetadata(artifact.path);
  const temporary = path.join(spoolPath, `artifact-${newObjectId()}`);
  const { digest: firstDigest, size: copied } = copyAndDigest(
    artifact.path,
    temporary,
    metadata.size,
  );
  const { digest: secondDigest, size: verified } = digestFile(
    artifact.path,
    metadata.size,
  );
  if (firstDigest !== secondDigest || copied !== verified) {
    throw incompleteCandidate();
  }
  const frozenPath = path.join(
    spoolPath,
    firstDigest.replace("sha256:", ""),
  );
  if (existsSync(frozenPath)) {
    const { digest: storedDigest, size: storedSize } = digestFile(
      frozenPath,
      copied,
    );
    if (storedDigest !== firstDigest || storedSize !== copied) {
      throw new ManagedError(
        "OBJECT_DIGEST_MISMATCH",
        "The object bytes do not match the bound digest.",
      );
    }
    unlinkSync(temporary);
  } else {
    renameSync(temporary, frozenPath);
  }
  return {
    mediaType: artifact.mediaType,
    objectId: artifact.objectId,
    path: frozenPath,
    role: artifact.role,
    uri: artifact.uri,
  };
}

export function artifactMetadata(filePath) {
  let metadata;
  try {
    metadata = lstatSync(filePath);
  } catch {
    throw incompleteCandidate();
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > MAX_CAPTURE_ARTIFACT_BYTES
  ) {
    throw incompleteCandidate();
  }
  return metadata;
}

function copyAndDigest(source, target, expected) {
  try {
    copyFileSync(source, target);
  } catch {
    throw new ManagedError(
      "SERVICE_UNAVAILABLE",
      "Repro It could not create the bounded local ciphertext staging area.",
    );
  }
  const copy = digestFile(target, expected);
  if (copy.size !== expected) {
    throw incompleteCandidate();
  }
  return copy;
}

export function digestFile(filePath, expected) {
  const hasher = createHash("sha256");
  let total = 0;
  let descriptor;
  try {
    descriptor = openSync(filePath, "r");
  } catch {
    throw incompleteCandidate();
  }
  try {
    const buffer = Buffer.alloc(COPY_BUFFER_BYTES);
    for (;;) {
      const read = readSync(descriptor, buffer, 0, buffer.length, null);
      if (read === 0) break;
      total += read;
      if (total > expected) {
        throw incompleteCandidate();
      }
      hasher.update(buffer.subarray(0, read));
    }
  } catch (error) {
    if (error instanceof ManagedError) throw error;
    throw incompleteCandidate();
  } finally {
    closeSync(descriptor);
  }
  if (total !== expected) {
    throw incompleteCandidate();
  }
  return { digest: `sha256:${hasher.digest("hex")}`, size: total };
}

export function readBounded(filePath, expected) {
  let descriptor;
  try {
    descriptor = openSync(filePath, "r");
  } catch {
    throw incompleteCandidate();
  }
  try {
    const buffer = Buffer.alloc(expected + 1);
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
    if (total !== expected) {
      throw incompleteCandidate();
    }
    return Buffer.from(buffer.subarray(0, expected));
  } catch (error) {
    if (error instanceof ManagedError) throw error;
    throw incompleteCandidate();
  } finally {
    closeSync(descriptor);
  }
}

// Hash a stable regular file, failing closed if it changes underneath.
export function hashFile(filePath) {
  const before = artifactMetadata(filePath);
  const beforeStat = lstatSync(filePath, { bigint: true });
  const { digest, size } = digestFile(filePath, before.size);
  const after = artifactMetadata(filePath);
  const afterStat = lstatSync(filePath, { bigint: true });
  if (after.size !== size || afterStat.mtimeNs !== beforeStat.mtimeNs) {
    throw incompleteCandidate();
  }
  return { digest, size };
}
