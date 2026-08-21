// Managed workload identity: a protected local Ed25519 key file.
//
// Mirrors crates/reproit-sdk-rust/src/managed_identity.rs. The key file holds
// exactly 32 secret bytes with mode 0600 inside a directory that group and
// other users cannot write. Every deviation fails closed.

import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalBytes } from "./index.js";
import {
  ManagedError,
  canonicalDigest,
  isObject,
  parseStrictJson,
  signBytes,
  validDigest,
  validTimestamp,
  validTypedId,
  verificationKey,
} from "./managed-protocol.js";

export const WORKLOAD_KEY_BYTES = 32;
export const MAX_MANAGED_DEPLOYMENT_METADATA_BYTES = 256;
export const MAX_MANAGED_WORKLOAD_RECEIPT_BYTES = 512;

export { signBytes, verificationKey };

// Protected workload identity state for one stable deployment binding.
export class ManagedWorkloadIdentityState {
  #directory;

  constructor(stateRoot, bindingDigest) {
    validateStateRoot(stateRoot);
    if (!validDigest(bindingDigest)) {
      throw stateRootInvalid();
    }
    ensurePrivatePath(stateRoot);
    const reproit = path.join(stateRoot, "reproit");
    ensurePrivateDirectory(reproit);
    const workloads = path.join(reproit, "workloads");
    ensurePrivateDirectory(workloads);
    this.#directory = path.join(workloads, bindingDigest);
    ensurePrivateDirectory(this.#directory);
  }

  static fromEnvironment(bindingDigest) {
    const configured = process.env.XDG_STATE_HOME;
    const stateRoot =
      typeof configured === "string" && configured.length > 0
        ? configured
        : path.join(os.homedir(), ".local", "state");
    return new ManagedWorkloadIdentityState(stateRoot, bindingDigest);
  }

  get directory() {
    return this.#directory;
  }

  loadOrCreateKey() {
    validatePrivateDirectory(this.#directory);
    return loadOrCreateManagedWorkloadKey(
      path.join(this.#directory, "workload.key"),
    );
  }

  loadOrCreateDeploymentSignedAt(bindingDigest, proposedSignedAt) {
    if (!validDigest(bindingDigest) || !validTimestamp(proposedSignedAt)) {
      throw deploymentMetadataInvalid();
    }
    validatePrivateDirectory(this.#directory);
    const metadata = {
      binding_digest: bindingDigest,
      format: 1,
      signed_at: proposedSignedAt,
    };
    const metadataPath = path.join(this.#directory, "deployment.json");
    const stored = readCanonicalState(
      metadataPath,
      MAX_MANAGED_DEPLOYMENT_METADATA_BYTES,
      validateDeploymentMetadata,
    );
    if (stored !== null) {
      if (stored.binding_digest !== bindingDigest) {
        throw deploymentMetadataScopeMismatch();
      }
      return stored.signed_at;
    }
    atomicCreate(metadataPath, canonicalBytes(metadata));
    const persisted = readCanonicalState(
      metadataPath,
      MAX_MANAGED_DEPLOYMENT_METADATA_BYTES,
      validateDeploymentMetadata,
    );
    if (persisted.binding_digest !== bindingDigest) {
      throw deploymentMetadataScopeMismatch();
    }
    return persisted.signed_at;
  }

  loadRegistrationReceipt(expected) {
    validateRegistrationReceipt(expected);
    validatePrivateDirectory(this.#directory);
    const receipt = readCanonicalState(
      path.join(this.#directory, "registration.json"),
      MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
      validateRegistrationReceipt,
    );
    if (receipt === null) return null;
    if (!sameReceipt(receipt, expected)) {
      throw receiptScopeMismatch();
    }
    return receipt;
  }

  persistRegistrationReceipt(receipt) {
    validateRegistrationReceipt(receipt);
    validatePrivateDirectory(this.#directory);
    const receiptPath = path.join(this.#directory, "registration.json");
    const existing = readCanonicalState(
      receiptPath,
      MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
      validateRegistrationReceipt,
    );
    if (existing !== null) {
      if (!sameReceipt(existing, receipt)) throw receiptScopeMismatch();
      return;
    }
    atomicCreate(receiptPath, canonicalBytes(receipt));
    const persisted = readCanonicalState(
      receiptPath,
      MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
      validateRegistrationReceipt,
    );
    if (!sameReceipt(persisted, receipt)) throw receiptScopeMismatch();
  }
}

// Create or load the 32-byte managed workload signing key at keyPath.
export function loadOrCreateManagedWorkloadKey(keyPath) {
  const parent = path.dirname(keyPath);
  if (parent === keyPath) {
    throw keyStoreInvalid();
  }
  validateParent(parent);
  let metadata;
  try {
    metadata = lstatSync(keyPath);
  } catch (error) {
    if (error.code !== "ENOENT") throw keyStoreUnavailable();
    metadata = null;
  }
  if (metadata !== null) return readKey(keyPath, parent);
  const key = randomBytes(WORKLOAD_KEY_BYTES);
  atomicCreate(keyPath, key);
  return readKey(keyPath, parent);
}

function readKey(keyPath, parent) {
  validateFile(keyPath, parent);
  let descriptor;
  try {
    descriptor = openSync(keyPath, "r");
  } catch {
    throw keyStoreUnavailable();
  }
  try {
    const buffer = Buffer.alloc(WORKLOAD_KEY_BYTES + 1);
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
    if (total !== WORKLOAD_KEY_BYTES) {
      throw keyStoreInvalid();
    }
    return Buffer.from(buffer.subarray(0, WORKLOAD_KEY_BYTES));
  } catch (error) {
    if (error instanceof ManagedError) throw error;
    throw keyStoreUnavailable();
  } finally {
    closeSync(descriptor);
  }
}

function validateParent(parent) {
  let metadata;
  try {
    metadata = lstatSync(parent);
  } catch {
    throw keyStoreInvalid();
  }
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    (metadata.mode & 0o022) !== 0
  ) {
    throw keyStoreInvalid();
  }
}

function validateStateRoot(stateRoot) {
  if (
    typeof stateRoot !== "string" ||
    stateRoot.length === 0 ||
    !path.isAbsolute(stateRoot) ||
    path.normalize(stateRoot) !== stateRoot
  ) {
    throw stateRootInvalid();
  }
}

function ensurePrivatePath(stateRoot) {
  const parsed = path.parse(stateRoot);
  let current = parsed.root;
  for (const component of stateRoot.slice(parsed.root.length).split(path.sep)) {
    if (component.length === 0) continue;
    current = path.join(current, component);
    if (!existsSync(current)) {
      try {
        mkdirSync(current, { mode: 0o700 });
      } catch {
        throw stateRootUnavailable();
      }
    }
    let metadata;
    try {
      metadata = lstatSync(current);
    } catch {
      throw stateRootUnavailable();
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw stateRootInvalid();
    }
  }
}

function ensurePrivateDirectory(directory) {
  if (!existsSync(directory)) {
    try {
      mkdirSync(directory, { mode: 0o700 });
    } catch {
      throw stateRootUnavailable();
    }
  }
  validatePrivateDirectory(directory);
}

function validatePrivateDirectory(directory) {
  let metadata;
  try {
    metadata = lstatSync(directory);
  } catch {
    throw stateRootInvalid();
  }
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    (metadata.mode & 0o777) !== 0o700
  ) {
    throw stateRootInvalid();
  }
}

function validateFile(keyPath, parent) {
  let metadata;
  let parentMetadata;
  try {
    metadata = lstatSync(keyPath);
    parentMetadata = statSync(parent);
  } catch {
    throw keyStoreInvalid();
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size !== WORKLOAD_KEY_BYTES ||
    (metadata.mode & 0o077) !== 0 ||
    metadata.uid !== parentMetadata.uid
  ) {
    throw keyStoreInvalid();
  }
}

function readCanonicalState(filePath, maximumBytes, validate) {
  if (!existsSync(filePath)) return null;
  validateStateFile(filePath, maximumBytes);
  let bytes;
  try {
    bytes = readFileSync(filePath);
  } catch {
    throw keyStoreUnavailable();
  }
  let value;
  try {
    value = parseStrictJson(bytes, maximumBytes);
    validate(value);
  } catch (error) {
    if (error instanceof ManagedError) throw error;
    throw keyStoreInvalid();
  }
  if (!Buffer.from(canonicalBytes(value)).equals(bytes)) {
    throw keyStoreInvalid();
  }
  return value;
}

function validateStateFile(filePath, maximumBytes) {
  let metadata;
  let parentMetadata;
  try {
    metadata = lstatSync(filePath);
    parentMetadata = statSync(path.dirname(filePath));
  } catch {
    throw keyStoreInvalid();
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > maximumBytes ||
    (metadata.mode & 0o077) !== 0 ||
    metadata.uid !== parentMetadata.uid
  ) {
    throw keyStoreInvalid();
  }
}

function atomicCreate(filePath, bytes) {
  if (bytes.length === 0) throw keyStoreInvalid();
  const temporary = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${randomBytes(12).toString("base64url")}.pending`,
  );
  let descriptor = null;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeAll(descriptor, bytes);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    try {
      linkSync(temporary, filePath);
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
  } catch {
    throw keyStoreUnavailable();
  } finally {
    if (descriptor !== null) closeSync(descriptor);
    try {
      rmSync(temporary, { force: true });
    } catch {
      // The next protected-state read rejects any unexpected state file.
    }
  }
  syncDirectory(path.dirname(filePath));
}

function writeAll(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(
      descriptor,
      bytes,
      offset,
      bytes.length - offset,
      null,
    );
    if (written <= 0) throw keyStoreUnavailable();
    offset += written;
  }
}

function syncDirectory(directory) {
  let descriptor;
  try {
    descriptor = openSync(directory, "r");
    fsyncSync(descriptor);
  } catch {
    throw keyStoreUnavailable();
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function validateDeploymentMetadata(value) {
  if (
    !isObject(value) ||
    Object.keys(value).sort().join(" ") !==
      "binding_digest format signed_at" ||
    value.format !== 1 ||
    !validDigest(value.binding_digest) ||
    !validTimestamp(value.signed_at)
  ) {
    throw deploymentMetadataInvalid();
  }
}

function validateRegistrationReceipt(value) {
  if (
    !isObject(value) ||
    Object.keys(value).sort().join(" ") !==
      "deployment_digest service_id workload_key_id" ||
    !validDigest(value.deployment_digest) ||
    !validTypedId(value.service_id, "service_id") ||
    !/^managed-workload-sha256:[0-9a-f]{64}$/u.test(value.workload_key_id)
  ) {
    throw receiptInvalid();
  }
}

function sameReceipt(left, right) {
  return canonicalDigest(left) === canonicalDigest(right);
}

function keyStoreInvalid() {
  return new ManagedError(
    "CONFIG_CONFLICT",
    "The managed workload key file is not private or valid.",
  );
}

function keyStoreUnavailable() {
  return new ManagedError(
    "SERVICE_UNAVAILABLE",
    "The managed workload key file is unavailable.",
  );
}

function stateRootInvalid() {
  return new ManagedError(
    "CONFIG_CONFLICT",
    "The managed workload state directory is not private or valid.",
  );
}

function stateRootUnavailable() {
  return new ManagedError(
    "SERVICE_UNAVAILABLE",
    "The managed workload state directory is unavailable.",
  );
}

function deploymentMetadataInvalid() {
  return new ManagedError(
    "CONFIG_CONFLICT",
    "The managed deployment metadata is invalid.",
  );
}

function deploymentMetadataScopeMismatch() {
  return new ManagedError(
    "AUTHORIZATION_DENIED",
    "The managed deployment metadata belongs to another deployment.",
  );
}

function receiptInvalid() {
  return new ManagedError(
    "CONFIG_CONFLICT",
    "The managed workload registration receipt is invalid.",
  );
}

function receiptScopeMismatch() {
  return new ManagedError(
    "AUTHORIZATION_DENIED",
    "The managed workload registration receipt has different scope.",
  );
}
