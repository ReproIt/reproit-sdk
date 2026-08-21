// The bounded managed candidate upload session.
//
// Mirrors the upload half of crates/reproit-sdk-rust/src/managed.rs: the
// start, missing, object-PUT, commit, and cancel state machine, the bounded
// per-object attempts, and the size-scaled commit timeout.

import { Buffer } from "node:buffer";
import { lstatSync, rmSync } from "node:fs";

import { canonicalBytes } from "./index.js";
import {
  CIPHER_SUITE,
  MAX_CHUNK_BYTES,
  ManagedError,
  digestBytes,
  signBytes,
  validateUploadRequest,
  verifyCaptureGrant,
} from "./managed-protocol.js";
import { readBounded } from "./managed-closure.js";

export const GRANT_TIMEOUT_MS = 5_000;
// The ingress verifies every stored ciphertext object before it commits, so
// the commit wait scales with the declared closure. The floor covers control
// latency, the rate is a conservative verification throughput, and the cap
// bounds the wait for the largest closures. Mirrors the Rust reference.
export const COMMIT_TIMEOUT_FLOOR_MS = 5_000;
export const COMMIT_VERIFICATION_BYTES_PER_SECOND = 4 * 1024 * 1024;
export const COMMIT_TIMEOUT_CAP_MS = 180_000;

export function commitTimeoutMs(totalCiphertextBytes) {
  const verificationSeconds = Math.ceil(
    totalCiphertextBytes / COMMIT_VERIFICATION_BYTES_PER_SECOND,
  );
  return Math.min(
    COMMIT_TIMEOUT_CAP_MS,
    COMMIT_TIMEOUT_FLOOR_MS + verificationSeconds * 1_000,
  );
}

// The sealed upload request plus its private ciphertext spool.
export class SealedManagedCandidate {
  #candidateKey;
  #ciphertext;
  #deploymentDigest;
  #spool;

  constructor(request, candidateKey, ciphertext, spool, deploymentDigest) {
    this.request = request;
    this.#candidateKey = candidateKey;
    this.#ciphertext = ciphertext;
    this.#deploymentDigest = deploymentDigest;
    this.#spool = spool;
  }

  ciphertextDigests() {
    return [...this.#ciphertext.keys()].sort();
  }

  ciphertextPath(digest) {
    return this.#ciphertext.get(digest);
  }

  dispose() {
    if (this.#spool !== null) {
      rmSync(this.#spool, { force: true, recursive: true });
      this.#spool = null;
    }
  }

  async requestCaptureGrantRenewal(delivery, signerKeyId, signingKey) {
    const identity = this.request.ciphertext_identity;
    const request = {
      candidate_identity_digest: identity.candidate_identity_digest,
      capture_id: identity.capture_id,
      cipher_suite: CIPHER_SUITE,
      deployment_digest: this.#deploymentDigest,
      organization_id: identity.organization_id,
      processing_mode: "managed",
      project_id: identity.project_id,
      service_id: identity.service_id,
      signature: "",
      signer_key_id: signerKeyId,
    };
    request.signature = signBytes(canonicalBytes(request), signingKey);
    return delivery.requestEncryptionGrant(request, GRANT_TIMEOUT_MS);
  }

  applyRenewedCaptureGrant(
    response,
    now,
    captureSignerId,
    captureSignerPublicKey,
  ) {
    const identity = this.request.ciphertext_identity;
    if (
      !Buffer.from(response.candidateKey).equals(
        Buffer.from(this.#candidateKey),
      ) ||
      response.captureGrant.candidate_key_reference !==
        identity.candidate_key_reference
    ) {
      throw new ManagedError(
        "CAPTURE_ID_CONFLICT",
        "The renewed managed capture grant does not match the live candidate key.",
      );
    }
    verifyCaptureGrant(
      response.captureGrant,
      {
        candidate_identity_digest: identity.candidate_identity_digest,
        candidate_key_reference: identity.candidate_key_reference,
        capture_id: identity.capture_id,
        organization_id: identity.organization_id,
        project_id: identity.project_id,
        service_id: identity.service_id,
        signer_key_id: captureSignerId,
      },
      now,
      captureSignerPublicKey,
    );
    this.request.capture_grant = response.captureGrant;
    validateUploadRequest(this.request);
  }

  async upload(delivery) {
    const commitTimeout = commitTimeoutMs(
      this.request.ciphertext_identity.total_ciphertext_bytes,
    );
    const start = await delivery.start(this.request, GRANT_TIMEOUT_MS);
    if (start.state === "COMMITTED") {
      return this.#verifiedCommit(
        await delivery.commit(start.upload_id, start.upload_token, commitTimeout),
      );
    }
    if (!["OPEN", "UPLOADING"].includes(start.state)) {
      throw uploadStateError();
    }
    try {
      await this.#uploadMissing(delivery, start);
    } catch (error) {
      if (error instanceof ManagedError) {
        await this.#cancelQuietly(delivery, start);
      }
      throw error;
    }
    let commit;
    try {
      commit = await delivery.commit(
        start.upload_id,
        start.upload_token,
        commitTimeout,
      );
    } catch (error) {
      if (error instanceof ManagedError) {
        await this.#cancelQuietly(delivery, start);
      }
      throw error;
    }
    return this.#verifiedCommit(commit);
  }

  #verifiedCommit(commit) {
    const identity = this.request.ciphertext_identity;
    if (
      commit.capture_id !== this.request.capture_grant.capture_id ||
      commit.candidate_identity_digest !==
        identity.candidate_identity_digest ||
      commit.candidate_key_reference !== identity.candidate_key_reference ||
      commit.encrypted_candidate_digest !==
        this.request.encrypted_candidate_digest ||
      commit.state !== "CLOUD_PROTECTED"
    ) {
      throw uploadStateError();
    }
    return { ...commit };
  }

  async #uploadMissing(delivery, start) {
    const limits = start.limits;
    const attempts = limits.object_attempts;
    let page = {
      missing_objects: [...start.missing_objects],
      next_missing_cursor: start.next_missing_cursor,
    };
    const seen = new Set();
    const maximumPages = Math.ceil(this.#ciphertext.size / 100) + 1;
    for (let pageIndex = 0; pageIndex < maximumPages; pageIndex += 1) {
      if (page.missing_objects.length > 100) {
        throw uploadStateError();
      }
      for (const missing of page.missing_objects) {
        const digest = missing.cipher_digest;
        if (seen.has(digest) || !this.#ciphertext.has(digest)) {
          throw uploadStateError();
        }
        seen.add(digest);
      }
      for (const missing of page.missing_objects) {
        await this.#uploadOne(delivery, missing, attempts);
      }
      const cursor = page.next_missing_cursor;
      if (cursor === null) {
        return;
      }
      page = await delivery.missing(
        start.upload_id,
        start.upload_token,
        cursor,
        GRANT_TIMEOUT_MS,
      );
    }
    throw uploadStateError();
  }

  async #uploadOne(delivery, missing, attempts) {
    if (
      !Number.isSafeInteger(attempts) ||
      attempts === 0 ||
      attempts > 5
    ) {
      throw uploadStateError();
    }
    const digest = missing.cipher_digest;
    const filePath = this.#ciphertext.get(digest);
    let metadata;
    try {
      metadata = lstatSync(filePath);
    } catch {
      throw localStorageError();
    }
    if (!metadata.isFile() || metadata.size > MAX_CHUNK_BYTES + 28) {
      throw localStorageError();
    }
    let value;
    try {
      value = readBounded(filePath, metadata.size);
    } catch {
      throw localStorageError();
    }
    if (digestBytes(value) !== digest) {
      throw new ManagedError(
        "OBJECT_DIGEST_MISMATCH",
        "The object bytes do not match the bound digest.",
      );
    }
    let lastError = null;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        await delivery.uploadObject(
          missing.upload_url,
          digest,
          value,
          GRANT_TIMEOUT_MS,
        );
        return;
      } catch (error) {
        if (!(error instanceof ManagedError) || !error.retryable) {
          throw error;
        }
        lastError = error;
      }
    }
    throw lastError ?? uploadStateError();
  }

  async #cancelQuietly(delivery, start) {
    try {
      await delivery.cancel(
        start.upload_id,
        start.upload_token,
        GRANT_TIMEOUT_MS,
      );
    } catch {
      // Cancellation is best effort. The original failure is reported.
    }
  }
}

export function localStorageError() {
  return new ManagedError(
    "SERVICE_UNAVAILABLE",
    "Repro It could not create the bounded local ciphertext staging area.",
  );
}

export function uploadStateError() {
  return new ManagedError(
    "SERVICE_UNAVAILABLE",
    "The managed candidate upload did not reach a valid durable state.",
  );
}
