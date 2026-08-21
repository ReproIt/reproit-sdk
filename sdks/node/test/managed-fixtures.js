// Shared fixtures for the managed-mode capture client tests. Mirrors
// sdks/python/tests/managed_fixtures.py.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { Sdk, canonicalBytes } from "../src/index.js";
import { MemorySink } from "./memory-sink.js";
import {
  CAPTURE_GRANT_FORMAT,
  CIPHER_SUITE,
  canonicalDigest,
  chunkKeyContext,
  decryptChunk,
  deriveChunkKey,
  deriveObjectKey,
  digestBytes,
  encodeBase64url,
  objectKeyContext,
  signBytes,
  verificationKey,
} from "../src/managed-protocol.js";
import {
  EncryptionResponse,
  managedWorkloadKeyId,
} from "../src/managed-transport.js";
import { packageRunningNodeSubject, subjectBinding } from "../src/managed-subject.js";

const specsV1 = path.resolve(import.meta.dirname, "..", "..", "..", "specs", "v1");

export const CAPTURE_ID = "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc";
export const OPERATION_ID = "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1";
export const ORGANIZATION_ID = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd";
export const PROJECT_ID = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe";
export const SERVICE_ID = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf";
export const UPLOAD_ID = "upl_01890f3e-7b1c-7cc0-8a1b-123456789ac1";

export const CAPTURE_SIGNER_SEED = Buffer.alloc(32, 0x83);
export const WORKLOAD_SEED = Buffer.alloc(32, 0x77);
export const CANDIDATE_KEY = Buffer.alloc(32, 0x42);
export const KEY_REFERENCE = encodeBase64url(Buffer.alloc(32, 0x91));
export const GRANT_ID = encodeBase64url(Buffer.alloc(32, 0x92));
export const CAPTURE_SIGNER_ID = "managed-candidate-capture-test";
export const WORKLOAD_KEY_ID = managedWorkloadKeyId(
  encodeBase64url(verificationKey(WORKLOAD_SEED)),
);

// Any well-formed X.509 certificate satisfies endpoint construction. The
// loopback tests bypass TLS entirely, mirroring the Python PlainHttpEndpoint.
const TEST_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBmjCCAT+gAwIBAgIUAoWRJdYm2VRxX5oCfxM6pRcB67gwCgYIKoZIzj0EAwIw
IjEgMB4GA1UEAwwXcmVwcm9pdC1tYW5hZ2VkLXRlc3QtY2EwHhcNMjYwODE1MDIx
NzQwWhcNMzYwODEyMDIxNzQwWjAiMSAwHgYDVQQDDBdyZXByb2l0LW1hbmFnZWQt
dGVzdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNFRDF6Csuj8yX5rCytk
8kkzw6niKiUFg0niQD4NQH5PPskJpC4FA43uip7bSPFYDIqFIfivWnq2Y6pp6CCQ
ZNmjUzBRMB0GA1UdDgQWBBSVnfWvAwfI2BPtIvO0LGTiIk8U6jAfBgNVHSMEGDAW
gBSVnfWvAwfI2BPtIvO0LGTiIk8U6jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMCA0kAMEYCIQCf5Wf7pN88XdfL2ZRSEEJ5+lHqV4xIbvjOdLjlOBVRAAIhAPJA
VwrVo/ydR3vgphdKMLoyb2Fm2tzdrHgmsyYUiru1
-----END CERTIFICATE-----
`;

let caPathCache = null;
let subjectCache = null;
let subjectFixtureRoot = null;

function cleanupSharedFixtures() {
  if (subjectCache !== null) {
    subjectCache.dispose();
    subjectCache = null;
  }
  if (subjectFixtureRoot !== null) {
    fs.rmSync(subjectFixtureRoot, { force: true, recursive: true });
    subjectFixtureRoot = null;
  }
  if (caPathCache !== null) {
    fs.rmSync(path.dirname(caPathCache), { force: true, recursive: true });
    caPathCache = null;
  }
}

process.once("exit", cleanupSharedFixtures);

// One valid CA certificate file for endpoint construction tests.
export function testCaPath() {
  if (caPathCache === null || !fs.existsSync(caPathCache)) {
    const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "reproit-node-test-ca-"),
    );
    caPathCache = path.join(directory, "test-ca.pem");
    fs.writeFileSync(caPathCache, TEST_CA_PEM);
  }
  return caPathCache;
}

export function loadProtocolVectors() {
  const vectorsPath =
    process.env.REPROIT_PROTOCOL_VECTORS ??
    path.join(specsV1, "protocol-vectors.json");
  return JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
}

export function loadCloudApiVectors() {
  const vectorsPath =
    process.env.REPROIT_CLOUD_API_VECTORS ??
    path.join(specsV1, "cloud-api-vectors.json");
  return JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
}

// Package one running-subject closure and reuse it across tests.
export function sharedSubject() {
  if (subjectCache === null) {
    subjectFixtureRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "reproit-node-subject-fixture-"),
    );
    const script = path.join(subjectFixtureRoot, "captured-app.js");
    fs.writeFileSync(script, "throw new Error('captured failure fixture');\n");
    subjectCache = packageRunningNodeSubject(script);
  }
  return subjectCache;
}

export function emptyWorld() {
  return {
    created_at: "2026-01-01T00:00:00.000Z",
    format: "reproit.world-checkpoint.v1",
    points: [],
  };
}

export function boundDeployment(
  subject,
  workloadSeed = WORKLOAD_SEED,
  signerKeyId = WORKLOAD_KEY_ID,
) {
  const deployment = {
    format: "reproit.deployment.v1",
    organization_id: ORGANIZATION_ID,
    processing_mode: "managed",
    project_id: PROJECT_ID,
    repository_id: "source.example/acme/commerce",
    runtime_capabilities: ["runtime.node"],
    runtime_endpoint: "https://managed.reproit.example",
    service_id: SERVICE_ID,
    service_path: "services/orders",
    signature: "",
    signed_at: "2026-01-01T00:00:00.000Z",
    signer_key_id: signerKeyId,
    source_revision: "0123456789abcdef",
    subject: subjectBinding(subject.manifest),
  };
  const capabilities = [
    ...deployment.runtime_capabilities,
    subject.manifest.architecture,
    subject.manifest.operating_system,
  ];
  deployment.runtime_capabilities = [...new Set(capabilities)].sort();
  deployment.signature = signBytes(canonicalBytes(deployment), workloadSeed);
  return deployment;
}

// Capture one complete managed candidate through the existing SDK.
export function capturedCandidate(deployment, worldId) {
  const vectors = loadProtocolVectors().positive;
  const sink = new MemorySink();
  const sdk = new Sdk(sink);
  const start = {
    captureId: CAPTURE_ID,
    deployment,
    operationId: OPERATION_ID,
    worldId,
  };
  sdk.begin(start, structuredClone(vectors.operation_begin_payload.value));
  sdk.recordInput(
    OPERATION_ID,
    structuredClone(vectors.operation_input_payload.value),
  );
  sdk.fail(OPERATION_ID, structuredClone(vectors.failure_payload.value));
  return JSON.parse(Buffer.from(sink.candidates[0]).toString("utf8"));
}

export function signedCaptureGrant(request, options = {}) {
  const grant = {
    candidate_identity_digest: request.candidate_identity_digest,
    candidate_key_reference: options.keyReference ?? KEY_REFERENCE,
    capture_id: request.capture_id,
    cipher_suite: CIPHER_SUITE,
    expires_at: options.expiresAt ?? "2026-01-01T00:01:00.000Z",
    format: CAPTURE_GRANT_FORMAT,
    grant_id: GRANT_ID,
    not_before: options.notBefore ?? "2026-01-01T00:00:00.000Z",
    operation: "encrypt-and-upload-candidate",
    organization_id: request.organization_id,
    processing_mode: "managed",
    project_id: request.project_id,
    service_id: request.service_id,
    signature: "",
    signer_key_id: CAPTURE_SIGNER_ID,
  };
  grant.signature = signBytes(
    canonicalBytes(grant),
    options.signerSeed ?? CAPTURE_SIGNER_SEED,
  );
  return grant;
}

// A grant delivery double that records every request it receives.
export class GrantDeliverySpy {
  constructor(options = {}) {
    this.calls = [];
    this.candidateKey = options.candidateKey ?? CANDIDATE_KEY;
    this.keyReference = options.keyReference ?? KEY_REFERENCE;
  }

  async requestEncryptionGrant(request, timeoutMs) {
    void timeoutMs;
    this.calls.push(structuredClone(request));
    return new EncryptionResponse(
      this.candidateKey,
      signedCaptureGrant(request, { keyReference: this.keyReference }),
    );
  }
}

// Independently decrypt every sealed object and verify plain digests.
export function openSealedObjectBytes(sealed, candidateKey) {
  const identity = sealed.request.ciphertext_identity;
  const recovered = new Map();
  for (const entry of identity.objects) {
    const descriptor = entry.descriptor;
    const context = objectKeyContext(
      identity,
      descriptor.object_id,
      descriptor.role,
    );
    const objectKey = deriveObjectKey(
      candidateKey,
      identity.capture_id,
      context,
    );
    const contextDigest = canonicalDigest(context);
    const parts = [];
    for (const chunk of entry.chunks) {
      const chunkContext = chunkKeyContext(
        contextDigest,
        entry.chunks.length,
        chunk.index,
        chunk.cipher_size - 28,
      );
      const chunkKey = deriveChunkKey(objectKey, chunkContext);
      const stored = fs.readFileSync(sealed.ciphertextPath(chunk.cipher_digest));
      parts.push(decryptChunk(chunkKey, stored, chunkContext));
    }
    const content = Buffer.concat(parts);
    if (digestBytes(content) !== descriptor.plain_digest) {
      throw new Error("decrypted object digest mismatch");
    }
    recovered.set(descriptor.object_id, content);
  }
  return recovered;
}

export function openSealedManifest(sealed, candidateKey) {
  const identity = sealed.request.ciphertext_identity;
  const manifestObject = identity.manifest_object;
  const context = objectKeyContext(
    identity,
    manifestObject.object_id,
    "capture-batch-manifest",
  );
  const objectKey = deriveObjectKey(candidateKey, identity.capture_id, context);
  const chunkContext = chunkKeyContext(
    canonicalDigest(context),
    1,
    0,
    manifestObject.cipher_size - 28,
  );
  const chunkKey = deriveChunkKey(objectKey, chunkContext);
  const stored = fs.readFileSync(
    sealed.ciphertextPath(manifestObject.cipher_digest),
  );
  return JSON.parse(
    decryptChunk(chunkKey, stored, chunkContext).toString("utf8"),
  );
}

// Apply one negative-vector JSON-pointer replace mutation.
export function applyMutation(base, mutation) {
  if (mutation.operation !== "replace") {
    throw new Error("only replace mutations are supported");
  }
  const changed = structuredClone(base);
  const parts = mutation.path.replace(/^\//u, "").split("/");
  let target = changed;
  for (const part of parts.slice(0, -1)) {
    target = Array.isArray(target) ? target[Number(part)] : target[part];
  }
  const leaf = parts.at(-1);
  if (Array.isArray(target)) {
    target[Number(leaf)] = mutation.value;
  } else {
    target[leaf] = mutation.value;
  }
  return changed;
}
