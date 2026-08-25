// Managed-mode conformance tests: canonical vectors from disk, the pinned
// cross-implementation seal parity bytes, the workload key file, subject
// packaging, prepare/seal negative controls, and the transport validators.
// Mirrors sdks/python/tests/test_managed_conformance.py.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import "./setup.js";

import * as fixtures from "./managed-fixtures.js";
import {
  packagedRuntime,
  preparedForSubject,
  runtimeEvidence,
  subjectFixture,
} from "./managed-subject-fixtures.js";
import { canonicalBytes } from "../src/index.js";
import {
  ManagedError,
  canonicalDigest,
  chunkKeyContext,
  decodeBase64url,
  decryptChunk,
  deriveChunkKey,
  deriveObjectKey,
  digestBytes,
  encodeBase64url,
  encryptChunk,
  signBytes,
  validateCaptureGrant,
  validateCiphertextIdentity,
  validateManagedCandidateIdentity,
  validateUploadRequest,
  verificationKey,
  verifyCaptureGrant,
  verifySignedValue,
} from "../src/managed-protocol.js";
import {
  MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
  ManagedWorkloadIdentityState,
  loadOrCreateManagedWorkloadKey,
} from "../src/managed-identity.js";
import {
  FrozenManagedCaptureClosure,
  PreparedManagedCandidate,
} from "../src/managed-candidate.js";
import {
  packageNodeSubjectWithRuntimeEvidence,
  packageRunningNodeSubject,
  subjectBinding,
} from "../src/managed-subject.js";
import {
  COMMIT_TIMEOUT_CAP_MS,
  COMMIT_TIMEOUT_FLOOR_MS,
  commitTimeoutMs,
} from "../src/managed-upload.js";
import {
  HttpResponseParser,
  ManagedProjectToken,
  ManagedTlsEndpoint,
  managedWorkloadKeyId,
  validateGrantRequest,
  validateWorkloadKeyRegistration,
} from "../src/managed-transport.js";

const GRANT_VERIFICATION_TIME = "2026-01-01T00:00:30.000Z";

const protocolVectors = fixtures.loadProtocolVectors();
const cloudVectors = fixtures.loadCloudApiVectors();
const positive = protocolVectors.positive;
const cloudPositive = cloudVectors.positive;

function grantExpectation(grant) {
  return {
    candidate_identity_digest: grant.candidate_identity_digest,
    candidate_key_reference: grant.candidate_key_reference,
    capture_id: grant.capture_id,
    organization_id: grant.organization_id,
    project_id: grant.project_id,
    service_id: grant.service_id,
    signer_key_id: grant.signer_key_id,
  };
}

test("candidate identity digest matches the canonical vector", () => {
  const identity = positive.managed_candidate_identity.value;
  validateManagedCandidateIdentity(identity);
  assert.equal(
    canonicalDigest(identity),
    protocolVectors.canonical_sha256.managed_candidate_identity,
  );
});

test("ciphertext identity digest binds the commit vector", () => {
  const identity = positive.managed_candidate_ciphertext_identity.value;
  validateCiphertextIdentity(identity);
  const digest = canonicalDigest(identity);
  assert.equal(
    digest,
    protocolVectors.canonical_sha256.managed_candidate_ciphertext_identity,
  );
  const commit = cloudPositive.managed_candidate_commit.value;
  assert.equal(digest, commit.encrypted_candidate_digest);
});

test("capture grant verifies with the published key", () => {
  const grant = positive.managed_candidate_capture_grant.value;
  const publicKey = decodeBase64url(
    protocolVectors.verification_keys["managed-candidate-capture-test"],
    32,
  );
  verifyCaptureGrant(
    grant,
    grantExpectation(grant),
    GRANT_VERIFICATION_TIME,
    publicKey,
  );
});

test("capture grant negative vectors are rejected", () => {
  const grant = positive.managed_candidate_capture_grant.value;
  const publicKey = decodeBase64url(
    protocolVectors.verification_keys["managed-candidate-capture-test"],
    32,
  );
  const expectation = grantExpectation(grant);
  const mutations = protocolVectors.negative.filter(
    (entry) => entry.base === "managed_candidate_capture_grant",
  );
  assert.equal(mutations.length, 3);
  for (const mutation of mutations) {
    const changed = fixtures.applyMutation(grant, mutation);
    assert.throws(
      () =>
        verifyCaptureGrant(
          changed,
          expectation,
          GRANT_VERIFICATION_TIME,
          publicKey,
        ),
      (error) =>
        error instanceof ManagedError && error.code === mutation.expected,
      mutation.name,
    );
  }
});

test("upload request vector validates", () => {
  validateUploadRequest(cloudPositive.managed_candidate_upload_request.value);
});

test("upload request key reference mutation is rejected", () => {
  const request = cloudPositive.managed_candidate_upload_request.value;
  const mutation = cloudVectors.negative.find(
    (entry) =>
      entry.name === "managed-candidate-key-reference-differs-from-capture-grant",
  );
  const changed = fixtures.applyMutation(request, mutation);
  assert.throws(
    () => validateUploadRequest(changed),
    (error) =>
      error instanceof ManagedError && error.code === "ATTESTATION_SCOPE",
  );
});

test("encryption response vector decodes", () => {
  const response = cloudPositive.managed_candidate_encryption_response.value;
  assert.deepEqual(
    Object.keys(response).sort(),
    ["candidate_key", "capture_grant"],
  );
  const candidateKey = decodeBase64url(response.candidate_key, 32);
  assert.equal(candidateKey.length, 32);
  validateCaptureGrant(response.capture_grant);
  const grantRequest =
    cloudPositive.managed_candidate_encryption_grant_request.value;
  assert.equal(
    grantRequest.candidate_identity_digest,
    response.capture_grant.candidate_identity_digest,
  );
});

test("signed workload registration matches the Cloud vector", () => {
  const registration = cloudPositive.workload_key_registration.value;
  validateWorkloadKeyRegistration(registration);
  assert.equal(
    managedWorkloadKeyId(registration.public_key),
    registration.deployment.signer_key_id,
  );
  assert.equal(
    canonicalDigest(registration.deployment),
    cloudPositive.workload_key_registration_result.value.deployment_digest,
  );
});

test("signed grant request matches its registered workload", () => {
  const registration = cloudPositive.workload_key_registration.value;
  const request = cloudPositive.managed_candidate_encryption_grant_request.value;
  validateGrantRequest(request);
  assert.equal(request.deployment_digest, canonicalDigest(registration.deployment));
  assert.equal(request.signer_key_id, registration.deployment.signer_key_id);
  verifySignedValue(request, decodeBase64url(registration.public_key, 32));
});

test("workload registration negative vectors fail closed", () => {
  const registration = cloudPositive.workload_key_registration.value;
  const mutations = cloudVectors.negative.filter(
    (entry) =>
      entry.base === "workload_key_registration" &&
      entry.operation === "replace",
  );
  assert.ok(mutations.length >= 5);
  for (const mutation of mutations) {
    const changed = fixtures.applyMutation(registration, mutation);
    assert.throws(
      () => validateWorkloadKeyRegistration(changed),
      (error) => error instanceof ManagedError,
      mutation.name,
    );
  }
});

test("key context vectors match canonical digests", () => {
  for (const name of ["object_key_context", "chunk_key_context"]) {
    assert.equal(
      canonicalDigest(positive[name].value),
      protocolVectors.canonical_sha256[name],
      name,
    );
  }
});

test("signing matches the Rust reference signature", () => {
  // The vector grant was signed by reproit-core with the test seed
  // 0x83 * 32. Deterministic Ed25519 over identical canonical bytes must
  // reproduce the exact signature.
  const grant = positive.managed_candidate_capture_grant.value;
  const seed = Buffer.alloc(32, 0x83);
  assert.equal(
    encodeBase64url(verificationKey(seed)),
    protocolVectors.verification_keys["managed-candidate-capture-test"],
  );
  const unsigned = { ...grant, signature: "" };
  assert.equal(signBytes(canonicalBytes(unsigned), seed), grant.signature);
});

test("seal matches the Rust reference ciphertext byte for byte", () => {
  // Pinned cross-implementation vector, identical to the constants the
  // Python port pinned in test_seal_matches_the_rust_reference_ciphertext.
  // The expected bytes were produced by reproit-core (derive_object_key,
  // derive_chunk_key, encrypt_chunk) with these exact inputs, so this test
  // proves the HKDF-SHA-256 and AES-256-GCM AAD contract byte for byte.
  const context = {
    capture_batch_format: "reproit.capture-batch.v1",
    capture_id: "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc",
    format: "reproit.object-key-context.v1",
    object_id: "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4",
    organization_id: "org_01890f3e-7b1c-7cc0-8a1b-123456789abd",
    processing_mode: "managed",
    project_id: "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe",
    role: "trigger",
    service_id: "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf",
  };
  const candidateKey = Buffer.alloc(32, 0x42);
  const plaintext = Buffer.from("cross-language managed seal vector");
  const objectKey = deriveObjectKey(candidateKey, context.capture_id, context);
  const chunkContext = chunkKeyContext(
    canonicalDigest(context),
    1,
    0,
    plaintext.length,
  );
  assert.equal(
    chunkContext.object_context_digest,
    "sha256:06e6fa3d4a4185d0eff5cd92e01ed2d5aa3dc873f5b5cdead8313556855afa84",
  );
  const chunkKey = deriveChunkKey(objectKey, chunkContext);
  const stored = encryptChunk(
    chunkKey,
    Buffer.alloc(12, 0x07),
    plaintext,
    chunkContext,
  );
  assert.equal(
    stored.toString("hex"),
    "0707070707070707070707076feaeb515f76709f385b2542dff02ead97170a34" +
      "b32eba411bf935a7e778ce0dbb1b49d747d17d71f9b507a035d4647f312f",
  );
  assert.ok(decryptChunk(chunkKey, stored, chunkContext).equals(plaintext));
});

test("managed candidate manifest vector binds its identity", () => {
  const manifest = positive.managed_candidate_manifest.value;
  validateManagedCandidateIdentity(manifest.candidate_identity);
  assert.equal(
    canonicalDigest(manifest.candidate_identity),
    manifest.candidate_identity_digest,
  );
  assert.equal(
    canonicalDigest(manifest),
    protocolVectors.canonical_sha256.managed_candidate_manifest,
  );
});

function workloadKeyDirectory(t) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "reproit-node-workload-"),
  );
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return directory;
}

test("workload key file: create and reload round trip", (t) => {
  const directory = workloadKeyDirectory(t);
  const keyPath = path.join(directory, "workload.key");
  const key = loadOrCreateManagedWorkloadKey(keyPath);
  assert.equal(key.length, 32);
  assert.equal(fs.lstatSync(keyPath).mode & 0o777, 0o600);
  assert.ok(loadOrCreateManagedWorkloadKey(keyPath).equals(key));
});

test("workload key file: rejects a world-readable key", (t) => {
  const directory = workloadKeyDirectory(t);
  const keyPath = path.join(directory, "workload.key");
  loadOrCreateManagedWorkloadKey(keyPath);
  fs.chmodSync(keyPath, 0o644);
  assert.throws(
    () => loadOrCreateManagedWorkloadKey(keyPath),
    (error) =>
      error instanceof ManagedError && error.code === "CONFIG_CONFLICT",
  );
});

test("workload key file: rejects a symlinked key", (t) => {
  const directory = workloadKeyDirectory(t);
  const target = path.join(directory, "target.key");
  fs.writeFileSync(target, Buffer.alloc(32));
  fs.chmodSync(target, 0o600);
  const keyPath = path.join(directory, "workload.key");
  fs.symlinkSync(target, keyPath);
  assert.throws(
    () => loadOrCreateManagedWorkloadKey(keyPath),
    (error) =>
      error instanceof ManagedError && error.code === "CONFIG_CONFLICT",
  );
});

test("workload key file: rejects the wrong size", (t) => {
  const directory = workloadKeyDirectory(t);
  const keyPath = path.join(directory, "workload.key");
  fs.writeFileSync(keyPath, Buffer.alloc(16));
  fs.chmodSync(keyPath, 0o600);
  assert.throws(
    () => loadOrCreateManagedWorkloadKey(keyPath),
    (error) =>
      error instanceof ManagedError && error.code === "CONFIG_CONFLICT",
  );
});

test("workload key file: rejects a group-writable parent", (t) => {
  const directory = workloadKeyDirectory(t);
  fs.chmodSync(directory, 0o770);
  assert.throws(
    () => loadOrCreateManagedWorkloadKey(path.join(directory, "workload.key")),
    (error) =>
      error instanceof ManagedError && error.code === "CONFIG_CONFLICT",
  );
});

test("protected workload state persists exact metadata and receipt", (t) => {
  const stateRoot = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-state-")),
  );
  fs.chmodSync(stateRoot, 0o700);
  t.after(() => fs.rmSync(stateRoot, { force: true, recursive: true }));
  const bindingDigest = digestBytes(Buffer.from("node deployment binding"));
  const state = new ManagedWorkloadIdentityState(stateRoot, bindingDigest);
  const signedAt = state.loadOrCreateDeploymentSignedAt(
    bindingDigest,
    "2026-01-01T00:00:00.000Z",
  );
  assert.equal(
    state.loadOrCreateDeploymentSignedAt(
      bindingDigest,
      "2026-01-02T00:00:00.000Z",
    ),
    signedAt,
  );
  const receipt = {
    deployment_digest: digestBytes(Buffer.from("signed deployment")),
    service_id: fixtures.SERVICE_ID,
    workload_key_id: fixtures.WORKLOAD_KEY_ID,
  };
  assert.equal(state.loadRegistrationReceipt(receipt), null);
  state.persistRegistrationReceipt(receipt);
  assert.deepEqual(state.loadRegistrationReceipt(receipt), receipt);
  assert.equal(fs.statSync(state.directory).mode & 0o777, 0o700);
  assert.equal(
    fs.statSync(path.join(state.directory, "registration.json")).mode & 0o777,
    0o600,
  );
});

test("protected workload state rejects corrupt, linked, and oversized receipts", (t) => {
  const stateRoot = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-state-")),
  );
  fs.chmodSync(stateRoot, 0o700);
  t.after(() => fs.rmSync(stateRoot, { force: true, recursive: true }));
  const bindingDigest = digestBytes(Buffer.from("node deployment binding"));
  const state = new ManagedWorkloadIdentityState(stateRoot, bindingDigest);
  const receipt = {
    deployment_digest: digestBytes(Buffer.from("signed deployment")),
    service_id: fixtures.SERVICE_ID,
    workload_key_id: fixtures.WORKLOAD_KEY_ID,
  };
  const receiptPath = path.join(state.directory, "registration.json");
  fs.writeFileSync(
    receiptPath,
    Buffer.alloc(MAX_MANAGED_WORKLOAD_RECEIPT_BYTES + 1, 0x61),
    { mode: 0o600 },
  );
  assert.throws(() => state.loadRegistrationReceipt(receipt));
  fs.rmSync(receiptPath);
  const target = path.join(state.directory, "receipt-target.json");
  fs.writeFileSync(target, "{}", { mode: 0o600 });
  fs.symlinkSync(target, receiptPath);
  assert.throws(() => state.loadRegistrationReceipt(receipt));
});

test("running subject is complete and content-addressed", () => {
  const subject = fixtures.sharedSubject();
  const manifest = subject.manifest;
  assert.equal(manifest.runtime_family, "node");
  assert.equal(manifest.format, "reproit.subject-closure.v1");
  assert.equal(manifest.debug_artifacts.length, 1);
  assert.equal(
    manifest.debug_artifacts[0].kind,
    "interpreted-source-identity",
  );
  const executable = manifest.launch.executable;
  assert.ok(
    manifest.files.some(
      (entry) => entry.path === executable && entry.executable,
    ),
  );
  for (const packaged of subject.objects) {
    const content = fs.readFileSync(packaged.path);
    assert.equal(digestBytes(content), packaged.digest);
    assert.equal(content.length, packaged.size);
  }
});

test("running subject captures application dependencies and source maps", (t) => {
  const fixture = subjectFixture(t);
  const subject = packageNodeSubjectWithRuntimeEvidence(
    fixture.entry,
    runtimeEvidence(t),
  );
  t.after(() => subject.dispose());
  const manifest = subject.manifest;
  const paths = new Set(manifest.files.map((entry) => entry.path));
  const applicationPrefix = manifest.launch.working_directory;
  const runtimeObject = manifest.objects.find((entry) => entry.kind === "runtime");
  const runtimeFile = manifest.files.find(
    (entry) => entry.object_digest === runtimeObject.digest,
  );
  assert.equal(runtimeFile.path, manifest.launch.executable);
  assert.equal(runtimeFile.executable, true);
  assert.ok(runtimeFile.path.startsWith("/reproit/subject/runtime/"));
  assert.ok(paths.has(`${applicationPrefix}/package.json`));
  assert.ok(paths.has(`${applicationPrefix}/src/main.mjs`));
  assert.ok(paths.has(`${applicationPrefix}/src/main.mjs.map`));
  assert.ok(paths.has(`${applicationPrefix}/src/settings.json`));
  assert.ok(paths.has(`${applicationPrefix}/src/empty.txt`));
  assert.ok(paths.has(`${applicationPrefix}/src/empty-map.js.map`));
  assert.ok(paths.has(`${applicationPrefix}/node_modules/example/package.json`));
  assert.ok(paths.has(`${applicationPrefix}/node_modules/example/index.js`));
  assert.ok(paths.has(`${applicationPrefix}/node_modules/example/index.js.map`));

  const packaged = new Map(subject.objects.map((entry) => [entry.digest, entry]));
  assert.equal(packaged.size, manifest.objects.length);
  assert.equal(
    manifest.total_bytes,
    manifest.objects.reduce((total, entry) => total + entry.size, 0),
  );
  for (const file of manifest.files) {
    const object = packaged.get(file.object_digest);
    assert.ok(object, file.path);
    const content = fs.readFileSync(object.path);
    assert.equal(digestBytes(content), file.object_digest);
    assert.equal(content.length, object.size);
  }
  assert.equal(
    manifest.launch.arguments[process.execArgv.length],
    `${applicationPrefix}/src/main.mjs`,
  );
  assert.deepEqual(
    manifest.launch.arguments.slice(0, process.execArgv.length),
    process.execArgv,
  );
  const emptyMap = manifest.debug_artifacts.find(
    (entry) => entry.path === `${applicationPrefix}/src/empty-map.js.map`,
  );
  assert.equal(emptyMap.kind, "source-map");
  assert.equal(packaged.get(emptyMap.artifact_digest).size, 0);
  const emptyNative = manifest.files.find(
    (entry) =>
      entry.path.startsWith("/reproit/subject/native/") &&
      packaged.get(entry.object_digest).size === 0,
  );
  assert.equal(packaged.get(emptyNative.object_digest).size, 0);

  const mainModule = manifest.modules.find(
    (entry) => entry.path === `${applicationPrefix}/src/main.mjs`,
  );
  const mainMap = manifest.debug_artifacts.find(
    (entry) => entry.path === `${applicationPrefix}/src/main.mjs.map`,
  );
  assert.equal(mainMap.kind, "source-map");
  assert.equal(mainMap.module_digest, mainModule.module_digest);
  const dependencyModule = manifest.modules.find(
    (entry) =>
      entry.path === `${applicationPrefix}/node_modules/example/index.js`,
  );
  const dependencyMap = manifest.debug_artifacts.find(
    (entry) =>
      entry.path === `${applicationPrefix}/node_modules/example/index.js.map`,
  );
  assert.equal(dependencyMap.kind, "source-map");
  assert.equal(dependencyMap.module_digest, dependencyModule.module_digest);

  const dependencyIdentity = manifest.files.find(
    (entry) => entry.path === "/reproit/subject/node/dependencies.json",
  );
  const dependencyObject = packaged.get(dependencyIdentity.object_digest);
  const dependencies = JSON.parse(fs.readFileSync(dependencyObject.path, "utf8"));
  assert.deepEqual(
    dependencies.packages.map((entry) => [entry.name, entry.version]),
    [["example", "2.0.0"]],
  );
  assert.equal(
    dependencies.packages[0].manifest_digest,
    manifest.files.find(
      (entry) =>
        entry.path === `${applicationPrefix}/node_modules/example/package.json`,
    ).object_digest,
  );
});

test("zero-byte subject files pass local closure and sealing", async (t) => {
  const fixture = subjectFixture(t);
  const subject = packageNodeSubjectWithRuntimeEvidence(
    fixture.entry,
    runtimeEvidence(t),
  );
  t.after(() => subject.dispose());
  const preparedCandidate = preparedForSubject(subject);
  const response = await preparedCandidate.requestEncryptionGrant(
    new fixtures.GrantDeliverySpy(),
    fixtures.WORKLOAD_KEY_ID,
    fixtures.WORKLOAD_SEED,
  );
  const sealed = preparedCandidate.seal(
    response,
    GRANT_VERIFICATION_TIME,
    fixtures.CAPTURE_SIGNER_ID,
    verificationKey(fixtures.CAPTURE_SIGNER_SEED),
  );
  t.after(() => sealed.dispose());
  assert.ok(sealed.ciphertextDigests().length > 0);
});

test("running subject rejects a missing captured Node runtime", (t) => {
  const fixture = subjectFixture(t);
  const subject = packageNodeSubjectWithRuntimeEvidence(
    fixture.entry,
    runtimeEvidence(t),
  );
  t.after(() => subject.dispose());
  fs.rmSync(packagedRuntime(subject).path);
  assert.throws(
    () => preparedForSubject(subject),
    (error) =>
      error instanceof ManagedError && error.code === "INCOMPLETE_CANDIDATE",
  );
});

test("running subject rejects corrupt captured Node runtime bytes", (t) => {
  const fixture = subjectFixture(t);
  const subject = packageNodeSubjectWithRuntimeEvidence(
    fixture.entry,
    runtimeEvidence(t),
  );
  t.after(() => subject.dispose());
  fs.writeFileSync(packagedRuntime(subject).path, "corrupt runtime");
  assert.throws(
    () => preparedForSubject(subject),
    (error) =>
      error instanceof ManagedError && error.code === "INCOMPLETE_CANDIDATE",
  );
});

test("running subject rejects a missing required source map", (t) => {
  const fixture = subjectFixture(t);
  fs.rmSync(path.join(fixture.root, "src", "main.mjs.map"));
  assert.throws(
    () => packageRunningNodeSubject(fixture.entry),
    (error) =>
      error instanceof ManagedError && error.code === "INCOMPLETE_CANDIDATE",
  );
});

test("running subject rejects a symbolic-link dependency", (t) => {
  const fixture = subjectFixture(t);
  const target = path.join(fixture.root, "dependency-target.js");
  fs.writeFileSync(target, "export default 2;\n");
  fs.symlinkSync(
    target,
    path.join(fixture.root, "node_modules", "example", "linked.js"),
  );
  assert.throws(
    () => packageRunningNodeSubject(fixture.entry),
    (error) => error instanceof ManagedError && error.code === "UNSUPPORTED",
  );
});

test("running subject rejects one package manifest over its byte bound", (t) => {
  const fixture = subjectFixture(t);
  fs.writeFileSync(
    path.join(fixture.root, "node_modules", "example", "package.json"),
    Buffer.alloc(1_048_577, 0x20),
  );
  assert.throws(
    () => packageRunningNodeSubject(fixture.entry),
    (error) =>
      error instanceof ManagedError && error.code === "UPLOAD_LIMIT_EXCEEDED",
  );
});

test("subject binding matches the manifest", () => {
  const subject = fixtures.sharedSubject();
  const binding = subjectBinding(subject.manifest);
  assert.equal(binding.artifact_digest, canonicalDigest(subject.manifest));
  assert.equal(binding.executable, subject.manifest.launch.executable);
  assert.equal(binding.operating_system, subject.manifest.operating_system);
});

function prepareFixture() {
  const subject = fixtures.sharedSubject();
  const world = fixtures.emptyWorld();
  const worldId = canonicalDigest(world);
  const deployment = fixtures.boundDeployment(subject);
  const candidate = fixtures.capturedCandidate(deployment, worldId);
  return { candidate, deployment, subject, world, worldId };
}

function freshClosure(world) {
  return new FrozenManagedCaptureClosure({
    artifacts: [],
    completion: "return",
    world: structuredClone(world),
  });
}

function prepared(shared) {
  return PreparedManagedCandidate.prepareComplete(
    structuredClone(shared.candidate),
    shared.subject,
    freshClosure(shared.world),
  );
}

async function sealedCandidate(shared, delivery = new fixtures.GrantDeliverySpy()) {
  const preparedCandidate = prepared(shared);
  const response = await preparedCandidate.requestEncryptionGrant(
    delivery,
    fixtures.WORKLOAD_KEY_ID,
    fixtures.WORKLOAD_SEED,
  );
  return preparedCandidate.seal(
    response,
    GRANT_VERIFICATION_TIME,
    fixtures.CAPTURE_SIGNER_ID,
    verificationKey(fixtures.CAPTURE_SIGNER_SEED),
  );
}

test("key request occurs only after exact local closure", async () => {
  const shared = prepareFixture();
  const delivery = new fixtures.GrantDeliverySpy();
  const incomplete = structuredClone(shared.candidate);
  incomplete.world_id = `sha256:${"a".repeat(64)}`;
  assert.throws(
    () =>
      PreparedManagedCandidate.prepareComplete(
        incomplete,
        shared.subject,
        freshClosure(shared.world),
      ),
    (error) =>
      error instanceof ManagedError && error.code === "INCOMPLETE_CANDIDATE",
  );
  assert.deepEqual(delivery.calls, []);

  const preparedCandidate = prepared(shared);
  await preparedCandidate.requestEncryptionGrant(
    delivery,
    fixtures.WORKLOAD_KEY_ID,
    fixtures.WORKLOAD_SEED,
  );
  assert.equal(delivery.calls.length, 1);
  assert.equal(
    delivery.calls[0].candidate_identity_digest,
    canonicalDigest(preparedCandidate.identity),
  );
  assert.equal(delivery.calls[0].processing_mode, "managed");
  assert.equal(
    delivery.calls[0].deployment_digest,
    canonicalDigest(shared.deployment),
  );
  assert.equal(delivery.calls[0].signer_key_id, fixtures.WORKLOAD_KEY_ID);
  verifySignedValue(
    delivery.calls[0],
    verificationKey(fixtures.WORKLOAD_SEED),
  );
});

test("incomplete record sequence stops before any request", () => {
  const shared = prepareFixture();
  const delivery = new fixtures.GrantDeliverySpy();
  const incomplete = structuredClone(shared.candidate);
  incomplete.records.pop();
  assert.throws(
    () =>
      PreparedManagedCandidate.prepareComplete(
        incomplete,
        shared.subject,
        freshClosure(shared.world),
      ),
    (error) =>
      error instanceof ManagedError && error.code === "INCOMPLETE_CANDIDATE",
  );
  assert.deepEqual(delivery.calls, []);
});

test("seal round trip preserves objects and keeps the key secret", async (t) => {
  const shared = prepareFixture();
  const sealed = await sealedCandidate(shared);
  t.after(() => sealed.dispose());
  for (const digest of sealed.ciphertextDigests()) {
    const stored = fs.readFileSync(sealed.ciphertextPath(digest));
    assert.equal(digestBytes(stored), digest);
  }
  const recovered = fixtures.openSealedObjectBytes(
    sealed,
    fixtures.CANDIDATE_KEY,
  );
  const identity = sealed.request.ciphertext_identity;
  const candidateObject = identity.objects.find(
    (entry) =>
      entry.descriptor.media_type === "application/vnd.reproit.candidate.v1+json",
  ).descriptor;
  assert.deepEqual(
    JSON.parse(recovered.get(candidateObject.object_id).toString("utf8")),
    shared.candidate,
  );
  const manifest = fixtures.openSealedManifest(sealed, fixtures.CANDIDATE_KEY);
  assert.equal(
    manifest.candidate_identity_digest,
    identity.candidate_identity_digest,
  );
  assert.equal(
    manifest.candidate_key_reference,
    identity.candidate_key_reference,
  );
  const requestBytes = Buffer.from(canonicalBytes(sealed.request));
  assert.equal(
    requestBytes.includes(encodeBase64url(fixtures.CANDIDATE_KEY)),
    false,
  );
  assert.throws(() =>
    fixtures.openSealedObjectBytes(sealed, Buffer.alloc(32, 0x43)),
  );
});

test("seal rejects an identity digest mismatch as a typed error", async () => {
  const shared = prepareFixture();
  const preparedCandidate = prepared(shared);
  const delivery = new fixtures.GrantDeliverySpy();
  await preparedCandidate.requestEncryptionGrant(
    delivery,
    fixtures.WORKLOAD_KEY_ID,
    fixtures.WORKLOAD_SEED,
  );
  const tamperedRequest = {
    ...delivery.calls[0],
    candidate_identity_digest: `sha256:${"9".repeat(64)}`,
  };
  const tampered = new fixtures.GrantDeliverySpy();
  const tamperedResponse = await tampered.requestEncryptionGrant(
    tamperedRequest,
    5_000,
  );
  assert.throws(
    () =>
      preparedCandidate.seal(
        tamperedResponse,
        GRANT_VERIFICATION_TIME,
        fixtures.CAPTURE_SIGNER_ID,
        verificationKey(fixtures.CAPTURE_SIGNER_SEED),
      ),
    (error) =>
      error instanceof ManagedError && error.code === "ATTESTATION_SCOPE",
  );
});

test("renewal cannot rotate the key or the key reference", async (t) => {
  const shared = prepareFixture();
  const sealed = await sealedCandidate(shared);
  t.after(() => sealed.dispose());
  const ingress = new RecordingIngress();

  const rotatedKey = new fixtures.GrantDeliverySpy({
    candidateKey: Buffer.alloc(32, 0x43),
  });
  let renewal = await sealed.requestCaptureGrantRenewal(
    rotatedKey,
    fixtures.WORKLOAD_KEY_ID,
    fixtures.WORKLOAD_SEED,
  );
  assert.throws(
    () =>
      sealed.applyRenewedCaptureGrant(
        renewal,
        GRANT_VERIFICATION_TIME,
        fixtures.CAPTURE_SIGNER_ID,
        verificationKey(fixtures.CAPTURE_SIGNER_SEED),
      ),
    (error) =>
      error instanceof ManagedError && error.code === "CAPTURE_ID_CONFLICT",
  );

  const rotatedReference = new fixtures.GrantDeliverySpy({
    keyReference: encodeBase64url(Buffer.alloc(32, 0x96)),
  });
  renewal = await sealed.requestCaptureGrantRenewal(
    rotatedReference,
    fixtures.WORKLOAD_KEY_ID,
    fixtures.WORKLOAD_SEED,
  );
  assert.throws(
    () =>
      sealed.applyRenewedCaptureGrant(
        renewal,
        GRANT_VERIFICATION_TIME,
        fixtures.CAPTURE_SIGNER_ID,
        verificationKey(fixtures.CAPTURE_SIGNER_SEED),
      ),
    (error) =>
      error instanceof ManagedError && error.code === "CAPTURE_ID_CONFLICT",
  );
  assert.deepEqual(ingress.sequence, []);
});

test("a valid renewal is accepted", async (t) => {
  const shared = prepareFixture();
  const sealed = await sealedCandidate(shared);
  t.after(() => sealed.dispose());
  const renewal = await sealed.requestCaptureGrantRenewal(
    new fixtures.GrantDeliverySpy(),
    fixtures.WORKLOAD_KEY_ID,
    fixtures.WORKLOAD_SEED,
  );
  sealed.applyRenewedCaptureGrant(
    renewal,
    GRANT_VERIFICATION_TIME,
    fixtures.CAPTURE_SIGNER_ID,
    verificationKey(fixtures.CAPTURE_SIGNER_SEED),
  );
  validateUploadRequest(sealed.request);
});

test("upload session success drives start, puts, and commit", async (t) => {
  const shared = prepareFixture();
  const sealed = await sealedCandidate(shared);
  t.after(() => sealed.dispose());
  const ingress = new RecordingIngress();
  const commit = await sealed.upload(ingress);
  assert.equal(commit.state, "CLOUD_PROTECTED");
  const expected = new Set(sealed.ciphertextDigests());
  assert.deepEqual(ingress.uploadedDigests, expected);
  assert.equal(ingress.sequence[0], "start");
  assert.equal(ingress.sequence.at(-1), "commit");
  assert.equal(
    ingress.sequence.filter((step) => step === "upload_object").length,
    expected.size,
  );
  assert.equal(ingress.sequence.includes("cancel"), false);
});

test("upload cancels on failure before and after commit", async (t) => {
  const shared = prepareFixture();
  const sealed = await sealedCandidate(shared);
  t.after(() => sealed.dispose());
  const failing = new RecordingIngress({ failObjectUploads: true });
  await assert.rejects(
    () => sealed.upload(failing),
    (error) => error instanceof ManagedError,
  );
  assert.ok(failing.sequence.includes("cancel"));
  assert.equal(failing.sequence.includes("commit"), false);

  const failingCommit = new RecordingIngress({ failCommit: true });
  await assert.rejects(
    () => sealed.upload(failingCommit),
    (error) => error instanceof ManagedError,
  );
  assert.equal(failingCommit.sequence.at(-1), "cancel");
});

// An in-memory ingress double that verifies the upload session order.
class RecordingIngress {
  constructor(options = {}) {
    this.sequence = [];
    this.expectedDigests = new Set();
    this.uploadedDigests = new Set();
    this.request = null;
    this.failObjectUploads = options.failObjectUploads ?? false;
    this.failCommit = options.failCommit ?? false;
  }

  async start(request, timeoutMs) {
    void timeoutMs;
    validateUploadRequest(request);
    this.sequence.push("start");
    this.request = structuredClone(request);
    const identity = request.ciphertext_identity;
    this.expectedDigests = new Set([identity.manifest_object.cipher_digest]);
    for (const entry of identity.objects) {
      for (const chunk of entry.chunks) {
        this.expectedDigests.add(chunk.cipher_digest);
      }
    }
    return {
      expires_at: "2026-01-01T00:01:00.000Z",
      limits: fixtures.loadCloudApiVectors().positive.managed_candidate_limits
        .value,
      missing_objects: [...this.expectedDigests].sort().map((digest) => ({
        cipher_digest: digest,
        expires_at: "2026-01-01T00:01:00.000Z",
        upload_url: `https://upload.reproit.example/${digest}`,
      })),
      next_missing_cursor: null,
      state: "OPEN",
      upload_id: fixtures.UPLOAD_ID,
      upload_token: encodeBase64url(Buffer.alloc(32, 0x93)),
    };
  }

  async missing() {
    throw new Error("one bounded page contains this fixture");
  }

  async uploadObject(uploadUrl, digest, value, timeoutMs) {
    void uploadUrl;
    void timeoutMs;
    this.sequence.push("upload_object");
    if (this.failObjectUploads) {
      throw new ManagedError("SCHEMA_INVALID", "the double rejects this object");
    }
    assert.equal(digestBytes(value), digest);
    assert.ok(this.expectedDigests.has(digest));
    this.uploadedDigests.add(digest);
  }

  async commit(uploadId, uploadToken, timeoutMs) {
    void uploadToken;
    void timeoutMs;
    this.sequence.push("commit");
    if (this.failCommit) {
      throw new ManagedError("SCHEMA_INVALID", "the double rejects this commit");
    }
    assert.deepEqual(this.expectedDigests, this.uploadedDigests);
    const identity = this.request.ciphertext_identity;
    return {
      candidate_identity_digest: identity.candidate_identity_digest,
      candidate_key_reference: identity.candidate_key_reference,
      capture_id: identity.capture_id,
      encrypted_candidate_digest: this.request.encrypted_candidate_digest,
      state: "CLOUD_PROTECTED",
      upload_id: uploadId,
    };
  }

  async cancel() {
    this.sequence.push("cancel");
    return { cancelled: true };
  }
}

test("commit timeout scales with the ciphertext size and is capped", () => {
  // Mirrors the Rust reference: a 5s floor, 4 MiB/s of verification
  // throughput, and a 180s cap.
  const rate = 4 * 1024 * 1024;
  assert.equal(commitTimeoutMs(0), COMMIT_TIMEOUT_FLOOR_MS);
  assert.equal(commitTimeoutMs(1), COMMIT_TIMEOUT_FLOOR_MS + 1_000);
  assert.equal(commitTimeoutMs(rate), COMMIT_TIMEOUT_FLOOR_MS + 1_000);
  assert.equal(commitTimeoutMs(rate + 1), COMMIT_TIMEOUT_FLOOR_MS + 2_000);
  assert.equal(commitTimeoutMs(100 * rate), 105_000);
  assert.equal(commitTimeoutMs(274_878_824_448), COMMIT_TIMEOUT_CAP_MS);
});

test("project token rules", () => {
  new ManagedProjectToken("a-valid-token");
  const controlToken = `control${String.fromCharCode(1)}`;
  for (const invalid of ["", "with space", controlToken, "x".repeat(1_025)]) {
    assert.throws(
      () => new ManagedProjectToken(invalid),
      (error) => error instanceof ManagedError,
    );
  }
});

test("endpoint requires TLS 1.3 and a valid CA", () => {
  const endpoint = new ManagedTlsEndpoint(
    "127.0.0.1",
    443,
    "managed.reproit.example",
    "managed.reproit.example",
    fixtures.testCaPath(),
  );
  assert.equal(endpoint._tls.minVersion, "TLSv1.3");
  assert.equal(endpoint._tls.maxVersion, "TLSv1.3");
  assert.equal(endpoint._tls.rejectUnauthorized, true);
  assert.equal(endpoint.origin, "https://managed.reproit.example");
});

test("endpoint rejects bad CA files", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-ca-"));
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const empty = path.join(directory, "empty.pem");
  fs.writeFileSync(empty, "");
  const garbage = path.join(directory, "garbage.pem");
  fs.writeFileSync(garbage, "not a certificate");
  const linked = path.join(directory, "linked.pem");
  fs.symlinkSync(fixtures.testCaPath(), linked);
  const absent = path.join(directory, "absent.pem");
  for (const caPath of [empty, garbage, linked, absent]) {
    assert.throws(
      () => new ManagedTlsEndpoint("127.0.0.1", 443, "example", "example", caPath),
      (error) => error instanceof ManagedError,
      caPath,
    );
  }
});

test("endpoint rejects an invalid authority", () => {
  for (const authority of [
    "",
    "bad/authority",
    "user@host",
    "with space",
    "x".repeat(513),
  ]) {
    assert.throws(
      () =>
        new ManagedTlsEndpoint(
          "127.0.0.1",
          443,
          "example",
          authority,
          fixtures.testCaPath(),
        ),
      (error) => error instanceof ManagedError,
      authority,
    );
  }
});

test("response reader rejects invalid responses", () => {
  const cases = [
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
    "HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n",
  ];
  for (const raw of cases) {
    const parser = new HttpResponseParser();
    assert.throws(
      () => {
        const response = parser.push(Buffer.from(raw, "ascii"));
        if (response === null) parser.finish();
      },
      (error) => error instanceof ManagedError,
      raw,
    );
  }
  const unterminated = new HttpResponseParser();
  assert.equal(
    unterminated.push(Buffer.from("garbage without terminator", "ascii")),
    null,
  );
  assert.throws(
    () => unterminated.finish(),
    (error) => error instanceof ManagedError && error.code === "SCHEMA_INVALID",
  );
});

test("response reader accepts a bounded body", () => {
  const parser = new HttpResponseParser();
  const response = parser.push(
    Buffer.from("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", "ascii"),
  );
  assert.equal(response.status, 204);
  assert.equal(response.body.length, 0);

  const withBody = new HttpResponseParser();
  assert.equal(
    withBody.push(Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")),
    null,
  );
  const complete = withBody.push(Buffer.from("{}"));
  assert.equal(complete.status, 200);
  assert.equal(complete.body.toString("utf8"), "{}");
});
