// End-to-end managed session tests over a loopback node:http double that
// validates the exact request sequence and bodies through CLOUD_PROTECTED.
// Mirrors sdks/python/tests/test_managed_session.py.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import * as fixtures from "./managed-fixtures.js";
import { Sdk, canonicalBytes } from "../src/index.js";
import {
  ManagedError,
  canonicalDigest,
  decodeBase64url,
  encodeBase64url,
  validateUploadRequest,
  verificationKey,
  verifySignedValue,
} from "../src/managed-protocol.js";
import { ManagedCandidateSink } from "../src/managed-sink.js";
import {
  ManagedProjectToken,
  ManagedTlsClient,
  ManagedTlsEndpoint,
  managedWorkloadKeyId,
  validateGrantRequest,
  validateWorkloadKeyRegistration,
} from "../src/managed-transport.js";

const PROJECT_TOKEN = "test-project-token";
const UPLOAD_TOKEN = "managed-upload-token-1";

function timestamp(offsetMs) {
  return new Date(Date.now() + offsetMs).toISOString();
}

// A loopback endpoint that skips TLS. Unit-test double only.
class PlainHttpEndpoint extends ManagedTlsEndpoint {
  #plainHost;
  #plainPort;

  constructor(host, port, authority) {
    super(host, port, "loopback", authority, fixtures.testCaPath());
    this.#plainHost = host;
    this.#plainPort = port;
  }

  _connect(timeoutMs) {
    void timeoutMs;
    return {
      connection: net.createConnection({
        host: this.#plainHost,
        port: this.#plainPort,
      }),
      readyEvent: "connect",
    };
  }
}

// One loopback HTTP double for the key service and managed ingress.
class LoopbackManagedService {
  constructor() {
    this.state = {
      expected: new Set(),
      authorizations: [],
      grantFailureStatus: null,
      grantRequests: [],
      issuedGrants: [],
      limits: fixtures.loadCloudApiVectors().positive.managed_candidate_limits
        .value,
      registeredPublicKey: null,
      registeredDeployment: null,
      requests: [],
      uploadRequest: null,
      uploaded: new Set(),
    };
    this.server = http.createServer((request, response) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        this.#route(request, Buffer.concat(chunks), response);
      });
    });
  }

  async listen() {
    await new Promise((resolve) =>
      this.server.listen(0, "127.0.0.1", resolve),
    );
    const address = this.server.address();
    this.authority = `${address.address}:${address.port}`;
    this.endpoint = new PlainHttpEndpoint(
      address.address,
      address.port,
      this.authority,
    );
    this.client = new ManagedTlsClient(this.endpoint, this.endpoint);
  }

  async close() {
    await new Promise((resolve) => this.server.close(resolve));
  }

  #reply(response, status, value) {
    const body = value !== undefined ? Buffer.from(canonicalBytes(value)) : null;
    const headers = { "Content-Length": body === null ? 0 : body.length };
    if (body !== null) {
      headers["Content-Type"] = "application/json";
    }
    response.writeHead(status, headers);
    response.end(body ?? undefined);
  }

  #reject(response, status, code, message) {
    this.#reply(response, status, {
      code,
      message,
      retryable: [429, 503].includes(status),
    });
  }

  #route(request, body, response) {
    const url = new URL(request.url, `http://${this.authority}`);
    const routePath = url.pathname;
    this.state.requests.push([request.method, routePath]);
    this.state.authorizations.push(request.headers.authorization ?? null);
    if (request.method === "POST" && routePath === "/v1/workload-keys") {
      return this.#registerWorkloadKey(request, body, response);
    }
    if (
      request.method === "POST" &&
      routePath === "/v1/managed-candidate-encryption-grants"
    ) {
      return this.#issueGrant(request, body, response);
    }
    if (request.method === "POST" && routePath === "/v1/managed-candidates") {
      return this.#startUpload(body, response);
    }
    if (
      request.method === "POST" &&
      routePath === `/v1/managed-candidates/${fixtures.UPLOAD_ID}/commit`
    ) {
      return this.#commit(request, response);
    }
    if (request.method === "PUT") {
      return this.#putObject(url, body, response);
    }
    if (
      request.method === "DELETE" &&
      routePath === `/v1/managed-candidates/${fixtures.UPLOAD_ID}`
    ) {
      return this.#cancel(response);
    }
    return this.#reject(response, 404, "NOT_FOUND", "Unknown route.");
  }

  #authorized(request, expected) {
    return request.headers.authorization === expected;
  }

  #registerWorkloadKey(request, body, response) {
    if (!this.#authorized(request, `Bearer ${PROJECT_TOKEN}`)) {
      return this.#reject(
        response,
        401,
        "AUTHENTICATION_REQUIRED",
        "Missing project token.",
      );
    }
    const value = JSON.parse(body.toString("utf8"));
    try {
      validateWorkloadKeyRegistration(value);
    } catch {
      return this.#reject(response, 400, "SCHEMA_INVALID", "Invalid registration.");
    }
    this.state.registeredPublicKey = value.public_key;
    this.state.registeredDeployment = value.deployment;
    this.#reply(response, 200, {
      deployment_digest: canonicalDigest(value.deployment),
      key_id: managedWorkloadKeyId(value.public_key),
      service_id: fixtures.SERVICE_ID,
    });
  }

  #issueGrant(request, body, response) {
    if (request.headers.authorization !== undefined) {
      return this.#reject(response, 401, "AUTHENTICATION_REQUIRED", "Unexpected token.");
    }
    if (this.state.grantFailureStatus !== null) {
      return this.#reject(
        response,
        this.state.grantFailureStatus,
        "SERVICE_UNAVAILABLE",
        "Grant unavailable.",
      );
    }
    const grantRequest = JSON.parse(body.toString("utf8"));
    try {
      validateGrantRequest(grantRequest);
      verifySignedValue(
        grantRequest,
        decodeBase64url(this.state.registeredPublicKey, 32),
      );
      if (
        grantRequest.deployment_digest !==
          canonicalDigest(this.state.registeredDeployment) ||
        grantRequest.signer_key_id !==
          this.state.registeredDeployment.signer_key_id
      ) {
        throw new Error("registration mismatch");
      }
    } catch {
      return this.#reject(response, 400, "SCHEMA_INVALID", "Invalid grant request.");
    }
    this.state.grantRequests.push(grantRequest);
    const grant = fixtures.signedCaptureGrant(grantRequest, {
      expiresAt: timestamp(5 * 60_000),
      notBefore: timestamp(-5 * 60_000),
    });
    this.state.issuedGrants.push(grant);
    this.#reply(response, 200, {
      candidate_key: encodeBase64url(fixtures.CANDIDATE_KEY),
      capture_grant: grant,
    });
  }

  #startUpload(body, response) {
    const uploadRequest = JSON.parse(body.toString("utf8"));
    try {
      validateUploadRequest(uploadRequest);
    } catch {
      return this.#reject(response, 400, "SCHEMA_INVALID", "Invalid upload request.");
    }
    const issued = this.state.issuedGrants.map((grant) =>
      Buffer.from(canonicalBytes(grant)).toString("hex"),
    );
    const presented = Buffer.from(
      canonicalBytes(uploadRequest.capture_grant),
    ).toString("hex");
    if (!issued.includes(presented)) {
      return this.#reject(response, 403, "ATTESTATION_SCOPE", "Unknown capture grant.");
    }
    this.state.uploadRequest = uploadRequest;
    const identity = uploadRequest.ciphertext_identity;
    const expected = new Set([identity.manifest_object.cipher_digest]);
    for (const entry of identity.objects) {
      for (const chunk of entry.chunks) {
        expected.add(chunk.cipher_digest);
      }
    }
    this.state.expected = expected;
    this.state.uploaded = new Set();
    const origin = `https://${this.authority}`;
    this.#reply(response, 200, {
      expires_at: timestamp(60_000),
      limits: this.state.limits,
      missing_objects: [...expected].sort().map((digest) => ({
        cipher_digest: digest,
        expires_at: timestamp(60_000),
        upload_url:
          `${origin}/v1/managed-candidates/${fixtures.UPLOAD_ID}` +
          `/objects/${digest}?token=up`,
      })),
      next_missing_cursor: null,
      state: "OPEN",
      upload_id: fixtures.UPLOAD_ID,
      upload_token: UPLOAD_TOKEN,
    });
  }

  #putObject(url, body, response) {
    const prefix = `/v1/managed-candidates/${fixtures.UPLOAD_ID}/objects/`;
    if (!url.pathname.startsWith(prefix) || url.search !== "?token=up") {
      return this.#reject(response, 404, "NOT_FOUND", "Unknown object route.");
    }
    const digest = url.pathname.slice(prefix.length);
    const actual = `sha256:${createHash("sha256").update(body).digest("hex")}`;
    if (!this.state.expected.has(digest) || actual !== digest) {
      return this.#reject(
        response,
        400,
        "OBJECT_DIGEST_MISMATCH",
        "Digest mismatch.",
      );
    }
    this.state.uploaded.add(digest);
    this.#reply(response, 204);
  }

  #commit(request, response) {
    if (!this.#authorized(request, `Bearer ${UPLOAD_TOKEN}`)) {
      return this.#reject(
        response,
        401,
        "AUTHENTICATION_REQUIRED",
        "Missing upload token.",
      );
    }
    if (
      this.state.expected.size !== this.state.uploaded.size ||
      [...this.state.expected].some(
        (digest) => !this.state.uploaded.has(digest),
      )
    ) {
      return this.#reject(response, 409, "UPLOAD_INCOMPLETE", "Objects are missing.");
    }
    const uploadRequest = this.state.uploadRequest;
    const identity = uploadRequest.ciphertext_identity;
    this.#reply(response, 200, {
      candidate_identity_digest: identity.candidate_identity_digest,
      candidate_key_reference: identity.candidate_key_reference,
      capture_id: identity.capture_id,
      encrypted_candidate_digest: uploadRequest.encrypted_candidate_digest,
      state: "CLOUD_PROTECTED",
      upload_id: fixtures.UPLOAD_ID,
    });
  }

  #cancel(response) {
    const uploadRequest = this.state.uploadRequest;
    if (uploadRequest === null) {
      return this.#reject(response, 404, "NOT_FOUND", "Unknown upload.");
    }
    const identity = uploadRequest.ciphertext_identity;
    this.#reply(response, 200, {
      candidate_identity_digest: identity.candidate_identity_digest,
      candidate_key_reference: identity.candidate_key_reference,
      capture_id: identity.capture_id,
      encrypted_candidate_digest: uploadRequest.encrypted_candidate_digest,
      expires_at: null,
      missing_digests: [],
      state: "CANCELLED",
      upload_id: fixtures.UPLOAD_ID,
    });
  }
}

function sinkConfiguration() {
  return {
    captureSignerId: fixtures.CAPTURE_SIGNER_ID,
    captureSignerPublicKey: verificationKey(fixtures.CAPTURE_SIGNER_SEED),
    projectToken: new ManagedProjectToken(PROJECT_TOKEN),
    serviceId: fixtures.SERVICE_ID,
  };
}

function unsignedDeployment() {
  return {
    format: "reproit.deployment.v1",
    organization_id: fixtures.ORGANIZATION_ID,
    processing_mode: "managed",
    project_id: fixtures.PROJECT_ID,
    repository_id: "source.example/acme/commerce",
    runtime_capabilities: ["runtime.node"],
    runtime_endpoint: "https://managed.reproit.example",
    service_id: fixtures.SERVICE_ID,
    service_path: "services/orders",
    signature: "",
    signed_at: "2026-01-01T00:00:00.000Z",
    signer_key_id: "",
    source_revision: "0123456789abcdef",
    subject: {},
  };
}

async function loopbackSink(t, configuration = sinkConfiguration()) {
  const service = new LoopbackManagedService();
  await service.listen();
  t.after(() => service.close());
  const subject = fixtures.sharedSubject();
  const world = fixtures.emptyWorld();
  const stateRoot = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-state-")),
  );
  fs.chmodSync(stateRoot, 0o700);
  t.after(() => fs.rmSync(stateRoot, { force: true, recursive: true }));
  const deployment = unsignedDeployment();
  const sink = await ManagedCandidateSink.create(
    service.client,
    { artifacts: [], completion: "return", world: structuredClone(world) },
    configuration,
    { deployment, subject, workloadStateRoot: stateRoot },
  );
  return { deployment, service, sink, subject, stateRoot, world };
}

function boundDeployment(sink) {
  const deployment = unsignedDeployment();
  sink.bindDeployment(deployment);
  return deployment;
}

function captureFailure(sink, deployment, worldId) {
  const vectors = fixtures.loadProtocolVectors().positive;
  const sdk = new Sdk(sink);
  const start = {
    captureId: fixtures.CAPTURE_ID,
    deployment,
    operationId: fixtures.OPERATION_ID,
    worldId,
  };
  sdk.begin(start, structuredClone(vectors.operation_begin_payload.value));
  sdk.recordInput(
    fixtures.OPERATION_ID,
    structuredClone(vectors.operation_input_payload.value),
  );
  sdk.fail(
    fixtures.OPERATION_ID,
    structuredClone(vectors.failure_payload.value),
  );
}

test("first complete failure registers the signed deployment", async (t) => {
  const { deployment, service, sink } = await loopbackSink(t);
  captureFailure(sink, deployment, sink.worldId);
  assert.ok(await sink.waitUntilIdle(10_000));
  assert.equal(
    sink.workloadKeyId,
    managedWorkloadKeyId(encodeBase64url(sink.workloadPublicKey)),
  );
  assert.equal(
    service.state.requests.filter(
      (entry) => entry[0] === "POST" && entry[1] === "/v1/workload-keys",
    ).length,
    1,
  );
  assert.equal(
    service.state.registeredPublicKey,
    encodeBase64url(sink.workloadPublicKey),
  );
  assert.equal(service.state.authorizations[0], `Bearer ${PROJECT_TOKEN}`);
  assert.equal(service.state.authorizations[1], null);
});

test("restart reuses the protected registration without a project token", async (t) => {
  const first = await loopbackSink(t);
  captureFailure(first.sink, first.deployment, first.sink.worldId);
  assert.ok(await first.sink.waitUntilIdle(10_000));
  const requestCount = first.service.state.requests.length;
  const restartedDeployment = unsignedDeployment();
  const restarted = await ManagedCandidateSink.create(
    first.service.client,
    {
      artifacts: [],
      completion: "return",
      world: structuredClone(first.world),
    },
    { ...sinkConfiguration(), projectToken: null },
    {
      deployment: restartedDeployment,
      subject: first.subject,
      workloadStateRoot: first.stateRoot,
    },
  );
  assert.equal(restarted.workloadKeyId, first.sink.workloadKeyId);
  assert.equal(restartedDeployment.signed_at, first.deployment.signed_at);
  assert.equal(restartedDeployment.signature, first.deployment.signature);
  assert.equal(first.service.state.requests.length, requestCount);
});

test("complete candidate reaches CLOUD_PROTECTED with the exact sequence", async (t) => {
  const { service, sink } = await loopbackSink(t);
  const deployment = boundDeployment(sink);
  captureFailure(sink, deployment, sink.worldId);
  assert.ok(await sink.waitUntilIdle(10_000));
  const counters = sink.recallCounters;
  assert.equal(
    counters.candidate_durably_accepted,
    1,
    JSON.stringify({ counters, requests: service.state.requests }),
  );
  assert.equal(counters.candidate_incomplete, 0);
  assert.equal(counters.candidate_rejected, 0);
  assert.equal(sink.queuedBytes, 0);

  const requests = service.state.requests;
  assert.deepEqual(requests[0], ["POST", "/v1/workload-keys"]);
  assert.deepEqual(requests[1], [
    "POST",
    "/v1/managed-candidate-encryption-grants",
  ]);
  assert.deepEqual(requests[2], [
    "POST",
    "/v1/managed-candidate-encryption-grants",
  ]);
  assert.deepEqual(requests[3], ["POST", "/v1/managed-candidates"]);
  const objectPuts = requests.filter((entry) => entry[0] === "PUT");
  assert.equal(objectPuts.length, service.state.expected.size);
  assert.deepEqual(requests.at(-1), [
    "POST",
    `/v1/managed-candidates/${fixtures.UPLOAD_ID}/commit`,
  ]);
  assert.deepEqual(service.state.expected, service.state.uploaded);

  const grantRequests = service.state.grantRequests;
  assert.equal(grantRequests.length, 2);
  assert.deepEqual(grantRequests[0], grantRequests[1]);
  assert.equal(service.state.authorizations[1], null);
  assert.equal(service.state.authorizations[2], null);
  assert.equal(grantRequests[0].signer_key_id, sink.workloadKeyId);
  verifySignedValue(grantRequests[0], sink.workloadPublicKey);
  const uploadRequest = service.state.uploadRequest;
  assert.equal(
    grantRequests[0].candidate_identity_digest,
    uploadRequest.ciphertext_identity.candidate_identity_digest,
  );
});

test("successful operation makes no capture request", async (t) => {
  let tokenRequests = 0;
  const configuration = {
    ...sinkConfiguration(),
    projectToken: undefined,
    projectTokenProvider() {
      tokenRequests += 1;
      return new ManagedProjectToken(PROJECT_TOKEN);
    },
  };
  const { service, sink } = await loopbackSink(t, configuration);
  const deployment = boundDeployment(sink);
  const vectors = fixtures.loadProtocolVectors().positive;
  const sdk = new Sdk(sink);
  sdk.begin(
    {
      captureId: fixtures.CAPTURE_ID,
      deployment,
      operationId: fixtures.OPERATION_ID,
      worldId: sink.worldId,
    },
    structuredClone(vectors.operation_begin_payload.value),
  );
  sdk.recordInput(
    fixtures.OPERATION_ID,
    structuredClone(vectors.operation_input_payload.value),
  );
  sdk.succeed(fixtures.OPERATION_ID);
  assert.ok(await sink.waitUntilIdle(1_000));
  assert.deepEqual(service.state.requests, []);
  assert.equal(tokenRequests, 0);
});

test("incomplete candidate stops locally with a counter", async (t) => {
  let tokenRequests = 0;
  const configuration = {
    ...sinkConfiguration(),
    projectToken: undefined,
    projectTokenProvider() {
      tokenRequests += 1;
      return new ManagedProjectToken(PROJECT_TOKEN);
    },
  };
  const { service, sink } = await loopbackSink(t, configuration);
  const deployment = boundDeployment(sink);
  const vectors = fixtures.loadProtocolVectors().positive;
  const sdk = new Sdk(sink);
  const start = {
    captureId: "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
    deployment,
    operationId: "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4",
    worldId: `sha256:${"a".repeat(64)}`,
  };
  sdk.begin(start, structuredClone(vectors.operation_begin_payload.value));
  sdk.recordInput(
    start.operationId,
    structuredClone(vectors.operation_input_payload.value),
  );
  sdk.fail(start.operationId, structuredClone(vectors.failure_payload.value));
  assert.ok(await sink.waitUntilIdle(10_000));
  const counters = sink.recallCounters;
  assert.equal(counters.candidate_incomplete, 1);
  assert.equal(counters.candidate_durably_accepted, 0);
  assert.deepEqual(service.state.requests, []);
  assert.equal(tokenRequests, 0);
});

test("non-canonical candidate is refused without enqueue", async (t) => {
  const { sink } = await loopbackSink(t);
  const deployment = boundDeployment(sink);
  const candidate = fixtures.capturedCandidate(deployment, sink.worldId);
  const raw = Buffer.concat([
    Buffer.from(canonicalBytes(candidate)),
    Buffer.from(" "),
  ]);
  assert.equal(sink.trySend(fixtures.CAPTURE_ID, raw), false);
  assert.equal(sink.recallCounters.candidate_incomplete, 1);
});

test("foreign workload signature is refused", async (t) => {
  const { sink, subject } = await loopbackSink(t);
  const deployment = fixtures.boundDeployment(
    subject,
    Buffer.alloc(32, 0x55),
    fixtures.WORKLOAD_KEY_ID,
  );
  const candidate = fixtures.capturedCandidate(deployment, sink.worldId);
  assert.equal(
    sink.trySend(fixtures.CAPTURE_ID, canonicalBytes(candidate)),
    false,
  );
  assert.equal(sink.recallCounters.candidate_incomplete, 1);
});

test("grant outage is fail open and counted as retryable", async (t) => {
  const { service, sink } = await loopbackSink(t);
  service.state.grantFailureStatus = 503;
  const deployment = boundDeployment(sink);
  captureFailure(sink, deployment, sink.worldId);
  assert.ok(await sink.waitUntilIdle(10_000));
  const counters = sink.recallCounters;
  assert.equal(counters.candidate_durably_accepted, 0);
  assert.equal(counters.candidate_delivery_expired, 1);
  assert.equal(
    service.state.requests.some(
      (entry) => entry[0] === "POST" && entry[1] === "/v1/managed-candidates",
    ),
    false,
  );
});

// A client double that registers and then refuses grant delivery once a
// release gate opens. Mirrors the Python _StubRegistrationClient.
class StubRegistrationClient {
  constructor() {
    this.grantCalls = 0;
    this.released = false;
    this.waiters = [];
  }

  release() {
    this.released = true;
    for (const waiter of this.waiters) waiter();
    this.waiters = [];
  }

  async registerWorkloadKey(projectToken, request, timeoutMs) {
    void projectToken;
    void timeoutMs;
    return {
      deployment_digest: canonicalDigest(request.deployment),
      key_id: managedWorkloadKeyId(request.public_key),
      service_id: request.service_id,
    };
  }

  async requestEncryptionGrant(request, timeoutMs) {
    void request;
    void timeoutMs;
    this.grantCalls += 1;
    if (!this.released) {
      await new Promise((resolve) => this.waiters.push(resolve));
    }
    throw new ManagedError("SCHEMA_INVALID", "The double refuses grants.");
  }
}

async function stubSink(t, client) {
  const stateRoot = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-state-")),
  );
  fs.chmodSync(stateRoot, 0o700);
  t.after(() => fs.rmSync(stateRoot, { force: true, recursive: true }));
  return ManagedCandidateSink.create(
    client,
    {
      artifacts: [],
      completion: "return",
      world: fixtures.emptyWorld(),
    },
    sinkConfiguration(),
    {
      deployment: unsignedDeployment(),
      subject: fixtures.sharedSubject(),
      workloadStateRoot: stateRoot,
    },
  );
}

test("queue bound counts queue full and stays fail open", async (t) => {
  const client = new StubRegistrationClient();
  const sink = await stubSink(t, client);
  const subject = fixtures.sharedSubject();
  const deployment = unsignedDeployment();
  sink.bindDeployment(deployment);
  const candidate = fixtures.capturedCandidate(deployment, sink.worldId);
  const raw = canonicalBytes(candidate);
  let accepted = 0;
  for (let index = 0; index < 17; index += 1) {
    if (sink.trySend(fixtures.CAPTURE_ID, raw)) accepted += 1;
  }
  assert.equal(accepted, 16);
  assert.equal(sink.recallCounters.candidate_queue_full, 1);
  client.release();
  assert.ok(await sink.waitUntilIdle(20_000));
  const counters = sink.recallCounters;
  const terminal =
    counters.candidate_rejected +
    counters.candidate_delivery_expired +
    counters.candidate_incomplete +
    counters.candidate_durably_accepted;
  assert.equal(terminal, 16);
  assert.equal(counters.candidate_durably_accepted, 0);
  assert.equal(sink.queuedBytes, 0);
});

test("processing modes are managed only", async (t) => {
  const sink = await stubSink(t, new StubRegistrationClient());
  assert.ok(sink.processingModes instanceof Set);
  assert.deepEqual([...sink.processingModes], ["managed"]);
});

test("expired queue entries are counted, not delivered", async (t) => {
  const client = new StubRegistrationClient();
  client.release();
  const sink = await stubSink(t, client);
  const deployment = unsignedDeployment();
  sink.bindDeployment(deployment);
  const candidate = fixtures.capturedCandidate(deployment, sink.worldId);
  sink._deliveryLifetimeMs = 0;
  assert.ok(sink.trySend(fixtures.CAPTURE_ID, canonicalBytes(candidate)));
  assert.ok(await sink.waitUntilIdle(5_000));
  assert.equal(sink.recallCounters.candidate_delivery_expired, 1);
  assert.equal(client.grantCalls, 0);
});
