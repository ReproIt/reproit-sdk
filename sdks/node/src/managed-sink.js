// Bounded managed candidate sink with fail-open delivery.
//
// Mirrors crates/reproit-sdk-rust/src/managed_sink.rs: a bounded in-process
// queue, one sequential delivery worker, recall counters without customer
// values, and fail-open semantics. A managed SDK failure never changes the
// application's behavior.

import { Buffer } from "node:buffer";

import {
  MAX_GLOBAL_BYTES,
  MAX_OPERATION_BYTES,
  MAX_QUEUED_CANDIDATES,
  canonicalBytes,
} from "./index.js";
import {
  FrozenManagedCaptureClosure,
  PreparedManagedCandidate,
} from "./managed-candidate.js";
import {
  ManagedWorkloadIdentityState,
} from "./managed-identity.js";
import {
  ManagedError,
  canonicalDigest,
  decodeBase64url,
  encodeBase64url,
  isObject,
  nowTimestamp,
  requireTypedId,
  schemaInvalid,
  signBytes,
  validTimestamp,
  validTypedId,
  validateCapabilities,
  verificationKey,
  verifySignedValue,
} from "./managed-protocol.js";
import {
  managedWorkloadKeyId,
} from "./managed-transport.js";
import {
  packageRunningNodeSubject,
  subjectBinding,
} from "./managed-subject.js";
import { captureProcessorCapabilities } from "./processor-capture.js";

export const REGISTRATION_TIMEOUT_MS = 5_000;
export const CANDIDATE_DELIVERY_LIFETIME_MS = 1_000;
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

// Deliver complete managed candidates through the bounded upload session.
// Construct with the async factory: ManagedCandidateSink.create(...).
export class ManagedCandidateSink {
  #active = false;
  #client;
  #closure;
  #configuration;
  #operationId;
  #processing = false;
  #queue = [];
  #queuedBytes = 0;
  #queuedCandidates = 0;
  #recall = Object.fromEntries(RECALL_KEYS.map((key) => [key, 0]));
  #registration;
  #subject;
  #signedDeployment;
  #workloadSigningKey;
  #workloadKeyId;
  #workloadPublicKey;
  #worldId;
  // The delivery lifetime is a protocol constant. Tests may shorten it.
  _deliveryLifetimeMs = CANDIDATE_DELIVERY_LIFETIME_MS;

  constructor(
    token,
    client,
    closure,
    configuration,
    subject,
    signedDeployment,
    workloadSigningKey,
    registration,
    options,
  ) {
    if (token !== constructionToken) {
      throw new TypeError(
        "Use ManagedCandidateSink.create to construct the managed sink.",
      );
    }
    this.#client = client;
    this.#closure = closure;
    this.#configuration = {
      captureSignerId: configuration.captureSignerId,
      captureSignerPublicKey: configuration.captureSignerPublicKey,
      serviceId: configuration.serviceId,
    };
    this.#registration = registration;
    this.#subject = subject;
    this.#workloadSigningKey = workloadSigningKey;
    this.#operationId = options.operationId ?? null;
    this.#worldId = closure.worldId();
    this.#workloadPublicKey = verificationKey(workloadSigningKey);
    this.#workloadKeyId = options.workloadKeyId;
    this.#signedDeployment = structuredClone(signedDeployment);
  }

  // Validate the configuration, freeze the closure, package the running
  // subject when none is supplied, and register the signed deployment.
  static async create(client, closure, configuration, options = {}) {
    validateConfiguration(configuration);
    if (!(closure instanceof FrozenManagedCaptureClosure)) {
      closure = new FrozenManagedCaptureClosure(closure);
    }
    if (options.operationId !== undefined && options.operationId !== null) {
      requireTypedId(options.operationId, "operation_id");
    }
    const subject = options.subject ?? packageRunningNodeSubject();
    if (!isObject(options.deployment)) {
      throw schemaInvalid("The managed deployment is required.");
    }
    const deployment = options.deployment;
    prepareManagedDeployment(deployment, subject.manifest, configuration.serviceId);
    validateUnsignedDeployment(deployment);
    const bindingDigest = managedDeploymentBindingDigest(deployment);
    const workloadState = options.workloadStateRoot === undefined
      ? ManagedWorkloadIdentityState.fromEnvironment(bindingDigest)
      : new ManagedWorkloadIdentityState(options.workloadStateRoot, bindingDigest);
    const workloadSigningKey = workloadState.loadOrCreateKey();
    deployment.signed_at = workloadState.loadOrCreateDeploymentSignedAt(
      bindingDigest,
      nowTimestamp(),
    );
    const workloadPublicKey = verificationKey(workloadSigningKey);
    const publicKey = encodeBase64url(workloadPublicKey);
    const workloadKeyId = managedWorkloadKeyId(publicKey);
    deployment.signer_key_id = workloadKeyId;
    deployment.signature = "";
    deployment.signature = signBytes(
      canonicalBytes(deployment),
      workloadSigningKey,
    );
    validateDeployment(deployment);
    const registrationRequest = {
      algorithm: "Ed25519",
      deployment: structuredClone(deployment),
      public_key: publicKey,
      service_id: configuration.serviceId,
    };
    const receipt = {
      deployment_digest: canonicalDigest(deployment),
      service_id: configuration.serviceId,
      workload_key_id: workloadKeyId,
    };
    const registered = workloadState.loadRegistrationReceipt(receipt) !== null;
    return new ManagedCandidateSink(
      constructionToken,
      client,
      closure,
      configuration,
      subject,
      deployment,
      workloadSigningKey,
      {
        projectTokenProvider: projectTokenProvider(configuration),
        receipt,
        registered,
        request: registrationRequest,
        workloadState,
      },
      {
        operationId: options.operationId ?? null,
        workloadKeyId,
      },
    );
  }

  get processingModes() {
    return new Set(["managed"]);
  }

  get queuedBytes() {
    return this.#queuedBytes;
  }

  // Bounded counters that contain no customer values.
  get recallCounters() {
    return { ...this.#recall };
  }

  get subjectManifest() {
    return this.#subject.manifest;
  }

  get workloadKeyId() {
    return this.#workloadKeyId;
  }

  get workloadPublicKey() {
    return this.#workloadPublicKey;
  }

  get worldId() {
    return this.#worldId;
  }

  // Bind the deployment to this subject and sign it as this workload.
  bindDeployment(deployment) {
    prepareManagedDeployment(
      deployment,
      this.#subject.manifest,
      this.#configuration.serviceId,
    );
    if (
      managedDeploymentBindingDigest(deployment) !==
      managedDeploymentBindingDigest(this.#signedDeployment)
    ) {
      throw new ManagedError(
        "AUTHORIZATION_DENIED",
        "The managed deployment does not match the registered deployment.",
      );
    }
    for (const key of Object.keys(deployment)) delete deployment[key];
    Object.assign(deployment, structuredClone(this.#signedDeployment));
  }

  async waitUntilIdle(timeoutMs) {
    const deadline = performance.now() + timeoutMs;
    while (this.#active || this.#queuedCandidates !== 0) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) {
        return false;
      }
      await new Promise((resolve) =>
        setTimeout(resolve, Math.min(10, Math.max(1, remaining))),
      );
    }
    return true;
  }

  // Queue one complete candidate. Never throw into the application.
  trySend(captureId, candidate) {
    let value;
    try {
      value = this.#authorizedCandidate(captureId, candidate);
    } catch {
      this.#increment("candidate_incomplete");
      return false;
    }
    if (
      this.#queuedCandidates >= MAX_QUEUED_CANDIDATES ||
      this.#queuedBytes + candidate.length > MAX_GLOBAL_BYTES
    ) {
      this.#increment("candidate_queue_full");
      return false;
    }
    this.#queue.push({
      enqueued: performance.now(),
      size: candidate.length,
      value,
    });
    this.#queuedBytes += candidate.length;
    this.#queuedCandidates += 1;
    queueMicrotask(() => this.#work());
    return true;
  }

  #authorizedCandidate(captureId, candidate) {
    const bytes = Buffer.from(candidate);
    if (bytes.length > MAX_OPERATION_BYTES) {
      throw schemaInvalid();
    }
    const value = JSON.parse(bytes.toString("utf8"));
    if (
      !isObject(value) ||
      !Buffer.from(canonicalBytes(value)).equals(bytes) ||
      value.capture_id !== captureId ||
      value.processing_mode !== "managed"
    ) {
      throw schemaInvalid();
    }
    const deployment = value.deployment;
    if (
      !isObject(deployment) ||
      deployment.processing_mode !== "managed" ||
      deployment.service_id !== this.#configuration.serviceId ||
      deployment.signer_key_id !== this.#workloadKeyId ||
      (this.#operationId !== null &&
        value.operation_id !== this.#operationId)
    ) {
      throw new ManagedError(
        "AUTHORIZATION_DENIED",
        "The managed deployment does not use the registered workload key.",
      );
    }
    verifySignedValue(deployment, this.#workloadPublicKey);
    return value;
  }

  async #work() {
    if (this.#processing) return;
    this.#processing = true;
    try {
      while (this.#queue.length > 0) {
        const candidate = this.#queue.shift();
        try {
          if (
            performance.now() - candidate.enqueued >=
            this._deliveryLifetimeMs
          ) {
            this.#increment("candidate_delivery_expired");
            continue;
          }
          this.#active = true;
          try {
            await this.#deliver(candidate.value);
            this.#increment("candidate_durably_accepted");
          } catch (error) {
            if (error instanceof ManagedError) {
              this.#recordFailure(error);
            } else {
              this.#increment("candidate_rejected");
            }
          }
        } finally {
          this.#active = false;
          this.#queuedBytes = Math.max(0, this.#queuedBytes - candidate.size);
          this.#queuedCandidates = Math.max(0, this.#queuedCandidates - 1);
        }
      }
    } finally {
      this.#processing = false;
    }
  }

  async #deliver(candidate) {
    const configuration = this.#configuration;
    const prepared = PreparedManagedCandidate.prepareComplete(
      candidate,
      this.#subject,
      this.#closure,
    );
    await this.#ensureRegistered();
    const grant = await prepared.requestEncryptionGrant(
      this.#client,
      this.#workloadKeyId,
      this.#workloadSigningKey,
    );
    const sealed = prepared.seal(
      grant,
      nowTimestamp(),
      configuration.captureSignerId,
      configuration.captureSignerPublicKey,
    );
    try {
      const renewal = await sealed.requestCaptureGrantRenewal(
        this.#client,
        this.#workloadKeyId,
        this.#workloadSigningKey,
      );
      sealed.applyRenewedCaptureGrant(
        renewal,
        nowTimestamp(),
        configuration.captureSignerId,
        configuration.captureSignerPublicKey,
      );
      await sealed.upload(this.#client);
    } finally {
      sealed.dispose();
    }
  }

  async #ensureRegistered() {
    if (this.#registration.registered) return;
    if (this.#registration.projectTokenProvider === null) {
      throw registrationTokenRequired();
    }
    const projectToken = await this.#registration.projectTokenProvider();
    const registration = await this.#client.registerWorkloadKey(
      projectToken,
      this.#registration.request,
      REGISTRATION_TIMEOUT_MS,
    );
    const receipt = this.#registration.receipt;
    if (
      registration.key_id !== receipt.workload_key_id ||
      registration.deployment_digest !== receipt.deployment_digest ||
      registration.service_id !== receipt.service_id
    ) {
      throw new ManagedError(
        "ATTESTATION_SCOPE",
        "The managed workload registration does not match this deployment.",
      );
    }
    this.#registration.workloadState.persistRegistrationReceipt(receipt);
    this.#registration.registered = true;
    this.#registration.projectTokenProvider = null;
  }

  #recordFailure(error) {
    if (error.code === "INCOMPLETE_CANDIDATE") {
      this.#increment("candidate_incomplete");
    } else if (error.retryable) {
      this.#increment("candidate_delivery_expired");
    } else {
      this.#increment("candidate_rejected");
    }
  }

  #increment(key) {
    this.#recall[key] = Math.min(COUNTER_MAXIMUM, this.#recall[key] + 1);
  }
}

const constructionToken = Symbol("reproit-managed-sink-construction");

function validateConfiguration(configuration) {
  if (
    !isObject(configuration) ||
    typeof configuration.captureSignerId !== "string" ||
    configuration.captureSignerId.length === 0 ||
    configuration.captureSignerId.length > 256 ||
    !(configuration.captureSignerPublicKey instanceof Uint8Array) ||
    configuration.captureSignerPublicKey.length !== 32
  ) {
    throw schemaInvalid();
  }
  requireTypedId(configuration.serviceId, "service_id");
}

function projectTokenProvider(configuration) {
  if (typeof configuration.projectTokenProvider === "function") {
    return configuration.projectTokenProvider;
  }
  if (configuration.projectToken !== null && configuration.projectToken !== undefined) {
    return () => configuration.projectToken;
  }
  return null;
}

function validateUnsignedDeployment(deployment) {
  const repositoryId = deployment.repository_id;
  const runtimeEndpoint = deployment.runtime_endpoint;
  const servicePath = deployment.service_path;
  const sourceRevision = deployment.source_revision;
  if (
    deployment.format !== "reproit.deployment.v1" ||
    deployment.processing_mode !== "managed" ||
    !validTypedId(deployment.organization_id, "organization_id") ||
    !validTypedId(deployment.project_id, "project_id") ||
    !validTypedId(deployment.service_id, "service_id") ||
    typeof repositoryId !== "string" ||
    repositoryId.length < 1 ||
    repositoryId.length > 256 ||
    typeof runtimeEndpoint !== "string" ||
    runtimeEndpoint.length < 1 ||
    runtimeEndpoint.length > 2_048 ||
    typeof servicePath !== "string" ||
    servicePath.startsWith("/") ||
    servicePath.split("/").some((part) => part === "..") ||
    typeof sourceRevision !== "string" ||
    sourceRevision.length < 1 ||
    sourceRevision.length > 256
  ) {
    throw schemaInvalid();
  }
  validateCapabilities(deployment.runtime_capabilities);
}

function prepareManagedDeployment(deployment, manifest, serviceId) {
  if (deployment.service_id !== serviceId) {
    throw new ManagedError(
      "AUTHORIZATION_DENIED",
      "The managed deployment belongs to a different service.",
    );
  }
  deployment.processing_mode = "managed";
  deployment.subject = subjectBinding(manifest);
  const capabilities = [...(deployment.runtime_capabilities ?? [])];
  capabilities.push(manifest.architecture, manifest.operating_system);
  // The candidate includes the process-visible processor requirements.
  capabilities.push(...captureProcessorCapabilities());
  deployment.runtime_capabilities = [...new Set(capabilities)].sort();
  deployment.signer_key_id = "";
  deployment.signature = "";
}

export function managedDeploymentBindingDigest(deployment) {
  const binding = {
    format: deployment.format,
    organization_id: deployment.organization_id,
    processing_mode: deployment.processing_mode,
    project_id: deployment.project_id,
    repository_id: deployment.repository_id,
    runtime_capabilities: deployment.runtime_capabilities,
    runtime_endpoint: deployment.runtime_endpoint,
    service_id: deployment.service_id,
    service_path: deployment.service_path,
    source_revision: deployment.source_revision,
    subject: deployment.subject,
  };
  return canonicalDigest(binding);
}

function registrationTokenRequired() {
  return new ManagedError(
    "AUTHENTICATION_REQUIRED",
    "The managed project token is required for first registration.",
  );
}

// Mirror the reproit-core Deployment::validate checks the SDK can prove.
function validateDeployment(deployment) {
  validateUnsignedDeployment(deployment);
  const repositoryId = deployment.repository_id;
  const runtimeEndpoint = deployment.runtime_endpoint;
  const servicePath = deployment.service_path;
  const signerKeyId = deployment.signer_key_id;
  const sourceRevision = deployment.source_revision;
  if (
    deployment.format !== "reproit.deployment.v1" ||
    typeof repositoryId !== "string" ||
    repositoryId.length < 1 ||
    repositoryId.length > 256 ||
    typeof runtimeEndpoint !== "string" ||
    runtimeEndpoint.length < 1 ||
    runtimeEndpoint.length > 2_048 ||
    typeof servicePath !== "string" ||
    servicePath.length === 0 ||
    servicePath.startsWith("/") ||
    servicePath.split("/").some((part) => part === "..") ||
    typeof signerKeyId !== "string" ||
    signerKeyId.length < 1 ||
    signerKeyId.length > 256 ||
    typeof sourceRevision !== "string" ||
    sourceRevision.length < 1 ||
    sourceRevision.length > 256 ||
    !validTimestamp(deployment.signed_at)
  ) {
    throw schemaInvalid();
  }
  validateCapabilities(deployment.runtime_capabilities);
  decodeBase64url(deployment.signature, 64);
}
