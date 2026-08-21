// Immutable managed release bindings for the official Node.js SDK entry.

import {
  ManagedError,
  decodeBase64url,
} from "./managed-protocol.js";
import { randomBytes } from "node:crypto";
import { ManagedCandidateSink } from "./managed-sink.js";
import { ManagedTlsClient, ManagedTlsEndpoint } from "./managed-transport.js";

const OFFICIAL_MANAGED_HTTPS_ORIGIN =
  "__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__";
const OFFICIAL_CAPTURE_GRANT_SIGNER_ID =
  "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_ID_SENTINEL__";
const OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY =
  "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY_SENTINEL__";

const FIXTURE_CAPTURE_SIGNER_PUBLIC_KEYS = new Set([
  "1238bj1eePRsVOlCHJedzcDZ0DmBthqGWrICsYCNzpA",
  "Pm6nrLpZVoxfNqy0GBb7FqsrJ6sTq9OLCSTKJpGtZZk",
  "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI",
  "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY",
  "p_bfr484uJuozmSbWU-R5NAf3Ff5yUk99DteUKmYc2c",
]);

export class OfficialManagedProject {
  #project;
  #sourceRevision;

  constructor(project, buildRepositoryId, sourceRevision) {
    officialManagedConfiguration();
    validateProject(project, buildRepositoryId, sourceRevision);
    this.#project = structuredClone(project);
    this.#sourceRevision = sourceRevision;
  }

  startOperation(worldId) {
    if (typeof worldId !== "string" || !worldId.startsWith("sha256:")) {
      throw projectBindingInvalid();
    }
    return new OfficialManagedOperation(
      newIdentifier("cap_"),
      newIdentifier("op_"),
      worldId,
      deployment(this.#project, this.#sourceRevision),
    );
  }
}

export class OfficialManagedOperation {
  #deployment;

  constructor(captureId, operationId, worldId, value) {
    this.captureId = captureId;
    this.operationId = operationId;
    this.worldId = worldId;
    this.#deployment = value;
  }

  get deployment() {
    return this.#deployment;
  }

  async candidateSink(closure, configuration, options = {}) {
    const { deployment: bound, sink } = await officialManagedCandidateSink(
      closure,
      configuration,
      { ...options, deployment: this.#deployment, operationId: this.operationId },
    );
    this.#deployment = bound;
    return sink;
  }
}

// Create the official managed sink without customer-selected service routes
// or capture-grant verification keys.
export async function createOfficialManagedCandidateSink(
  closure,
  configuration,
  options,
) {
  const { sink } = await officialManagedCandidateSink(
    closure,
    configuration,
    options,
  );
  return sink;
}

async function officialManagedCandidateSink(closure, configuration, options) {
  const release = officialManagedConfiguration();
  if (configuration === null || typeof configuration !== "object") {
    throw releaseBindingInvalid();
  }
  if (
    options === null ||
    typeof options !== "object" ||
    options.deployment === null ||
    typeof options.deployment !== "object"
  ) {
    throw releaseBindingInvalid();
  }
  const boundOptions = structuredClone(options);
  boundOptions.deployment.runtime_endpoint = release.managedOrigin;
  const sink = await ManagedCandidateSink.create(
    release.client,
    closure,
    {
      captureSignerId: release.captureSignerId,
      captureSignerPublicKey: release.captureSignerPublicKey,
      projectTokenProvider: configuration.projectTokenProvider,
      serviceId: configuration.serviceId,
    },
    boundOptions,
  );
  return { deployment: boundOptions.deployment, sink };
}

export function officialManagedConfiguration() {
  if (
    isReleaseSentinel(OFFICIAL_MANAGED_HTTPS_ORIGIN) ||
    isReleaseSentinel(OFFICIAL_CAPTURE_GRANT_SIGNER_ID) ||
    isReleaseSentinel(OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY)
  ) {
    throw new ManagedError(
      "CONFIG_CONFLICT",
      "This Repro It SDK has no official managed release binding.",
    );
  }
  validateSignerId(OFFICIAL_CAPTURE_GRANT_SIGNER_ID);
  const publicKey = decodeBase64url(
    OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY,
    32,
  );
  if (
    publicKey.every((byte) => byte === 0) ||
    FIXTURE_CAPTURE_SIGNER_PUBLIC_KEYS.has(
      OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY,
    ) ||
    !isStrongEd25519Point(publicKey)
  ) {
    throw releaseBindingInvalid();
  }
  const endpoint = ManagedTlsEndpoint.official(OFFICIAL_MANAGED_HTTPS_ORIGIN);
  return {
    captureSignerId: OFFICIAL_CAPTURE_GRANT_SIGNER_ID,
    captureSignerPublicKey: publicKey,
    client: new ManagedTlsClient(endpoint, endpoint),
    managedOrigin: OFFICIAL_MANAGED_HTTPS_ORIGIN,
  };
}

function isReleaseSentinel(value) {
  return (
    value.startsWith("__REPROIT_OFFICIAL_") &&
    value.endsWith("_SENTINEL__")
  );
}

function validateSignerId(value) {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value)
  ) {
    throw releaseBindingInvalid();
  }
}

function isStrongEd25519Point(encoded) {
  const prime = (1n << 255n) - 19n;
  const sign = BigInt(encoded[31] >> 7);
  const yBytes = Buffer.from(encoded);
  yBytes[31] &= 0x7f;
  let y = 0n;
  for (let index = yBytes.length - 1; index >= 0; index -= 1) {
    y = (y << 8n) | BigInt(yBytes[index]);
  }
  if (y >= prime) return false;
  const d = modulo(-121665n * powerModulo(121666n, prime - 2n, prime), prime);
  const ySquared = modulo(y * y, prime);
  const xSquared = modulo(
    (ySquared - 1n) * powerModulo(d * ySquared + 1n, prime - 2n, prime),
    prime,
  );
  let x = powerModulo(xSquared, (prime + 3n) / 8n, prime);
  if (modulo(x * x - xSquared, prime) !== 0n) {
    const squareRootOfMinusOne = powerModulo(2n, (prime - 1n) / 4n, prime);
    x = modulo(x * squareRootOfMinusOne, prime);
  }
  if (modulo(x * x - xSquared, prime) !== 0n) return false;
  if (x === 0n && sign !== 0n) return false;
  if ((x & 1n) !== sign) x = prime - x;
  let point = [x, y];
  for (let index = 0; index < 3; index += 1) {
    point = addEd25519Points(point, point, prime, d);
  }
  return point[0] !== 0n || point[1] !== 1n;
}

function addEd25519Points(left, right, prime, d) {
  const [x1, y1] = left;
  const [x2, y2] = right;
  const product = modulo(d * x1 * x2 * y1 * y2, prime);
  return [
    modulo(
      (x1 * y2 + y1 * x2) * powerModulo(1n + product, prime - 2n, prime),
      prime,
    ),
    modulo(
      (y1 * y2 + x1 * x2) * powerModulo(1n - product, prime - 2n, prime),
      prime,
    ),
  ];
}

function powerModulo(base, exponent, modulus) {
  let result = 1n;
  let factor = modulo(base, modulus);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = modulo(result * factor, modulus);
    factor = modulo(factor * factor, modulus);
    remaining >>= 1n;
  }
  return result;
}

function modulo(value, modulus) {
  return ((value % modulus) + modulus) % modulus;
}

function releaseBindingInvalid() {
  return new ManagedError(
    "CONFIG_CONFLICT",
    "The official managed release binding is invalid.",
  );
}

function validateProject(project, buildRepositoryId, sourceRevision) {
  if (
    project === null ||
    typeof project !== "object" ||
    project.format !== 1 ||
    project.profile !== "backend" ||
    project.profile_format !== 1 ||
    project.processing_mode !== "managed" ||
    project.sdk !== "node" ||
    project.repository_id !== buildRepositoryId ||
    !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(sourceRevision) ||
    typeof project.service_path !== "string" ||
    project.service_path === "" ||
    project.service_path.startsWith("/") ||
    project.service_path.split("/").includes("..") ||
    !["organization_id", "project_id", "service_id"].every(
      (name) => typeof project[name] === "string",
    )
  ) {
    throw projectBindingInvalid();
  }
}

function deployment(project, sourceRevision) {
  return {
    format: "reproit.deployment.v1",
    organization_id: project.organization_id,
    processing_mode: "managed",
    project_id: project.project_id,
    repository_id: project.repository_id,
    runtime_capabilities: ["runtime.node-native"],
    runtime_endpoint: "pending-official-managed-origin",
    service_id: project.service_id,
    service_path: project.service_path,
    signature: "A".repeat(86),
    signed_at: "1970-01-01T00:00:00.000Z",
    signer_key_id: "pending-managed-registration",
    source_revision: sourceRevision,
    subject: {},
  };
}

function newIdentifier(prefix) {
  const bytes = randomBytes(16);
  const milliseconds = BigInt(Date.now());
  for (let index = 0; index < 6; index += 1) {
    bytes[5 - index] = Number((milliseconds >> BigInt(index * 8)) & 0xffn);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const value = bytes.toString("hex");
  return `${prefix}${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

function projectBindingInvalid() {
  return new ManagedError(
    "CONFIG_CONFLICT",
    "The managed project build binding is invalid.",
  );
}
