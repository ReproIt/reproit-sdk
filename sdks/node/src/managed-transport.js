// Managed key-service and ingress HTTP client with strict bounds.
//
// Mirrors crates/reproit-sdk-rust/src/managed_transport.rs: TLS 1.3 only,
// HTTP/1.1 with Connection: close, bounded request and response sizes, the
// exact routes and JSON bodies the Rust client sends, and typed rejection of
// every invalid response.

import { Buffer } from "node:buffer";
import { X509Certificate } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import tls from "node:tls";

import { canonicalBytes } from "./index.js";
import {
  ERROR_CODES,
  ManagedError,
  canonicalDigest,
  decodeBase64url,
  digestBytes,
  encodeBase64url,
  parseStrictJson,
  requireTypedId,
  schemaInvalid,
  validDigest,
  validOpaqueReference,
  validTimestamp,
  validTypedId,
  validateCaptureGrant,
  validateCapabilities,
  validateUploadRequest,
  verifySignedValue,
} from "./managed-protocol.js";

export const MAX_CA_BYTES = 1_048_576;
export const MAX_HEADER_BYTES = 8_192;
export const MAX_JSON_RESPONSE_BYTES = 8_388_608;
export const MAX_PROJECT_TOKEN_BYTES = 1_024;
export const MAX_REGISTRATION_BYTES = 3_372_783;

const UPLOAD_STATES = new Set([
  "CANCELLED",
  "COMMITTED",
  "COMMITTING",
  "EXPIRED",
  "OPEN",
  "UPLOADING",
]);
const DURABILITY_STATES = new Set(["CLOUD_PROTECTED", "LOCAL_ONLY"]);
const LIMIT_KEYS = [
  "max_candidate_bytes",
  "max_object_bytes",
  "max_objects",
  "max_total_ciphertext_bytes",
  "missing_page_size",
  "object_attempts",
  "upload_lifetime_ms",
];
const HEADER_TERMINATOR = Buffer.from("\r\n\r\n", "ascii");

// A project token restricted to the first workload registration.
export class ManagedProjectToken {
  #value;

  constructor(value) {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > MAX_PROJECT_TOKEN_BYTES ||
      !/^[!-~]+$/u.test(value)
    ) {
      throw schemaInvalid("The managed project token is invalid.");
    }
    this.#value = value;
  }

  authorization() {
    return `Bearer ${this.#value}`;
  }
}

// The managed candidate key and its signed capture grant.
export class EncryptionResponse {
  constructor(candidateKey, captureGrant) {
    this.candidateKey = candidateKey;
    this.captureGrant = captureGrant;
  }
}

// An incremental bounded HTTP/1.1 response reader. It mirrors the Python
// reference _read_response rules exactly: a terminated header within
// MAX_HEADER_BYTES, no transfer coding, one non-negative Content-Length
// within the JSON response bound, and the exact body byte count.
export class HttpResponseParser {
  #bodyLength = 0;
  #buffer = Buffer.alloc(0);
  #headerParsed = false;
  #status = 0;

  // Consume one chunk. Returns {status, body} when complete, null otherwise.
  push(chunk) {
    this.#buffer = Buffer.concat([this.#buffer, Buffer.from(chunk)]);
    if (!this.#headerParsed) {
      const terminator = this.#buffer.indexOf(HEADER_TERMINATOR);
      if (terminator === -1 || terminator + 4 > MAX_HEADER_BYTES) {
        if (this.#buffer.length >= MAX_HEADER_BYTES) {
          throw responseInvalid();
        }
        return null;
      }
      this.#parseHeader(this.#buffer.subarray(0, terminator + 4));
      this.#buffer = this.#buffer.subarray(terminator + 4);
      this.#headerParsed = true;
    }
    if (this.#buffer.length < this.#bodyLength) {
      return null;
    }
    if (this.#buffer.length > this.#bodyLength) {
      throw responseInvalid();
    }
    return { body: Buffer.from(this.#buffer), status: this.#status };
  }

  // The peer closed the connection before the response completed.
  finish() {
    if (!this.#headerParsed) {
      throw responseInvalid();
    }
    throw serviceUnavailable();
  }

  #parseHeader(header) {
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(header);
    } catch {
      throw responseInvalid();
    }
    const lines = text.split("\r\n");
    const statusParts = lines[0].split(/\s+/u);
    if (statusParts.length < 2 || !/^\d+$/u.test(statusParts[1])) {
      throw responseInvalid();
    }
    this.#status = Number(statusParts[1]);
    let contentLength = null;
    for (const line of lines.slice(1)) {
      if (line.length === 0) continue;
      const separator = line.indexOf(":");
      if (separator === -1) {
        throw responseInvalid();
      }
      const name = line.slice(0, separator).toLowerCase();
      const value = line.slice(separator + 1).trim();
      if (name === "transfer-encoding") {
        throw responseInvalid();
      }
      if (name === "content-length") {
        if (contentLength !== null || !/^\d+$/u.test(value)) {
          throw responseInvalid();
        }
        contentLength = Number(value);
      }
    }
    this.#bodyLength = contentLength ?? 0;
    if (this.#bodyLength > MAX_JSON_RESPONSE_BYTES) {
      throw responseInvalid();
    }
  }
}

// One TLS 1.3 origin for the managed key service or managed ingress.
export class ManagedTlsEndpoint {
  #authority;
  #ca;
  #host;
  #origin;
  #port;
  #serverName;
  // Test-visible TLS parameters, mirroring the Python endpoint's context.
  _tls = {
    maxVersion: "TLSv1.3",
    minVersion: "TLSv1.3",
    rejectUnauthorized: true,
  };

  constructor(host, port, serverName, authority, caCertificatePath) {
    if (
      typeof host !== "string" ||
      host.length === 0 ||
      host.length > 253 ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65_535 ||
      typeof serverName !== "string" ||
      serverName.length === 0 ||
      serverName.length > 253
    ) {
      throw endpointInvalid();
    }
    validateAuthority(authority);
    this.#host = host;
    this.#port = port;
    this.#serverName = serverName;
    this.#authority = authority;
    this.#origin = `https://${authority}`;
    this.#ca =
      caCertificatePath === null ? null : readCaCertificate(caCertificatePath);
  }

  static official(origin) {
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw endpointInvalid();
    }
    if (
      parsed.protocol !== "https:" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.port !== "" ||
      parsed.pathname !== "/" ||
      parsed.search !== "" ||
      parsed.hash !== "" ||
      parsed.hostname.length === 0 ||
      parsed.hostname.length > 253
    ) {
      throw endpointInvalid();
    }
    return new ManagedTlsEndpoint(
      parsed.hostname,
      443,
      parsed.hostname,
      parsed.hostname,
      null,
    );
  }

  get origin() {
    return this.#origin;
  }

  request(method, target, authorization, contentType, body, timeoutMs) {
    validateRequestComponent(method);
    validateTarget(target);
    if (authorization !== null) {
      validateHeaderValue(authorization);
    }
    if (contentType !== null) {
      validateHeaderValue(contentType);
    }
    let header =
      `${method} ${target} HTTP/1.1\r\n` +
      `Host: ${this.#authority}\r\nConnection: close\r\n`;
    if (authorization !== null) {
      header += `Authorization: ${authorization}\r\n`;
    }
    if (contentType !== null) {
      header += `Content-Type: ${contentType}\r\n`;
    }
    header += `Content-Length: ${body.length}\r\n\r\n`;
    const request = Buffer.concat([
      Buffer.from(header, "ascii"),
      Buffer.from(body),
    ]);
    return new Promise((resolve, reject) => {
      const { connection, readyEvent } = this._connect(timeoutMs);
      const parser = new HttpResponseParser();
      let settled = false;
      const finish = (failure, response) => {
        if (settled) return;
        settled = true;
        connection.destroy();
        if (failure !== null) reject(failure);
        else resolve(response);
      };
      connection.setTimeout(Math.max(1, Math.floor(timeoutMs)), () =>
        finish(serviceUnavailable(), null),
      );
      connection.once(readyEvent, () => connection.write(request));
      connection.once("error", (error) =>
        finish(
          tlsFailure(error) ? endpointInvalid() : serviceUnavailable(),
          null,
        ),
      );
      connection.on("data", (chunk) => {
        let response;
        try {
          response = parser.push(chunk);
        } catch (error) {
          return finish(error, null);
        }
        if (response !== null) finish(null, response);
      });
      connection.once("end", () => {
        try {
          parser.finish();
        } catch (error) {
          finish(error, null);
        }
      });
    });
  }

  uploadTarget(uploadUrl) {
    if (typeof uploadUrl !== "string" || !uploadUrl.startsWith(this.#origin)) {
      throw endpointInvalid();
    }
    const target = uploadUrl.slice(this.#origin.length);
    validateTarget(target);
    return target;
  }

  _connect(timeoutMs) {
    void timeoutMs;
    const trust = this.#ca === null ? {} : { ca: this.#ca };
    return {
      connection: tls.connect({
        ...trust,
        host: this.#host,
        maxVersion: this._tls.maxVersion,
        minVersion: this._tls.minVersion,
        port: this.#port,
        rejectUnauthorized: this._tls.rejectUnauthorized,
        servername: this.#serverName,
      }),
      readyEvent: "secureConnect",
    };
  }
}

function readCaCertificate(caCertificatePath) {
  let metadata;
  try {
    metadata = lstatSync(caCertificatePath);
  } catch {
    throw endpointInvalid();
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size <= 0 ||
    metadata.size > MAX_CA_BYTES
  ) {
    throw endpointInvalid();
  }
  let certificate;
  try {
    certificate = readFileSync(caCertificatePath);
  } catch {
    throw endpointInvalid();
  }
  if (certificate.length !== metadata.size) {
    throw endpointInvalid();
  }
  try {
    new X509Certificate(certificate);
  } catch {
    throw endpointInvalid();
  }
  return certificate;
}

function tlsFailure(error) {
  const code = error?.code;
  return (
    typeof code === "string" &&
    (code.startsWith("ERR_TLS_") ||
      code.startsWith("ERR_SSL_") ||
      code.includes("CERT") ||
      code.includes("SSL"))
  );
}

// The SDK-side client for the managed key service and managed ingress.
export class ManagedTlsClient {
  #ingress;
  #keyService;

  constructor(keyService, ingress) {
    this.#ingress = ingress;
    this.#keyService = keyService;
  }

  async registerWorkloadKey(projectToken, request, timeoutMs) {
    if (!(projectToken instanceof ManagedProjectToken)) {
      throw schemaInvalid();
    }
    validateWorkloadKeyRegistration(request);
    const body = canonicalBytes(request);
    if (body.length > MAX_REGISTRATION_BYTES) throw schemaInvalid();
    const response = await this.#keyService.request(
      "POST",
      "/v1/workload-keys",
      projectToken.authorization(),
      "application/json",
      body,
      timeoutMs,
    );
    const registration = decodeJson(response, 200);
    const expectedKeyId = managedWorkloadKeyId(request.public_key);
    const expectedDeploymentDigest = canonicalDigest(request.deployment);
    if (
      !sameResponseKeys(registration, [
        "deployment_digest",
        "key_id",
        "service_id",
      ]) ||
      registration.service_id !== request.service_id ||
      registration.key_id !== expectedKeyId ||
      registration.deployment_digest !== expectedDeploymentDigest
    ) {
      throw responseInvalid();
    }
    return registration;
  }

  async requestEncryptionGrant(request, timeoutMs) {
    validateGrantRequest(request);
    const response = await this.#keyService.request(
      "POST",
      "/v1/managed-candidate-encryption-grants",
      null,
      "application/json",
      canonicalBytes(request),
      timeoutMs,
    );
    const value = decodeJson(response, 200);
    if (!sameResponseKeys(value, ["candidate_key", "capture_grant"])) {
      throw responseInvalid();
    }
    const candidateKey = decodeBase64url(value.candidate_key, 32);
    validateCaptureGrant(value.capture_grant);
    return new EncryptionResponse(candidateKey, value.capture_grant);
  }

  async start(request, timeoutMs) {
    validateUploadRequest(request);
    const response = await this.#ingress.request(
      "POST",
      "/v1/managed-candidates",
      null,
      "application/json",
      canonicalBytes(request),
      timeoutMs,
    );
    return validateStart(decodeJson(response, 200));
  }

  async missing(uploadId, uploadToken, cursor, timeoutMs) {
    requireTypedId(uploadId, "upload_id");
    validateToken(uploadToken);
    if (cursor !== null) {
      validateCursor(cursor);
    }
    let target = `/v1/managed-candidates/${uploadId}/missing?limit=100`;
    if (cursor !== null) {
      target += `&cursor=${cursor}`;
    }
    const response = await this.#ingress.request(
      "GET",
      target,
      `Bearer ${uploadToken}`,
      null,
      Buffer.alloc(0),
      timeoutMs,
    );
    return validateMissingPage(decodeJson(response, 200));
  }

  async uploadObject(uploadUrl, digest, value, timeoutMs) {
    if (digestBytes(value) !== digest) {
      throw new ManagedError(
        "OBJECT_DIGEST_MISMATCH",
        "The object bytes do not match the bound digest.",
      );
    }
    const target = this.#ingress.uploadTarget(uploadUrl);
    const response = await this.#ingress.request(
      "PUT",
      target,
      null,
      "application/octet-stream",
      value,
      timeoutMs,
    );
    expectEmpty(response, 204);
  }

  async commit(uploadId, uploadToken, timeoutMs) {
    requireTypedId(uploadId, "upload_id");
    validateToken(uploadToken);
    const response = await this.#ingress.request(
      "POST",
      `/v1/managed-candidates/${uploadId}/commit`,
      `Bearer ${uploadToken}`,
      null,
      Buffer.alloc(0),
      timeoutMs,
    );
    return validateCommit(decodeJson(response, 200));
  }

  async cancel(uploadId, uploadToken, timeoutMs) {
    requireTypedId(uploadId, "upload_id");
    validateToken(uploadToken);
    const response = await this.#ingress.request(
      "DELETE",
      `/v1/managed-candidates/${uploadId}`,
      `Bearer ${uploadToken}`,
      null,
      Buffer.alloc(0),
      timeoutMs,
    );
    return validateStatus(decodeJson(response, 200));
  }
}

export function validateGrantRequest(value) {
  if (
    !sameResponseKeys(value, [
      "candidate_identity_digest",
      "capture_id",
      "cipher_suite",
      "deployment_digest",
      "organization_id",
      "processing_mode",
      "project_id",
      "service_id",
      "signature",
      "signer_key_id",
    ]) ||
    value.processing_mode !== "managed" ||
    value.cipher_suite !== "AES-256-GCM+HKDF-SHA-256" ||
    !validDigest(value.candidate_identity_digest) ||
    !validDigest(value.deployment_digest) ||
    !validTypedId(value.capture_id, "capture_id") ||
    !validTypedId(value.organization_id, "organization_id") ||
    !validTypedId(value.project_id, "project_id") ||
    !validTypedId(value.service_id, "service_id") ||
    !validManagedWorkloadKeyId(value.signer_key_id) ||
    typeof value.signature !== "string" ||
    value.signature.length !== 86
  ) {
    throw schemaInvalid();
  }
  decodeBase64url(value.signature, 64);
}

export function managedWorkloadKeyId(publicKey) {
  decodeBase64url(publicKey, 32);
  return `managed-workload-${digestBytes(Buffer.from(publicKey, "ascii"))}`;
}

export function validManagedWorkloadKeyId(value) {
  return (
    typeof value === "string" &&
    /^managed-workload-sha256:[0-9a-f]{64}$/u.test(value)
  );
}

export function validateWorkloadKeyRegistration(value) {
  if (
    !sameResponseKeys(value, [
      "algorithm",
      "deployment",
      "public_key",
      "service_id",
    ]) ||
    value.algorithm !== "Ed25519" ||
    !isManagedDeployment(value.deployment) ||
    value.deployment.service_id !== value.service_id
  ) {
    throw schemaInvalid();
  }
  const publicKey = decodeBase64url(value.public_key, 32);
  if (managedWorkloadKeyId(value.public_key) !== value.deployment.signer_key_id) {
    throw schemaInvalid();
  }
  verifySignedValue(value.deployment, publicKey);
}

function isManagedDeployment(value) {
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    sameResponseKeys(value, [
      "format",
      "organization_id",
      "processing_mode",
      "project_id",
      "repository_id",
      "runtime_capabilities",
      "runtime_endpoint",
      "service_id",
      "service_path",
      "signature",
      "signed_at",
      "signer_key_id",
      "source_revision",
      "subject",
    ]) &&
    value.format === "reproit.deployment.v1" &&
    value.processing_mode === "managed" &&
    validTypedId(value.organization_id, "organization_id") &&
    validTypedId(value.project_id, "project_id") &&
    validTypedId(value.service_id, "service_id") &&
    boundedString(value.repository_id, 1, 256) &&
    boundedString(value.runtime_endpoint, 1, 2_048) &&
    boundedString(value.service_path, 0, 1_024) &&
    boundedString(value.source_revision, 1, 256) &&
    validTimestamp(value.signed_at) &&
    validManagedWorkloadKeyId(value.signer_key_id) &&
    typeof value.signature === "string" &&
    value.signature.length === 86 &&
    isManagedSubject(value.subject)
  ) {
    try {
      validateCapabilities(value.runtime_capabilities);
      decodeBase64url(value.signature, 64);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function isManagedSubject(value) {
  return (
    sameResponseKeys(value, [
      "architecture",
      "arguments",
      "artifact_digest",
      "artifact_media_type",
      "artifact_uri",
      "environment_names",
      "executable",
      "format",
      "operating_system",
      "working_directory",
    ]) &&
    value.format === "reproit.subject.v1" &&
    boundedString(value.architecture, 1, 128) &&
    boundedString(value.operating_system, 1, 128) &&
    validDigest(value.artifact_digest) &&
    boundedString(value.artifact_media_type, 1, 256) &&
    boundedString(value.artifact_uri, 1, 2_048) &&
    boundedString(value.executable, 1, 4_096) &&
    boundedString(value.working_directory, 1, 4_096) &&
    boundedStringArray(value.arguments, 256, 4_096) &&
    boundedStringArray(value.environment_names, 256, 256)
  );
}

function boundedString(value, minimum, maximum) {
  return (
    typeof value === "string" &&
    Buffer.byteLength(value, "utf8") >= minimum &&
    Buffer.byteLength(value, "utf8") <= maximum
  );
}

function boundedStringArray(value, maximumItems, maximumBytes) {
  return (
    Array.isArray(value) &&
    value.length <= maximumItems &&
    value.every((entry) => boundedString(entry, 0, maximumBytes))
  );
}

function validateMissingObject(value) {
  if (
    !sameResponseKeys(value, ["cipher_digest", "expires_at", "upload_url"]) ||
    !validDigest(value.cipher_digest) ||
    !validTimestamp(value.expires_at) ||
    typeof value.upload_url !== "string" ||
    value.upload_url.length === 0 ||
    value.upload_url.length > 4_096
  ) {
    throw responseInvalid();
  }
}

function validateLimits(value) {
  if (
    !sameResponseKeys(value, LIMIT_KEYS) ||
    LIMIT_KEYS.some(
      (key) => !Number.isSafeInteger(value[key]) || value[key] < 0,
    )
  ) {
    throw responseInvalid();
  }
}

function validateStart(value) {
  if (
    !sameResponseKeys(value, [
      "expires_at",
      "limits",
      "missing_objects",
      "next_missing_cursor",
      "state",
      "upload_id",
      "upload_token",
    ]) ||
    !validTimestamp(value.expires_at) ||
    !UPLOAD_STATES.has(value.state) ||
    !validTypedId(value.upload_id, "upload_id") ||
    !Array.isArray(value.missing_objects)
  ) {
    throw responseInvalid();
  }
  validateLimits(value.limits);
  validateToken(value.upload_token);
  if (value.next_missing_cursor !== null) {
    validateCursor(value.next_missing_cursor);
  }
  for (const missing of value.missing_objects) {
    validateMissingObject(missing);
  }
  return value;
}

function validateMissingPage(value) {
  if (
    !sameResponseKeys(value, ["missing_objects", "next_missing_cursor"]) ||
    !Array.isArray(value.missing_objects)
  ) {
    throw responseInvalid();
  }
  if (value.next_missing_cursor !== null) {
    validateCursor(value.next_missing_cursor);
  }
  for (const missing of value.missing_objects) {
    validateMissingObject(missing);
  }
  return value;
}

function validateCommit(value) {
  if (
    !sameResponseKeys(value, [
      "candidate_identity_digest",
      "candidate_key_reference",
      "capture_id",
      "encrypted_candidate_digest",
      "state",
      "upload_id",
    ]) ||
    !validDigest(value.candidate_identity_digest) ||
    !validOpaqueReference(value.candidate_key_reference) ||
    !validTypedId(value.capture_id, "capture_id") ||
    !validDigest(value.encrypted_candidate_digest) ||
    !DURABILITY_STATES.has(value.state) ||
    !validTypedId(value.upload_id, "upload_id")
  ) {
    throw responseInvalid();
  }
  return value;
}

function validateStatus(value) {
  if (
    !sameResponseKeys(value, [
      "candidate_identity_digest",
      "candidate_key_reference",
      "capture_id",
      "encrypted_candidate_digest",
      "expires_at",
      "missing_digests",
      "state",
      "upload_id",
    ]) ||
    !validDigest(value.candidate_identity_digest) ||
    !validOpaqueReference(value.candidate_key_reference) ||
    !validTypedId(value.capture_id, "capture_id") ||
    !validDigest(value.encrypted_candidate_digest) ||
    !(value.expires_at === null || validTimestamp(value.expires_at)) ||
    !Array.isArray(value.missing_digests) ||
    value.missing_digests.some((digest) => !validDigest(digest)) ||
    !UPLOAD_STATES.has(value.state) ||
    !validTypedId(value.upload_id, "upload_id")
  ) {
    throw responseInvalid();
  }
  return value;
}

function decodeJson(response, expectedStatus) {
  if (response.status !== expectedStatus) {
    throw decodeServerError(response.status, response.body);
  }
  if (response.body.length === 0) {
    throw responseInvalid();
  }
  try {
    return parseStrictJson(response.body, MAX_JSON_RESPONSE_BYTES);
  } catch {
    throw responseInvalid();
  }
}

function expectEmpty(response, expectedStatus) {
  if (response.status !== expectedStatus) {
    throw decodeServerError(response.status, response.body);
  }
  if (response.body.length !== 0) {
    throw responseInvalid();
  }
}

function decodeServerError(status, body) {
  if (body.length !== 0) {
    let value = null;
    try {
      value = parseStrictJson(body, MAX_JSON_RESPONSE_BYTES);
    } catch {
      value = null;
    }
    if (
      sameResponseKeys(value, ["code", "message", "retryable"]) &&
      ERROR_CODES.has(value.code) &&
      typeof value.message === "string" &&
      typeof value.retryable === "boolean"
    ) {
      return new ManagedError(value.code, value.message, value.retryable);
    }
  }
  if ([429, 502, 503, 504].includes(status)) {
    return serviceUnavailable();
  }
  return responseInvalid();
}

function sameResponseKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(" ") === [...keys].sort().join(" ")
  );
}

function validateAuthority(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512 ||
    !/^[!-~]+$/u.test(value) ||
    /[/?#@]/u.test(value)
  ) {
    throw endpointInvalid();
  }
}

function validateRequestComponent(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 16 ||
    !/^[A-Z]+$/u.test(value)
  ) {
    throw endpointInvalid();
  }
}

function validateTarget(value) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.length > 4_096 ||
    value.includes("#") ||
    /[\u0000-\u0020\u007f]/u.test(value)
  ) {
    throw endpointInvalid();
  }
}

function validateHeaderValue(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4_096 ||
    !/^[ -~]+$/u.test(value)
  ) {
    throw endpointInvalid();
  }
}

function validateToken(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw responseInvalid();
  }
}

function validateCursor(value) {
  validateToken(value);
}

function endpointInvalid() {
  return new ManagedError(
    "SCHEMA_INVALID",
    "The managed TLS endpoint configuration is invalid.",
  );
}

function responseInvalid() {
  return new ManagedError(
    "SCHEMA_INVALID",
    "The managed service response is invalid.",
  );
}

function serviceUnavailable() {
  return new ManagedError(
    "SERVICE_UNAVAILABLE",
    "The managed capture service is unavailable.",
  );
}
