import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { Sdk, canonicalBytes } from "./index.js";
import { ManagedProjectToken } from "./managed-transport.js";
import {
  canonicalDigest,
  digestBytes,
  encodeBase64url,
  newObjectId,
} from "./managed-protocol.js";
import { OfficialManagedProject } from "./official-managed.js";

const MAX_CAPTURED_INPUT_BYTES = 32 * 1_024;
const MAX_CONTENT_TYPE_BYTES = 256;
const MAX_DEPENDENCIES = 1_024;
const MAX_EVENT_BYTES = 65_536;
const MAX_OPERATION_NAME_BYTES = 128;
const MAX_PROJECT_BYTES = 65_536;
const MAX_PROJECT_SEARCH_DEPTH = 64;
const INTERNAL_INIT = Symbol("ReproIt.init");

export class ManagedWorldCapture {
  constructor(worldId, complete) {
    if (typeof complete !== "function") {
      throw new TypeError("The World completion operation is unavailable.");
    }
    this.worldId = worldId;
    this.complete = complete;
  }
}

export class OperationCapture {
  #dependencies = [];
  #valid = true;

  constructor(operationId = null) {
    this.operationId = operationId;
  }

  get dependencies() {
    return this.#valid ? structuredClone(this.#dependencies) : null;
  }

  recordDependency(dependency) {
    if (!this.#valid) return;
    try {
      const copied = structuredClone(dependency);
      if (
        this.#dependencies.length >= MAX_DEPENDENCIES ||
        canonicalBytes(copied).length > MAX_EVENT_BYTES
      ) {
        this.#valid = false;
        this.#dependencies = [];
        return;
      }
      this.#dependencies.push(copied);
    } catch {
      this.#valid = false;
      this.#dependencies = [];
    }
  }
}

export class ReproIt {
  #project = null;
  #worldCapture;

  constructor(project, buildRepositoryId, sourceRevision, worldCapture) {
    if (project === INTERNAL_INIT) {
      this.#worldCapture = automaticWorldCapture;
      return;
    }
    if (typeof worldCapture !== "function") {
      throw new TypeError("The World capture operation is unavailable.");
    }
    this.#project = new OfficialManagedProject(
      project,
      buildRepositoryId,
      sourceRevision,
    );
    this.#worldCapture = worldCapture;
  }

  static init() {
    const capture = new ReproIt(INTERNAL_INIT);
    try {
      const projectFile = findProjectFile(process.cwd());
      const project = parseProjectConfig(fs.readFileSync(projectFile));
      const repositoryId = project.repository_id;
      if (typeof repositoryId !== "string") {
        return capture;
      }
      const sourceRevision = gitSourceRevision(path.dirname(path.dirname(projectFile)));
      capture.#project = new OfficialManagedProject(
        project,
        repositoryId,
        sourceRevision,
      );
    } catch {
      // Initialization failure disables capture without changing the application.
    }
    return capture;
  }

  operation(operationName, input, operation) {
    return this.run(
      operationName,
      "application/octet-stream",
      input,
      () => operation(),
      (error) => automaticFailurePayload(operationName, error),
    );
  }

  run(operationName, contentType, input, operation, classifyFailure) {
    return this.#runKind(
      "request-response",
      operationName,
      contentType,
      input,
      operation,
      classifyFailure,
    );
  }

  runStream(operationName, contentType, input, operation, classifyFailure) {
    return this.#runKind(
      "stream",
      operationName,
      contentType,
      input,
      operation,
      classifyFailure,
    );
  }

  runDeliveredWork(
    operationName,
    contentType,
    input,
    operation,
    classifyFailure,
  ) {
    return this.#runKind(
      "delivered-work",
      operationName,
      contentType,
      input,
      operation,
      classifyFailure,
    );
  }

  #runKind(
    operationKind,
    operationName,
    contentType,
    input,
    operation,
    classifyFailure,
  ) {
    const active = this.#start(operationKind, operationName, contentType, input);
    const context = active?.context ?? new OperationCapture();
    try {
      const result = operation(context);
      if (result && typeof result.then === "function") {
        return result.catch((original) => {
          void this.#captureFailure(active, original, classifyFailure);
          throw original;
        });
      }
      return result;
    } catch (original) {
      void this.#captureFailure(active, original, classifyFailure);
      throw original;
    }
  }

  #start(operationKind, operationName, contentType, input) {
    try {
      const bytes = Buffer.from(input);
      validateBoundary(operationKind, operationName, contentType, bytes);
      const world = this.#worldCapture();
      if (!(world instanceof ManagedWorldCapture)) return null;
      if (this.#project === null) return null;
      const operation = this.#project.startOperation(world.worldId);
      return {
        contentType,
        context: new OperationCapture(operation.operationId),
        input: bytes,
        operation,
        operationKind,
        operationName,
        world,
      };
    } catch {
      return null;
    }
  }

  async #captureFailure(active, original, classifyFailure) {
    try {
      if (!active || typeof classifyFailure !== "function") return;
      const dependencies = active.context.dependencies;
      const failure = classifyFailure(original);
      if (dependencies === null || failure === null || failure === undefined) {
        return;
      }
      const closure = await active.world.complete(active.operation.operationId);
      const sink = await active.operation.candidateSink(closure, {
        projectTokenProvider: () =>
          new ManagedProjectToken(process.env.REPROIT_MANAGED_PROJECT_TOKEN),
        serviceId: active.operation.deployment.service_id,
      });
      const sdk = new Sdk(sink);
      sdk.begin(
        candidateStart(active.operation),
        operationBegin(active.operationKind, active.operationName),
      );
      sdk.recordInput(
        active.operation.operationId,
        operationInput(active.contentType, active.input),
      );
      for (const dependency of dependencies) {
        sdk.recordDependency(active.operation.operationId, dependency);
      }
      sdk.fail(active.operation.operationId, failure);
    } catch {
      // Capture failure must not change application behavior.
    }
  }
}

function validateBoundary(operationKind, operationName, contentType, input) {
  if (
    !["request-response", "stream", "delivered-work"].includes(operationKind) ||
    typeof operationName !== "string" ||
    operationName.length === 0 ||
    Buffer.byteLength(operationName) > MAX_OPERATION_NAME_BYTES ||
    typeof contentType !== "string" ||
    contentType.length === 0 ||
    Buffer.byteLength(contentType) > MAX_CONTENT_TYPE_BYTES ||
    input.length > MAX_CAPTURED_INPUT_BYTES
  ) {
    throw new TypeError("The operation boundary is invalid.");
  }
}

function candidateStart(operation) {
  return {
    captureId: operation.captureId,
    deployment: operation.deployment,
    operationId: operation.operationId,
    worldId: operation.worldId,
  };
}

function operationBegin(operationKind, operationName) {
  return {
    adapter_id: "sdk",
    adapter_version: "1.0.0",
    causal_parent_ids: [],
    format: "reproit.operation-begin.v1",
    operation_kind: operationKind,
    operation_name: operationName,
  };
}

function operationInput(contentType, value) {
  return {
    channel: "input",
    content_type: contentType,
    format: "reproit.operation-input.v1",
    input_index: 0,
    value: encodeBase64url(value),
    value_digest: digestBytes(value),
  };
}

function automaticWorldCapture() {
  const world = {
    created_at: new Date().toISOString(),
    format: "reproit.world-checkpoint.v1",
    points: [],
  };
  return new ManagedWorldCapture(canonicalDigest(world), () => ({
    artifacts: [],
    completion: "return",
    world: structuredClone(world),
  }));
}

function automaticFailurePayload(operationName, error) {
  const type = error?.constructor?.name || "Error";
  const identity = {
    category: "exception",
    cause_types: [],
    frames: [],
    operation_kind: "request-response",
    operation_name: operationName,
    runtime_family: "node",
    schema: "reproit.failure.v1",
    stable_code: type,
    type,
  };
  return {
    failure: {
      category: "exception",
      identity: canonicalDigest(identity),
      matcher: "exception-exact-v1",
      object_id: newObjectId(),
      schema: "reproit.failure.v1",
    },
    format: "reproit.failure-payload.v1",
    identity,
  };
}

function findProjectFile(start) {
  let directory = path.resolve(start);
  for (let depth = 0; depth < MAX_PROJECT_SEARCH_DEPTH; depth += 1) {
    const candidate = path.join(directory, ".reproit", "project.toml");
    try {
      const directoryMetadata = fs.lstatSync(path.dirname(candidate));
      const metadata = fs.lstatSync(candidate);
      if (
        directoryMetadata.isDirectory() &&
        !directoryMetadata.isSymbolicLink() &&
        metadata.isFile() &&
        !metadata.isSymbolicLink() &&
        metadata.size <= MAX_PROJECT_BYTES
      ) {
        return candidate;
      }
    } catch {
      // Continue toward the repository root.
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  throw new Error("Repro It could not load the reviewed project configuration.");
}

function parseProjectConfig(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_PROJECT_BYTES) {
    throw new Error("The Repro It project configuration is invalid.");
  }
  const project = {};
  for (const sourceLine of bytes.toString("utf8").split(/\r?\n/u)) {
    const line = sourceLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    if (line.startsWith("[")) break;
    const separator = line.indexOf("=");
    if (separator <= 0) {
      throw new Error("The Repro It project configuration is invalid.");
    }
    const key = line.slice(0, separator).trim();
    const raw = line.slice(separator + 1).trim();
    if (!/^[A-Za-z0-9_-]+$/u.test(key) || Object.hasOwn(project, key)) {
      throw new Error("The Repro It project configuration is invalid.");
    }
    if (raw.startsWith('"')) {
      const value = JSON.parse(raw);
      if (typeof value !== "string") throw new TypeError("Invalid string.");
      project[key] = value;
      continue;
    }
    if (!/^(0|[1-9][0-9]*)$/u.test(raw)) {
      throw new Error("The Repro It project configuration is invalid.");
    }
    project[key] = Number.parseInt(raw, 10);
  }
  return project;
}

function gitSourceRevision(projectRoot) {
  const revision = execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
    cwd: projectRoot,
    encoding: "ascii",
    maxBuffer: 65,
    timeout: 2_000,
  }).trim();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(revision)) {
    throw new Error("Repro It could not identify the deployed source revision.");
  }
  return revision;
}
