import { Buffer } from "node:buffer";

import { Sdk, canonicalBytes } from "./index.js";
import { ManagedProjectToken } from "./managed-transport.js";
import { digestBytes, encodeBase64url } from "./managed-protocol.js";
import { OfficialManagedProject } from "./official-managed.js";

const MAX_CAPTURED_INPUT_BYTES = 32 * 1_024;
const MAX_CONTENT_TYPE_BYTES = 256;
const MAX_DEPENDENCIES = 1_024;
const MAX_EVENT_BYTES = 65_536;
const MAX_OPERATION_NAME_BYTES = 128;
const requestOperations = new WeakMap();

export function operationFromRequest(request) {
  return requestOperations.get(request) ?? null;
}

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
  #project;
  #worldCapture;

  constructor(project, buildRepositoryId, sourceRevision, worldCapture) {
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

  http(operationName, captureInput, classifyFailure, handler) {
    return (request, response) => {
      let prepared;
      try {
        prepared = captureInput(request);
      } catch {
        return handler(request, response);
      }
      return this.run(
        operationName,
        prepared.contentType,
        prepared.input,
        (operation) => {
          requestOperations.set(request, operation);
          try {
            const result = handler(request, response);
            if (result && typeof result.finally === "function") {
              return result.finally(() => requestOperations.delete(request));
            }
            requestOperations.delete(request);
            return result;
          } catch (error) {
            requestOperations.delete(request);
            throw error;
          }
        },
        classifyFailure,
      );
    };
  }

  #start(operationKind, operationName, contentType, input) {
    try {
      const bytes = Buffer.from(input);
      validateBoundary(operationKind, operationName, contentType, bytes);
      const world = this.#worldCapture();
      if (!(world instanceof ManagedWorldCapture)) return null;
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
