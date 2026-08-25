import { AsyncLocalStorage } from "node:async_hooks";

import { packageRunningNodeSubject } from "./managed-subject.js";
import {
  NATIVE_ENGINE_MAX_SINK_WAIT_MS,
  NATIVE_ENGINE_MAX_SINK_WAITERS,
  loadNativeEngine,
} from "./native-engine.js";
import { acquireRuntimeObservationAdapters } from "./runtime-observation-adapters.js";

const POLL_MILLISECONDS = 50;
const OPEN_DEPENDENCY = Symbol("open-dependency");
const OPEN_OBSERVATION = Symbol("open-observation");
const MARK_UNOWNED = Symbol("mark-unowned");
const ACTIVE_OPERATION = new AsyncLocalStorage();
const PROJECT_CONSTRUCTOR = Symbol("project-constructor");

// Own one packaged shared engine and its bounded delivery waiters.
export class ManagedEngineProject {
  #bridge;
  #closed = false;
  #engineHandle;
  #projectTokenProvider;
  #releaseRuntimeAdapters;
  #sinkHandles = new Set();

  constructor(
    constructor,
    bridge,
    engineHandle,
    projectTokenProvider,
    releaseRuntimeAdapters = () => {},
  ) {
    if (constructor !== PROJECT_CONSTRUCTOR) {
      throw new TypeError("Use ManagedEngineProject.open().");
    }
    this.#bridge = bridge;
    this.#engineHandle = engineHandle;
    this.#projectTokenProvider = projectTokenProvider;
    this.#releaseRuntimeAdapters = releaseRuntimeAdapters;
  }

  static open(options) {
    const bridge = loadNativeEngine();
    bridge.contract();
    const subject = packageRunningNodeSubject(options.entryScript);
    return openPreparedProject(options, bridge, subject);
  }

  close() {
    if (this.#closed) return;
    this.#closed = true;
    this.#sinkHandles.clear();
    try {
      this.#bridge.engineClose(this.#engineHandle);
    } finally {
      this.#releaseRuntimeAdapters();
    }
  }

  begin(begin) {
    if (this.#closed) return new OperationContext();
    let native;
    try {
      native = this.#bridge.operationBegin(this.#engineHandle, begin);
    } catch {
      return new OperationContext();
    }
    return new OperationContext(this, native);
  }

  call(name, ...values) {
    return this.#bridge[name](...values);
  }

  projectToken() {
    return this.#projectTokenProvider();
  }

  waitForSink(sinkHandle) {
    if (
      this.#closed ||
      this.#sinkHandles.size >= NATIVE_ENGINE_MAX_SINK_WAITERS
    ) {
      return;
    }
    this.#sinkHandles.add(sinkHandle);
    const deadline = Date.now() + NATIVE_ENGINE_MAX_SINK_WAIT_MS;
    const poll = () => {
      if (
        this.#closed ||
        !this.#sinkHandles.has(sinkHandle) ||
        Date.now() >= deadline
      ) {
        this.#sinkHandles.delete(sinkHandle);
        return;
      }
      try {
        if (this.#bridge.sinkWait(sinkHandle, 0)) {
          this.#sinkHandles.delete(sinkHandle);
          return;
        }
      } catch {
        this.#sinkHandles.delete(sinkHandle);
        return;
      }
      const timer = setTimeout(poll, POLL_MILLISECONDS);
      timer.unref?.();
    };
    const timer = setTimeout(poll, 0);
    timer.unref?.();
  }
}

// This seam exercises the normal open lifecycle with package-test resources.
// It is not exported from the public package entry point.
export function openManagedEngineProjectWithForTest(options, bridge, subject) {
  return openPreparedProject(options, bridge, subject);
}

function openPreparedProject(options, bridge, subject) {
  let engineHandle;
  let releaseRuntimeAdapters = () => {};
  let opened = false;
  let subjectDisposed = false;
  try {
    releaseRuntimeAdapters = acquireRuntimeObservationAdapters();
    engineHandle = bridge.engineOpen({
      buildRepositoryId: options.buildRepositoryId,
      projectToml: options.projectToml,
      sourceRevision: options.sourceRevision,
      subjectManifest: subject.manifest,
      subjectObjects: subject.objects.map((value) => ({
        digest: value.digest,
        path: value.path,
        size: value.size,
      })),
    });
    opened = true;
  } finally {
    try {
      subject.dispose();
      subjectDisposed = true;
    } finally {
      if (!opened || !subjectDisposed) {
        closeFailedOpen(bridge, engineHandle, opened);
        releaseRuntimeAdapters();
      }
    }
  }
  return new ManagedEngineProject(
    PROJECT_CONSTRUCTOR,
    bridge,
    engineHandle,
    options.projectTokenProvider,
    releaseRuntimeAdapters,
  );
}

function closeFailedOpen(bridge, engineHandle, opened) {
  if (!opened) return;
  try {
    bridge.engineClose(engineHandle);
  } catch {
    // Cleanup must not replace the subject disposal error.
  }
}

// This seam is available to direct package tests. It is not exported from the
// public package entry point.
export function createManagedEngineProjectForTest(
  bridge,
  engineHandle,
  projectTokenProvider,
) {
  return new ManagedEngineProject(
    PROJECT_CONSTRUCTOR,
    bridge,
    engineHandle,
    projectTokenProvider,
  );
}

// Translate semantic observations into one shared engine operation.
export class OperationContext {
  #native;
  #project;

  constructor(project = null, native = null) {
    this.#project = project;
    this.#native = native;
  }

  get operationId() {
    return this.#native?.operationId ?? null;
  }

  recordInput(value) {
    this.#call("operationInput", value);
  }

  [OPEN_OBSERVATION](observationClass, causalParentId = null) {
    if (this.#project === null || this.#native === null) return null;
    let observation;
    try {
      observation = this.#project.call(
        "observationOpen",
        this.#native.operationHandle,
        observationClass,
        causalParentId,
      );
    } catch {
      this.abandon();
      return null;
    }
    return new ObservationSession(this, this.#project, observation);
  }

  [OPEN_DEPENDENCY](request, causalParentId = null) {
    if (this.#project === null || this.#native === null) return null;
    let dependency;
    try {
      dependency = this.#project.call(
        "dependencyOpen",
        this.#native.operationHandle,
        request,
        causalParentId,
      );
    } catch {
      this.abandon();
      return null;
    }
    return new DependencySession(this, this.#project, dependency);
  }

  [MARK_UNOWNED](observationClass, evidence, causalParentId = null) {
    this.#call(
      "operationUnowned",
      observationClass,
      evidence,
      causalParentId,
    );
  }

  closeSuccess(completion) {
    const state = this.#take();
    if (state === null) return;
    try {
      state.project.call("operationSucceed", state.native.operationHandle);
    } catch {
      safeAbandon(state);
    }
  }

  closeFailure(completion, failure) {
    const state = this.#take();
    if (state === null) return;
    if (failure === null || failure === undefined) {
      safeAbandon(state);
      return;
    }
    let sinkHandle;
    try {
      state.project.call(
        "operationCloseWorld",
        state.native.operationHandle,
        completion,
      );
      sinkHandle = state.project.call(
        "operationFail",
        state.native.operationHandle,
        failure,
        state.project.projectToken(),
      );
    } catch {
      safeAbandon(state);
      return;
    }
    state.project.waitForSink(sinkHandle);
  }

  abandon() {
    const state = this.#take();
    if (state !== null) safeAbandon(state);
  }

  #call(name, ...values) {
    if (this.#project === null || this.#native === null) return;
    try {
      this.#project.call(
        name,
        this.#native.operationHandle,
        ...values,
      );
    } catch {
      this.abandon();
    }
  }

  #take() {
    if (this.#project === null || this.#native === null) return null;
    const state = { native: this.#native, project: this.#project };
    this.#native = null;
    return state;
  }
}

class ObservationSession {
  #context;
  #native;
  #project;

  constructor(context, project, native) {
    this.#context = context;
    this.#project = project;
    this.#native = native;
  }

  writeRequest(chunk) {
    return this.#write("request", chunk);
  }

  writeResponse(chunk) {
    return this.#write("response", chunk);
  }

  dispatch() {
    if (this.#native === null) return null;
    try {
      return this.#project.call(
        "observationDispatch",
        this.#native.observationHandle,
      );
    } catch {
      this.#fail();
      return null;
    }
  }

  readResponse() {
    if (this.#native === null) return null;
    try {
      return this.#project.call(
        "observationRead",
        this.#native.observationHandle,
      );
    } catch {
      this.#fail();
      return null;
    }
  }

  finish(outcome) {
    if (this.#native === null) return false;
    const native = this.#native;
    try {
      this.#project.call(
        "observationFinish",
        native.observationHandle,
        outcome,
        native.sessionPosition,
      );
    } catch {
      this.#fail();
      return false;
    }
    this.#native = null;
    return true;
  }

  abandon() {
    const native = this.#take();
    if (native !== null) {
      try {
        this.#project.call("observationAbandon", native.observationHandle);
      } catch {
        // Observation cleanup must not change application behavior.
      }
    }
    this.#context.abandon();
  }

  #write(stream, chunk) {
    if (this.#native === null) return false;
    try {
      this.#project.call(
        "observationWrite",
        this.#native.observationHandle,
        stream,
        chunk,
      );
    } catch {
      this.#fail();
      return false;
    }
    return true;
  }

  #fail() {
    const native = this.#take();
    if (native !== null) {
      try {
        this.#project.call("observationAbandon", native.observationHandle);
      } catch {
        // Observation cleanup must not change application behavior.
      }
    }
    this.#context.abandon();
  }

  #take() {
    const native = this.#native;
    this.#native = null;
    return native;
  }
}

class DependencySession {
  #context;
  #native;
  #project;

  constructor(context, project, native) {
    this.#context = context;
    this.#project = project;
    this.#native = native;
  }

  get action() {
    return this.#native?.action ?? null;
  }

  readResponse() {
    if (this.#native === null) return null;
    try {
      return this.#project.call(
        "observationRead",
        this.#native.dependencyHandle,
      );
    } catch {
      this.#fail();
      return null;
    }
  }

  finish(response) {
    if (this.#native === null) return null;
    const native = this.#native;
    try {
      const outcome = this.#project.call(
        "dependencyFinish",
        native.dependencyHandle,
        response,
      );
      this.#native = null;
      return outcome;
    } catch {
      this.#fail();
      return null;
    }
  }

  abandon() {
    this.#native = null;
    this.#context.abandon();
  }

  #fail() {
    this.#native = null;
    this.#context.abandon();
  }
}

// These seams are for package-owned semantic adapters. They are not exported
// from the public package entry point.
export function openObservation(
  context,
  observationClass,
  causalParentId = null,
) {
  return context[OPEN_OBSERVATION](observationClass, causalParentId);
}

export function openDependency(context, request, causalParentId = null) {
  return context[OPEN_DEPENDENCY](request, causalParentId);
}

export function markOperationUnowned(
  context,
  observationClass,
  evidence,
  causalParentId = null,
) {
  context[MARK_UNOWNED](observationClass, evidence, causalParentId);
}

// Return the operation owned by the current package execution context.
// This function is not exported from the public package entry point.
export function currentOperationContext() {
  const context = ACTIVE_OPERATION.getStore();
  return context?.operationId === null || context === undefined
    ? null
    : context;
}

// Run one framework-neutral boundary without changing its outcome.
export function runOperation(project, preparation, operation, failure) {
  const context = project.begin(preparation.begin);
  for (const value of preparation.inputs) context.recordInput(value);
  return ACTIVE_OPERATION.run(context, () => {
    let result;
    try {
      result = operation(context);
    } catch (original) {
      finishFailure(context, preparation.completion, original, failure);
      throw original;
    }
    if (result !== null && typeof result?.then === "function") {
      return Promise.resolve(result).then(
        (value) => {
          context.closeSuccess(preparation.completion);
          return value;
        },
        (original) => {
          finishFailure(context, preparation.completion, original, failure);
          throw original;
        },
      );
    }
    context.closeSuccess(preparation.completion);
    return result;
  });
}

function finishFailure(context, completion, original, failure) {
  if (original?.name === "AbortError") {
    context.abandon();
    return;
  }
  let translated;
  try {
    translated = failure(original);
  } catch {
    context.abandon();
    return;
  }
  context.closeFailure(completion, translated);
}

function safeAbandon(state) {
  try {
    state.project.call("operationAbandon", state.native.operationHandle);
  } catch {
    // Capture cleanup must not change application behavior.
  }
}
