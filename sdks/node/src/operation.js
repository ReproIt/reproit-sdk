export function runOperation(sdk, start, begin, inputs, operation, failure) {
  return runPreparedOperation(
    sdk,
    { begin, dependencies: [], inputs, start },
    operation,
    failure,
  );
}

export function runPreparedOperation(sdk, preparation, operation, failure) {
  const captureActive = startCapture(sdk, preparation);
  const finishSuccess = () => {
    if (!captureActive) return;
    try {
      sdk.succeed(preparation.start.operationId);
    } catch {
      abandonIncomplete(sdk, preparation.start.operationId);
    }
  };
  const finishFailure = (original) => {
    if (!captureActive) return;
    try {
      sdk.fail(preparation.start.operationId, failure(original));
    } catch {
      // Capture failure must not replace the application failure.
    } finally {
      abandonIncomplete(sdk, preparation.start.operationId);
    }
  };
  try {
    const result = operation();
    if (result && typeof result.then === "function") {
      return result.then(
        (value) => {
          finishSuccess();
          return value;
        },
        (original) => {
          finishFailure(original);
          throw original;
        },
      );
    }
    finishSuccess();
    return result;
  } catch (original) {
    finishFailure(original);
    throw original;
  }
}

export function runStreamOperation(sdk, preparation, operation, failure) {
  return runPreparedKind(sdk, preparation, "stream", operation, failure);
}

export function runDeliveredWork(sdk, preparation, operation, failure) {
  return runPreparedKind(
    sdk,
    preparation,
    "delivered-work",
    operation,
    failure,
  );
}

function runPreparedKind(sdk, preparation, expectedKind, operation, failure) {
  if (preparation?.begin?.operation_kind !== expectedKind) return operation();
  return runPreparedOperation(sdk, preparation, operation, failure);
}

function startCapture(sdk, preparation) {
  try {
    sdk.begin(preparation.start, preparation.begin);
    for (const input of preparation.inputs) {
      sdk.recordInput(preparation.start.operationId, input);
    }
    for (const dependency of preparation.dependencies) {
      sdk.recordDependency(preparation.start.operationId, dependency);
    }
    return true;
  } catch {
    abandonIncomplete(sdk, preparation?.start?.operationId);
    return false;
  }
}

function abandonIncomplete(sdk, operationId) {
  try {
    sdk.abandonIncomplete(operationId);
  } catch {
    try {
      sdk.cancel(operationId);
    } catch {
      // Cleanup failure must not change application behavior.
    }
  }
}
