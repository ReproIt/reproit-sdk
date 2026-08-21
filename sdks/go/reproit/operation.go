package reproit

// OperationPreparation contains the complete SDK-owned records available before an operation.
type OperationPreparation struct {
	Begin        map[string]any
	Dependencies []map[string]any
	Inputs       []map[string]any
	Start        CandidateStart
}

// RunOperation captures one operation and preserves its exact application error.
func RunOperation(
	sdk *SDK,
	start CandidateStart,
	begin map[string]any,
	inputs []map[string]any,
	operation func() error,
	failure func(error) map[string]any,
) error {
	return RunPreparedOperation(sdk, OperationPreparation{
		Begin: begin, Inputs: inputs, Start: start,
	}, operation, failure)
}

// RunPreparedOperation captures request-response, stream, or delivered-work operations.
func RunPreparedOperation(
	sdk *SDK,
	preparation OperationPreparation,
	operation func() error,
	failure func(error) map[string]any,
) error {
	captureActive := startPreparedCapture(sdk, preparation)
	defer func() {
		if recovered := recover(); recovered != nil {
			if captureActive {
				safelyAbandonCapture(sdk, preparation.Start.OperationID)
			}
			panic(recovered)
		}
	}()
	result := operation()
	if result != nil {
		if captureActive {
			recordApplicationFailure(sdk, preparation.Start.OperationID, result, failure)
		}
		return result
	}
	if captureActive {
		completeCapture(sdk, preparation.Start.OperationID)
	}
	return nil
}

// RunStreamOperation captures one ordered stream operation.
func RunStreamOperation(
	sdk *SDK,
	preparation OperationPreparation,
	operation func() error,
	failure func(error) map[string]any,
) error {
	return runPreparedKind(sdk, preparation, "stream", operation, failure)
}

// RunDeliveredWork captures one delivered-work operation.
func RunDeliveredWork(
	sdk *SDK,
	preparation OperationPreparation,
	operation func() error,
	failure func(error) map[string]any,
) error {
	return runPreparedKind(sdk, preparation, "delivered-work", operation, failure)
}

func runPreparedKind(
	sdk *SDK,
	preparation OperationPreparation,
	expectedKind string,
	operation func() error,
	failure func(error) map[string]any,
) error {
	if preparation.Begin["operation_kind"] != expectedKind {
		return operation()
	}
	return RunPreparedOperation(sdk, preparation, operation, failure)
}

func startPreparedCapture(sdk *SDK, preparation OperationPreparation) (active bool) {
	operationID := preparation.Start.OperationID
	defer func() {
		if recover() != nil {
			active = false
			safelyAbandonCapture(sdk, operationID)
		}
	}()
	if sdk.Begin(preparation.Start, preparation.Begin) != nil {
		return false
	}
	for _, input := range preparation.Inputs {
		if sdk.RecordInput(operationID, input) != nil {
			sdk.AbandonIncomplete(operationID)
			return false
		}
	}
	for _, dependency := range preparation.Dependencies {
		if sdk.RecordDependency(operationID, dependency) != nil {
			sdk.AbandonIncomplete(operationID)
			return false
		}
	}
	return true
}

func recordApplicationFailure(
	sdk *SDK,
	operationID string,
	applicationError error,
	failure func(error) map[string]any,
) {
	defer safelyAbandonCapture(sdk, operationID)
	defer func() { _ = recover() }()
	_ = sdk.Fail(operationID, failure(applicationError))
}

func recordApplicationPanic(
	sdk *SDK,
	operationID string,
	applicationPanic any,
	failure func(any) map[string]any,
) {
	defer safelyAbandonCapture(sdk, operationID)
	defer func() { _ = recover() }()
	_ = sdk.Fail(operationID, failure(applicationPanic))
}

func completeCapture(sdk *SDK, operationID string) {
	defer func() { _ = recover() }()
	sdk.Succeed(operationID)
}

func safelyAbandonCapture(sdk *SDK, operationID string) {
	defer func() { _ = recover() }()
	sdk.AbandonIncomplete(operationID)
}
