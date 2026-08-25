package reproit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAutomaticWorldCoordinatorMethodsAreNotPublic(t *testing.T) {
	operation := reflect.TypeOf((*AutomaticOperation)(nil))
	for _, name := range []string{
		"Observe", "MarkUnowned", "CloseWorld", "ActiveOperation",
	} {
		if _, found := operation.MethodByName(name); found {
			t.Fatal("The automatic operation exposes an internal World coordinator method.")
		}
	}
}

func TestAutomaticOperationContextRestoresNestedAndClosedOperations(t *testing.T) {
	project := automaticContextProject(t)
	defer project.Close()
	outerContext, outer, err := project.StartOperationContext(
		context.Background(), automaticContextStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if active, ok := activeAutomaticOperation(outerContext); !ok || active != outer {
		t.Fatal("The operation context did not bind the outer operation.")
	}
	innerContext, inner, err := project.StartOperationContext(
		outerContext, automaticContextStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if active, ok := activeAutomaticOperation(innerContext); !ok || active != inner {
		t.Fatal("The nested operation context did not bind the inner operation.")
	}
	inner.Close()
	retained, _ := operationBinding(innerContext).snapshot()
	if retained != nil {
		t.Fatal("The operation context retained a closed inner operation.")
	}
	if active, ok := activeAutomaticOperation(innerContext); !ok || active != outer {
		t.Fatal("The nested operation context did not restore the outer operation.")
	}
	outer.Close()
	if _, ok := activeAutomaticOperation(innerContext); ok {
		t.Fatal("The operation context retained a closed operation.")
	}
}

func TestAutomaticOperationContextsStayDistinctAcrossGoroutines(t *testing.T) {
	project := automaticContextProject(t)
	defer project.Close()
	firstContext, first, err := project.StartOperationContext(
		context.Background(), automaticContextStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	secondContext, second, err := project.StartOperationContext(
		context.Background(), automaticContextStart(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	results := make(chan bool, 2)
	go func() {
		active, ok := activeAutomaticOperation(firstContext)
		results <- ok && active == first
	}()
	go func() {
		active, ok := activeAutomaticOperation(secondContext)
		results <- ok && active == second
	}()
	if !<-results || !<-results {
		t.Fatal("Concurrent operation contexts shared active state.")
	}
}

func TestAutomaticOperationContextCancellationClosesTheOperation(t *testing.T) {
	project := automaticContextProject(t)
	defer project.Close()
	parent, cancel := context.WithCancel(context.Background())
	bound, operation, err := project.StartOperationContext(parent, automaticContextStart())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, ok := activeAutomaticOperation(bound); ok {
		t.Fatal("A canceled context returned an active operation.")
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for operation.isActive() {
		select {
		case <-deadline.C:
			t.Fatal("Context cancellation did not close the operation.")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, _, err := project.StartOperationContext(
		canceled, automaticContextStart(),
	); err == nil {
		t.Fatal("The project started an operation for a canceled context.")
	}
}

func automaticContextProject(t *testing.T) *AutomaticProject {
	t.Helper()
	operationIndex := 0
	bridge := automaticTestBridge(t, func(input []byte, output []byte) int64 {
		var request map[string]any
		_ = json.Unmarshal(input, &request)
		result := `{}`
		switch request["operation"] {
		case sdkEngineOperationOpenEngine:
			result = `{"engine_handle":71}`
		case sdkEngineOperationBegin:
			operationIndex++
			result = fmt.Sprintf(
				`{"operation_handle":%d,"operation_id":"op_context_%d"}`,
				71+operationIndex,
				operationIndex,
			)
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
	project, err := openAutomaticProjectWith(
		AutomaticProjectOptions{}, bridge,
		&GoSubjectPackage{Manifest: map[string]any{}, Objects: []PackagedSubjectObject{{
			Digest: "sha256:" + strings.Repeat("f", 64), Path: "/subject", Size: 1,
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func automaticContextStart() AutomaticOperationStart {
	return AutomaticOperationStart{
		AdapterID: "generic", AdapterVersion: "1.0.0",
		Kind: OperationRequestResponse, Name: "operation",
	}
}

func TestAutomaticOperationUsesSharedEngineLifecycle(t *testing.T) {
	requests := make(chan map[string]any, 16)
	bridge := automaticTestBridge(t, func(input []byte, output []byte) int64 {
		var request map[string]any
		if err := json.Unmarshal(input, &request); err != nil {
			t.Fatal("The automatic operation request is not JSON.")
		}
		requests <- request
		var result string
		switch request["operation"] {
		case sdkEngineOperationOpenEngine:
			result = `{"engine_handle":21}`
		case sdkEngineOperationBegin:
			result = `{"operation_handle":22,"operation_id":"op_automatic"}`
		case sdkEngineObservationOpen:
			result = `{"observation_handle":24,"session_position":0}`
		case sdkEngineObservationDispatch:
			result = `{"action":"capture"}`
		case sdkEngineOperationFail:
			result = `{"sink_handle":23}`
		case sdkEngineOperationWaitForSink:
			result = `{"idle":true}`
		default:
			result = `{}`
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
	token, err := NewManagedProjectToken("project-token")
	if err != nil {
		t.Fatal(err)
	}
	project, err := openAutomaticProjectWith(
		AutomaticProjectOptions{
			BuildRepositoryID: "repository",
			ProjectTOML:       "project",
			ProjectTokenProvider: func() (*ManagedProjectToken, error) {
				return token, nil
			},
			SourceRevision: "revision",
		},
		bridge,
		&GoSubjectPackage{
			Manifest: map[string]any{"format": "reproit.subject-closure.v1"},
			Objects: []PackagedSubjectObject{{
				Digest: "sha256:" + strings.Repeat("a", 64), Path: "/subject", Size: 7,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer project.Close()
	operation, err := project.StartOperation(AutomaticOperationStart{
		AdapterID:       "generic-http",
		AdapterVersion:  "1.0.0",
		CausalParentIDs: []string{"op_parent"},
		Kind:            OperationRequestResponse,
		Name:            "orders.place",
	})
	if err != nil || operation.OperationID() != "op_automatic" {
		t.Fatal("The automatic project did not start the shared-engine operation.")
	}
	if err := operation.RecordInput(AutomaticInputChunk{
		Channel: InputData, ContentType: "application/json", Value: []byte("request"),
	}); err != nil {
		t.Fatal(err)
	}
	session, err := operation.openObservationSession(observationDatabase, nil)
	if err != nil || session.writeRequest([]byte("database query")) != nil {
		t.Fatal("The automatic operation did not open an observation session.")
	}
	if action, dispatchErr := session.dispatch(); dispatchErr != nil || action != observationCapture {
		t.Fatal("The automatic operation did not dispatch the observation session.")
	}
	if session.writeResponse([]byte("database result")) != nil ||
		session.finish(observationResponse) != nil {
		t.Fatal(err)
	}
	if err := operation.Fail(CompletionReturn, map[string]any{
		"category":       "explicit",
		"operation_kind": "request-response",
	}); err != nil {
		t.Fatal(err)
	}

	operations := make([]string, 0, 8)
	var inputRequest map[string]any
	var beginRequest map[string]any
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(operations) < 11 {
		select {
		case request := <-requests:
			name := request["operation"].(string)
			operations = append(operations, name)
			if name == sdkEngineOperationBegin {
				beginRequest = request
			}
			if name == sdkEngineOperationInput {
				inputRequest = request
			}
		case <-deadline.C:
			t.Fatal("The automatic operation did not finish shared-engine cleanup.")
		}
	}
	want := []string{
		sdkEngineOperationOpenEngine,
		sdkEngineOperationBegin,
		sdkEngineOperationInput,
		sdkEngineObservationOpen,
		sdkEngineObservationWrite,
		sdkEngineObservationDispatch,
		sdkEngineObservationWrite,
		sdkEngineObservationFinish,
		sdkEngineOperationCloseWorld,
		sdkEngineOperationFail,
		sdkEngineOperationWaitForSink,
	}
	if strings.Join(operations, ",") != strings.Join(want, ",") {
		t.Fatal("The automatic operation did not use the shared-engine lifecycle.")
	}
	begin := beginRequest["begin"].(map[string]any)
	if begin["operation_kind"] != "request-response" ||
		begin["causal_parent_ids"].([]any)[0] != "op_parent" {
		t.Fatal("The automatic operation lost its kind or causal parent.")
	}
	input := inputRequest["input"].(map[string]any)
	if input["input_index"] != float64(0) || input["value"] != "cmVxdWVzdA" {
		t.Fatal("The automatic operation changed its ordered input chunk.")
	}
}

func TestAutomaticOperationSuccessCancellationAndCleanupUseEngine(t *testing.T) {
	var operations []string
	bridge := automaticTestBridge(t, func(input []byte, output []byte) int64 {
		var request map[string]any
		_ = json.Unmarshal(input, &request)
		operation := request["operation"].(string)
		operations = append(operations, operation)
		result := `{}`
		if operation == sdkEngineOperationOpenEngine {
			result = `{"engine_handle":31}`
		} else if operation == sdkEngineOperationBegin {
			result = `{"operation_handle":32,"operation_id":"op_cleanup"}`
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
	project, err := openAutomaticProjectWith(
		AutomaticProjectOptions{}, bridge,
		&GoSubjectPackage{Manifest: map[string]any{}, Objects: []PackagedSubjectObject{{
			Digest: "sha256:" + strings.Repeat("b", 64), Path: "/subject", Size: 1,
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := project.StartOperation(AutomaticOperationStart{})
	first.Succeed()
	second, _ := project.StartOperation(AutomaticOperationStart{})
	second.Cancel()
	third, _ := project.StartOperation(AutomaticOperationStart{})
	third.Close()
	project.Close()
	want := []string{
		sdkEngineOperationOpenEngine,
		sdkEngineOperationBegin,
		sdkEngineOperationSucceed,
		sdkEngineOperationBegin,
		sdkEngineOperationAbandon,
		sdkEngineOperationBegin,
		sdkEngineOperationAbandon,
		sdkEngineOperationCloseEngine,
	}
	if strings.Join(operations, ",") != strings.Join(want, ",") {
		t.Fatal("The automatic operation terminal cleanup changed.")
	}
}

func TestAutomaticOperationFailureDoesNotExposeTokenProviderError(t *testing.T) {
	bridge := automaticTestBridge(t, func(input []byte, output []byte) int64 {
		var request map[string]any
		_ = json.Unmarshal(input, &request)
		result := `{}`
		if request["operation"] == sdkEngineOperationOpenEngine {
			result = `{"engine_handle":41}`
		} else if request["operation"] == sdkEngineOperationBegin {
			result = `{"operation_handle":42,"operation_id":"op_error"}`
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
	const secret = "private-token-provider-detail"
	project, err := openAutomaticProjectWith(
		AutomaticProjectOptions{ProjectTokenProvider: func() (*ManagedProjectToken, error) {
			return nil, errors.New(secret)
		}},
		bridge,
		&GoSubjectPackage{Manifest: map[string]any{}, Objects: []PackagedSubjectObject{{
			Digest: "sha256:" + strings.Repeat("c", 64), Path: "/subject", Size: 1,
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer project.Close()
	operation, _ := project.StartOperation(AutomaticOperationStart{})
	err = operation.Fail(CompletionReturn, map[string]any{})
	if !errors.Is(err, ErrAutomaticCapture) || strings.Contains(err.Error(), secret) {
		t.Fatal("The automatic operation exposed a project-token provider error.")
	}
}

func TestAutomaticOperationRejectCleanupUsesAbandon(t *testing.T) {
	var operations []string
	bridge := automaticTestBridge(t, func(input []byte, output []byte) int64 {
		var request map[string]any
		_ = json.Unmarshal(input, &request)
		name := request["operation"].(string)
		operations = append(operations, name)
		result := sdkEngineSuccess(`{}`)
		switch name {
		case sdkEngineOperationOpenEngine:
			result = sdkEngineSuccess(`{"engine_handle":61}`)
		case sdkEngineOperationBegin:
			result = sdkEngineSuccess(
				`{"operation_handle":62,"operation_id":"op_reject_cleanup"}`,
			)
		case sdkEngineOperationSucceed, sdkEngineOperationFail:
			result = sdkEngineRejected()
		}
		return int64(copy(output, result))
	})
	token, _ := NewManagedProjectToken("project-token")
	project, err := openAutomaticProjectWith(
		AutomaticProjectOptions{ProjectTokenProvider: func() (*ManagedProjectToken, error) {
			return token, nil
		}},
		bridge,
		&GoSubjectPackage{Manifest: map[string]any{}, Objects: []PackagedSubjectObject{{
			Digest: "sha256:" + strings.Repeat("e", 64), Path: "/subject", Size: 1,
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	success, _ := project.StartOperation(AutomaticOperationStart{})
	success.Succeed()
	failure, _ := project.StartOperation(AutomaticOperationStart{})
	if failure.Fail(CompletionReturn, map[string]any{}) == nil {
		t.Fatal("The automatic operation accepted a rejected Failure.")
	}
	project.Close()
	joined := strings.Join(operations, ",")
	if !strings.Contains(joined, "operation-succeed,operation-abandon") ||
		!strings.Contains(joined, "operation-fail,operation-abandon") {
		t.Fatal("The automatic operation retained state after terminal rejection.")
	}
}

func sdkEngineRejected() string {
	return `{"error_code":"SCHEMA_INVALID","format":"reproit.sdk-engine-response.v1",` +
		`"ok":false,"result":{}}`
}

func TestAutomaticProjectCloseStopsSinkPollingBeforeNativeUnload(t *testing.T) {
	waitStarted := make(chan struct{})
	releaseWait := make(chan struct{})
	nativeClosed := make(chan struct{})
	var waitOnce sync.Once
	engine := &fakeSDKEngine{
		version: sdkEngineABIVersion,
		closeResult: func() {
			close(nativeClosed)
		},
		callResult: func(input []byte, output []byte) int64 {
			var request map[string]any
			_ = json.Unmarshal(input, &request)
			result := `{"error_code":null,"format":"reproit.sdk-engine-response.v1",` +
				`"ok":true,"result":{}}`
			switch request["operation"] {
			case sdkEngineOperationOpenEngine:
				result = sdkEngineSuccess(`{"engine_handle":51}`)
			case sdkEngineOperationBegin:
				result = sdkEngineSuccess(
					`{"operation_handle":52,"operation_id":"op_wait_close"}`,
				)
			case sdkEngineOperationFail:
				result = sdkEngineSuccess(`{"sink_handle":53}`)
			case sdkEngineOperationWaitForSink:
				if request["timeout_ms"] != float64(0) {
					t.Error("The sink poll used a blocking native timeout.")
				}
				waitOnce.Do(func() { close(waitStarted) })
				<-releaseWait
				result = sdkEngineSuccess(`{"idle":false}`)
			}
			return int64(copy(output, result))
		},
	}
	bridge, err := openSDKEngineWith(func() (nativeSDKEngine, error) { return engine, nil })
	if err != nil {
		t.Fatal(err)
	}
	token, _ := NewManagedProjectToken("project-token")
	project, err := openAutomaticProjectWith(
		AutomaticProjectOptions{ProjectTokenProvider: func() (*ManagedProjectToken, error) {
			return token, nil
		}},
		bridge,
		&GoSubjectPackage{Manifest: map[string]any{}, Objects: []PackagedSubjectObject{{
			Digest: "sha256:" + strings.Repeat("d", 64), Path: "/subject", Size: 1,
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	operation, _ := project.StartOperation(AutomaticOperationStart{})
	if err := operation.Fail(CompletionReturn, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	<-waitStarted
	closed := make(chan struct{})
	go func() {
		project.Close()
		close(closed)
	}()
	select {
	case <-nativeClosed:
		t.Fatal("The native library unloaded during an active call.")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseWait)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Project close waited beyond the current bounded native call.")
	}
	select {
	case <-nativeClosed:
	default:
		t.Fatal("Project close did not unload the native library.")
	}
}

func automaticTestBridge(
	t *testing.T,
	call func(input []byte, output []byte) int64,
) *sdkEngineBridge {
	t.Helper()
	bridge, err := openSDKEngineWith(func() (nativeSDKEngine, error) {
		return &fakeSDKEngine{version: sdkEngineABIVersion, callResult: call}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bridge
}
