package reproit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestSDKEngineDependencyBridgeUsesExactCallShape(t *testing.T) {
	var calls []map[string]any
	bridge := operationTestBridge(t, func(input []byte, output []byte) int64 {
		var call map[string]any
		_ = json.Unmarshal(input, &call)
		calls = append(calls, call)
		result := `{}`
		if call["operation"] == sdkEngineDependencyOpen {
			result = `{"action":"capture","dependency_handle":41}`
		} else if call["operation"] == sdkEngineDependencyFinish {
			result = `{"outcome":"response"}`
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
	defer bridge.close()
	parent := "op_parent"
	started, err := bridge.openDependency(7, &parent, sdkEngineDependencyRequest{
		Encoding: "bytes",
		Metadata: []sdkEngineDependencyMetadata{
			{Name: "eC10YWc", Value: "Zmlyc3Q"},
			{Name: "eC10YWc", Value: "c2Vjb25k"},
		},
		ObservationClass: "outbound-http",
		Operation:        "outbound-http-request",
		Payload:          "cGF5bG9hZA",
		Protocol:         "http-1.1",
		Target:           "aHR0cHM6Ly9leGFtcGxlLmNvbQ",
	})
	if err != nil || started.Action != "capture" || started.Handle != 41 {
		t.Fatal("The dependency-open result was rejected.")
	}
	payload := ""
	outcome, err := bridge.finishDependency(started.Handle, &sdkEngineDependencyResponse{
		Metadata: []sdkEngineDependencyMetadata{}, Outcome: "response", Payload: &payload,
	})
	if err != nil || outcome != "response" {
		t.Fatal("The dependency-finish result was rejected.")
	}
	open := calls[0]
	request := open["request"].(map[string]any)
	metadata := request["metadata"].([]any)
	if !hasExactKeys(open,
		"causal_parent_id", "format", "operation", "operation_handle", "request") ||
		!hasExactKeys(request,
			"encoding", "metadata", "method", "observation_class", "operation", "payload",
			"protocol", "target") || open["causal_parent_id"] != parent ||
		metadata[0].(map[string]any)["value"] != "Zmlyc3Q" ||
		metadata[1].(map[string]any)["value"] != "c2Vjb25k" {
		t.Fatal("The dependency bridge changed its exact call shape or metadata order.")
	}
	finish := calls[1]
	if !hasExactKeys(finish, "dependency_handle", "format", "operation", "response") {
		t.Fatal("The dependency-finish call has unexpected fields.")
	}
}

func TestSemanticDependencyCapturePreservesLiveSuccessAndError(t *testing.T) {
	for _, outcome := range []observationOutcome{observationResponse, observationError} {
		t.Run(string(outcome), func(t *testing.T) {
			var calls []string
			bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
				name := call["operation"].(string)
				calls = append(calls, name)
				if name == sdkEngineDependencyFinish {
					return sdkEngineSuccess(`{"outcome":"` + string(outcome) + `"}`)
				}
				return ""
			})
			defer bridge.close()
			response := semanticTestResponse(outcome)
			sentinel := errors.New("sentinel dependency error")
			var liveErr error
			if outcome == observationError {
				liveErr = sentinel
			}
			liveCalls := 0
			got, gotErr := translateSemanticDependency(
				semanticTestOperation(bridge), semanticTestRequest(), nil,
				func() (semanticDependencyResponse, error) {
					liveCalls++
					return response, liveErr
				},
			)
			if liveCalls != 1 || gotErr != liveErr || !reflect.DeepEqual(got, response) ||
				!reflect.DeepEqual(calls, []string{sdkEngineDependencyOpen, sdkEngineDependencyFinish}) {
				t.Fatal("Capture changed the exact live result, error, or engine sequence.")
			}
		})
	}
}

func TestSemanticDependencyCaptureFailsOpenAtEveryEngineBoundary(t *testing.T) {
	tests := []struct {
		name             string
		failOperation    string
		oversizedRequest bool
		oversizedResult  bool
	}{
		{name: "request conversion", oversizedRequest: true},
		{name: "dependency open", failOperation: sdkEngineDependencyOpen},
		{name: "response conversion", oversizedResult: true},
		{name: "dependency finish", failOperation: sdkEngineDependencyFinish},
	}
	for _, test := range tests {
		for _, withError := range []bool{false, true} {
			t.Run(test.name, func(t *testing.T) {
				bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
					if call["operation"] == test.failOperation {
						return semanticEngineRejected()
					}
					return ""
				})
				defer bridge.close()
				request := semanticTestRequest()
				if test.oversizedRequest {
					request.Metadata = []semanticDependencyMetadata{{
						Name: make([]byte, sdkEngineMaxCallBytes+1),
					}}
				}
				response := semanticTestResponse(observationResponse)
				if test.oversizedResult {
					response.Metadata = []semanticDependencyMetadata{{
						Name: make([]byte, sdkEngineMaxCallBytes+1),
					}}
				}
				sentinel := errors.New("sentinel dependency error")
				var wantErr error
				if withError {
					wantErr = sentinel
				}
				liveCalls := 0
				got, gotErr := translateSemanticDependency(
					semanticTestOperation(bridge), request, nil,
					func() (semanticDependencyResponse, error) {
						liveCalls++
						return response, wantErr
					},
				)
				if liveCalls != 1 || gotErr != wantErr || !reflect.DeepEqual(got, response) {
					t.Fatal("A capture failure changed the exact live result or error.")
				}
			})
		}
	}
}

func TestSemanticDependencyReplayReadsChunksAfterEngineValidation(t *testing.T) {
	record := semanticPublishedResponse(t, "semantic_dependency_response_outbound_http")
	split := len(record) / 2
	reads := [][]byte{record[:split], record[split:]}
	bridge := semanticDependencyBridge(t, "replay", reads, nil)
	defer bridge.close()
	liveCalled := false
	response, err := translateSemanticDependency(
		semanticTestOperation(bridge), semanticTestRequest(), nil,
		func() (semanticDependencyResponse, error) {
			liveCalled = true
			return semanticDependencyResponse{}, nil
		},
	)
	if err != nil || liveCalled || response.Outcome != observationResponse ||
		response.StatusCode == nil || *response.StatusCode != 200 ||
		!response.HasPayload || string(response.Payload) != `{"available":true}` {
		t.Fatal("Replay did not reconstruct the engine-validated dependency response.")
	}
}

func TestSemanticDependencyUsesEngineValidatedOutcome(t *testing.T) {
	record := semanticPublishedResponse(t, "semantic_dependency_response_outbound_http")
	var wire map[string]any
	if json.Unmarshal(record, &wire) != nil {
		t.Fatal("The published dependency response could not be decoded.")
	}
	wire["outcome"] = "error"
	record, _ = json.Marshal(wire)
	response, err := reconstructSemanticDependencyResponse(record, "response")
	if err != nil || response.Outcome != observationResponse {
		t.Fatal("The language bridge duplicated the engine outcome validation.")
	}
}

func TestSemanticDependencyReplayNeverFallsBackToLive(t *testing.T) {
	tests := []struct {
		name          string
		reads         [][]byte
		finishFailure bool
	}{
		{name: "empty read", reads: [][]byte{{}}},
		{name: "record over bound", reads: [][]byte{
			make([]byte, sdkEngineMaxSemanticDependencyRecordBytes), {1},
		}},
		{name: "finish rejection", reads: [][]byte{[]byte(`{}`)}, finishFailure: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bridge := semanticDependencyBridge(t, "replay", test.reads, func(call map[string]any) string {
				if test.finishFailure && call["operation"] == sdkEngineDependencyFinish {
					return semanticEngineRejected()
				}
				return ""
			})
			defer bridge.close()
			liveCalled := false
			_, err := translateSemanticDependency(
				semanticTestOperation(bridge), semanticTestRequest(), nil,
				func() (semanticDependencyResponse, error) {
					liveCalled = true
					return semanticDependencyResponse{}, nil
				},
			)
			if !errors.Is(err, ErrAutomaticCapture) || liveCalled {
				t.Fatal("Strict replay fell back to the live dependency.")
			}
		})
	}
}

func semanticDependencyBridge(
	t *testing.T,
	action string,
	reads [][]byte,
	intercept func(map[string]any) string,
) *sdkEngineBridge {
	t.Helper()
	readIndex := 0
	return operationTestBridge(t, func(input []byte, output []byte) int64 {
		var call map[string]any
		_ = json.Unmarshal(input, &call)
		if intercept != nil {
			if result := intercept(call); result != "" {
				return int64(copy(output, result))
			}
		}
		result := `{}`
		switch call["operation"] {
		case sdkEngineDependencyOpen:
			result = `{"action":"` + action + `","dependency_handle":71}`
		case sdkEngineObservationRead:
			chunk := reads[readIndex]
			readIndex++
			result = `{"chunk":"` + base64.RawURLEncoding.EncodeToString(chunk) +
				`","eof":` + map[bool]string{true: "true", false: "false"}[readIndex == len(reads)] + `}`
		case sdkEngineDependencyFinish:
			result = `{"outcome":"response"}`
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
}

func semanticTestRequest() semanticDependencyRequest {
	method := "POST"
	return semanticDependencyRequest{
		Encoding: "http-1.1-message",
		Metadata: []semanticDependencyMetadata{
			{Name: []byte("x-tag"), Value: []byte("first")},
			{Name: []byte("x-tag"), Value: []byte("second")},
		},
		Method:           &method,
		ObservationClass: observationOutboundHTTP,
		Operation:        "outbound-http-request",
		Payload:          []byte(`{"quantity":1}`),
		Protocol:         "http-1.1",
		Target:           "https://inventory.example/v1/items/42",
	}
}

func semanticTestResponse(outcome observationOutcome) semanticDependencyResponse {
	if outcome == observationError {
		code := "other"
		return semanticDependencyResponse{ErrorCode: &code, Outcome: outcome}
	}
	status := uint16(200)
	return semanticDependencyResponse{
		Metadata: []semanticDependencyMetadata{{
			Name: []byte("content-type"), Value: []byte("application/json"),
		}},
		Outcome:    outcome,
		Payload:    []byte(`{"available":true}`),
		HasPayload: true,
		StatusCode: &status,
	}
}

func semanticPublishedResponse(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(os.Getenv("REPROIT_PROTOCOL_VECTORS"))
	if err != nil {
		t.Fatal("The published protocol vectors are unavailable.")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var vectors struct {
		Positive map[string]struct {
			Value map[string]any `json:"value"`
		} `json:"positive"`
	}
	if decoder.Decode(&vectors) != nil {
		t.Fatal("The published protocol vectors are invalid.")
	}
	record, err := CanonicalBytes(vectors.Positive[name].Value)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func semanticTestOperation(bridge *sdkEngineBridge) *AutomaticOperation {
	project := &AutomaticProject{bridge: bridge}
	return &AutomaticOperation{handle: 1, operationID: "op_semantic", project: project}
}

func semanticEngineRejected() string {
	return `{"error_code":"SCHEMA_INVALID","format":"` + engineResponseFormat +
		`","ok":false,"result":{}}`
}
