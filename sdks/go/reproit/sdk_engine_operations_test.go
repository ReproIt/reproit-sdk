package reproit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSDKEngineTypedOperations(t *testing.T) {
	wantOperations := []string{
		"engine-open", "operation-begin", "operation-input", "observation-open",
		"observation-write", "observation-dispatch", "observation-write",
		"observation-finish", "observation-open", "observation-abandon",
		"operation-unowned", "operation-close-world", "operation-succeed",
		"operation-abandon", "operation-fail", "sink-wait", "engine-close",
	}
	var gotOperations []string
	engine := &fakeSDKEngine{
		version: sdkEngineABIVersion,
		callResult: func(input []byte, output []byte) int64 {
			var request map[string]any
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal("The typed SDK engine request is not JSON.")
			}
			operation, _ := request["operation"].(string)
			gotOperations = append(gotOperations, operation)
			if request["format"] != sdkEngineCallFormat {
				t.Fatal("The typed SDK engine request has the wrong format.")
			}
			var result string
			switch operation {
			case "engine-open":
				if request["sdk"] != "go" || len(request["observation_adapters"].([]any)) != 0 {
					t.Fatal("The engine-open request lost its SDK.")
				}
				result = `{"engine_handle":11}`
			case "operation-begin":
				result = `{"operation_handle":12,"operation_id":"op_test"}`
			case "observation-open":
				result = `{"observation_handle":14,"session_position":0}`
			case "observation-dispatch":
				result = `{"action":"capture"}`
			case "operation-unowned":
				if request["causal_parent_id"] != "op_parent" {
					t.Fatal("The unowned observation lost its causal parent.")
				}
				result = `{}`
			case "operation-fail":
				if request["project_token"] != "project-token" {
					t.Fatal("The failure request lost its project token.")
				}
				result = `{"sink_handle":13}`
			case "sink-wait":
				if request["timeout_ms"] != float64(250) {
					t.Fatal("The sink wait request changed its timeout.")
				}
				result = `{"idle":true}`
			default:
				result = `{}`
			}
			return int64(copy(output, sdkEngineSuccess(result)))
		},
	}
	bridge, err := openSDKEngineWith(func() (nativeSDKEngine, error) { return engine, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()

	engineHandle, err := bridge.openEngine(sdkEngineOpenOptions{
		BuildRepositoryID: "repository",
		ProjectTOML:       "project",
		SDK:               "go",
		SourceRevision:    "revision",
		SubjectManifest:   json.RawMessage(`{}`),
		SubjectObjects: []sdkEngineSubjectObject{{
			Digest: "sha256:digest", Path: "/subject", Size: 7,
		}},
	})
	if err != nil || engineHandle != 11 {
		t.Fatal("The typed engine-open response was not accepted.")
	}
	start, err := bridge.beginOperation(engineHandle, json.RawMessage(`{}`), nil)
	if err != nil || start.Handle != 12 || start.OperationID != "op_test" {
		t.Fatal("The typed operation-begin response was not accepted.")
	}
	if err := bridge.recordInput(start.Handle, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	observation, err := bridge.openObservation(start.Handle, "outbound-http", nil)
	if err != nil || observation.Handle != 14 || observation.SessionPosition != 0 {
		t.Fatal(err)
	}
	if err := bridge.writeObservation(observation.Handle, "request", []byte{0xfb, 0xff}); err != nil {
		t.Fatal(err)
	}
	if action, err := bridge.dispatchObservation(observation.Handle); err != nil || action != "capture" {
		t.Fatal("The observation dispatch response was not accepted.")
	}
	if err := bridge.writeObservation(observation.Handle, "response", []byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := bridge.finishObservation(observation.Handle, "response", observation.SessionPosition); err != nil {
		t.Fatal(err)
	}
	abandoned, err := bridge.openObservation(start.Handle, "database", nil)
	if err != nil || bridge.abandonObservation(abandoned.Handle) != nil {
		t.Fatal("The observation abandon operation failed.")
	}
	parent := "op_parent"
	if err := bridge.markOperationUnowned(start.Handle, "database", &parent, nil); err != nil {
		t.Fatal(err)
	}
	if err := bridge.closeOperationWorld(start.Handle, "complete"); err != nil {
		t.Fatal(err)
	}
	if err := bridge.succeedOperation(start.Handle); err != nil {
		t.Fatal(err)
	}
	if err := bridge.abandonOperation(start.Handle); err != nil {
		t.Fatal(err)
	}
	sinkHandle, err := bridge.failOperation(
		start.Handle, json.RawMessage(`{}`), "project-token")
	if err != nil || sinkHandle != 13 {
		t.Fatal("The typed operation-fail response was not accepted.")
	}
	idle, err := bridge.waitForSink(sinkHandle, 250)
	if err != nil || !idle {
		t.Fatal("The typed sink-wait response was not accepted.")
	}
	if err := bridge.closeEngine(engineHandle); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotOperations, ",") != strings.Join(wantOperations, ",") {
		t.Fatal("The typed SDK engine operation order changed.")
	}
}

func TestSDKEngineObservationChunkBoundAndReplayEOF(t *testing.T) {
	called := 0
	bridge := operationTestBridge(t, func(input []byte, output []byte) int64 {
		called++
		var request map[string]any
		_ = json.Unmarshal(input, &request)
		if request["operation"] == sdkEngineObservationRead {
			return int64(copy(output, sdkEngineSuccess(`{"chunk":"cmVwbGF5","eof":true}`)))
		}
		return int64(copy(output, sdkEngineSuccess(`{}`)))
	})
	defer bridge.close()
	atLimit := make([]byte, sdkEngineMaxObservationChunkBytes)
	if err := bridge.writeObservation(1, "request", atLimit); err != nil {
		t.Fatal("The observation bridge rejected a chunk at the limit.")
	}
	before := called
	err := bridge.writeObservation(1, "request", make([]byte, len(atLimit)+1))
	if !errors.Is(err, errSDKEngineCall) || called != before {
		t.Fatal("The observation bridge sent a chunk above the limit.")
	}
	read, err := bridge.readObservation(1)
	if err != nil || string(read.Chunk) != "replay" || !read.EOF {
		t.Fatal("The observation bridge rejected replay EOF.")
	}
	oversized := base64.RawURLEncoding.EncodeToString(
		make([]byte, sdkEngineMaxObservationReadBytes+1),
	)
	oversizedBridge := operationTestBridge(t, func(_ []byte, output []byte) int64 {
		return int64(copy(output, sdkEngineSuccess(
			`{"chunk":"`+oversized+`","eof":true}`,
		)))
	})
	defer oversizedBridge.close()
	if _, err := oversizedBridge.readObservation(1); !errors.Is(err, errSDKEngineResponse) {
		t.Fatal("The observation bridge accepted a replay read above the limit.")
	}
}

func TestObservationSessionRejectsInvalidTransitionsLocally(t *testing.T) {
	called := 0
	bridge := operationTestBridge(t, func(input []byte, output []byte) int64 {
		called++
		var request map[string]any
		_ = json.Unmarshal(input, &request)
		result := `{}`
		if request["operation"] == sdkEngineObservationDispatch {
			result = `{"action":"replay"}`
		} else if request["operation"] == sdkEngineObservationRead {
			result = `{"chunk":"","eof":true}`
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
	defer bridge.close()
	session := &observationSession{
		bridge: bridge, handle: 1, sessionPosition: 0, state: observationRequestState,
	}
	before := called
	if err := session.writeResponse([]byte("invalid")); !errors.Is(err, ErrAutomaticCapture) ||
		called != before {
		t.Fatal("The observation session sent an invalid response transition.")
	}
	if err := session.writeRequest([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if action, err := session.dispatch(); err != nil || action != observationReplay {
		t.Fatal("The observation session rejected replay dispatch.")
	}
	chunk, eof, err := session.readResponse()
	if err != nil || len(chunk) != 0 || !eof {
		t.Fatal("The observation session rejected replay EOF.")
	}
	before = called
	if _, _, err := session.readResponse(); !errors.Is(err, ErrAutomaticCapture) || called != before {
		t.Fatal("The observation session sent a read after replay EOF.")
	}
	if err := session.finish(observationResponse); err != nil {
		t.Fatal("The observation session rejected a complete replay.")
	}
}

func TestObservationAdapterRegistryIsBoundedAndDefaultsEmpty(t *testing.T) {
	if got := installedObservationAdapters.snapshot(); len(got) != 0 {
		t.Fatal("The installed observation adapter registry is not empty by default.")
	}
	registry := observationAdapterRegistry{}
	classes := []automaticObservationClass{
		observationClock, observationDatabase, observationEnvironment, observationFilesystem,
		observationOutboundHTTP, observationQueue, observationRandomness,
	}
	for _, class := range classes {
		if err := registry.install(installedObservationAdapter{
			adapterID: "official", adapterVersion: "1.0.0", class: class,
			implementationDigest: "sha256:" + strings.Repeat("a", 64),
		}); err != nil {
			t.Fatal("The registry rejected a supported adapter within the bound.")
		}
	}
	if len(registry.snapshot()) != sdkEngineMaxObservationAdapters {
		t.Fatal("The registry lost an installed observation adapter.")
	}
	if err := registry.install(installedObservationAdapter{
		adapterID: "extra", adapterVersion: "1.0.0", class: observationClock,
		implementationDigest: "sha256:" + strings.Repeat("b", 64),
	}); !errors.Is(err, ErrAutomaticCapture) {
		t.Fatal("The registry accepted an adapter beyond its bound.")
	}
}

func TestSDKEngineOperationErrorIsBounded(t *testing.T) {
	const secret = "project-token-that-must-not-escape"
	bridge := operationTestBridge(t, func(_ []byte, output []byte) int64 {
		response := `{"error_code":"schema_invalid","format":"` + engineResponseFormat +
			`","ok":false,"result":{}}`
		return int64(copy(output, response))
	})
	defer bridge.close()
	_, err := bridge.failOperation(1, json.RawMessage(`{}`), secret)
	if !errors.Is(err, errSDKEngineCall) || strings.Contains(err.Error(), secret) ||
		strings.Contains(err.Error(), "schema_invalid") {
		t.Fatal("The SDK engine operation error exposed bounded engine or request data.")
	}
}

func TestSDKEngineRejectsOversizedOperationBeforeNativeCall(t *testing.T) {
	called := false
	bridge := operationTestBridge(t, func(_ []byte, _ []byte) int64 {
		called = true
		return 0
	})
	defer bridge.close()
	_, err := bridge.openEngine(sdkEngineOpenOptions{
		ProjectTOML: strings.Repeat("x", sdkEngineMaxCallBytes),
	})
	if !errors.Is(err, errSDKEngineCall) || called {
		t.Fatal("The SDK engine bridge sent an oversized operation to native code.")
	}
}

func TestSDKEngineRejectsMalformedTypedResult(t *testing.T) {
	bridge := operationTestBridge(t, func(_ []byte, output []byte) int64 {
		return int64(copy(output, sdkEngineSuccess(`{"engine_handle":0}`)))
	})
	defer bridge.close()
	_, err := bridge.openEngine(sdkEngineOpenOptions{SubjectManifest: json.RawMessage(`{}`)})
	if !errors.Is(err, errSDKEngineResponse) {
		t.Fatal("The SDK engine bridge accepted an invalid typed handle.")
	}
}

func operationTestBridge(
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

func sdkEngineSuccess(result string) string {
	return fmt.Sprintf(
		`{"error_code":null,"format":"%s","ok":true,"result":%s}`,
		engineResponseFormat,
		result,
	)
}
