package reproit

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type fakeSDKEngine struct {
	closeResult func()
	callResult  func(input []byte, output []byte) int64
	version     uint32
}

func (engine *fakeSDKEngine) abiVersion() uint32 { return engine.version }
func (engine *fakeSDKEngine) close() {
	if engine.closeResult != nil {
		engine.closeResult()
	}
}
func (engine *fakeSDKEngine) call(input []byte, output []byte) int64 {
	return engine.callResult(input, output)
}

func TestSDKEngineABIVersionAndContract(t *testing.T) {
	contract, err := json.Marshal(expectedSDKEngineContract())
	if err != nil {
		t.Fatal(err)
	}
	validResponse := sdkEngineSuccess(string(contract))
	engine := &fakeSDKEngine{
		version: sdkEngineABIVersion,
		callResult: func(input []byte, output []byte) int64 {
			if string(input) != sdkEngineContractRequest || len(output) != sdkEngineOutputCapacity {
				t.Fatal("The SDK engine bridge changed the bounded contract call.")
			}
			return int64(copy(output, validResponse))
		},
	}
	bridge, err := openSDKEngineWith(func() (nativeSDKEngine, error) { return engine, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()
	version, err := bridge.contract()
	if err != nil || version != sdkEngineABIVersion {
		t.Fatal("The SDK engine contract response was not accepted.")
	}
}

func TestSDKEngineContractRejectsChangedRequiredObservationClasses(t *testing.T) {
	for _, change := range []func([]any) []any{
		func(_ []any) []any { return nil },
		func(values []any) []any { return append([]any{values[1], values[0]}, values[2:]...) },
		func(values []any) []any { return append(append([]any{}, values...), "extra") },
		func(values []any) []any { return append([]any{}, values[:len(values)-1]...) },
	} {
		contract := expectedSDKEngineContract()
		values := contract["required_observation_classes"].([]any)
		if changed := change(values); changed == nil {
			delete(contract, "required_observation_classes")
		} else {
			contract["required_observation_classes"] = changed
		}
		response, _ := json.Marshal(contract)
		if err := contractError(t, []byte(sdkEngineSuccess(string(response))), -1); err == nil {
			t.Fatal("The SDK engine bridge accepted changed required observation classes.")
		}
	}
}

func TestRealSDKEngineContract(t *testing.T) {
	libraryPath := os.Getenv("REPROIT_TEST_SDK_ENGINE_LIBRARY")
	if libraryPath == "" {
		t.Skip("The real SDK engine library was not supplied to this test.")
	}
	bridge, err := openSDKEngineWith(func() (nativeSDKEngine, error) {
		return openNativeSDKEngine(libraryPath)
	})
	if err != nil {
		t.Fatal("The real SDK engine did not load.")
	}
	defer bridge.close()
	if _, err := bridge.contract(); err != nil {
		t.Fatal("The real SDK engine contract does not match the Go bridge.")
	}
}

func TestSDKEngineMissingLibraryIsBounded(t *testing.T) {
	bridge, err := openSDKEngineWith(func() (nativeSDKEngine, error) {
		return nil, errors.New("private loader detail")
	})
	if bridge != nil || !errors.Is(err, errSDKEngineUnavailable) ||
		strings.Contains(err.Error(), "private") {
		t.Fatal("The missing SDK engine exposed a loader detail.")
	}
}

func TestSDKEngineRejectsMalformedResponse(t *testing.T) {
	err := contractError(t, []byte(`{"ok":true`), -1)
	if !errors.Is(err, errSDKEngineResponse) {
		t.Fatal("The SDK engine bridge accepted malformed JSON.")
	}
}

func TestSDKEngineRejectsResponseAboveBound(t *testing.T) {
	err := contractError(t, nil, sdkEngineOutputCapacity+1)
	if !errors.Is(err, errSDKEngineResponse) {
		t.Fatal("The SDK engine bridge accepted an oversized response.")
	}
}

func TestSDKEngineDoesNotEchoSecretResponseBytes(t *testing.T) {
	const secret = "secret-value-that-must-not-escape"
	err := contractError(t, []byte(secret), -1)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("The SDK engine bridge exposed response bytes in an error.")
	}
}

func contractError(t *testing.T, response []byte, returned int) error {
	t.Helper()
	engine := &fakeSDKEngine{
		version: sdkEngineABIVersion,
		callResult: func(_ []byte, output []byte) int64 {
			copy(output, response)
			if returned >= 0 {
				return int64(returned)
			}
			return int64(len(response))
		},
	}
	bridge, err := openSDKEngineWith(func() (nativeSDKEngine, error) { return engine, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()
	_, err = bridge.contract()
	return err
}
