package reproit

import (
	"encoding/json"
	"errors"
	"sync"
)

const (
	sdkEngineABIContractDigest                  = "sha256:72e11b757a7a8e7d76b445001801acc349bc051b041d2e77ed784e731a60eb78"
	sdkEngineABIVersion                         = uint32(1)
	sdkEngineMaxEvidenceBytes                   = 785_408
	sdkEngineMaxObservationAdapters             = 7
	sdkEngineMaxObservationChunkBytes           = 32_768
	sdkEngineMaxObservationReadBytes            = 8_192
	sdkEngineMaxObservationSessions             = 1_024
	sdkEngineMaxObservationSessionsPerOperation = 64
	sdkEngineMaxSemanticDependencyRecordBytes   = 65_536
	sdkEngineMaxSinkWaiters                     = 16
	sdkEngineSinkWaitMilliseconds               = uint64(1_800_000)
	sdkEngineOutputCapacity                     = 16_384
	sdkEngineMaxCallBytes                       = 1_048_576
	sdkEngineContractRequest                    = `{"format":"reproit.sdk-engine-call.v1","operation":"contract"}`
	sdkEngineCallFormat                         = "reproit.sdk-engine-call.v1"
	engineResponseFormat                        = "reproit.sdk-engine-response.v1"
	sdkEngineABIVersionSymbol                   = "reproit_sdk_engine_abi_version"
	sdkEngineCallSymbol                         = "reproit_sdk_engine_call"
)

var (
	errSDKEngineUnavailable = errors.New("The Repro It SDK engine is unavailable.")
	errSDKEngineABI         = errors.New("The Repro It SDK engine ABI is not compatible.")
	errSDKEngineCall        = errors.New("The Repro It SDK engine rejected the operation.")
	errSDKEngineResponse    = errors.New("The Repro It SDK engine returned an invalid response.")
)

var sdkEngineRequiredObservationClasses = [...]automaticObservationClass{
	observationClock,
	observationDatabase,
	observationEnvironment,
	observationFilesystem,
	observationOutboundHTTP,
	observationQueue,
	observationRandomness,
}

type nativeSDKEngine interface {
	abiVersion() uint32
	call(input []byte, output []byte) int64
	close()
}

type sdkEngineBridge struct {
	closed bool
	mu     sync.Mutex
	native nativeSDKEngine
}

func openPackagedSDKEngine() (*sdkEngineBridge, error) {
	libraryPath, err := packagedSDKEnginePath()
	if err != nil {
		return nil, errSDKEngineUnavailable
	}
	return openSDKEngineWith(func() (nativeSDKEngine, error) {
		return openNativeSDKEngine(libraryPath)
	})
}

func openSDKEngineWith(open func() (nativeSDKEngine, error)) (*sdkEngineBridge, error) {
	native, err := open()
	if err != nil || native == nil {
		return nil, errSDKEngineUnavailable
	}
	if native.abiVersion() != sdkEngineABIVersion {
		native.close()
		return nil, errSDKEngineABI
	}
	return &sdkEngineBridge{native: native}, nil
}

func (bridge *sdkEngineBridge) contract() (uint32, error) {
	result, err := bridge.callJSON([]byte(sdkEngineContractRequest))
	if err != nil {
		return 0, err
	}
	equal, err := canonicalEqual(result, expectedSDKEngineContract())
	if err != nil || !equal {
		return 0, errSDKEngineResponse
	}
	return sdkEngineABIVersion, nil
}

func expectedSDKEngineContract() map[string]any {
	operations := make([]any, len(sdkEngineOperationNames))
	for index, operation := range sdkEngineOperationNames {
		operations[index] = operation
	}
	requiredObservationClasses := make([]any, len(sdkEngineRequiredObservationClasses))
	for index, observationClass := range sdkEngineRequiredObservationClasses {
		requiredObservationClasses[index] = string(observationClass)
	}
	return map[string]any{
		"abi_version": int64(sdkEngineABIVersion),
		"dependency_contract": map[string]any{
			"finish_fields":        []any{"dependency_handle", "response"},
			"finish_result_fields": []any{"outcome"},
			"open_fields": []any{
				"causal_parent_id", "operation_handle", "request",
			},
			"open_result_fields":    []any{"action", "dependency_handle"},
			"replay_read_operation": "observation-read",
			"request_fields": []any{
				"encoding", "metadata", "method", "observation_class", "operation",
				"payload", "protocol", "target",
			},
			"response_fields": []any{
				"error_code", "error_number", "metadata", "outcome", "payload", "status",
				"status_code",
			},
		},
		"error_behavior": map[string]any{
			"json_error": map[string]any{
				"error_code_source": "reproit-core-v1",
				"includes_message":  false,
				"includes_request":  false,
				"maximum_bytes":     256,
				"result":            map[string]any{},
			},
			"native_failures": []any{
				map[string]any{"code": -4, "condition": "response-length-overflow", "output_written": false},
				map[string]any{"code": -3, "condition": "output-capacity-exceeded", "output_written": false},
				map[string]any{"code": -2, "condition": "engine-panic", "output_written": false},
				map[string]any{"code": -1, "condition": "invalid-call-boundary", "output_written": false},
			},
			"success": "response-byte-count",
		},
		"format": "reproit.sdk-engine-abi.v1",
		"libraries": []any{
			map[string]any{"name": sdkEngineLinuxLibrary, "platform": "linux-arm64"},
			map[string]any{"name": sdkEngineLinuxLibrary, "platform": "linux-x86_64"},
			map[string]any{"name": sdkEngineMacOSLibrary, "platform": "macos-arm64"},
			map[string]any{"name": sdkEngineWindowsLibrary, "platform": "windows-x86_64"},
		},
		"limits": map[string]any{
			"engines":                            64,
			"evidence_bytes":                     sdkEngineMaxEvidenceBytes,
			"observation_adapters":               sdkEngineMaxObservationAdapters,
			"observation_chunk_bytes":            sdkEngineMaxObservationChunkBytes,
			"observation_response_read_bytes":    sdkEngineMaxObservationReadBytes,
			"observation_sessions":               sdkEngineMaxObservationSessions,
			"observation_sessions_per_operation": sdkEngineMaxObservationSessionsPerOperation,
			"operations":                         512,
			"semantic_dependency_record_bytes":   sdkEngineMaxSemanticDependencyRecordBytes,
			"sink_wait_ms":                       int64(sdkEngineSinkWaitMilliseconds),
			"sinks":                              sdkEngineMaxSinkWaiters,
		},
		"operations":          operations,
		"observation_actions": []any{"capture", "replay"},
		"observation_contract": map[string]any{
			"adapter_implementation_binding": []any{"subject-module-digest"},
			"adapter_registration_fields": []any{
				"adapter_id", "adapter_version", "class", "implementation_digest",
			},
			"finish_fields": []any{
				"observation_handle", "outcome", "session_position",
			},
			"open_fields": []any{
				"causal_parent_id", "class", "operation_handle",
			},
			"open_result_fields": []any{
				"observation_handle", "session_position",
			},
			"read_result_fields": []any{"chunk", "eof"},
			"write_fields":       []any{"chunk", "observation_handle", "stream"},
		},
		"request": map[string]any{
			"format": sdkEngineCallFormat, "maximum_bytes": sdkEngineMaxCallBytes,
		},
		"required_observation_classes": requiredObservationClasses,
		"response": map[string]any{
			"format": engineResponseFormat, "output_capacity_bytes": sdkEngineOutputCapacity,
		},
		"symbols": map[string]any{
			"abi_version": sdkEngineABIVersionSymbol, "call": sdkEngineCallSymbol,
		},
	}
}

func (bridge *sdkEngineBridge) close() {
	if bridge == nil {
		return
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if !bridge.closed && bridge.native != nil {
		bridge.closed = true
		bridge.native.close()
	}
}

func (bridge *sdkEngineBridge) call(request any) (map[string]any, error) {
	input, err := json.Marshal(request)
	if err != nil || len(input) > sdkEngineMaxCallBytes {
		return nil, errSDKEngineCall
	}
	return bridge.callJSON(input)
}

func (bridge *sdkEngineBridge) callJSON(input []byte) (map[string]any, error) {
	if len(input) > sdkEngineMaxCallBytes {
		return nil, errSDKEngineCall
	}
	output := make([]byte, sdkEngineOutputCapacity)
	bridge.mu.Lock()
	if bridge.closed {
		bridge.mu.Unlock()
		return nil, errSDKEngineUnavailable
	}
	written := bridge.native.call(input, output)
	bridge.mu.Unlock()
	if written < 0 || written > sdkEngineOutputCapacity {
		return nil, errSDKEngineResponse
	}
	return parseSDKEngineResponse(output[:written])
}

func parseSDKEngineResponse(value []byte) (map[string]any, error) {
	parsed, err := parseStrictJSON(value, sdkEngineOutputCapacity)
	response, ok := parsed.(map[string]any)
	if err != nil || !ok || !hasExactKeys(response, "error_code", "format", "ok", "result") ||
		response["format"] != engineResponseFormat {
		return nil, errSDKEngineResponse
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		return nil, errSDKEngineResponse
	}
	if response["ok"] == true && response["error_code"] == nil {
		return result, nil
	}
	errorCode, ok := response["error_code"].(string)
	if response["ok"] != false || !ok || errorCode == "" || len(errorCode) > 128 || len(result) != 0 {
		return nil, errSDKEngineResponse
	}
	return nil, errSDKEngineCall
}
