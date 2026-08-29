package reproit

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
)

const (
	sdkEngineOperationContract    = "contract"
	sdkEngineDependencyFinish     = "dependency-finish"
	sdkEngineDependencyOpen       = "dependency-open"
	sdkEngineOperationCloseEngine = "engine-close"
	sdkEngineOperationOpenEngine  = "engine-open"
	sdkEngineObservationAbandon   = "observation-abandon"
	sdkEngineObservationDispatch  = "observation-dispatch"
	sdkEngineObservationFinish    = "observation-finish"
	sdkEngineObservationOpen      = "observation-open"
	sdkEngineObservationRead      = "observation-read"
	sdkEngineObservationWrite     = "observation-write"
	sdkEngineOperationAbandon     = "operation-abandon"
	sdkEngineOperationBegin       = "operation-begin"
	sdkEngineOperationCloseWorld  = "operation-close-world"
	sdkEngineOperationFail        = "operation-fail"
	sdkEngineOperationInput       = "operation-input"
	sdkEngineOperationSucceed     = "operation-succeed"
	sdkEngineOperationUnowned     = "operation-unowned"
	sdkEngineOperationWaitForSink = "sink-wait"
)

var sdkEngineOperationNames = []string{
	sdkEngineOperationContract,
	sdkEngineDependencyFinish,
	sdkEngineDependencyOpen,
	sdkEngineOperationCloseEngine,
	sdkEngineOperationOpenEngine,
	sdkEngineObservationAbandon,
	sdkEngineObservationDispatch,
	sdkEngineObservationFinish,
	sdkEngineObservationOpen,
	sdkEngineObservationRead,
	sdkEngineObservationWrite,
	sdkEngineOperationAbandon,
	sdkEngineOperationBegin,
	sdkEngineOperationCloseWorld,
	sdkEngineOperationFail,
	sdkEngineOperationInput,
	sdkEngineOperationSucceed,
	sdkEngineOperationUnowned,
	sdkEngineOperationWaitForSink,
}

type sdkEngineHandle uint64
type sdkEngineOperationHandle uint64
type sdkEngineSinkHandle uint64
type sdkEngineObservationHandle uint64
type sdkEngineDependencyHandle uint64

type sdkEngineObservationAdapter struct {
	AdapterID            string `json:"adapter_id"`
	AdapterVersion       string `json:"adapter_version"`
	Class                string `json:"class"`
	ImplementationDigest string `json:"implementation_digest"`
}

type sdkEngineSubjectObject struct {
	Digest string `json:"digest"`
	Path   string `json:"path"`
	Size   uint64 `json:"size"`
}

type sdkEngineOpenOptions struct {
	BuildRepositoryID   string
	ProjectTOML         string
	SDK                 string
	SourceRevision      string
	SubjectManifest     json.RawMessage
	SubjectObjects      []sdkEngineSubjectObject
	ObservationAdapters []sdkEngineObservationAdapter
}

type sdkEngineOperationStart struct {
	Handle      sdkEngineOperationHandle
	OperationID string
}

type sdkEngineFuzzContextInput struct {
	Encoded         string `json:"encoded"`
	Now             string `json:"now"`
	ProjectID       string `json:"project_id"`
	ServiceID       string `json:"service_id"`
	VerificationKey string `json:"verification_key"`
}

type sdkEngineObservationStart struct {
	Handle          sdkEngineObservationHandle
	SessionPosition uint64
}

type sdkEngineObservationChunk struct {
	Chunk []byte
	EOF   bool
}

type sdkEngineDependencyStart struct {
	Action string
	Handle sdkEngineDependencyHandle
}

func (bridge *sdkEngineBridge) openEngine(options sdkEngineOpenOptions) (sdkEngineHandle, error) {
	observationAdapters := options.ObservationAdapters
	if observationAdapters == nil {
		observationAdapters = make([]sdkEngineObservationAdapter, 0)
	}
	result, err := bridge.call(struct {
		BuildRepositoryID   string                        `json:"build_repository_id"`
		Format              string                        `json:"format"`
		Operation           string                        `json:"operation"`
		ObservationAdapters []sdkEngineObservationAdapter `json:"observation_adapters"`
		ProjectTOML         string                        `json:"project_toml"`
		SDK                 string                        `json:"sdk"`
		SourceRevision      string                        `json:"source_revision"`
		SubjectManifest     json.RawMessage               `json:"subject_manifest"`
		SubjectObjects      []sdkEngineSubjectObject      `json:"subject_objects"`
	}{
		BuildRepositoryID:   options.BuildRepositoryID,
		Format:              sdkEngineCallFormat,
		Operation:           sdkEngineOperationOpenEngine,
		ObservationAdapters: observationAdapters,
		ProjectTOML:         options.ProjectTOML,
		SDK:                 options.SDK,
		SourceRevision:      options.SourceRevision,
		SubjectManifest:     options.SubjectManifest,
		SubjectObjects:      options.SubjectObjects,
	})
	if err != nil {
		return 0, err
	}
	handle, ok := positiveHandle(result, "engine_handle")
	return sdkEngineHandle(handle), resultError(ok)
}

func (bridge *sdkEngineBridge) closeEngine(handle sdkEngineHandle) error {
	return bridge.emptyResult(struct {
		EngineHandle sdkEngineHandle `json:"engine_handle"`
		Format       string          `json:"format"`
		Operation    string          `json:"operation"`
	}{handle, sdkEngineCallFormat, sdkEngineOperationCloseEngine})
}

func (bridge *sdkEngineBridge) beginOperation(
	handle sdkEngineHandle,
	begin json.RawMessage,
	fuzzContext *sdkEngineFuzzContextInput,
) (sdkEngineOperationStart, error) {
	result, err := bridge.call(struct {
		Begin        json.RawMessage            `json:"begin"`
		EngineHandle sdkEngineHandle            `json:"engine_handle"`
		Format       string                     `json:"format"`
		FuzzContext  *sdkEngineFuzzContextInput `json:"fuzz_context,omitempty"`
		Operation    string                     `json:"operation"`
	}{begin, handle, sdkEngineCallFormat, fuzzContext, sdkEngineOperationBegin})
	if err != nil {
		return sdkEngineOperationStart{}, err
	}
	nativeHandle, handleOK := positiveHandle(result, "operation_handle", "operation_id")
	operationID, idOK := result["operation_id"].(string)
	if !handleOK || !idOK || operationID == "" || len(operationID) > 256 {
		return sdkEngineOperationStart{}, errSDKEngineResponse
	}
	return sdkEngineOperationStart{sdkEngineOperationHandle(nativeHandle), operationID}, nil
}

func (bridge *sdkEngineBridge) recordInput(
	handle sdkEngineOperationHandle,
	input json.RawMessage,
) error {
	return bridge.emptyResult(struct {
		Format          string                   `json:"format"`
		Input           json.RawMessage          `json:"input"`
		Operation       string                   `json:"operation"`
		OperationHandle sdkEngineOperationHandle `json:"operation_handle"`
	}{sdkEngineCallFormat, input, sdkEngineOperationInput, handle})
}

func (bridge *sdkEngineBridge) openDependency(
	handle sdkEngineOperationHandle,
	causalParentID *string,
	request sdkEngineDependencyRequest,
) (sdkEngineDependencyStart, error) {
	result, err := bridge.call(struct {
		CausalParentID  *string                    `json:"causal_parent_id"`
		Format          string                     `json:"format"`
		Operation       string                     `json:"operation"`
		OperationHandle sdkEngineOperationHandle   `json:"operation_handle"`
		Request         sdkEngineDependencyRequest `json:"request"`
	}{causalParentID, sdkEngineCallFormat, sdkEngineDependencyOpen, handle, request})
	if err != nil {
		return sdkEngineDependencyStart{}, err
	}
	dependencyHandle, handleOK := positiveHandle(result, "dependency_handle", "action")
	action, actionOK := result["action"].(string)
	if !handleOK || !actionOK || (action != "capture" && action != "replay") {
		return sdkEngineDependencyStart{}, errSDKEngineResponse
	}
	return sdkEngineDependencyStart{
		Action: action, Handle: sdkEngineDependencyHandle(dependencyHandle),
	}, nil
}

func (bridge *sdkEngineBridge) finishDependency(
	handle sdkEngineDependencyHandle,
	response *sdkEngineDependencyResponse,
) (string, error) {
	result, err := bridge.call(struct {
		DependencyHandle sdkEngineDependencyHandle    `json:"dependency_handle"`
		Format           string                       `json:"format"`
		Operation        string                       `json:"operation"`
		Response         *sdkEngineDependencyResponse `json:"response"`
	}{handle, sdkEngineCallFormat, sdkEngineDependencyFinish, response})
	if err != nil {
		return "", err
	}
	outcome, ok := result["outcome"].(string)
	if !hasExactKeys(result, "outcome") || !ok ||
		(outcome != "error" && outcome != "response") {
		return "", errSDKEngineResponse
	}
	return outcome, nil
}

func (bridge *sdkEngineBridge) openObservation(
	handle sdkEngineOperationHandle,
	class string,
	causalParentID *string,
) (sdkEngineObservationStart, error) {
	result, err := bridge.call(struct {
		CausalParentID  *string                  `json:"causal_parent_id"`
		Class           string                   `json:"class"`
		Format          string                   `json:"format"`
		Operation       string                   `json:"operation"`
		OperationHandle sdkEngineOperationHandle `json:"operation_handle"`
	}{causalParentID, class, sdkEngineCallFormat, sdkEngineObservationOpen, handle})
	if err != nil {
		return sdkEngineObservationStart{}, err
	}
	nativeHandle, handleOK := positiveHandle(result, "observation_handle", "session_position")
	position, positionOK := uint64Value(result["session_position"])
	if !handleOK || !positionOK {
		return sdkEngineObservationStart{}, errSDKEngineResponse
	}
	return sdkEngineObservationStart{sdkEngineObservationHandle(nativeHandle), position}, nil
}

func (bridge *sdkEngineBridge) writeObservation(
	handle sdkEngineObservationHandle, stream string, chunk []byte,
) error {
	if len(chunk) == 0 || len(chunk) > sdkEngineMaxObservationChunkBytes {
		return errSDKEngineCall
	}
	return bridge.emptyResult(struct {
		Chunk             string                     `json:"chunk"`
		Format            string                     `json:"format"`
		ObservationHandle sdkEngineObservationHandle `json:"observation_handle"`
		Operation         string                     `json:"operation"`
		Stream            string                     `json:"stream"`
	}{base64.RawURLEncoding.EncodeToString(chunk), sdkEngineCallFormat, handle,
		sdkEngineObservationWrite, stream})
}

func (bridge *sdkEngineBridge) dispatchObservation(handle sdkEngineObservationHandle) (string, error) {
	result, err := bridge.call(struct {
		Format            string                     `json:"format"`
		ObservationHandle sdkEngineObservationHandle `json:"observation_handle"`
		Operation         string                     `json:"operation"`
	}{sdkEngineCallFormat, handle, sdkEngineObservationDispatch})
	if err != nil {
		return "", err
	}
	action, ok := result["action"].(string)
	if !hasExactKeys(result, "action") || !ok || (action != "capture" && action != "replay") {
		return "", errSDKEngineResponse
	}
	return action, nil
}

func (bridge *sdkEngineBridge) readObservation(handle sdkEngineObservationHandle) (sdkEngineObservationChunk, error) {
	result, err := bridge.call(struct {
		Format            string                     `json:"format"`
		ObservationHandle sdkEngineObservationHandle `json:"observation_handle"`
		Operation         string                     `json:"operation"`
	}{sdkEngineCallFormat, handle, sdkEngineObservationRead})
	if err != nil {
		return sdkEngineObservationChunk{}, err
	}
	encoded, encodedOK := result["chunk"].(string)
	eof, eofOK := result["eof"].(bool)
	chunk, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
	if !hasExactKeys(result, "chunk", "eof") || !encodedOK || !eofOK || decodeErr != nil ||
		len(chunk) > sdkEngineMaxObservationReadBytes {
		return sdkEngineObservationChunk{}, errSDKEngineResponse
	}
	return sdkEngineObservationChunk{Chunk: chunk, EOF: eof}, nil
}

func (bridge *sdkEngineBridge) finishObservation(
	handle sdkEngineObservationHandle, outcome string, sessionPosition uint64,
) error {
	return bridge.emptyResult(struct {
		Format            string                     `json:"format"`
		ObservationHandle sdkEngineObservationHandle `json:"observation_handle"`
		Operation         string                     `json:"operation"`
		Outcome           string                     `json:"outcome"`
		SessionPosition   uint64                     `json:"session_position"`
	}{sdkEngineCallFormat, handle, sdkEngineObservationFinish, outcome, sessionPosition})
}

func (bridge *sdkEngineBridge) abandonObservation(handle sdkEngineObservationHandle) error {
	return bridge.emptyResult(struct {
		Format            string                     `json:"format"`
		ObservationHandle sdkEngineObservationHandle `json:"observation_handle"`
		Operation         string                     `json:"operation"`
	}{sdkEngineCallFormat, handle, sdkEngineObservationAbandon})
}

func (bridge *sdkEngineBridge) markOperationUnowned(
	handle sdkEngineOperationHandle,
	class string,
	causalParentID *string,
	evidence []byte,
) error {
	return bridge.unownedObservation(handle, class, causalParentID, evidence)
}

func (bridge *sdkEngineBridge) unownedObservation(
	handle sdkEngineOperationHandle,
	class string,
	causalParentID *string,
	evidence []byte,
) error {
	if len(evidence) > sdkEngineMaxEvidenceBytes {
		return errSDKEngineCall
	}
	return bridge.emptyResult(struct {
		CausalParentID  *string                  `json:"causal_parent_id"`
		Class           string                   `json:"class"`
		Evidence        string                   `json:"evidence"`
		Format          string                   `json:"format"`
		Operation       string                   `json:"operation"`
		OperationHandle sdkEngineOperationHandle `json:"operation_handle"`
	}{causalParentID, class, base64.RawURLEncoding.EncodeToString(evidence), sdkEngineCallFormat,
		sdkEngineOperationUnowned, handle})
}

func (bridge *sdkEngineBridge) closeOperationWorld(
	handle sdkEngineOperationHandle,
	completion string,
) error {
	return bridge.emptyResult(struct {
		Completion      string                   `json:"completion"`
		Format          string                   `json:"format"`
		Operation       string                   `json:"operation"`
		OperationHandle sdkEngineOperationHandle `json:"operation_handle"`
	}{completion, sdkEngineCallFormat, sdkEngineOperationCloseWorld, handle})
}

func (bridge *sdkEngineBridge) succeedOperation(handle sdkEngineOperationHandle) error {
	return bridge.operationTerminal(sdkEngineOperationSucceed, handle)
}

func (bridge *sdkEngineBridge) abandonOperation(handle sdkEngineOperationHandle) error {
	return bridge.operationTerminal(sdkEngineOperationAbandon, handle)
}

func (bridge *sdkEngineBridge) operationTerminal(
	operation string,
	handle sdkEngineOperationHandle,
) error {
	return bridge.emptyResult(struct {
		Format          string                   `json:"format"`
		Operation       string                   `json:"operation"`
		OperationHandle sdkEngineOperationHandle `json:"operation_handle"`
	}{sdkEngineCallFormat, operation, handle})
}

func (bridge *sdkEngineBridge) failOperation(
	handle sdkEngineOperationHandle,
	failure json.RawMessage,
	projectToken string,
) (sdkEngineSinkHandle, error) {
	result, err := bridge.call(struct {
		Failure         json.RawMessage          `json:"failure"`
		Format          string                   `json:"format"`
		Operation       string                   `json:"operation"`
		OperationHandle sdkEngineOperationHandle `json:"operation_handle"`
		ProjectToken    string                   `json:"project_token"`
	}{failure, sdkEngineCallFormat, sdkEngineOperationFail, handle, projectToken})
	if err != nil {
		return 0, err
	}
	nativeHandle, ok := positiveHandle(result, "sink_handle")
	return sdkEngineSinkHandle(nativeHandle), resultError(ok)
}

func (bridge *sdkEngineBridge) waitForSink(
	handle sdkEngineSinkHandle,
	timeoutMilliseconds uint64,
) (bool, error) {
	result, err := bridge.call(struct {
		Format     string              `json:"format"`
		Operation  string              `json:"operation"`
		SinkHandle sdkEngineSinkHandle `json:"sink_handle"`
		TimeoutMS  uint64              `json:"timeout_ms"`
	}{sdkEngineCallFormat, sdkEngineOperationWaitForSink, handle, timeoutMilliseconds})
	if err != nil {
		return false, err
	}
	idle, ok := result["idle"].(bool)
	if !ok || !hasExactKeys(result, "idle") {
		return false, errSDKEngineResponse
	}
	return idle, nil
}

func (bridge *sdkEngineBridge) emptyResult(request any) error {
	result, err := bridge.call(request)
	if err != nil {
		return err
	}
	if len(result) != 0 {
		return errSDKEngineResponse
	}
	return nil
}

func positiveHandle(result map[string]any, keys ...string) (uint64, bool) {
	if !hasExactKeys(result, keys...) {
		return 0, false
	}
	value, ok := uint64Value(result[keys[0]])
	if !ok || value == 0 {
		return 0, false
	}
	return value, true
}

func uint64Value(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	return parsed, err == nil && strconv.FormatUint(parsed, 10) == number.String()
}

func resultError(ok bool) error {
	if !ok {
		return errSDKEngineResponse
	}
	return nil
}
