package reproit

import (
	"encoding/base64"
	"encoding/json"
)

type semanticDependencyMetadata struct {
	Name  []byte
	Value []byte
}

type semanticDependencyRequest struct {
	Encoding         string
	Metadata         []semanticDependencyMetadata
	Method           *string
	ObservationClass automaticObservationClass
	Operation        string
	Payload          []byte
	Protocol         string
	Target           string
}

type semanticDependencyResponse struct {
	ErrorCode   *string
	ErrorNumber *uint32
	Metadata    []semanticDependencyMetadata
	Outcome     observationOutcome
	Payload     []byte
	HasPayload  bool
	Status      *string
	StatusCode  *uint16
}

type sdkEngineDependencyMetadata struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type sdkEngineDependencyRequest struct {
	Encoding         string                        `json:"encoding"`
	Metadata         []sdkEngineDependencyMetadata `json:"metadata"`
	Method           *string                       `json:"method"`
	ObservationClass string                        `json:"observation_class"`
	Operation        string                        `json:"operation"`
	Payload          string                        `json:"payload"`
	Protocol         string                        `json:"protocol"`
	Target           string                        `json:"target"`
}

type sdkEngineDependencyResponse struct {
	ErrorCode   *string                       `json:"error_code"`
	ErrorNumber *uint32                       `json:"error_number"`
	Metadata    []sdkEngineDependencyMetadata `json:"metadata"`
	Outcome     string                        `json:"outcome"`
	Payload     *string                       `json:"payload"`
	Status      *string                       `json:"status"`
	StatusCode  *uint16                       `json:"status_code"`
}

func translateSemanticDependency(
	operation *AutomaticOperation,
	request semanticDependencyRequest,
	causalParentID *string,
	live func() (semanticDependencyResponse, error),
) (semanticDependencyResponse, error) {
	requestInput, err := makeSDKEngineDependencyRequest(request)
	if err != nil {
		return live()
	}
	started, err := operation.openSemanticDependency(requestInput, causalParentID)
	if err != nil {
		return live()
	}
	finished := false
	defer func() {
		if !finished {
			_ = operation.project.bridge.abandonObservation(
				sdkEngineObservationHandle(started.Handle),
			)
		}
	}()
	if started.Action == "capture" {
		response, liveErr := live()
		responseInput, convertErr := makeSDKEngineDependencyResponse(response)
		if convertErr == nil {
			outcome, finishErr := operation.project.bridge.finishDependency(
				started.Handle, &responseInput,
			)
			finished = finishErr == nil && outcome == string(response.Outcome)
		}
		if !finished {
			_ = operation.markUnowned(request.ObservationClass, causalParentID, nil)
		}
		return response, liveErr
	}
	record, err := readSDKEngineDependencyResponse(operation.project.bridge, started.Handle)
	if err != nil {
		return semanticDependencyResponse{}, ErrAutomaticCapture
	}
	outcome, err := operation.project.bridge.finishDependency(started.Handle, nil)
	if err != nil {
		return semanticDependencyResponse{}, ErrAutomaticCapture
	}
	response, err := reconstructSemanticDependencyResponse(record, outcome)
	if err != nil {
		return semanticDependencyResponse{}, ErrAutomaticCapture
	}
	finished = true
	return response, nil
}

func (operation *AutomaticOperation) openSemanticDependency(
	request sdkEngineDependencyRequest,
	causalParentID *string,
) (sdkEngineDependencyStart, error) {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished || operation.worldComplete {
		return sdkEngineDependencyStart{}, ErrAutomaticCapture
	}
	started, err := operation.project.bridge.openDependency(
		operation.handle, causalParentID, request,
	)
	if err != nil {
		operation.abandonLocked()
		return sdkEngineDependencyStart{}, ErrAutomaticCapture
	}
	return started, nil
}

func makeSDKEngineDependencyRequest(
	request semanticDependencyRequest,
) (sdkEngineDependencyRequest, error) {
	metadata, err := makeSDKEngineDependencyMetadata(request.Metadata)
	if err != nil || !boundedDependencyBytes(
		len(request.Encoding), len(request.Operation), len(request.Payload),
		len(request.Protocol), len(request.Target),
	) {
		return sdkEngineDependencyRequest{}, ErrAutomaticCapture
	}
	return sdkEngineDependencyRequest{
		Encoding:         request.Encoding,
		Metadata:         metadata,
		Method:           request.Method,
		ObservationClass: string(request.ObservationClass),
		Operation:        request.Operation,
		Payload:          base64.RawURLEncoding.EncodeToString(request.Payload),
		Protocol:         request.Protocol,
		Target:           base64.RawURLEncoding.EncodeToString([]byte(request.Target)),
	}, nil
}

func makeSDKEngineDependencyResponse(
	response semanticDependencyResponse,
) (sdkEngineDependencyResponse, error) {
	metadata, err := makeSDKEngineDependencyMetadata(response.Metadata)
	if err != nil || !boundedDependencyBytes(len(response.Payload)) {
		return sdkEngineDependencyResponse{}, ErrAutomaticCapture
	}
	var payload *string
	if response.HasPayload {
		encoded := base64.RawURLEncoding.EncodeToString(response.Payload)
		payload = &encoded
	}
	return sdkEngineDependencyResponse{
		ErrorCode:   response.ErrorCode,
		ErrorNumber: response.ErrorNumber,
		Metadata:    metadata,
		Outcome:     string(response.Outcome),
		Payload:     payload,
		Status:      response.Status,
		StatusCode:  response.StatusCode,
	}, nil
}

func makeSDKEngineDependencyMetadata(
	metadata []semanticDependencyMetadata,
) ([]sdkEngineDependencyMetadata, error) {
	if len(metadata) > sdkEngineMaxCallBytes {
		return nil, ErrAutomaticCapture
	}
	totalBytes := 0
	result := make([]sdkEngineDependencyMetadata, 0, len(metadata))
	for _, field := range metadata {
		if len(field.Name) > sdkEngineMaxCallBytes-totalBytes {
			return nil, ErrAutomaticCapture
		}
		totalBytes += len(field.Name)
		if len(field.Value) > sdkEngineMaxCallBytes-totalBytes {
			return nil, ErrAutomaticCapture
		}
		totalBytes += len(field.Value)
		result = append(result, sdkEngineDependencyMetadata{
			Name:  base64.RawURLEncoding.EncodeToString(field.Name),
			Value: base64.RawURLEncoding.EncodeToString(field.Value),
		})
	}
	return result, nil
}

func readSDKEngineDependencyResponse(
	bridge *sdkEngineBridge,
	handle sdkEngineDependencyHandle,
) ([]byte, error) {
	result := make([]byte, 0, sdkEngineMaxObservationReadBytes)
	for {
		chunk, err := bridge.readObservation(sdkEngineObservationHandle(handle))
		if err != nil || (!chunk.EOF && len(chunk.Chunk) == 0) ||
			len(chunk.Chunk) > sdkEngineMaxSemanticDependencyRecordBytes-len(result) {
			return nil, ErrAutomaticCapture
		}
		result = append(result, chunk.Chunk...)
		if chunk.EOF {
			if len(result) == 0 {
				return nil, ErrAutomaticCapture
			}
			return result, nil
		}
	}
}

func reconstructSemanticDependencyResponse(
	record []byte,
	validatedOutcome string,
) (semanticDependencyResponse, error) {
	var wire sdkEngineDependencyResponse
	if json.Unmarshal(record, &wire) != nil || wire.Outcome != validatedOutcome {
		return semanticDependencyResponse{}, ErrAutomaticCapture
	}
	metadata := make([]semanticDependencyMetadata, 0, len(wire.Metadata))
	for _, field := range wire.Metadata {
		name, nameErr := base64.RawURLEncoding.DecodeString(field.Name)
		value, valueErr := base64.RawURLEncoding.DecodeString(field.Value)
		if nameErr != nil || valueErr != nil {
			return semanticDependencyResponse{}, ErrAutomaticCapture
		}
		metadata = append(metadata, semanticDependencyMetadata{Name: name, Value: value})
	}
	response := semanticDependencyResponse{
		ErrorCode:   wire.ErrorCode,
		ErrorNumber: wire.ErrorNumber,
		Metadata:    metadata,
		Outcome:     observationOutcome(wire.Outcome),
		Status:      wire.Status,
		StatusCode:  wire.StatusCode,
	}
	if wire.Payload != nil {
		payload, err := base64.RawURLEncoding.DecodeString(*wire.Payload)
		if err != nil {
			return semanticDependencyResponse{}, ErrAutomaticCapture
		}
		response.Payload = payload
		response.HasPayload = true
	}
	return response, nil
}

func boundedDependencyBytes(values ...int) bool {
	total := 0
	for _, value := range values {
		if value < 0 || value > sdkEngineMaxCallBytes-total {
			return false
		}
		total += value
	}
	return true
}
