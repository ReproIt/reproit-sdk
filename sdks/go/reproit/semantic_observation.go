package reproit

import (
	"bytes"
	"encoding/base64"
)

const (
	semanticObservationMaxRecordBytes = 64 * 1024
	semanticObservationMaxReads       = 8
)

type semanticObservationRequest struct {
	length    *int
	offset    *int
	operation string
	target    *string
}

func makeSemanticObservationRequest(request semanticObservationRequest) ([]byte, error) {
	var length any
	if request.length != nil {
		length = *request.length
	}
	var offset any
	if request.offset != nil {
		offset = *request.offset
	}
	var target any
	if request.target != nil {
		target = *request.target
	}
	return CanonicalBytes(map[string]any{
		"format":    "reproit.semantic-observation-request.v1",
		"length":    length,
		"offset":    offset,
		"operation": request.operation,
		"target":    target,
	})
}

func makeSemanticObservationResponse(
	operation string,
	request []byte,
	value []byte,
) ([]byte, error) {
	return CanonicalBytes(map[string]any{
		"error_code":     nil,
		"error_number":   nil,
		"format":         "reproit.semantic-observation-response.v1",
		"operation":      operation,
		"outcome":        "response",
		"request_digest": digestBytes(request),
		"value":          base64.RawURLEncoding.EncodeToString(value),
	})
}

func writeSemanticObservationResponse(session *observationSession, value []byte) error {
	if len(value) == 0 || len(value) > semanticObservationMaxRecordBytes {
		return ErrAutomaticCapture
	}
	for start := 0; start < len(value); start += sdkEngineMaxObservationChunkBytes {
		end := min(start+sdkEngineMaxObservationChunkBytes, len(value))
		if session.writeResponse(value[start:end]) != nil {
			return ErrAutomaticCapture
		}
	}
	return nil
}

func readSemanticObservationResponse(session *observationSession) ([]byte, error) {
	result := make([]byte, 0, sdkEngineMaxObservationReadBytes)
	for range semanticObservationMaxReads {
		chunk, eof, err := session.readResponse()
		if err != nil || len(chunk) > semanticObservationMaxRecordBytes-len(result) {
			return nil, ErrAutomaticCapture
		}
		result = append(result, chunk...)
		if eof {
			if len(result) == 0 {
				return nil, ErrAutomaticCapture
			}
			return result, nil
		}
	}
	return nil, ErrAutomaticCapture
}

func decodeSemanticObservationResponse(
	value []byte,
	request []byte,
	operation string,
	exactValueBytes int,
) ([]byte, error) {
	parsed, err := parseStrictJSON(value, semanticObservationMaxRecordBytes)
	response, ok := parsed.(map[string]any)
	if err != nil || !ok || !hasExactKeys(
		response, "error_code", "error_number", "format", "operation", "outcome",
		"request_digest", "value",
	) {
		return nil, ErrAutomaticCapture
	}
	canonical, canonicalErr := CanonicalBytes(response)
	encoded, encodedOK := response["value"].(string)
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
	if canonicalErr != nil || !bytes.Equal(canonical, value) || !encodedOK ||
		decodeErr != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded ||
		len(decoded) != exactValueBytes || response["error_code"] != nil ||
		response["error_number"] != nil ||
		response["format"] != "reproit.semantic-observation-response.v1" ||
		response["operation"] != operation || response["outcome"] != "response" ||
		response["request_digest"] != digestBytes(request) {
		return nil, ErrAutomaticCapture
	}
	return decoded, nil
}
