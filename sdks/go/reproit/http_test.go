package reproit

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

type HTTPPreparation struct {
	Begin        map[string]any
	Dependencies []map[string]any
	Inputs       []map[string]any
	Start        CandidateStart
}

func HTTPMiddleware(
	sdk *SDK,
	prepare func(*http.Request) HTTPPreparation,
	failure func(any) map[string]any,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		capture, prepared := prepareHTTP(request, prepare)
		captureActive := prepared && startPreparedCapture(sdk, OperationPreparation{
			Begin: capture.Begin, Dependencies: capture.Dependencies,
			Inputs: capture.Inputs, Start: capture.Start,
		})
		state := &httpCaptureState{
			active: captureActive, complete: len(capture.Inputs) > 0 || request.Body == nil ||
				request.Body == http.NoBody,
			inputIndex: len(capture.Inputs),
		}
		if captureActive && request.Body != nil && request.Body != http.NoBody {
			request.Body = &capturedRequestBody{
				ReadCloser: request.Body, contentType: request.Header.Get("Content-Type"),
				operationID: capture.Start.OperationID, sdk: sdk, state: state,
			}
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				if state.active && state.complete {
					recordApplicationPanic(sdk, capture.Start.OperationID, recovered, failure)
				} else if state.active {
					sdk.AbandonIncomplete(capture.Start.OperationID)
				}
				panic(recovered)
			}
			if state.active {
				completeCapture(sdk, capture.Start.OperationID)
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

type httpCaptureState struct {
	active     bool
	complete   bool
	inputIndex int
}

type capturedRequestBody struct {
	io.ReadCloser
	contentType string
	operationID string
	sdk         *SDK
	state       *httpCaptureState
}

func (body *capturedRequestBody) Read(target []byte) (int, error) {
	count, readErr := body.ReadCloser.Read(target)
	if body.state.active && count > 0 {
		contentType := body.contentType
		if contentType == "" || len(contentType) > 128 {
			contentType = "application/octet-stream"
		}
		for offset := 0; offset < count; offset += 32 * 1024 {
			end := min(offset+32*1024, count)
			chunk := target[offset:end]
			digest := sha256.Sum256(chunk)
			value := map[string]any{
				"channel": "input", "content_type": contentType,
				"format":       "reproit.operation-input.v1",
				"input_index":  body.state.inputIndex,
				"value":        base64.RawURLEncoding.EncodeToString(chunk),
				"value_digest": fmt.Sprintf("sha256:%x", digest),
			}
			if err := body.sdk.RecordInput(body.operationID, value); err != nil {
				body.state.active = false
				body.sdk.AbandonIncomplete(body.operationID)
				break
			}
			body.state.inputIndex++
		}
	}
	if readErr == io.EOF {
		body.state.complete = true
	}
	return count, readErr
}

func prepareHTTP(
	request *http.Request,
	prepare func(*http.Request) HTTPPreparation,
) (preparation HTTPPreparation, prepared bool) {
	defer func() {
		if recover() != nil {
			preparation = HTTPPreparation{}
			prepared = false
		}
	}()
	return prepare(request), true
}
