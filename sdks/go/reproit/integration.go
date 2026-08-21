package reproit

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
)

const (
	maxCapturedInputBytes = 32 * 1_024
	maxContentTypeBytes   = 256
	maxOperationNameBytes = 128
)

// ManagedWorldCapture holds one initial World ID and its completion operation.
type ManagedWorldCapture struct {
	WorldID  string
	Complete func(string) (ManagedCaptureClosure, error)
}

// OperationCapture records dependency cursors for one application operation.
type OperationCapture struct {
	dependencies []map[string]any
	operationID  string
	mu           sync.Mutex
	valid        bool
}

func newOperationCapture(operationID string) *OperationCapture {
	return &OperationCapture{operationID: operationID, valid: true}
}

// OperationID returns the package-owned operation ID when capture is active.
func (capture *OperationCapture) OperationID() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.operationID
}

// RecordDependency records one bounded dependency cursor.
func (capture *OperationCapture) RecordDependency(dependency map[string]any) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if !capture.valid {
		return
	}
	copied, err := cloneMap(dependency)
	if err != nil || len(capture.dependencies) >= MaxEvents {
		capture.valid = false
		capture.dependencies = nil
		return
	}
	encoded, err := CanonicalBytes(copied)
	if err != nil || len(encoded) > MaxEventBytes {
		capture.valid = false
		capture.dependencies = nil
		return
	}
	capture.dependencies = append(capture.dependencies, copied)
}

// ReproIt captures operations through the official managed SDK entry.
type ReproIt struct {
	project      *OfficialManagedProject
	worldCapture func() (ManagedWorldCapture, error)
}

type operationContextKey struct{}

// OperationFromRequest returns the active Repro It operation when one exists.
func OperationFromRequest(request *http.Request) *OperationCapture {
	capture, _ := request.Context().Value(operationContextKey{}).(*OperationCapture)
	return capture
}

// HTTP wraps one standard HTTP handler without a framework-specific package.
func (capture *ReproIt) HTTP(
	operationName string,
	captureInput func(*http.Request) (string, []byte, error),
	classifyFailure func(int, []byte) map[string]any,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		contentType, input, ok := safeHTTPInput(captureInput, request)
		if !ok {
			next.ServeHTTP(writer, request)
			return
		}
		observed := &capturedResponseWriter{
			ResponseWriter: writer, status: http.StatusOK, valid: true,
		}
		var failure map[string]any
		_ = capture.Run(
			operationName,
			contentType,
			input,
			func(operation *OperationCapture) error {
				context := context.WithValue(request.Context(), operationContextKey{}, operation)
				next.ServeHTTP(observed, request.WithContext(context))
				if observed.valid {
					failure = safeHTTPFailure(classifyFailure, observed.status, observed.body)
				}
				if failure != nil {
					return errHTTPFailure
				}
				return nil
			},
			func(error) map[string]any { return failure },
		)
	})
}

func safeHTTPInput(
	captureInput func(*http.Request) (string, []byte, error), request *http.Request,
) (contentType string, input []byte, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if captureInput == nil {
		return "", nil, false
	}
	contentType, input, err := captureInput(request)
	return contentType, input, err == nil
}

func safeHTTPFailure(
	classifyFailure func(int, []byte) map[string]any, status int, body []byte,
) (failure map[string]any) {
	defer func() {
		if recover() != nil {
			failure = nil
		}
	}()
	if classifyFailure == nil {
		return nil
	}
	return classifyFailure(status, body)
}

var errHTTPFailure = errors.New("Repro It observed an application Failure")

type capturedResponseWriter struct {
	http.ResponseWriter
	body   []byte
	status int
	valid  bool
}

func (writer *capturedResponseWriter) WriteHeader(statusCode int) {
	writer.status = statusCode
	writer.ResponseWriter.WriteHeader(statusCode)
}

func (writer *capturedResponseWriter) Write(value []byte) (int, error) {
	if writer.valid && len(writer.body)+len(value) <= maxCapturedInputBytes {
		writer.body = append(writer.body, value...)
	} else {
		writer.valid = false
		writer.body = nil
	}
	return writer.ResponseWriter.Write(value)
}

func (writer *capturedResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

// Start validates one reviewed build and prepares application capture.
func Start(
	project map[string]any,
	buildRepositoryID string,
	sourceRevision string,
	worldCapture func() (ManagedWorldCapture, error),
) (*ReproIt, error) {
	bound, err := NewOfficialManagedProject(project, buildRepositoryID, sourceRevision)
	if err != nil {
		return nil, err
	}
	if worldCapture == nil {
		return nil, errProjectBindingInvalid()
	}
	return &ReproIt{project: bound, worldCapture: worldCapture}, nil
}

// Run captures one operation and preserves its exact application error.
func (capture *ReproIt) Run(
	operationName string,
	contentType string,
	input []byte,
	operation func(*OperationCapture) error,
	classifyFailure func(error) map[string]any,
) error {
	return capture.runKind(
		"request-response", operationName, contentType, input, operation, classifyFailure,
	)
}

// RunStream captures one ordered stream operation.
func (capture *ReproIt) RunStream(
	operationName string,
	contentType string,
	input []byte,
	operation func(*OperationCapture) error,
	classifyFailure func(error) map[string]any,
) error {
	return capture.runKind(
		"stream", operationName, contentType, input, operation, classifyFailure,
	)
}

// RunDeliveredWork captures one delivered-work operation.
func (capture *ReproIt) RunDeliveredWork(
	operationName string,
	contentType string,
	input []byte,
	operation func(*OperationCapture) error,
	classifyFailure func(error) map[string]any,
) error {
	return capture.runKind(
		"delivered-work", operationName, contentType, input, operation, classifyFailure,
	)
}

func (capture *ReproIt) runKind(
	operationKind string,
	operationName string,
	contentType string,
	input []byte,
	operation func(*OperationCapture) error,
	classifyFailure func(error) map[string]any,
) error {
	active := capture.startOperation(operationKind, operationName, contentType, input)
	context := newOperationCapture("")
	if active != nil {
		context = active.context
	}
	result := operation(context)
	if result == nil {
		return nil
	}
	captureFailure(active, result, classifyFailure)
	return result
}

type activeOperation struct {
	contentType   string
	context       *OperationCapture
	input         []byte
	operation     *OfficialManagedOperation
	operationKind string
	operationName string
	world         ManagedWorldCapture
}

func (capture *ReproIt) startOperation(
	operationKind string, operationName string, contentType string, input []byte,
) (active *activeOperation) {
	defer func() {
		if recover() != nil {
			active = nil
		}
	}()
	if !validBoundary(operationKind, operationName, contentType, input) {
		return nil
	}
	world, err := capture.worldCapture()
	if err != nil || world.Complete == nil {
		return nil
	}
	operation, err := capture.project.StartOperation(world.WorldID)
	if err != nil {
		return nil
	}
	return &activeOperation{
		contentType:   contentType,
		context:       newOperationCapture(operation.OperationID),
		input:         append([]byte(nil), input...),
		operation:     operation,
		operationKind: operationKind,
		operationName: operationName,
		world:         world,
	}
}

func captureFailure(
	active *activeOperation, applicationError error,
	classifyFailure func(error) map[string]any,
) {
	defer func() { _ = recover() }()
	if active == nil || classifyFailure == nil {
		return
	}
	active.context.mu.Lock()
	valid := active.context.valid
	dependencies := append([]map[string]any(nil), active.context.dependencies...)
	active.context.mu.Unlock()
	if !valid {
		return
	}
	failure := classifyFailure(applicationError)
	if failure == nil {
		return
	}
	closure, err := active.world.Complete(active.operation.OperationID)
	if err != nil {
		return
	}
	token, err := NewManagedProjectToken(os.Getenv("REPROIT_MANAGED_PROJECT_TOKEN"))
	if err != nil {
		return
	}
	sink, err := active.operation.CandidateSink(token, closure, nil)
	if err != nil {
		return
	}
	sdk := New(sink)
	start := CandidateStart{
		CaptureID:   active.operation.CaptureID,
		Deployment:  active.operation.Deployment(),
		OperationID: active.operation.OperationID,
		WorldID:     active.operation.WorldID,
	}
	input := operationInput(active.contentType, active.input)
	if sdk.Begin(start, operationBegin(active.operationKind, active.operationName)) != nil ||
		sdk.RecordInput(active.operation.OperationID, input) != nil {
		sdk.AbandonIncomplete(active.operation.OperationID)
		return
	}
	for _, dependency := range dependencies {
		if sdk.RecordDependency(active.operation.OperationID, dependency) != nil {
			sdk.AbandonIncomplete(active.operation.OperationID)
			return
		}
	}
	_ = sdk.Fail(active.operation.OperationID, failure)
}

func validBoundary(
	operationKind string, operationName string, contentType string, input []byte,
) bool {
	return (operationKind == "request-response" || operationKind == "stream" ||
		operationKind == "delivered-work") &&
		operationName != "" && len(operationName) <= maxOperationNameBytes &&
		contentType != "" && len(contentType) <= maxContentTypeBytes &&
		len(input) <= maxCapturedInputBytes
}

func operationBegin(operationKind string, operationName string) map[string]any {
	return map[string]any{
		"adapter_id":        "sdk",
		"adapter_version":   "1.0.0",
		"causal_parent_ids": []any{},
		"format":            "reproit.operation-begin.v1",
		"operation_kind":    operationKind,
		"operation_name":    operationName,
	}
}

func operationInput(contentType string, value []byte) map[string]any {
	return map[string]any{
		"channel":      "input",
		"content_type": contentType,
		"format":       "reproit.operation-input.v1",
		"input_index":  0,
		"value":        encodeBase64URL(value),
		"value_digest": digestBytes(value),
	}
}
