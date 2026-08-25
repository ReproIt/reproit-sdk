package reproit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// AutomaticOperationKind identifies one framework-neutral Backend Trigger.
type AutomaticOperationKind string

const (
	OperationRequestResponse AutomaticOperationKind = "request-response"
	OperationStream          AutomaticOperationKind = "stream"
	OperationDeliveredWork   AutomaticOperationKind = "delivered-work"
)

// AutomaticInputChannel identifies the meaning of one ordered input chunk.
type AutomaticInputChannel string

const (
	InputControl  AutomaticInputChannel = "control"
	InputData     AutomaticInputChannel = "input"
	InputMetadata AutomaticInputChannel = "metadata"
)

type automaticObservationClass string

const (
	observationClock        automaticObservationClass = "clock"
	observationDatabase     automaticObservationClass = "database"
	observationEnvironment  automaticObservationClass = "environment"
	observationFilesystem   automaticObservationClass = "filesystem"
	observationOutboundHTTP automaticObservationClass = "outbound-http"
	observationQueue        automaticObservationClass = "queue"
	observationRandomness   automaticObservationClass = "randomness"
)

// AutomaticTriggerCompletion identifies how one Trigger ended.
type AutomaticTriggerCompletion string

const (
	CompletionAcknowledgment AutomaticTriggerCompletion = "acknowledgment"
	CompletionReturn         AutomaticTriggerCompletion = "return"
	CompletionStreamEnd      AutomaticTriggerCompletion = "stream-end"
	CompletionTaskEnd        AutomaticTriggerCompletion = "task-end"
)

// AutomaticProjectOptions binds one installed SDK to one reviewed project and subject.
type AutomaticProjectOptions struct {
	BuildRepositoryID    string
	ProjectTOML          string
	ProjectTokenProvider func() (*ManagedProjectToken, error)
	SourceRevision       string
	SubjectExecutable    string
}

// AutomaticOperationStart describes one framework-neutral operation.
type AutomaticOperationStart struct {
	AdapterID       string
	AdapterVersion  string
	CausalParentIDs []string
	Kind            AutomaticOperationKind
	Name            string
}

// AutomaticInputChunk contains one ordered, application-visible Trigger input.
type AutomaticInputChunk struct {
	Channel     AutomaticInputChannel
	ContentType string
	Value       []byte
}

// AutomaticProject owns one shared native capture engine.
type AutomaticProject struct {
	automaticHTTP *automaticHTTPAdapterLease
	bridge        *sdkEngineBridge
	closed        bool
	closedSignal  chan struct{}
	handle        sdkEngineHandle
	mu            sync.Mutex
	sinkWaiters   chan struct{}
	tokenProvider func() (*ManagedProjectToken, error)
}

// AutomaticOperation owns one shared-engine operation until a terminal action.
type AutomaticOperation struct {
	binding                 *automaticOperationBinding
	finished                bool
	handle                  sdkEngineOperationHandle
	inputIndex              uint16
	mu                      sync.Mutex
	operationID             string
	project                 *AutomaticProject
	stopContextCancellation func() bool
	worldComplete           bool
}

type automaticOperationContextKey struct{}

type automaticOperationBinding struct {
	mu        sync.RWMutex
	operation *AutomaticOperation
	parent    *automaticOperationBinding
}

var ErrAutomaticCapture = errors.New("Repro It could not capture the operation.")

const (
	automaticMaxInputBytes = 65_536
	automaticMaxInputs     = 1_024
)

// OpenAutomaticProject opens the packaged shared engine for one running Go subject.
func OpenAutomaticProject(options AutomaticProjectOptions) (*AutomaticProject, error) {
	bridge, err := openPackagedSDKEngine()
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	if _, err := bridge.contract(); err != nil {
		bridge.close()
		return nil, ErrAutomaticCapture
	}
	subject, err := PackageRunningGoSubject(options.SubjectExecutable)
	if err != nil {
		bridge.close()
		return nil, ErrAutomaticCapture
	}
	defer subject.Close()
	httpLease := acquireAutomaticHTTPAdapter()
	if httpLease == nil {
		bridge.close()
		return nil, ErrAutomaticCapture
	}
	project, err := openAutomaticProjectWith(options, bridge, subject)
	if err != nil {
		httpLease.release()
		return nil, err
	}
	project.automaticHTTP = httpLease
	return project, nil
}

func openAutomaticProjectWith(
	options AutomaticProjectOptions,
	bridge *sdkEngineBridge,
	subject *GoSubjectPackage,
) (*AutomaticProject, error) {
	manifest, err := CanonicalBytes(subject.Manifest)
	if err != nil {
		bridge.close()
		return nil, ErrAutomaticCapture
	}
	objects := make([]sdkEngineSubjectObject, len(subject.Objects))
	for index, object := range subject.Objects {
		if object.Size <= 0 {
			bridge.close()
			return nil, ErrAutomaticCapture
		}
		objects[index] = sdkEngineSubjectObject{
			Digest: object.Digest,
			Path:   object.Path,
			Size:   uint64(object.Size),
		}
	}
	handle, err := bridge.openEngine(sdkEngineOpenOptions{
		BuildRepositoryID:   options.BuildRepositoryID,
		ProjectTOML:         options.ProjectTOML,
		SDK:                 "go",
		SourceRevision:      options.SourceRevision,
		SubjectManifest:     json.RawMessage(manifest),
		SubjectObjects:      objects,
		ObservationAdapters: installedObservationAdapters.snapshot(),
	})
	if err != nil {
		bridge.close()
		return nil, ErrAutomaticCapture
	}
	return &AutomaticProject{
		bridge:        bridge,
		closedSignal:  make(chan struct{}),
		handle:        handle,
		sinkWaiters:   make(chan struct{}, sdkEngineMaxSinkWaiters),
		tokenProvider: options.ProjectTokenProvider,
	}, nil
}

// StartOperation starts one request-response, stream, or delivered-work operation.
func (project *AutomaticProject) StartOperation(
	start AutomaticOperationStart,
) (*AutomaticOperation, error) {
	project.mu.Lock()
	defer project.mu.Unlock()
	if project.closed {
		return nil, ErrAutomaticCapture
	}
	causalParents := make([]any, len(start.CausalParentIDs))
	for index, parent := range start.CausalParentIDs {
		causalParents[index] = parent
	}
	begin, err := CanonicalBytes(map[string]any{
		"adapter_id":        start.AdapterID,
		"adapter_version":   start.AdapterVersion,
		"causal_parent_ids": causalParents,
		"format":            "reproit.operation-begin.v1",
		"operation_kind":    string(start.Kind),
		"operation_name":    start.Name,
	})
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	started, err := project.bridge.beginOperation(project.handle, json.RawMessage(begin))
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	return &AutomaticOperation{
		handle: started.Handle, operationID: started.OperationID, project: project,
	}, nil
}

// StartOperationContext starts an operation and binds it to one child context.
func (project *AutomaticProject) StartOperationContext(
	parent context.Context,
	start AutomaticOperationStart,
) (context.Context, *AutomaticOperation, error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, ErrAutomaticCapture
	}
	operation, err := project.StartOperation(start)
	if err != nil {
		return nil, nil, err
	}
	binding := &automaticOperationBinding{
		operation: operation,
		parent:    operationBinding(parent),
	}
	operation.mu.Lock()
	operation.binding = binding
	operation.mu.Unlock()
	child := context.WithValue(parent, automaticOperationContextKey{}, binding)
	stop := context.AfterFunc(child, operation.Cancel)
	operation.setContextCancellation(stop)
	if child.Err() != nil {
		operation.Cancel()
		return nil, nil, ErrAutomaticCapture
	}
	return child, operation, nil
}

func activeAutomaticOperation(
	ctx context.Context,
) (*AutomaticOperation, bool) {
	if ctx == nil || ctx.Err() != nil {
		return nil, false
	}
	binding := operationBinding(ctx)
	for depth := 0; binding != nil && depth < 64; depth++ {
		operation, parent := binding.snapshot()
		if operation != nil && operation.isActive() {
			return operation, true
		}
		binding = parent
	}
	return nil, false
}

func operationBinding(ctx context.Context) *automaticOperationBinding {
	binding, _ := ctx.Value(automaticOperationContextKey{}).(*automaticOperationBinding)
	return binding
}

func (binding *automaticOperationBinding) snapshot() (
	*AutomaticOperation,
	*automaticOperationBinding,
) {
	binding.mu.RLock()
	defer binding.mu.RUnlock()
	return binding.operation, binding.parent
}

func (binding *automaticOperationBinding) clear(operation *AutomaticOperation) {
	binding.mu.Lock()
	defer binding.mu.Unlock()
	if binding.operation == operation {
		binding.operation = nil
	}
}

// OperationID returns the stable identity for causal child operations.
func (operation *AutomaticOperation) OperationID() string {
	return operation.operationID
}

func (operation *AutomaticOperation) setContextCancellation(stop func() bool) {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished {
		stop()
		return
	}
	operation.stopContextCancellation = stop
}

func (operation *AutomaticOperation) isActive() bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return !operation.finished && !operation.worldComplete
}

// RecordInput records one ordered Trigger input chunk.
func (operation *AutomaticOperation) RecordInput(input AutomaticInputChunk) error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished || len(input.Value) > automaticMaxInputBytes ||
		operation.inputIndex == automaticMaxInputs {
		return ErrAutomaticCapture
	}
	digest := sha256.Sum256(input.Value)
	payload, err := CanonicalBytes(map[string]any{
		"channel":      string(input.Channel),
		"content_type": input.ContentType,
		"format":       "reproit.operation-input.v1",
		"input_index":  int(operation.inputIndex),
		"value":        base64.RawURLEncoding.EncodeToString(input.Value),
		"value_digest": "sha256:" + hex.EncodeToString(digest[:]),
	})
	if err != nil || operation.project.bridge.recordInput(
		operation.handle, json.RawMessage(payload),
	) != nil {
		operation.abandonLocked()
		return ErrAutomaticCapture
	}
	operation.inputIndex++
	return nil
}

func (operation *AutomaticOperation) markUnowned(
	class automaticObservationClass,
	causalParentID *string,
	evidence []byte,
) error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished || operation.worldComplete {
		return ErrAutomaticCapture
	}
	err := operation.project.bridge.markOperationUnowned(
		operation.handle, string(class), causalParentID, evidence,
	)
	if err != nil {
		operation.abandonLocked()
		return ErrAutomaticCapture
	}
	return nil
}

func (operation *AutomaticOperation) closeWorld(completion AutomaticTriggerCompletion) error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return operation.closeWorldLocked(completion)
}

func (operation *AutomaticOperation) closeWorldLocked(
	completion AutomaticTriggerCompletion,
) error {
	if operation.finished || operation.worldComplete {
		return ErrAutomaticCapture
	}
	if operation.project.bridge.closeOperationWorld(
		operation.handle, string(completion),
	) != nil {
		operation.abandonLocked()
		return ErrAutomaticCapture
	}
	operation.worldComplete = true
	return nil
}

// Succeed deletes a successful operation without delivery.
func (operation *AutomaticOperation) Succeed() {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished {
		return
	}
	if operation.project.bridge.succeedOperation(operation.handle) != nil {
		_ = operation.project.bridge.abandonOperation(operation.handle)
	}
	operation.finishLocked()
}

// Cancel deletes a cancelled operation without delivery.
func (operation *AutomaticOperation) Cancel() {
	operation.Close()
}

// Fail closes the World and sends one typed Failure to the shared engine.
func (operation *AutomaticOperation) Fail(
	completion AutomaticTriggerCompletion,
	failureIdentity map[string]any,
) error {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished {
		return ErrAutomaticCapture
	}
	if !operation.worldComplete {
		if err := operation.closeWorldLocked(completion); err != nil {
			return err
		}
	}
	if operation.project.tokenProvider == nil {
		operation.abandonLocked()
		return ErrAutomaticCapture
	}
	token, err := operation.project.tokenProvider()
	if err != nil || token == nil || token.sdkEngineValue() == "" {
		operation.abandonLocked()
		return ErrAutomaticCapture
	}
	failure, err := CanonicalBytes(failureIdentity)
	if err != nil {
		operation.abandonLocked()
		return ErrAutomaticCapture
	}
	sink, err := operation.project.bridge.failOperation(
		operation.handle, json.RawMessage(failure), token.sdkEngineValue(),
	)
	if err != nil {
		_ = operation.project.bridge.abandonOperation(operation.handle)
		operation.finishLocked()
		return ErrAutomaticCapture
	}
	operation.finishLocked()
	operation.project.startSinkWait(sink)
	return nil
}

// Close deletes an unfinished operation. Close is safe to call more than once.
func (operation *AutomaticOperation) Close() {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	operation.abandonLocked()
}

func (operation *AutomaticOperation) abandonLocked() {
	if !operation.finished {
		_ = operation.project.bridge.abandonOperation(operation.handle)
		operation.finishLocked()
	}
}

func (operation *AutomaticOperation) finishLocked() {
	operation.finished = true
	if operation.binding != nil {
		operation.binding.clear(operation)
		operation.binding = nil
	}
	if operation.stopContextCancellation != nil {
		operation.stopContextCancellation()
		operation.stopContextCancellation = nil
	}
}

func (project *AutomaticProject) startSinkWait(handle sdkEngineSinkHandle) {
	project.mu.Lock()
	if project.closed {
		project.mu.Unlock()
		return
	}
	select {
	case project.sinkWaiters <- struct{}{}:
		project.mu.Unlock()
		go project.pollSink(handle)
	default:
		project.mu.Unlock()
	}
}

func (project *AutomaticProject) pollSink(handle sdkEngineSinkHandle) {
	defer func() { <-project.sinkWaiters }()
	deadline := time.NewTimer(time.Duration(sdkEngineSinkWaitMilliseconds) * time.Millisecond)
	defer deadline.Stop()
	for {
		select {
		case <-project.closedSignal:
			return
		case <-deadline.C:
			return
		default:
		}
		idle, err := project.bridge.waitForSink(handle, 0)
		if err != nil || idle {
			return
		}
		poll := time.NewTimer(25 * time.Millisecond)
		select {
		case <-project.closedSignal:
			if !poll.Stop() {
				<-poll.C
			}
			return
		case <-deadline.C:
			if !poll.Stop() {
				<-poll.C
			}
			return
		case <-poll.C:
		}
	}
}

// Close deletes active shared-engine state. Close is safe to call more than once.
func (project *AutomaticProject) Close() {
	project.mu.Lock()
	if project.closed {
		project.mu.Unlock()
		return
	}
	project.closed = true
	close(project.closedSignal)
	_ = project.bridge.closeEngine(project.handle)
	project.bridge.close()
	httpLease := project.automaticHTTP
	project.automaticHTTP = nil
	project.mu.Unlock()
	httpLease.release()
}
