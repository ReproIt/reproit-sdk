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
	automaticAdapters *automaticAdapterLeases
	bridge            *sdkEngineBridge
	closed            bool
	closedSignal      chan struct{}
	handle            sdkEngineHandle
	mu                sync.Mutex
	sinkWaiters       chan struct{}
	tokenProvider     func() (*ManagedProjectToken, error)
}

// AutomaticOperation owns one shared-engine operation until a terminal action.
type AutomaticOperation struct {
	activeRegistered        bool
	binding                 *automaticOperationBinding
	finished                bool
	handle                  sdkEngineOperationHandle
	inputIndex              uint16
	mu                      sync.Mutex
	operationID             string
	ownerGoroutineID        uint64
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

type automaticActiveOperationRegistry struct {
	byGoroutine map[uint64][]*AutomaticOperation
	mu          sync.RWMutex
	operations  map[*AutomaticOperation]*AutomaticProject
}

var automaticActiveOperations automaticActiveOperationRegistry

const (
	automaticMaxActiveOperations = 512
	automaticMaxInputBytes       = 65_536
	automaticMaxInputs           = 1_024
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
	adapters := acquireAutomaticAdapters(subject.adapterImplementationDigest)
	if adapters == nil {
		bridge.close()
		return nil, ErrAutomaticCapture
	}
	project, err := openAutomaticProjectWith(options, bridge, subject)
	if err != nil {
		adapters.release()
		return nil, err
	}
	project.automaticAdapters = adapters
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
	return project.startOperation(start, nil)
}

func (project *AutomaticProject) startOperation(
	start AutomaticOperationStart,
	fuzzContext *FuzzCampaignContext,
) (*AutomaticOperation, error) {
	project.mu.Lock()
	defer project.mu.Unlock()
	if project.closed {
		return nil, ErrAutomaticCapture
	}
	causalParentIDs := append([]string(nil), start.CausalParentIDs...)
	if fuzzContext != nil && fuzzContext.parentOperation != "" &&
		!containsString(causalParentIDs, fuzzContext.parentOperation) {
		causalParentIDs = append(causalParentIDs, fuzzContext.parentOperation)
	}
	causalParents := make([]any, len(causalParentIDs))
	for index, parent := range causalParentIDs {
		causalParents[index] = parent
	}
	beginValue := map[string]any{
		"adapter_id":        start.AdapterID,
		"adapter_version":   start.AdapterVersion,
		"causal_parent_ids": causalParents,
		"format":            "reproit.operation-begin.v1",
		"operation_kind":    string(start.Kind),
		"operation_name":    start.Name,
	}
	if fuzzContext != nil {
		beginValue["campaign_context"] = fuzzContext.beginIdentity()
		beginValue["format"] = "reproit.operation-begin.v2"
	}
	begin, err := CanonicalBytes(beginValue)
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	var nativeFuzzContext *sdkEngineFuzzContextInput
	if fuzzContext != nil {
		nativeFuzzContext = fuzzContext.nativeInput()
	}
	started, err := project.bridge.beginOperation(
		project.handle,
		json.RawMessage(begin),
		nativeFuzzContext,
	)
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	operation := &AutomaticOperation{
		handle: started.Handle, operationID: started.OperationID, project: project,
	}
	if !registerAutomaticOperation(operation) {
		_ = project.bridge.abandonOperation(operation.handle)
		operation.finished = true
		return nil, ErrAutomaticCapture
	}
	operation.activeRegistered = true
	return operation, nil
}

// StartOperationContext starts an operation and binds it to one child context.
func (project *AutomaticProject) StartOperationContext(
	parent context.Context,
	start AutomaticOperationStart,
) (context.Context, *AutomaticOperation, error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, ErrAutomaticCapture
	}
	fuzzContext, _ := fuzzContextFromContext(parent)
	operation, err := project.startOperation(start, fuzzContext)
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
	if fuzzContext != nil {
		child = context.WithValue(child, fuzzContextKey{}, fuzzContext.withParent(operation.operationID))
	}
	stop := context.AfterFunc(child, operation.Cancel)
	operation.setContextCancellation(stop)
	if child.Err() != nil {
		operation.Cancel()
		return nil, nil, ErrAutomaticCapture
	}
	return child, operation, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
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
	if operation.markUnhealthyAdaptersLocked() != nil {
		operation.abandonLocked()
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

func (operation *AutomaticOperation) markUnhealthyAdaptersLocked() error {
	for _, check := range operation.project.automaticAdapters.health() {
		if !check.healthy && operation.project.bridge.markOperationUnowned(
			operation.handle,
			string(check.class),
			nil,
			nil,
		) != nil {
			return ErrAutomaticCapture
		}
	}
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
	if operation.activeRegistered {
		unregisterAutomaticOperation(operation)
		operation.activeRegistered = false
	}
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
	for _, operation := range takeAutomaticProjectOperations(project) {
		operation.mu.Lock()
		operation.finishLocked()
		operation.mu.Unlock()
	}
	_ = project.bridge.closeEngine(project.handle)
	project.bridge.close()
	adapters := project.automaticAdapters
	project.automaticAdapters = nil
	project.mu.Unlock()
	adapters.release()
}

func registerAutomaticOperation(operation *AutomaticOperation) bool {
	automaticActiveOperations.mu.Lock()
	defer automaticActiveOperations.mu.Unlock()
	if len(automaticActiveOperations.operations) >= automaticMaxActiveOperations {
		return false
	}
	if automaticActiveOperations.operations == nil {
		automaticActiveOperations.operations = make(
			map[*AutomaticOperation]*AutomaticProject,
		)
	}
	if _, exists := automaticActiveOperations.operations[operation]; exists {
		return false
	}
	owner, ownerKnown := currentAutomaticGoroutineID()
	if ownerKnown {
		if automaticActiveOperations.byGoroutine == nil {
			automaticActiveOperations.byGoroutine = make(map[uint64][]*AutomaticOperation)
		}
		stack := automaticActiveOperations.byGoroutine[owner]
		automaticActiveOperations.byGoroutine[owner] = append(stack, operation)
		operation.ownerGoroutineID = owner
	}
	automaticActiveOperations.operations[operation] = operation.project
	return true
}

func unregisterAutomaticOperation(operation *AutomaticOperation) {
	automaticActiveOperations.mu.Lock()
	defer automaticActiveOperations.mu.Unlock()
	delete(automaticActiveOperations.operations, operation)
	owner := operation.ownerGoroutineID
	operation.ownerGoroutineID = 0
	if owner == 0 {
		return
	}
	stack := automaticActiveOperations.byGoroutine[owner]
	for index := len(stack) - 1; index >= 0; index-- {
		if stack[index] != operation {
			continue
		}
		stack = append(stack[:index], stack[index+1:]...)
		break
	}
	if len(stack) == 0 {
		delete(automaticActiveOperations.byGoroutine, owner)
	} else {
		automaticActiveOperations.byGoroutine[owner] = stack
	}
}

func currentAutomaticOperation() *AutomaticOperation {
	owner, ok := currentAutomaticGoroutineID()
	if !ok {
		return nil
	}
	automaticActiveOperations.mu.RLock()
	stack := automaticActiveOperations.byGoroutine[owner]
	var operation *AutomaticOperation
	if len(stack) > 0 {
		operation = stack[len(stack)-1]
	}
	automaticActiveOperations.mu.RUnlock()
	if operation != nil && operation.isActive() {
		return operation
	}
	return nil
}

func snapshotAutomaticOperations() []*AutomaticOperation {
	automaticActiveOperations.mu.RLock()
	candidates := make([]*AutomaticOperation, 0, len(automaticActiveOperations.operations))
	for operation := range automaticActiveOperations.operations {
		candidates = append(candidates, operation)
	}
	automaticActiveOperations.mu.RUnlock()
	result := make([]*AutomaticOperation, 0, len(candidates))
	for _, operation := range candidates {
		if operation.isActive() {
			result = append(result, operation)
		}
	}
	return result
}

func takeAutomaticProjectOperations(project *AutomaticProject) []*AutomaticOperation {
	automaticActiveOperations.mu.Lock()
	defer automaticActiveOperations.mu.Unlock()
	result := make([]*AutomaticOperation, 0)
	for operation, owner := range automaticActiveOperations.operations {
		if owner == project {
			delete(automaticActiveOperations.operations, operation)
			result = append(result, operation)
		}
	}
	return result
}
