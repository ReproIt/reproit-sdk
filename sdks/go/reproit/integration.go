package reproit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxCapturedInputBytes = 32 * 1_024
	maxContentTypeBytes   = 256
	maxOperationNameBytes = 128
	maxProjectConfigBytes = 65_536
	maxProjectSearchDepth = 64
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

// Init loads the reviewed project configuration without changing the application.
func Init() *ReproIt {
	capture := &ReproIt{worldCapture: automaticWorldCapture}
	projectFile, err := findProjectFile()
	if err != nil {
		return capture
	}
	projectBytes, err := os.ReadFile(projectFile)
	if err != nil || len(projectBytes) > maxProjectConfigBytes {
		return capture
	}
	project, err := parseProjectConfig(projectBytes)
	if err != nil {
		return capture
	}
	repositoryID, ok := project["repository_id"].(string)
	if !ok {
		return capture
	}
	revision, err := gitSourceRevision(filepath.Dir(filepath.Dir(projectFile)))
	if err != nil {
		return capture
	}
	capture.project, _ = NewOfficialManagedProject(project, repositoryID, revision)
	return capture
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

// Operation runs one framework-neutral operation and preserves its exact error.
func (capture *ReproIt) Operation(
	operationName string,
	input []byte,
	operation func() error,
) error {
	return capture.Run(
		operationName,
		"application/octet-stream",
		input,
		func(*OperationCapture) error { return operation() },
		func(applicationError error) map[string]any {
			typeName := fmt.Sprintf("%T", applicationError)
			return failurePayload("exception", operationName, typeName, typeName)
		},
	)
}

// Operation runs one framework-neutral operation with a value result.
func Operation[T any](
	capture *ReproIt,
	operationName string,
	input []byte,
	operation func() (T, error),
) (T, error) {
	var result T
	err := capture.Operation(operationName, input, func() error {
		var operationError error
		result, operationError = operation()
		return operationError
	})
	return result, err
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
	if capture == nil || capture.project == nil || capture.worldCapture == nil {
		return nil
	}
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
	failure := classifyFailure(applicationError)
	if failure == nil {
		return
	}
	captureFailurePayload(active, failure)
}

func captureFailurePayload(active *activeOperation, failure map[string]any) {
	active.context.mu.Lock()
	valid := active.context.valid
	dependencies := append([]map[string]any(nil), active.context.dependencies...)
	active.context.mu.Unlock()
	if !valid {
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

func failurePayload(
	category string, operationName string, stableCode string, typeName string,
) map[string]any {
	identity := map[string]any{
		"category":       category,
		"cause_types":    []any{},
		"frames":         []any{},
		"operation_kind": "request-response",
		"operation_name": operationName,
		"runtime_family": "go",
		"schema":         "reproit.failure.v1",
		"stable_code":    stableCode,
		"type":           typeName,
	}
	identityDigest, _ := canonicalDigest(identity)
	objectID, _ := newObjectID()
	return map[string]any{
		"failure": map[string]any{
			"category":  category,
			"identity":  identityDigest,
			"matcher":   "exception-exact-v1",
			"object_id": objectID,
			"schema":    "reproit.failure.v1",
		},
		"format":   "reproit.failure-payload.v1",
		"identity": identity,
	}
}

func automaticWorldCapture() (ManagedWorldCapture, error) {
	world := map[string]any{
		"created_at": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"format":     "reproit.world-checkpoint.v1",
		"points":     []any{},
	}
	worldID, err := canonicalDigest(world)
	if err != nil {
		return ManagedWorldCapture{}, err
	}
	return ManagedWorldCapture{
		WorldID: worldID,
		Complete: func(string) (ManagedCaptureClosure, error) {
			copied, err := cloneMap(world)
			if err != nil {
				return ManagedCaptureClosure{}, err
			}
			return ManagedCaptureClosure{
				Artifacts: []ManagedCandidateArtifact{}, Completion: "return", World: copied,
			}, nil
		},
	}, nil
}

func findProjectFile() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for range maxProjectSearchDepth {
		configurationDirectory := filepath.Join(directory, ".reproit")
		directoryMetadata, directoryErr := os.Lstat(configurationDirectory)
		candidate := filepath.Join(configurationDirectory, "project.toml")
		metadata, metadataErr := os.Lstat(candidate)
		if directoryErr == nil && directoryMetadata.IsDir() &&
			directoryMetadata.Mode()&os.ModeSymlink == 0 &&
			metadataErr == nil && metadata.Mode().IsRegular() {
			return candidate, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return "", errors.New("Repro It could not load the reviewed project configuration")
}

func parseProjectConfig(value []byte) (map[string]any, error) {
	project := make(map[string]any)
	scanner := bufio.NewScanner(bytes.NewReader(value))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			break
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New("The Repro It project configuration is invalid")
		}
		key := strings.TrimSpace(parts[0])
		raw := strings.TrimSpace(parts[1])
		if _, exists := project[key]; key == "" || exists {
			return nil, errors.New("The Repro It project configuration is invalid")
		}
		if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
			project[key] = raw[1 : len(raw)-1]
			continue
		}
		number, err := strconv.Atoi(raw)
		if err != nil {
			return nil, errors.New("The Repro It project configuration is invalid")
		}
		project[key] = number
	}
	return project, scanner.Err()
}

func gitSourceRevision(projectRoot string) (string, error) {
	context, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(context, "git", "rev-parse", "--verify", "HEAD")
	command.Dir = projectRoot
	output, err := command.Output()
	if err != nil || len(output) > 65 {
		return "", errors.New("Repro It could not identify the deployed source revision")
	}
	revision := strings.TrimSpace(string(output))
	if len(revision) != 40 && len(revision) != 64 {
		return "", errors.New("Repro It could not identify the deployed source revision")
	}
	for _, character := range revision {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return "", errors.New("Repro It could not identify the deployed source revision")
		}
	}
	return revision, nil
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
