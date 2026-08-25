// Package reproit captures bounded Backend operations and sends complete failed candidates.
package reproit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxGlobalBytes            = 1_048_576
	MaxOperationBytes         = 262_144
	MaxEventBytes             = 65_536
	MaxEvents                 = 1_024
	MaxActiveOperations       = 512
	MaxQueuedCandidates       = 16
	MaxFailureStormIdentities = 256
	deliveryLifetime          = 30 * time.Minute
	maxResponseHeaderBytes    = 4_096
	maxProcessLogicalBytes    = int64(4 * 1024 * 1024 * 1024)
)

var (
	ErrCaptureLimit        = errors.New("The SDK capture limit was reached.")
	ErrIncompleteCapture   = errors.New("The operation does not have complete capture state.")
	ErrDuplicateOperation  = errors.New("The operation already has capture state.")
	errUnexpectedTLSCipher = errors.New("The Runtime selected an unsupported TLS cipher suite.")
)

type CandidateSink interface {
	AllowsProcessingMode(mode string) bool
	QueuedBytes() int
	TrySend(captureID string, candidate []byte) bool
}

type discardCandidateSink struct{}

func (discardCandidateSink) AllowsProcessingMode(mode string) bool {
	return mode == "managed" || mode == "private"
}
func (discardCandidateSink) QueuedBytes() int            { return 0 }
func (discardCandidateSink) TrySend(string, []byte) bool { return false }

type RecallCounters struct {
	CandidateDeliveryExpired       uint64 `json:"candidate_delivery_expired"`
	CandidateDurablyAccepted       uint64 `json:"candidate_durably_accepted"`
	CandidateIncomplete            uint64 `json:"candidate_incomplete"`
	CandidateQueueFull             uint64 `json:"candidate_queue_full"`
	CandidateRejected              uint64 `json:"candidate_rejected"`
	EligibleFailureObserved        uint64 `json:"eligible_failure_observed"`
	SuppressedExactStorm           uint64 `json:"suppressed_exact_storm"`
	SuppressedHighCardinalityStorm uint64 `json:"suppressed_high_cardinality_storm"`
}

type recallSource interface {
	RecallCounters() RecallCounters
}

type CandidateStart struct {
	CaptureID   string
	Deployment  map[string]any
	OperationID string
	WorldID     string
}

type operation struct {
	bytes   int
	records []map[string]any
	start   CandidateStart
}

type stormEntry struct {
	admitted   time.Time
	observed   time.Time
	suppressed uint64
}

type sdkProcessResources struct {
	activeBytes      int
	activeOperations map[string]bool
	mu               sync.Mutex
	queuedBytes      int
	queuedCandidates int
	logicalBytes     int64
	stormAdmitted    map[string]stormEntry
	stormLastRefill  time.Time
	stormRejected    uint64
	stormTokens      float64
}

var processResources = newSDKProcessResources()

func newSDKProcessResources() *sdkProcessResources {
	return &sdkProcessResources{
		activeOperations: make(map[string]bool),
		stormAdmitted:    make(map[string]stormEntry),
		stormLastRefill:  time.Now(),
		stormTokens:      4,
	}
}

type SDK struct {
	allowPrivate bool
	mu           sync.Mutex
	operations   map[string]*operation
	sink         CandidateSink
	recall       RecallCounters
}

func New(sink CandidateSink) *SDK {
	if sink == nil {
		sink = discardCandidateSink{}
	}
	return &SDK{
		operations: make(map[string]*operation),
		sink:       sink,
	}
}

func (sdk *SDK) ActiveOperations() int {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()
	return len(sdk.operations)
}

func (sdk *SDK) RecallCounters() RecallCounters {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()
	counters := sdk.recall
	if source, ok := sdk.sink.(recallSource); ok {
		counters.merge(source.RecallCounters())
	}
	return counters
}

func (sdk *SDK) Begin(start CandidateStart, value map[string]any) error {
	if !validPrefixedUUIDv7(start.CaptureID, "cap_") ||
		!validPrefixedUUIDv7(start.OperationID, "op_") || !validDigest(start.WorldID) {
		return ErrIncompleteCapture
	}
	mode, modeOK := start.Deployment["processing_mode"].(string)
	if !modeOK || mode != "managed" && !(sdk.allowPrivate && mode == "private") {
		return ErrIncompleteCapture
	}
	record, err := eventRecord("begin", 0, value)
	if err != nil {
		return err
	}
	size := recordSize(record)
	sdk.mu.Lock()
	defer sdk.mu.Unlock()
	if _, exists := sdk.operations[start.OperationID]; exists {
		return ErrDuplicateOperation
	}
	if err := processResources.reserveOperation(start.OperationID, size); err != nil {
		return err
	}
	deployment, err := cloneMap(start.Deployment)
	if err != nil {
		processResources.releaseOperation(start.OperationID, size)
		return ErrIncompleteCapture
	}
	start.Deployment = deployment
	sdk.operations[start.OperationID] = &operation{bytes: size, records: []map[string]any{record}, start: start}
	return nil
}

func (sdk *SDK) RecordInput(operationID string, value map[string]any) error {
	return sdk.append(operationID, "input", value)
}

func (sdk *SDK) RecordDependency(operationID string, value map[string]any) error {
	return sdk.append(operationID, "dependency", value)
}

func (sdk *SDK) Succeed(operationID string) {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()
	sdk.delete(operationID)
}

func (sdk *SDK) Cancel(operationID string) {
	sdk.Succeed(operationID)
}

// AbandonIncomplete removes local capture state and records a fail-closed capture.
func (sdk *SDK) AbandonIncomplete(operationID string) {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()
	if sdk.operations[operationID] == nil {
		return
	}
	sdk.delete(operationID)
	increment(&sdk.recall.CandidateIncomplete)
}

func (sdk *SDK) Fail(operationID string, value map[string]any) error {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()
	increment(&sdk.recall.EligibleFailureObserved)
	active := sdk.operations[operationID]
	if active == nil {
		increment(&sdk.recall.CandidateIncomplete)
		return ErrIncompleteCapture
	}
	failure, err := eventRecord("failure", len(active.records), value)
	if err != nil {
		sdk.delete(operationID)
		increment(&sdk.recall.CandidateIncomplete)
		return err
	}
	failureSize := recordSize(failure)
	sdk.delete(operationID)
	if !withinOperation(active, failureSize) {
		increment(&sdk.recall.CandidateIncomplete)
		return ErrCaptureLimit
	}
	active.records = append(active.records, failure)
	terminalValue := map[string]any{
		"complete": true, "event_count": len(active.records), "format": "reproit.terminal.v1",
	}
	terminal, err := eventRecord("terminal", len(active.records), terminalValue)
	if err != nil || active.bytes+failureSize+recordSize(terminal) > MaxOperationBytes {
		increment(&sdk.recall.CandidateIncomplete)
		return ErrCaptureLimit
	}
	active.records = append(active.records, terminal)
	failureReference, ok := value["failure"].(map[string]any)
	if !ok {
		increment(&sdk.recall.CandidateIncomplete)
		return ErrIncompleteCapture
	}
	candidate := map[string]any{
		"capture_id": active.start.CaptureID, "deployment": active.start.Deployment,
		"failure": failureReference, "format": "reproit.candidate.v1",
		"operation_id": operationID, "processing_mode": active.start.Deployment["processing_mode"],
		"records": active.records, "world_id": active.start.WorldID,
	}
	if err := validateCandidate(candidate); err != nil {
		increment(&sdk.recall.CandidateIncomplete)
		return err
	}
	admission, err := processResources.admitFailure(candidate, value)
	if err != nil {
		return err
	}
	if admission == "suppressed-exact" {
		increment(&sdk.recall.SuppressedExactStorm)
		return nil
	}
	if admission == "suppressed-high-cardinality" {
		increment(&sdk.recall.SuppressedHighCardinalityStorm)
		return nil
	}
	encoded, err := CanonicalBytes(candidate)
	mode, _ := candidate["processing_mode"].(string)
	if err != nil {
		increment(&sdk.recall.CandidateIncomplete)
		return ErrIncompleteCapture
	}
	if !sdk.sink.AllowsProcessingMode(mode) {
		increment(&sdk.recall.CandidateRejected)
		return ErrIncompleteCapture
	}
	if len(encoded) > MaxOperationBytes || !sdk.sink.TrySend(active.start.CaptureID, encoded) {
		increment(&sdk.recall.CandidateQueueFull)
		return ErrCaptureLimit
	}
	return nil
}

func (resources *sdkProcessResources) admitFailure(candidate, value map[string]any) (string, error) {
	identity, identityOK := value["identity"].(map[string]any)
	failure, failureOK := value["failure"].(map[string]any)
	deployment, deploymentOK := candidate["deployment"].(map[string]any)
	if !identityOK || !failureOK || !deploymentOK {
		return "", ErrIncompleteCapture
	}
	subject, subjectOK := deployment["subject"].(map[string]any)
	if !subjectOK {
		return "", ErrIncompleteCapture
	}
	stable := map[string]any{
		"failure_identity_digest": failure["identity"],
		"format":                  "reproit.failure-storm-identity.v1",
		"operation_kind":          identity["operation_kind"],
		"operation_name":          identity["operation_name"],
		"service_id":              deployment["service_id"],
		"source_revision":         deployment["source_revision"],
		"subject_artifact_digest": subject["artifact_digest"],
	}
	for _, part := range stable {
		value, ok := part.(string)
		if !ok || value == "" {
			return "", ErrIncompleteCapture
		}
	}
	encoded, err := CanonicalBytes(stable)
	if err != nil {
		return "", ErrIncompleteCapture
	}
	key := fmt.Sprintf("%x", sha256.Sum256(encoded))
	resources.mu.Lock()
	defer resources.mu.Unlock()
	now := time.Now()
	elapsed := max(0, now.Sub(resources.stormLastRefill).Seconds())
	resources.stormTokens = min(4, resources.stormTokens+elapsed*2)
	resources.stormLastRefill = now
	for known, entry := range resources.stormAdmitted {
		if now.Sub(entry.admitted) >= time.Minute {
			delete(resources.stormAdmitted, known)
		}
	}
	if entry, exists := resources.stormAdmitted[key]; exists {
		entry.observed = now
		if entry.suppressed < ^uint64(0) {
			entry.suppressed++
		}
		resources.stormAdmitted[key] = entry
		return "suppressed-exact", nil
	}
	if resources.stormTokens < 1 {
		if resources.stormRejected < ^uint64(0) {
			resources.stormRejected++
		}
		return "suppressed-high-cardinality", nil
	}
	if len(resources.stormAdmitted) >= MaxFailureStormIdentities {
		oldestKey := ""
		var oldest time.Time
		for known, entry := range resources.stormAdmitted {
			if oldestKey == "" || entry.observed.Before(oldest) || entry.observed.Equal(oldest) && known < oldestKey {
				oldestKey, oldest = known, entry.observed
			}
		}
		delete(resources.stormAdmitted, oldestKey)
	}
	resources.stormTokens--
	resources.stormAdmitted[key] = stormEntry{admitted: now, observed: now}
	return "admitted", nil
}

func (resources *sdkProcessResources) reserveOperation(operationID string, size int) error {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if resources.activeOperations[operationID] {
		return ErrDuplicateOperation
	}
	if len(resources.activeOperations) >= MaxActiveOperations ||
		resources.activeBytes+resources.queuedBytes+size > MaxGlobalBytes {
		return ErrCaptureLimit
	}
	resources.activeOperations[operationID] = true
	resources.activeBytes += size
	return nil
}

func (resources *sdkProcessResources) growOperation(operationID string, size int) bool {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if !resources.activeOperations[operationID] ||
		resources.activeBytes+resources.queuedBytes+size > MaxGlobalBytes {
		return false
	}
	resources.activeBytes += size
	return true
}

func (resources *sdkProcessResources) releaseOperation(operationID string, size int) {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if !resources.activeOperations[operationID] {
		return
	}
	delete(resources.activeOperations, operationID)
	resources.activeBytes = max(0, resources.activeBytes-size)
}

func (resources *sdkProcessResources) reserveCandidate(size int) bool {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if resources.queuedCandidates >= MaxQueuedCandidates ||
		resources.activeBytes+resources.queuedBytes+size > MaxGlobalBytes {
		return false
	}
	resources.queuedCandidates++
	resources.queuedBytes += size
	return true
}

func (resources *sdkProcessResources) releaseCandidate(size int) {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	resources.queuedCandidates = max(0, resources.queuedCandidates-1)
	resources.queuedBytes = max(0, resources.queuedBytes-size)
}

func (resources *sdkProcessResources) queuedByteCount() int {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	return resources.queuedBytes
}

func (resources *sdkProcessResources) reserveLogical(size int64) bool {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if size < 0 || resources.logicalBytes > maxProcessLogicalBytes-size {
		return false
	}
	resources.logicalBytes += size
	return true
}

func (resources *sdkProcessResources) releaseLogical(size int64) {
	resources.mu.Lock()
	defer resources.mu.Unlock()
	resources.logicalBytes = max(0, resources.logicalBytes-size)
}

func (counters *RecallCounters) merge(other RecallCounters) {
	mergeCounter := func(target *uint64, value uint64) {
		maximum := uint64(math.MaxInt64)
		if value >= maximum-*target {
			*target = maximum
			return
		}
		*target += value
	}
	mergeCounter(&counters.CandidateDeliveryExpired, other.CandidateDeliveryExpired)
	mergeCounter(&counters.CandidateDurablyAccepted, other.CandidateDurablyAccepted)
	mergeCounter(&counters.CandidateIncomplete, other.CandidateIncomplete)
	mergeCounter(&counters.CandidateQueueFull, other.CandidateQueueFull)
	mergeCounter(&counters.CandidateRejected, other.CandidateRejected)
	mergeCounter(&counters.EligibleFailureObserved, other.EligibleFailureObserved)
	mergeCounter(&counters.SuppressedExactStorm, other.SuppressedExactStorm)
	mergeCounter(&counters.SuppressedHighCardinalityStorm, other.SuppressedHighCardinalityStorm)
}

func increment(counter *uint64) {
	if *counter < math.MaxInt64 {
		(*counter)++
	}
}

func (sdk *SDK) append(operationID, kind string, value map[string]any) error {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()
	active := sdk.operations[operationID]
	if active == nil {
		increment(&sdk.recall.CandidateIncomplete)
		return ErrIncompleteCapture
	}
	record, err := eventRecord(kind, len(active.records), value)
	if err != nil {
		sdk.delete(operationID)
		increment(&sdk.recall.CandidateIncomplete)
		return err
	}
	size := recordSize(record)
	if !withinOperation(active, size) || !processResources.growOperation(operationID, size) {
		sdk.delete(operationID)
		increment(&sdk.recall.CandidateIncomplete)
		return ErrCaptureLimit
	}
	active.records = append(active.records, record)
	active.bytes += size
	return nil
}

func (sdk *SDK) delete(operationID string) {
	if active := sdk.operations[operationID]; active != nil {
		delete(sdk.operations, operationID)
		processResources.releaseOperation(operationID, active.bytes)
	}
}

func withinOperation(active *operation, size int) bool {
	return len(active.records) < MaxEvents && active.bytes+size <= MaxOperationBytes
}

func eventRecord(kind string, sequence int, value map[string]any) (map[string]any, error) {
	encoded, err := CanonicalBytes(value)
	if err != nil {
		return nil, ErrIncompleteCapture
	}
	if len(encoded) > MaxEventBytes {
		return nil, ErrCaptureLimit
	}
	return map[string]any{
		"kind": kind, "payload": base64.RawURLEncoding.EncodeToString(encoded), "sequence": sequence,
	}, nil
}

func recordSize(record map[string]any) int {
	return len(record["payload"].(string)) + 32
}

func validateCandidate(candidate map[string]any) error {
	records, ok := candidateRecords(candidate["records"])
	deployment, deploymentOK := candidate["deployment"].(map[string]any)
	failure, failureOK := candidate["failure"].(map[string]any)
	if !ok || !deploymentOK || !failureOK || len(candidate) != 8 || len(records) < 3 ||
		candidate["format"] != "reproit.candidate.v1" ||
		!validPrefixedUUIDv7(candidate["capture_id"], "cap_") ||
		!validPrefixedUUIDv7(candidate["operation_id"], "op_") ||
		!validDigest(candidate["world_id"]) ||
		candidate["processing_mode"] != deployment["processing_mode"] ||
		records[0]["kind"] != "begin" || records[len(records)-1]["kind"] != "terminal" {
		return ErrIncompleteCapture
	}
	failures := 0
	payloads := make([]map[string]any, len(records))
	for index, record := range records {
		sequence, sequenceOK := integerValue(record["sequence"])
		payload, payloadOK := decodedRecordPayload(record)
		if !sequenceOK || sequence != int64(index) || !payloadOK {
			return ErrIncompleteCapture
		}
		payloads[index] = payload
		if record["kind"] == "failure" {
			failures++
		}
	}
	if failures != 1 {
		return ErrIncompleteCapture
	}
	begin := payloads[0]
	terminal := payloads[len(payloads)-1]
	failurePayload := payloads[len(payloads)-2]
	identity, identityOK := failurePayload["identity"].(map[string]any)
	_, containedFailureOK := failurePayload["failure"].(map[string]any)
	eventCount, eventCountOK := integerValue(terminal["event_count"])
	if records[len(records)-2]["kind"] != "failure" || !identityOK || !containedFailureOK ||
		!eventCountOK || eventCount != int64(len(records)-1) || terminal["complete"] != true ||
		len(terminal) != 3 || terminal["format"] != "reproit.terminal.v1" ||
		!validBeginPayload(begin) || !validOperationKind(identity["operation_kind"]) ||
		!validBoundedString(identity["operation_name"], 128) ||
		begin["operation_kind"] != identity["operation_kind"] ||
		begin["operation_name"] != identity["operation_name"] {
		return ErrIncompleteCapture
	}
	if equal, err := canonicalEqual(failurePayload, map[string]any{
		"failure": failure, "format": failurePayload["format"], "identity": identity,
	}); err != nil || !equal || failurePayload["format"] != "reproit.failure-payload.v1" ||
		digestValue(identity) != failure["identity"] {
		return ErrIncompleteCapture
	}
	inputIndex := int64(0)
	for index, record := range records {
		payload := payloads[index]
		switch record["kind"] {
		case "begin":
			if index != 0 {
				return ErrIncompleteCapture
			}
		case "input":
			current, currentOK := integerValue(payload["input_index"])
			if !validInputPayload(payload) || !currentOK ||
				current != inputIndex || digestDecodedValue(payload["value"]) != payload["value_digest"] {
				return ErrIncompleteCapture
			}
			inputIndex++
		case "dependency":
			if !validDependencyCursor(payload) {
				return ErrIncompleteCapture
			}
		case "failure":
			if index != len(records)-2 {
				return ErrIncompleteCapture
			}
		case "terminal":
			if index != len(records)-1 {
				return ErrIncompleteCapture
			}
		default:
			return ErrIncompleteCapture
		}
	}
	return nil
}

func candidateRecords(value any) ([]map[string]any, bool) {
	switch records := value.(type) {
	case []map[string]any:
		return records, true
	case []any:
		result := make([]map[string]any, len(records))
		for index, record := range records {
			mapped, ok := record.(map[string]any)
			if !ok {
				return nil, false
			}
			result[index] = mapped
		}
		return result, true
	default:
		return nil, false
	}
}

func decodedRecordPayload(record map[string]any) (map[string]any, bool) {
	encoded, ok := record["payload"].(string)
	if !ok || len(encoded) > 87_382 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) > MaxEventBytes {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.UseNumber()
	var payload map[string]any
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	canonical, err := CanonicalBytes(payload)
	return payload, err == nil && bytes.Equal(canonical, decoded)
}

func integerValue(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case json.Number:
		parsed, err := number.Int64()
		return parsed, err == nil && strconv.FormatInt(parsed, 10) == number.String()
	default:
		return 0, false
	}
}

func digestDecodedValue(value any) any {
	encoded, ok := value.(string)
	if !ok {
		return nil
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil
	}
	return digestBytes(decoded)
}

func validDependencyCursor(value map[string]any) bool {
	if len(value) != 6 || value["format"] != "reproit.dependency-cursor.v1" ||
		!validAdapterID(value["adapter_id"]) ||
		!validBoundedString(value["adapter_version"], 64) ||
		!validDigest(value["cursor_digest"]) {
		return false
	}
	cursor, ok := value["cursor"].(string)
	if !ok || len(cursor) == 0 || len(cursor) > 16_384 {
		return false
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(cursor); err != nil {
		return false
	}
	parent := value["causal_parent_id"]
	return parent == nil || validOperationID(parent)
}

func validBeginPayload(value map[string]any) bool {
	if len(value) != 6 || value["format"] != "reproit.operation-begin.v1" ||
		!validAdapterID(value["adapter_id"]) ||
		!validBoundedString(value["adapter_version"], 64) ||
		!validOperationKind(value["operation_kind"]) ||
		!validBoundedString(value["operation_name"], 128) {
		return false
	}
	parents, ok := value["causal_parent_ids"].([]any)
	if !ok || len(parents) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(parents))
	for _, parent := range parents {
		text, textOK := parent.(string)
		if !textOK || !validOperationID(text) {
			return false
		}
		if _, duplicate := seen[text]; duplicate {
			return false
		}
		seen[text] = struct{}{}
	}
	return true
}

func validInputPayload(value map[string]any) bool {
	if len(value) != 6 || value["format"] != "reproit.operation-input.v1" ||
		!validBoundedString(value["content_type"], 128) || !validDigest(value["value_digest"]) {
		return false
	}
	channel, ok := value["channel"].(string)
	if !ok || channel != "control" && channel != "input" && channel != "metadata" {
		return false
	}
	encoded, ok := value["value"].(string)
	if !ok || len(encoded) > 87_382 {
		return false
	}
	_, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil
}

func cloneMap(value map[string]any) (map[string]any, error) {
	encoded, err := CanonicalBytes(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var clone map[string]any
	err = decoder.Decode(&clone)
	return clone, err
}

func CanonicalBytes(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := encodeCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func encodeCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(typed))
	case string:
		encoded, _ := json.Marshal(typed)
		text := string(encoded)
		text = strings.ReplaceAll(text, `\u003c`, "<")
		text = strings.ReplaceAll(text, `\u003e`, ">")
		text = strings.ReplaceAll(text, `\u0026`, "&")
		text = strings.ReplaceAll(text, `\u2028`, " ")
		text = strings.ReplaceAll(text, `\u2029`, " ")
		output.WriteString(text)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return err
		}
		if strconv.FormatInt(parsed, 10) != typed.String() {
			return errors.New("The protocol value contains a non-canonical integer.")
		}
		output.WriteString(typed.String())
	case int:
		output.WriteString(strconv.Itoa(typed))
	case int64:
		output.WriteString(strconv.FormatInt(typed, 10))
	case float64:
		return errors.New("The protocol value contains a floating-point number.")
	case []any:
		output.WriteByte('[')
		for index, element := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := encodeCanonical(output, element); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case []map[string]any:
		values := make([]any, len(typed))
		for index := range typed {
			values[index] = typed[index]
		}
		return encodeCanonical(output, values)
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := encodeCanonical(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := encodeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("The protocol value has unsupported type %T.", value)
	}
	return nil
}
