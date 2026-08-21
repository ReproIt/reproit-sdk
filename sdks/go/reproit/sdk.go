// Package reproit captures bounded Backend operations and sends complete failed candidates.
package reproit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
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
	deliveryLifetime          = time.Second
	maxResponseHeaderBytes    = 4_096
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

type SDK struct {
	globalBytes     int
	mu              sync.Mutex
	operations      map[string]*operation
	sink            CandidateSink
	recall          RecallCounters
	stormAdmitted   map[string]stormEntry
	stormLastRefill time.Time
	stormRejected   uint64
	stormTokens     float64
}

func New(sink CandidateSink) *SDK {
	if sink == nil {
		sink = discardCandidateSink{}
	}
	return &SDK{
		operations:      make(map[string]*operation),
		sink:            sink,
		stormAdmitted:   make(map[string]stormEntry),
		stormLastRefill: time.Now(),
		stormTokens:     4,
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
	if !modeOK || mode != "managed" && mode != "private" {
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
	if len(sdk.operations) >= MaxActiveOperations || sdk.globalBytes+sdk.sink.QueuedBytes()+size > MaxGlobalBytes {
		return ErrCaptureLimit
	}
	deployment, err := cloneMap(start.Deployment)
	if err != nil {
		return ErrIncompleteCapture
	}
	start.Deployment = deployment
	sdk.operations[start.OperationID] = &operation{bytes: size, records: []map[string]any{record}, start: start}
	sdk.globalBytes += size
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
	admitted, err := sdk.admitFailure(candidate, value)
	if err != nil {
		return err
	}
	if !admitted {
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

func (sdk *SDK) admitFailure(candidate, value map[string]any) (bool, error) {
	identity, identityOK := value["identity"].(map[string]any)
	failure, failureOK := value["failure"].(map[string]any)
	deployment, deploymentOK := candidate["deployment"].(map[string]any)
	if !identityOK || !failureOK || !deploymentOK {
		return false, ErrIncompleteCapture
	}
	subject, subjectOK := deployment["subject"].(map[string]any)
	if !subjectOK {
		return false, ErrIncompleteCapture
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
			return false, ErrIncompleteCapture
		}
	}
	encoded, err := CanonicalBytes(stable)
	if err != nil {
		return false, ErrIncompleteCapture
	}
	key := fmt.Sprintf("%x", sha256.Sum256(encoded))
	now := time.Now()
	elapsed := max(0, now.Sub(sdk.stormLastRefill).Seconds())
	sdk.stormTokens = min(4, sdk.stormTokens+elapsed*2)
	sdk.stormLastRefill = now
	for known, entry := range sdk.stormAdmitted {
		if now.Sub(entry.admitted) >= time.Minute {
			delete(sdk.stormAdmitted, known)
		}
	}
	if entry, exists := sdk.stormAdmitted[key]; exists {
		entry.observed = now
		if entry.suppressed < ^uint64(0) {
			entry.suppressed++
		}
		sdk.stormAdmitted[key] = entry
		increment(&sdk.recall.SuppressedExactStorm)
		return false, nil
	}
	if sdk.stormTokens < 1 {
		if sdk.stormRejected < ^uint64(0) {
			sdk.stormRejected++
		}
		increment(&sdk.recall.SuppressedHighCardinalityStorm)
		return false, nil
	}
	if len(sdk.stormAdmitted) >= MaxFailureStormIdentities {
		oldestKey := ""
		var oldest time.Time
		for known, entry := range sdk.stormAdmitted {
			if oldestKey == "" || entry.observed.Before(oldest) || entry.observed.Equal(oldest) && known < oldestKey {
				oldestKey, oldest = known, entry.observed
			}
		}
		delete(sdk.stormAdmitted, oldestKey)
	}
	sdk.stormTokens--
	sdk.stormAdmitted[key] = stormEntry{admitted: now, observed: now}
	return true, nil
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
	if !withinOperation(active, size) || sdk.globalBytes+sdk.sink.QueuedBytes()+size > MaxGlobalBytes {
		sdk.delete(operationID)
		increment(&sdk.recall.CandidateIncomplete)
		return ErrCaptureLimit
	}
	active.records = append(active.records, record)
	active.bytes += size
	sdk.globalBytes += size
	return nil
}

func (sdk *SDK) delete(operationID string) {
	if active := sdk.operations[operationID]; active != nil {
		delete(sdk.operations, operationID)
		sdk.globalBytes = max(0, sdk.globalBytes-active.bytes)
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

type queuedCandidate struct {
	bytes     []byte
	captureID string
	enqueued  time.Time
}

type runtimeSink struct {
	authorization func() string
	candidatePath string
	contentType   string
	dial          func(time.Duration) (net.Conn, error)
	host          string
	mu            sync.Mutex
	queue         chan queuedCandidate
	queuedBytes   int
	queuedCount   int
}

type unixRuntimeSink struct{ *runtimeSink }

type tlsRuntimeSink struct{ *runtimeSink }

func (sink *runtimeSink) AllowsProcessingMode(mode string) bool { return mode == "private" }

func newunixRuntimeSink(socketPath string, authorization func() string) (*unixRuntimeSink, error) {
	if !strings.HasPrefix(socketPath, "/") || authorization == nil {
		return nil, errors.New("The Runtime socket path must be absolute.")
	}
	sink := &runtimeSink{
		authorization: authorization,
		candidatePath: "/v1/candidates/{capture_id}",
		contentType:   "application/reproit-candidate+json",
		dial: func(timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, timeout)
		},
		host:  "reproit-runtime",
		queue: make(chan queuedCandidate, MaxQueuedCandidates),
	}
	go sink.worker()
	return &unixRuntimeSink{runtimeSink: sink}, nil
}

func newtlsRuntimeSink(
	address string,
	serverName string,
	caCertificatePath string,
	authorization func() string,
) (*tlsRuntimeSink, error) {
	if address == "" || len(address) > 512 || serverName == "" || len(serverName) > 253 {
		return nil, errors.New("The shared Runtime TLS endpoint is invalid.")
	}
	if authorization == nil {
		return nil, errors.New("The shared Runtime authorization source is invalid.")
	}
	metadata, err := os.Lstat(caCertificatePath)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Size() <= 0 || metadata.Size() > 1_048_576 {
		return nil, errors.New("The shared Runtime CA certificate is invalid.")
	}
	certificate, err := os.ReadFile(caCertificatePath)
	if err != nil || int64(len(certificate)) != metadata.Size() {
		return nil, errors.New("The shared Runtime CA certificate is invalid.")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("The shared Runtime CA certificate is invalid.")
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: serverName,
	}
	sink := &runtimeSink{
		authorization: authorization,
		candidatePath: "/v1/candidates/{capture_id}",
		contentType:   "application/reproit-candidate+json",
		dial: func(timeout time.Duration) (net.Conn, error) {
			connection, dialError := tls.DialWithDialer(
				&net.Dialer{Timeout: timeout}, "tcp", address, config,
			)
			if dialError != nil {
				return nil, dialError
			}
			if connection.ConnectionState().CipherSuite != tls.TLS_AES_256_GCM_SHA384 {
				_ = connection.Close()
				return nil, errUnexpectedTLSCipher
			}
			return connection, nil
		},
		host:  serverName,
		queue: make(chan queuedCandidate, MaxQueuedCandidates),
	}
	go sink.worker()
	return &tlsRuntimeSink{runtimeSink: sink}, nil
}

func (sink *runtimeSink) QueuedBytes() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.queuedBytes
}

func (sink *runtimeSink) TrySend(captureID string, candidate []byte) bool {
	if !validPrefixedUUIDv7(captureID, "cap_") {
		return false
	}
	sink.mu.Lock()
	if sink.queuedCount >= MaxQueuedCandidates || sink.queuedBytes+len(candidate) > MaxGlobalBytes {
		sink.mu.Unlock()
		return false
	}
	sink.queuedBytes += len(candidate)
	sink.queuedCount++
	sink.mu.Unlock()
	queued := queuedCandidate{bytes: bytes.Clone(candidate), captureID: captureID, enqueued: time.Now()}
	select {
	case sink.queue <- queued:
		return true
	default:
		sink.mu.Lock()
		sink.queuedBytes -= len(candidate)
		sink.queuedCount--
		sink.mu.Unlock()
		return false
	}
}

func (sink *runtimeSink) worker() {
	for candidate := range sink.queue {
		sink.deliverCandidate(candidate)
		sink.mu.Lock()
		sink.queuedBytes -= len(candidate.bytes)
		sink.queuedCount--
		sink.mu.Unlock()
	}
}

func (sink *runtimeSink) deliverCandidate(candidate queuedCandidate) {
	for _, offset := range []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond} {
		time.Sleep(max(0, candidate.enqueued.Add(offset).Sub(time.Now())))
		remaining := candidate.enqueued.Add(deliveryLifetime).Sub(time.Now())
		if remaining <= 0 {
			return
		}
		if sink.deliver(candidate, remaining) != "retry" {
			return
		}
	}
}

func (sink *runtimeSink) deliver(candidate queuedCandidate, timeout time.Duration) string {
	return sink.deliverBytes(candidate.captureID, candidate.bytes, timeout)
}

func (sink *runtimeSink) deliverBytes(captureID string, body []byte, timeout time.Duration) string {
	authorization := sink.authorization()
	if authorization == "" || len(authorization) > 4_096 || strings.ContainsAny(authorization, "\r\n") {
		return "reject"
	}
	connection, err := sink.dial(timeout)
	if err != nil {
		var verification *tls.CertificateVerificationError
		if errors.As(err, &verification) || errors.Is(err, errUnexpectedTLSCipher) {
			return "reject"
		}
		return "retry"
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	request := fmt.Sprintf(
		"PUT %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nIdempotency-Key: %s\r\nReproit-Protocol: 1\r\nAuthorization: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		strings.Replace(sink.candidatePath, "{capture_id}", captureID, 1), sink.host,
		sink.contentType, captureID, authorization, len(body),
	)
	if _, err = io.WriteString(connection, request); err != nil {
		return "retry"
	}
	if _, err = connection.Write(body); err != nil {
		return "retry"
	}
	reader := bufio.NewReaderSize(
		io.LimitReader(connection, maxResponseHeaderBytes+1_024),
		maxResponseHeaderBytes,
	)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "retry"
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return "retry"
	case http.StatusOK, http.StatusAccepted:
	default:
		return "reject"
	}
	if sink.candidatePath == "/v1/candidates/{capture_id}" {
		return "accept"
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1_025))
	if err != nil || len(responseBody) == 0 || len(responseBody) > 1_024 {
		return "reject"
	}
	var envelope struct {
		Identity struct {
			RequestDigest string `json:"request_digest"`
		} `json:"identity"`
	}
	var receipt struct {
		CaptureID     string `json:"capture_id"`
		RequestDigest string `json:"request_digest"`
		State         string `json:"state"`
	}
	if json.Unmarshal(body, &envelope) != nil || json.Unmarshal(responseBody, &receipt) != nil ||
		receipt.CaptureID != captureID || receipt.RequestDigest != envelope.Identity.RequestDigest {
		return "reject"
	}
	if receipt.State == "CLOUD_PROTECTED" {
		return "cloud_protected"
	}
	if sink.candidatePath == "/v1/staged-candidates/{capture_id}" && receipt.State == "LOCAL_ONLY" {
		return "local_only"
	}
	return "reject"
}
