package reproit

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingStagedDelivery struct {
	mu       sync.Mutex
	received [][]byte
}

type privateOnlySink struct {
	deliveries int
}

func newTestSDK(sink CandidateSink) *SDK {
	sdk := New(sink)
	sdk.allowPrivate = true
	return sdk
}

func (sink *privateOnlySink) AllowsProcessingMode(mode string) bool { return mode == "private" }
func (sink *privateOnlySink) QueuedBytes() int                      { return 0 }
func (sink *privateOnlySink) TrySend(string, []byte) bool {
	sink.deliveries++
	return true
}

func (delivery *recordingStagedDelivery) deliverBytes(
	_ string,
	body []byte,
	_ time.Duration,
) string {
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	delivery.received = append(delivery.received, bytes.Clone(body))
	return "cloud_protected"
}

func (delivery *recordingStagedDelivery) bytes() [][]byte {
	delivery.mu.Lock()
	defer delivery.mu.Unlock()
	result := make([][]byte, len(delivery.received))
	for index := range delivery.received {
		result[index] = bytes.Clone(delivery.received[index])
	}
	return result
}

func vectors(t *testing.T) map[string]any {
	t.Helper()
	input, err := os.ReadFile(os.Getenv("REPROIT_PROTOCOL_VECTORS"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var vectors map[string]any
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	return vectors["positive"].(map[string]any)
}

func value(positive map[string]any, name string) map[string]any {
	return positive[name].(map[string]any)["value"].(map[string]any)
}

func fixture(t *testing.T) (*SDK, *MemorySink, CandidateStart, map[string]any) {
	t.Helper()
	processResources = newSDKProcessResources()
	positive := vectors(t)
	expected := value(positive, "candidate")
	start := CandidateStart{
		CaptureID: expected["capture_id"].(string), Deployment: expected["deployment"].(map[string]any),
		OperationID: expected["operation_id"].(string), WorldID: expected["world_id"].(string),
	}
	sink := &MemorySink{}
	return newTestSDK(sink), sink, start, positive
}

func TestCandidateMatchesCanonicalVector(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	if err := sdk.Begin(start, value(positive, "operation_begin_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.RecordInput(start.OperationID, value(positive, "operation_input_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.Fail(start.OperationID, value(positive, "failure_payload")); err != nil {
		t.Fatal(err)
	}
	expected, _ := CanonicalBytes(value(positive, "candidate"))
	if len(sink.Candidates) != 1 || !bytes.Equal(sink.Candidates[0], expected) || sdk.ActiveOperations() != 0 {
		t.Fatal("failed candidate differs from the language-neutral vector")
	}
}

func TestRefreshedWorldDoesNotBypassFailureSuppression(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	if err := sdk.Begin(start, value(positive, "operation_begin_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.Fail(start.OperationID, value(positive, "failure_payload")); err != nil {
		t.Fatal(err)
	}
	start.CaptureID = "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3"
	start.OperationID = "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4"
	start.WorldID = "sha256:" + strings.Repeat("a", 64)
	if err := sdk.Begin(start, value(positive, "operation_begin_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.Fail(start.OperationID, value(positive, "failure_payload")); err != nil {
		t.Fatal(err)
	}
	if len(sink.Candidates) != 1 {
		t.Fatal("a refreshed World bypassed Failure suppression")
	}
	if counters := sdk.RecallCounters(); counters.EligibleFailureObserved != 2 || counters.SuppressedExactStorm != 1 {
		t.Fatal("the exact-storm recall counters are incorrect")
	}
}

func TestOneThousandExactFailuresUseOneCandidateToken(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	for index := 0; index < 1000; index++ {
		current := start
		current.CaptureID = fmt.Sprintf("cap_01890f3e-7b1c-7cc0-8a1b-%012x", index)
		current.OperationID = fmt.Sprintf("op_01890f3e-7b1c-7cc0-8a1b-%012x", index)
		if err := sdk.Begin(current, value(positive, "operation_begin_payload")); err != nil {
			t.Fatal(err)
		}
		if err := sdk.Fail(current.OperationID, value(positive, "failure_payload")); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.Candidates) != 1 {
		t.Fatal("exact Failure repetition consumed more than one candidate token")
	}
	if counters := sdk.RecallCounters(); counters.EligibleFailureObserved != 1000 || counters.SuppressedExactStorm != 999 {
		t.Fatal("the repeated-Failure recall counters are incorrect")
	}
}

func TestHighCardinalityStormStopsAtCandidateTokens(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	processResources.stormLastRefill = time.Now().Add(time.Hour)
	for index := 0; index < 257; index++ {
		failure, err := cloneMap(value(positive, "failure_payload"))
		if err != nil {
			t.Fatal(err)
		}
		identity := failure["identity"].(map[string]any)
		identity["stable_code"] = fmt.Sprintf("storm-%d", index)
		encoded, err := CanonicalBytes(identity)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		failure["failure"].(map[string]any)["identity"] = fmt.Sprintf("sha256:%x", digest)
		current := start
		current.CaptureID = fmt.Sprintf("cap_01890f3e-7b1c-7cc0-8a1b-%012x", index)
		current.OperationID = fmt.Sprintf("op_01890f3e-7b1c-7cc0-8a1b-%012x", index)
		if err := sdk.Begin(current, value(positive, "operation_begin_payload")); err != nil {
			t.Fatal(err)
		}
		if err := sdk.Fail(current.OperationID, failure); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.Candidates) != 4 {
		t.Fatal("high-cardinality churn bypassed the candidate token bucket")
	}
	if sdk.RecallCounters().SuppressedHighCardinalityStorm == 0 {
		t.Fatal("the high-cardinality recall counter did not advance")
	}
}

func TestSuccessCancellationAndApplicationError(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	begin := value(positive, "operation_begin_payload")
	_ = sdk.Begin(start, begin)
	sdk.Succeed(start.OperationID)
	_ = sdk.Begin(start, begin)
	sdk.Cancel(start.OperationID)
	if len(sink.Candidates) != 0 {
		t.Fatal("successful or cancelled operation reached the sink")
	}
	original := errors.New("customer failure")
	returned := RunOperation(
		sdk, start, begin, []map[string]any{value(positive, "operation_input_payload")},
		func() error { return original }, func(error) map[string]any { return value(positive, "failure_payload") },
	)
	if returned != original || len(sink.Candidates) != 1 {
		t.Fatal("capture changed the application error")
	}
}

func TestMissingCaptureSinkPreservesApplicationError(t *testing.T) {
	_, _, start, positive := fixture(t)
	sdk := newTestSDK(nil)
	original := errors.New("customer failure")
	returned := RunOperation(
		sdk, start, value(positive, "operation_begin_payload"), nil,
		func() error { return original },
		func(error) map[string]any { return value(positive, "failure_payload") },
	)
	if returned != original || sdk.ActiveOperations() != 0 {
		t.Fatal("the missing capture sink changed the application error or retained state")
	}
}

func TestMissingSDKPreservesOperationResult(t *testing.T) {
	_, _, start, positive := fixture(t)
	called := false
	returned := RunOperation(
		nil, start, value(positive, "operation_begin_payload"), nil,
		func() error {
			called = true
			return nil
		},
		func(error) map[string]any { return value(positive, "failure_payload") },
	)
	if returned != nil || !called {
		t.Fatal("the missing SDK changed the operation result")
	}
}

func TestAuthenticatedUnixDelivery(t *testing.T) {
	_, _, start, positive := fixture(t)
	directory, err := os.MkdirTemp("/tmp", "reproit-go-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		var header strings.Builder
		length := 0
		for {
			line, _ := reader.ReadString('\n')
			header.WriteString(line)
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				_, _ = fmt.Sscanf(line, "Content-Length: %d", &length)
			}
			if line == "\r\n" {
				break
			}
		}
		body := make([]byte, length)
		_, _ = io.ReadFull(reader, body)
		received <- append([]byte(header.String()), body...)
		_, _ = connection.Write([]byte("HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"))
	}()
	sink, err := newunixRuntimeSink(path, func() string { return "ReproIt workload-token" })
	if err != nil {
		t.Fatal(err)
	}
	sdk := newTestSDK(sink)
	_ = sdk.Begin(start, value(positive, "operation_begin_payload"))
	_ = sdk.RecordInput(start.OperationID, value(positive, "operation_input_payload"))
	if err := sdk.Fail(start.OperationID, value(positive, "failure_payload")); err != nil {
		t.Fatal(err)
	}
	select {
	case request := <-received:
		if !bytes.Contains(request, []byte("Reproit-Protocol: 1")) ||
			!bytes.Contains(request, []byte("Authorization: ReproIt workload-token")) {
			t.Fatal("authenticated protocol headers are missing")
		}
	case <-time.After(time.Second):
		t.Fatal("Runtime did not receive the candidate")
	}
}

func TestUnixDeliveryBoundsActiveAndWaitingCandidates(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	sink, err := newunixRuntimeSink("/tmp/reproit-missing-runtime.sock", func() string {
		startedOnce.Do(func() { close(started) })
		<-release
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sink.TrySend("cap_01890f3e-7b1c-7cc0-8a1b-000000000000", []byte("0")) {
		t.Fatal("the first candidate was rejected")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("the first delivery did not start")
	}
	for index := 1; index < MaxQueuedCandidates; index++ {
		captureID := fmt.Sprintf("cap_01890f3e-7b1c-7cc0-8a1b-%012x", index)
		if !sink.TrySend(captureID, []byte("0")) {
			t.Fatalf("candidate %d was rejected below the bound", index)
		}
	}
	if sink.TrySend("cap_01890f3e-7b1c-7cc0-8a1b-000000000010", []byte("0")) {
		t.Fatal("the candidate beyond the active and waiting bound was accepted")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for sink.QueuedBytes() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sink.QueuedBytes() != 0 {
		t.Fatal("the bounded queue did not drain")
	}
}

const queueRestartStateFormat = "reproit.sdk-queue-restart.v1"
const maxQueueRestartStateBytes = 4096

type queueRestartState struct {
	Format           string `json:"format"`
	OneOverAccepted  bool   `json:"one_over_accepted"`
	PID              int    `json:"pid"`
	QueuedBytes      int    `json:"queued_bytes"`
	QueuedCandidates int    `json:"queued_candidates"`
}

func TestProcessRestartRecoversExactQueueCapacity(t *testing.T) {
	mode := os.Getenv("REPROIT_QUEUE_RESTART_CHILD")
	if mode != "" {
		runQueueRestartChild(t, mode, os.Getenv("REPROIT_QUEUE_RESTART_STATE"))
		return
	}
	statePath := filepath.Join(t.TempDir(), "state.json")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := func(childMode string) *exec.Cmd {
		command := exec.Command(executable, "-test.run=^TestProcessRestartRecoversExactQueueCapacity$")
		command.Env = append(os.Environ(),
			"REPROIT_QUEUE_RESTART_CHILD="+childMode,
			"REPROIT_QUEUE_RESTART_STATE="+statePath,
		)
		return command
	}
	first := child("seed")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForQueueRestartState(statePath) {
		_ = first.Process.Kill()
		t.Fatal("the first queue process did not persist its bounded state")
	}
	if err := first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err == nil {
		t.Fatal("the first queue process was not terminated")
	}
	if output, err := child("recover").CombinedOutput(); err != nil {
		t.Fatalf("the restarted queue process failed: %v: %s", err, output)
	}
	if err := os.WriteFile(statePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child("recover").Run(); err == nil {
		t.Fatal("the restarted queue process accepted corrupt durable state")
	}
	over := queueRestartState{
		Format: queueRestartStateFormat, PID: first.Process.Pid,
		QueuedBytes:      MaxQueuedCandidates + 1,
		QueuedCandidates: MaxQueuedCandidates + 1,
	}
	if err := writeQueueRestartState(statePath, over); err != nil {
		t.Fatal(err)
	}
	if err := child("recover").Run(); err == nil {
		t.Fatal("the restarted queue process accepted one-over durable state")
	}
}

func runQueueRestartChild(t *testing.T, mode, statePath string) {
	positive := vectors(t)
	candidate, err := CanonicalBytes(value(positive, "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if mode == "recover" {
		if _, err := readQueueRestartState(statePath, len(candidate)); err != nil {
			t.Fatal(err)
		}
	} else if mode != "seed" {
		t.Fatal("the queue restart child mode is invalid")
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	sink, err := newunixRuntimeSink("/tmp/reproit-missing-runtime-restart.sock", func() string {
		once.Do(func() { close(started) })
		<-release
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sink.TrySend("cap_01890f3e-7b1c-7cc0-8a1b-000000000000", candidate) {
		t.Fatal("the queue restart child refused the first candidate")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("the queue restart child did not start delivery")
	}
	for index := 1; index < MaxQueuedCandidates; index++ {
		captureID := fmt.Sprintf("cap_01890f3e-7b1c-7cc0-8a1b-%012x", index)
		if !sink.TrySend(captureID, candidate) {
			t.Fatal("the queue restart child stopped below the bound")
		}
	}
	state := queueRestartState{
		Format: queueRestartStateFormat, PID: os.Getpid(),
		QueuedBytes: sink.QueuedBytes(), QueuedCandidates: MaxQueuedCandidates,
		OneOverAccepted: sink.TrySend(
			"cap_01890f3e-7b1c-7cc0-8a1b-000000000010", candidate),
	}
	if err := writeQueueRestartState(statePath, state); err != nil {
		t.Fatal(err)
	}
	if mode == "seed" {
		select {}
	}
}

func waitForQueueRestartState(path string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if information, err := os.Stat(path); err == nil && information.Size() > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func writeQueueRestartState(path string, state queueRestartState) error {
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) == 0 || len(encoded) > maxQueueRestartStateBytes {
		return errors.New("the queue restart state exceeds its bound")
	}
	temporary := path + ".tmp"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(encoded); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	return errors.Join(err, directory.Close())
}

func readQueueRestartState(path string, candidateSize int) (queueRestartState, error) {
	information, err := os.Lstat(path)
	if err != nil || !information.Mode().IsRegular() || information.Size() > maxQueueRestartStateBytes {
		return queueRestartState{}, errors.New("the queue restart state is invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return queueRestartState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var state queueRestartState
	if err := decoder.Decode(&state); err != nil || state.Format != queueRestartStateFormat ||
		state.OneOverAccepted || state.QueuedCandidates != MaxQueuedCandidates ||
		state.QueuedBytes != MaxQueuedCandidates*candidateSize || state.PID <= 0 ||
		state.PID == os.Getpid() {
		return queueRestartState{}, errors.New("the queue restart state is invalid")
	}
	return state, nil
}

func TestStagedDeliveryEncryptsOnceAndSendsTheSameCompleteCandidate(t *testing.T) {
	runtime := &recordingStagedDelivery{}
	deferred := &recordingStagedDelivery{}
	key := bytes.Repeat([]byte{0x63}, 32)
	sink, err := NewstagedCandidateSink(runtime, deferred, key)
	if err != nil {
		t.Fatal(err)
	}
	sdk, _, start, positive := fixture(t)
	sdk.sink = sink
	if err := sdk.Begin(start, value(positive, "operation_begin_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.RecordInput(start.OperationID, value(positive, "operation_input_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.Fail(start.OperationID, value(positive, "failure_payload")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for (len(runtime.bytes()) == 0 || len(deferred.bytes()) == 0 ||
		sink.RecallCounters().CandidateDurablyAccepted == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	runtimeBytes := runtime.bytes()
	deferredBytes := deferred.bytes()
	if len(runtimeBytes) != 1 || len(deferredBytes) != 1 || !bytes.Equal(runtimeBytes[0], deferredBytes[0]) {
		t.Fatal("the staged transports did not receive one identical envelope")
	}
	decoder := json.NewDecoder(bytes.NewReader(runtimeBytes[0]))
	decoder.UseNumber()
	var envelope map[string]any
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	stored, err := base64.RawURLEncoding.DecodeString(envelope["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	aad, _ := CanonicalBytes(envelope["identity"])
	plaintext, err := gcm.Open(nil, stored[:12], stored[12:], aad)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := CanonicalBytes(value(positive, "candidate"))
	if !bytes.Equal(plaintext, expected) || sink.QueuedBytes() != 0 {
		t.Fatal("the staged envelope did not contain the exact complete candidate")
	}
}

func TestIncompleteCandidateMakesNoStagedDeliveryRequest(t *testing.T) {
	runtime := &recordingStagedDelivery{}
	deferred := &recordingStagedDelivery{}
	sink, err := NewstagedCandidateSink(runtime, deferred, bytes.Repeat([]byte{0x63}, 32))
	if err != nil {
		t.Fatal(err)
	}
	candidate := value(vectors(t), "candidate")
	records := candidate["records"].([]any)
	candidate["records"] = records[:len(records)-1]
	encoded, _ := CanonicalBytes(candidate)
	if sink.TrySend(candidate["capture_id"].(string), encoded) {
		t.Fatal("the incomplete candidate entered staged delivery")
	}
	time.Sleep(time.Millisecond)
	if len(runtime.bytes()) != 0 || len(deferred.bytes()) != 0 || sink.QueuedBytes() != 0 {
		t.Fatal("the incomplete candidate made a staging request")
	}
	if sink.RecallCounters().CandidateIncomplete != 1 {
		t.Fatal("the incomplete candidate was not counted")
	}
}

func TestHTTPBoundaryPreservesPanic(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	original := &struct{ message string }{"customer failure"}
	handler := HTTPMiddleware(
		sdk,
		func(*http.Request) HTTPPreparation {
			return HTTPPreparation{
				Begin:  value(positive, "operation_begin_payload"),
				Inputs: []map[string]any{value(positive, "operation_input_payload")},
				Start:  start,
			}
		},
		func(any) map[string]any { return value(positive, "failure_payload") },
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(original) }),
	)
	defer func() {
		if recover() != original {
			t.Fatal("the HTTP boundary changed the application panic")
		}
		expected, _ := CanonicalBytes(value(positive, "candidate"))
		if len(sink.Candidates) != 1 || !bytes.Equal(sink.Candidates[0], expected) {
			t.Fatal("the HTTP failure did not produce the expected candidate")
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestHTTPBoundaryStreamsRequestBodyAsOrderedInputs(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	body := append(bytes.Repeat([]byte("a"), 32*1024), []byte("tail")...)
	original := &struct{ message string }{"customer failure"}
	handler := HTTPMiddleware(
		sdk,
		func(*http.Request) HTTPPreparation {
			return HTTPPreparation{
				Begin: value(positive, "operation_begin_payload"), Start: start,
			}
		},
		func(any) map[string]any { return value(positive, "failure_payload") },
		http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			if _, err := io.ReadAll(request.Body); err != nil {
				t.Fatal(err)
			}
			panic(original)
		}),
	)
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/octet-stream")
	defer func() {
		if recover() != original {
			t.Fatal("the HTTP boundary changed the application panic")
		}
		if len(sink.Candidates) != 1 {
			t.Fatal("the complete streamed request did not produce a candidate")
		}
		var candidate map[string]any
		decoder := json.NewDecoder(bytes.NewReader(sink.Candidates[0]))
		decoder.UseNumber()
		if err := decoder.Decode(&candidate); err != nil {
			t.Fatal(err)
		}
		records, ok := candidateRecords(candidate["records"])
		if !ok {
			t.Fatal("the candidate records are invalid")
		}
		captured := make([]byte, 0, len(body))
		inputIndex := int64(0)
		for _, record := range records {
			if record["kind"] != "input" {
				continue
			}
			payload, payloadOK := decodedRecordPayload(record)
			current, indexOK := integerValue(payload["input_index"])
			encoded, valueOK := payload["value"].(string)
			chunk, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
			if !payloadOK || !indexOK || !valueOK || decodeErr != nil || current != inputIndex {
				t.Fatal("the request body input order is invalid")
			}
			captured = append(captured, chunk...)
			inputIndex++
		}
		if !bytes.Equal(captured, body) {
			t.Fatal("the captured request body differs from the application body")
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), request)
}

func TestOversizedFailureDeletesOperation(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	if err := sdk.Begin(start, value(positive, "operation_begin_payload")); err != nil {
		t.Fatal(err)
	}
	failure := value(positive, "failure_payload")
	failure["oversized"] = strings.Repeat("x", MaxEventBytes)
	if !errors.Is(sdk.Fail(start.OperationID, failure), ErrCaptureLimit) {
		t.Fatal("the oversized failure returned the wrong result")
	}
	if sdk.ActiveOperations() != 0 || len(sink.Candidates) != 0 {
		t.Fatal("the oversized operation was retained or delivered")
	}
}

func TestActiveOperationCountIsBounded(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	operationIDs := make([]string, 0, MaxActiveOperations)
	for index := 0; index < MaxActiveOperations; index++ {
		operationID := fmt.Sprintf("op_01890f3e-7b1c-7cc0-8a1b-%012x", index)
		boundedStart := start
		boundedStart.OperationID = operationID
		if err := sdk.Begin(boundedStart, value(positive, "operation_begin_payload")); err != nil {
			t.Fatalf("operation %d was rejected below the active bound: %v", index, err)
		}
		operationIDs = append(operationIDs, operationID)
	}
	rejected := start
	rejected.OperationID = "op_01890f3e-7b1c-7cc0-8a1b-000000000200"
	if !errors.Is(sdk.Begin(rejected, value(positive, "operation_begin_payload")), ErrCaptureLimit) {
		t.Fatal("the operation beyond the active bound was accepted")
	}
	if sdk.ActiveOperations() != MaxActiveOperations || len(sink.Candidates) != 0 {
		t.Fatal("the active operation bound changed capture state")
	}
	for _, operationID := range operationIDs {
		sdk.Cancel(operationID)
	}
	if sdk.ActiveOperations() != 0 {
		t.Fatal("the bounded active operations were not released")
	}
}

func TestDependencyRecordIsBoundIntoCompleteCandidate(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	dependency := value(positive, "dependency_close_request")["cursor"].(map[string]any)
	if err := sdk.Begin(start, value(positive, "operation_begin_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.RecordInput(start.OperationID, value(positive, "operation_input_payload")); err != nil {
		t.Fatal(err)
	}
	if err := sdk.RecordDependency(start.OperationID, dependency); err != nil {
		t.Fatal(err)
	}
	if err := sdk.Fail(start.OperationID, value(positive, "failure_payload")); err != nil {
		t.Fatal(err)
	}
	if len(sink.Candidates) != 1 {
		t.Fatal("the complete dependency capture did not reach the sink")
	}
	decoder := json.NewDecoder(bytes.NewReader(sink.Candidates[0]))
	decoder.UseNumber()
	var candidate map[string]any
	if err := decoder.Decode(&candidate); err != nil {
		t.Fatal(err)
	}
	records, ok := candidateRecords(candidate["records"])
	if !ok || len(records) != 5 || records[2]["kind"] != "dependency" {
		t.Fatal("the dependency record order changed")
	}
	payload, ok := decodedRecordPayload(records[2])
	if !ok {
		t.Fatal("the dependency record payload is invalid")
	}
	equal, err := canonicalEqual(payload, dependency)
	if err != nil || !equal {
		t.Fatal("the dependency record differs from the captured cursor")
	}
}

func TestInvalidDependencyFailsClosedAndPreservesApplicationError(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	dependency := value(positive, "dependency_close_request")["cursor"].(map[string]any)
	dependency = cloneForTest(t, dependency)
	dependency["cursor_digest"] = "invalid"
	original := errors.New("customer failure")
	returned := RunPreparedOperation(
		sdk,
		OperationPreparation{
			Begin:        value(positive, "operation_begin_payload"),
			Dependencies: []map[string]any{dependency},
			Inputs:       []map[string]any{value(positive, "operation_input_payload")},
			Start:        start,
		},
		func() error { return original },
		func(error) map[string]any { return value(positive, "failure_payload") },
	)
	if returned != original || len(sink.Candidates) != 0 || sdk.ActiveOperations() != 0 {
		t.Fatal("incomplete dependency capture changed the application result or reached the sink")
	}
	if sdk.RecallCounters().CandidateIncomplete == 0 {
		t.Fatal("incomplete dependency capture was not counted")
	}
}

func TestInvalidCaptureIdentityStopsBeforeCandidateDelivery(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	start.CaptureID = "cap_invalid\r\nInjected: true"
	if !errors.Is(sdk.Begin(start, value(positive, "operation_begin_payload")), ErrIncompleteCapture) {
		t.Fatal("the invalid capture identity was accepted")
	}
	if sdk.ActiveOperations() != 0 || len(sink.Candidates) != 0 {
		t.Fatal("the invalid capture identity changed capture state or reached the sink")
	}
}

func TestManagedCandidateDoesNotEnterPrivateTransport(t *testing.T) {
	_, _, start, positive := fixture(t)
	start.Deployment = cloneForTest(t, start.Deployment)
	start.Deployment["processing_mode"] = "managed"
	sink := &privateOnlySink{}
	sdk := New(sink)
	if err := sdk.Begin(start, value(positive, "operation_begin_payload")); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(sdk.Fail(start.OperationID, value(positive, "failure_payload")), ErrIncompleteCapture) {
		t.Fatal("the managed candidate returned the wrong private-transport result")
	}
	if sink.deliveries != 0 || sdk.ActiveOperations() != 0 ||
		sdk.RecallCounters().CandidateRejected != 1 {
		t.Fatal("the managed candidate entered the private transport or retained state")
	}
}

func TestStreamAndDeliveredWorkBoundariesPreserveKindAndInputOrder(t *testing.T) {
	for _, test := range []struct {
		kind string
		run  func(*SDK, OperationPreparation, func() error, func(error) map[string]any) error
	}{
		{kind: "stream", run: RunStreamOperation},
		{kind: "delivered-work", run: RunDeliveredWork},
	} {
		t.Run(test.kind, func(t *testing.T) {
			sdk, sink, start, positive := fixture(t)
			begin := cloneForTest(t, value(positive, "operation_begin_payload"))
			begin["operation_kind"] = test.kind
			failure := cloneForTest(t, value(positive, "failure_payload"))
			identity := failure["identity"].(map[string]any)
			identity["operation_kind"] = test.kind
			failure["failure"].(map[string]any)["identity"] = digestValue(identity)
			secondInput := cloneForTest(t, value(positive, "operation_input_payload"))
			secondInput["input_index"] = 1
			secondInput["value"] = base64.RawURLEncoding.EncodeToString([]byte("second"))
			secondInput["value_digest"] = digestBytes([]byte("second"))
			original := errors.New("customer failure")
			returned := test.run(
				sdk,
				OperationPreparation{
					Begin: begin,
					Inputs: []map[string]any{
						value(positive, "operation_input_payload"), secondInput,
					},
					Start: start,
				},
				func() error { return original },
				func(error) map[string]any { return failure },
			)
			if returned != original || len(sink.Candidates) != 1 {
				t.Fatal("the operation boundary changed the application error or lost the candidate")
			}
			var candidate map[string]any
			decoder := json.NewDecoder(bytes.NewReader(sink.Candidates[0]))
			decoder.UseNumber()
			if err := decoder.Decode(&candidate); err != nil {
				t.Fatal(err)
			}
			records, ok := candidateRecords(candidate["records"])
			if !ok || len(records) != 5 || records[1]["kind"] != "input" ||
				records[2]["kind"] != "input" {
				t.Fatal("the ordered operation inputs changed sequence")
			}
		})
	}
}

func TestStreamBoundaryPreservesUnexpectedPanicAndReleasesCapture(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	begin := cloneForTest(t, value(positive, "operation_begin_payload"))
	begin["operation_kind"] = "stream"
	original := &struct{ message string }{"customer failure"}
	defer func() {
		if recover() != original {
			t.Fatal("the stream boundary changed the application panic")
		}
		if sdk.ActiveOperations() != 0 || len(sink.Candidates) != 0 ||
			sdk.RecallCounters().CandidateIncomplete == 0 {
			t.Fatal("the unexpected stream panic did not abandon incomplete capture")
		}
	}()
	_ = RunStreamOperation(
		sdk, OperationPreparation{Begin: begin, Start: start},
		func() error { panic(original) },
		func(error) map[string]any { return value(positive, "failure_payload") },
	)
}

func TestHTTPBoundaryPreservesOriginalPanicWhenCaptureFails(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	original := &struct{ message string }{"customer failure"}
	handler := HTTPMiddleware(
		sdk,
		func(*http.Request) HTTPPreparation {
			input := cloneForTest(t, value(positive, "operation_input_payload"))
			input["oversized"] = strings.Repeat("x", MaxEventBytes)
			return HTTPPreparation{
				Begin:  value(positive, "operation_begin_payload"),
				Inputs: []map[string]any{input}, Start: start,
			}
		},
		func(any) map[string]any { panic("capture mapper failure") },
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(original) }),
	)
	defer func() {
		if recover() != original {
			t.Fatal("capture failure changed the application panic")
		}
		if len(sink.Candidates) != 0 || sdk.ActiveOperations() != 0 {
			t.Fatal("incomplete HTTP capture reached the sink or retained state")
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestHTTPBoundaryPreservesOriginalPanicWhenFailureMapperPanics(t *testing.T) {
	sdk, sink, start, positive := fixture(t)
	original := &struct{ message string }{"customer failure"}
	handler := HTTPMiddleware(
		sdk,
		func(*http.Request) HTTPPreparation {
			return HTTPPreparation{
				Begin: value(positive, "operation_begin_payload"), Start: start,
			}
		},
		func(any) map[string]any { panic("capture mapper failure") },
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(original) }),
	)
	defer func() {
		if recover() != original {
			t.Fatal("the Failure mapper changed the application panic")
		}
		if len(sink.Candidates) != 0 || sdk.ActiveOperations() != 0 ||
			sdk.RecallCounters().CandidateIncomplete == 0 {
			t.Fatal("the failed Failure mapper did not abandon local capture")
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func cloneForTest(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	clone, err := cloneMap(value)
	if err != nil {
		t.Fatal(err)
	}
	return clone
}
