package reproit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const automaticHTTPTestDigest = "sha256:" +
	"97402c36e18fbb8783e51db8578a3ed0883dfa1e95860952800656a04dd4a65c"

type automaticHTTPRoundTripper func(*http.Request) (*http.Response, error)

type automaticHTTPTestBody struct {
	closeError error
	reader     io.Reader
}

func (body *automaticHTTPTestBody) Read(output []byte) (int, error) {
	return body.reader.Read(output)
}

func (body *automaticHTTPTestBody) Close() error {
	return body.closeError
}

type automaticHTTPErrorReader struct {
	error error
	value []byte
}

type automaticHTTPBlockingBody struct {
	closeError  error
	closed      chan struct{}
	once        sync.Once
	readError   error
	readStarted chan struct{}
}

func (body *automaticHTTPBlockingBody) Read([]byte) (int, error) {
	body.once.Do(func() { close(body.readStarted) })
	<-body.closed
	return 0, body.readError
}

func (body *automaticHTTPBlockingBody) Close() error {
	select {
	case <-body.closed:
	default:
		close(body.closed)
	}
	return body.closeError
}

func (reader *automaticHTTPErrorReader) Read(output []byte) (int, error) {
	if reader.value == nil {
		return 0, reader.error
	}
	count := copy(output, reader.value)
	reader.value = nil
	return count, reader.error
}

func (roundTrip automaticHTTPRoundTripper) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return roundTrip(request)
}

func TestAutomaticHTTPLeaseInstallsNestsAndRestores(t *testing.T) {
	originalClient := http.DefaultClient
	originalTransport := originalClient.Transport
	custom := automaticHTTPRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})
	originalClient.Transport = custom
	t.Cleanup(func() {
		originalClient.Transport = originalTransport
	})
	first := acquireAutomaticHTTPAdapter(automaticHTTPTestDigest)
	second := acquireAutomaticHTTPAdapter(automaticHTTPTestDigest)
	if first == nil || second == nil || first.transport != second.transport ||
		originalClient.Transport != first.transport {
		t.Fatal("The adapter lease did not install one shared transport.")
	}
	first.release()
	if originalClient.Transport != second.transport {
		t.Fatal("The nested lease restored the transport too early.")
	}
	second.release()
	if reflect.ValueOf(originalClient.Transport).Pointer() != reflect.ValueOf(custom).Pointer() {
		t.Fatal("The final lease did not restore the exact original transport.")
	}
}

func TestAutomaticHTTPIdentityIsAFrozenSubjectModule(t *testing.T) {
	subject, err := PackageRunningGoSubject("")
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Close()
	modules, ok := subject.Manifest["modules"].([]map[string]any)
	if !ok || subject.adapterImplementationDigest == "" {
		t.Fatal("The Go subject has no adapter implementation identity.")
	}
	for _, module := range modules {
		if module["module_digest"] == subject.adapterImplementationDigest {
			return
		}
	}
	t.Fatal("The Go adapter implementation is not a frozen subject module.")
}

func TestAutomaticHTTPLeaseDoesNotOverwriteApplicationReplacement(t *testing.T) {
	originalClient := http.DefaultClient
	originalTransport := originalClient.Transport
	t.Cleanup(func() {
		originalClient.Transport = originalTransport
	})
	lease := acquireAutomaticHTTPAdapter(automaticHTTPTestDigest)
	if lease == nil {
		t.Fatal("The adapter lease was not installed.")
	}
	replacement := automaticHTTPRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})
	originalClient.Transport = replacement
	lease.release()
	if reflect.ValueOf(originalClient.Transport).Pointer() != reflect.ValueOf(replacement).Pointer() {
		t.Fatal("Lease release overwrote the application transport replacement.")
	}
}

func TestAutomaticHTTPLeaseRejectsAChangedImplementationIdentity(t *testing.T) {
	originalClient := http.DefaultClient
	originalTransport := originalClient.Transport
	t.Cleanup(func() {
		originalClient.Transport = originalTransport
	})
	lease := acquireAutomaticHTTPAdapter(automaticHTTPTestDigest)
	if lease == nil {
		t.Fatal("The adapter lease was not installed.")
	}
	changed := "sha256:" + strings.Repeat("b", 64)
	if acquireAutomaticHTTPAdapter(changed) != nil || originalClient.Transport != lease.transport {
		t.Fatal("The adapter accepted a changed implementation identity.")
	}
	installed := installedObservationAdapters.snapshot()
	if len(installed) != 1 || installed[0].ImplementationDigest != automaticHTTPTestDigest {
		t.Fatal("The adapter registry lost its frozen implementation identity.")
	}
	lease.release()
}

func TestAutomaticHTTPLeaseRejectsOneOverItsBound(t *testing.T) {
	originalClient := http.DefaultClient
	originalTransport := originalClient.Transport
	t.Cleanup(func() {
		originalClient.Transport = originalTransport
	})
	leases := make([]*automaticHTTPAdapterLease, 0, automaticHTTPLeases)
	for index := 0; index < automaticHTTPLeases; index++ {
		lease := acquireAutomaticHTTPAdapter(automaticHTTPTestDigest)
		if lease == nil {
			t.Fatalf("The adapter rejected lease %d inside its bound.", index)
		}
		leases = append(leases, lease)
	}
	if acquireAutomaticHTTPAdapter(automaticHTTPTestDigest) != nil {
		t.Fatal("The adapter accepted one lease beyond its bound.")
	}
	for _, lease := range leases {
		lease.release()
	}
	if originalClient.Transport != originalTransport {
		t.Fatal("The bounded lease set did not restore the original transport.")
	}
}

func TestAutomaticHTTPRequestIsBoundedAndPreservesOrderedHeaders(t *testing.T) {
	request, err := http.NewRequest(
		http.MethodPost,
		"https://inventory.example/items?group=blue",
		bytes.NewBufferString("quantity=1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header["X-Tag"] = []string{"first", "second"}
	semantic, ok := makeAutomaticHTTPRequest(request)
	if !ok || semantic.Protocol != "https" || semantic.Target != request.URL.String() ||
		semantic.Method == nil || *semantic.Method != http.MethodPost ||
		len(semantic.Metadata) != 2 || string(semantic.Metadata[0].Value) != "first" ||
		string(semantic.Metadata[1].Value) != "second" {
		t.Fatal("The adapter changed the request protocol, target, method, or header order.")
	}
	oversized, err := http.NewRequest(
		http.MethodPost,
		"https://inventory.example/items",
		bytes.NewReader(make([]byte, automaticHTTPBodyBytes+1)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := makeAutomaticHTTPRequest(oversized); ok {
		t.Fatal("The adapter accepted a request body beyond its bound.")
	}
}

func TestAutomaticHTTPRequestRejectsCredentialsAndSensitiveHeaders(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "https://user:secret@example.test", nil)
	if _, ok := makeAutomaticHTTPRequest(request); ok {
		t.Fatal("The adapter accepted URL credentials.")
	}
	request, _ = http.NewRequest(http.MethodGet, "https://example.test", nil)
	request.Header.Set("Authorization", "secret")
	if _, ok := makeAutomaticHTTPRequest(request); ok {
		t.Fatal("The adapter accepted a sensitive request header.")
	}
	response := &http.Response{
		StatusCode: 200, Header: http.Header{"Set-Cookie": {"secret"}}, Body: http.NoBody,
	}
	if _, ok := makeAutomaticHTTPResponse(response, nil); ok {
		t.Fatal("The adapter accepted a sensitive response header.")
	}
}

func TestAutomaticHTTPCaptureReturnsExactLivePointerAndError(t *testing.T) {
	bridge := semanticDependencyBridge(t, "capture", nil, nil)
	defer bridge.close()
	operation := semanticTestOperation(bridge)
	ctx := automaticHTTPTestContext(operation)
	wantResponse := &http.Response{
		Status: "503 overloaded", StatusCode: 503, Proto: "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"X-Tag": {"first", "second"}},
		Body: http.NoBody, ContentLength: 0,
	}
	wantError := errors.New("live transport error")
	transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
		func(*http.Request) (*http.Response, error) { return wantResponse, wantError },
	)}
	transport.active.Store(true)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test", nil)
	gotResponse, gotError := transport.RoundTrip(request)
	if gotResponse != wantResponse || gotError != wantError {
		t.Fatal("Capture changed the exact live response pointer or error.")
	}
}

func TestAutomaticHTTPCaptureKeepsSupportedErrorIdentity(t *testing.T) {
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		bridge := semanticDependencyBridge(t, "capture", nil, nil)
		operation := semanticTestOperation(bridge)
		transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
			func(*http.Request) (*http.Response, error) { return nil, sentinel },
		)}
		transport.active.Store(true)
		request, _ := http.NewRequestWithContext(
			automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
		)
		response, gotError := transport.RoundTrip(request)
		bridge.close()
		if response != nil || gotError != sentinel {
			t.Fatal("Capture changed a supported standard error identity.")
		}
	}
}

func TestAutomaticHTTPErrorReplayNeverCallsLive(t *testing.T) {
	for _, test := range []struct {
		number uint32
		want   error
	}{{1, context.Canceled}, {2, context.DeadlineExceeded}} {
		code := "interrupted"
		wire, err := makeSDKEngineDependencyResponse(semanticDependencyResponse{
			ErrorCode: &code, ErrorNumber: &test.number,
			Metadata: []semanticDependencyMetadata{}, Outcome: observationError,
		})
		if err != nil {
			t.Fatal(err)
		}
		record, _ := json.Marshal(wire)
		bridge := semanticDependencyBridge(
			t, "replay", [][]byte{record}, func(call map[string]any) string {
				if call["operation"] == sdkEngineDependencyFinish {
					return sdkEngineSuccess(`{"outcome":"error"}`)
				}
				return ""
			},
		)
		operation := semanticTestOperation(bridge)
		transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
			func(*http.Request) (*http.Response, error) {
				t.Fatal("Error replay called the live transport.")
				return nil, nil
			},
		)}
		transport.active.Store(true)
		request, _ := http.NewRequestWithContext(
			automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
		)
		response, gotError := transport.RoundTrip(request)
		bridge.close()
		if response != nil || gotError != test.want {
			t.Fatal("Replay did not return the matching standard error sentinel.")
		}
	}
}

func TestAutomaticHTTPRejectsWrappedAndCorruptErrors(t *testing.T) {
	wrapped := fmt.Errorf("wrapped: %w", context.Canceled)
	if _, ok := makeAutomaticHTTPResponse(nil, wrapped); ok {
		t.Fatal("The adapter accepted a wrapped context error.")
	}
	code := "interrupted"
	badNumber := uint32(3)
	_, err := reconstructAutomaticHTTPResponse(nil, semanticDependencyResponse{
		ErrorCode: &code, ErrorNumber: &badNumber,
		Metadata: []semanticDependencyMetadata{}, Outcome: observationError,
	})
	if !errors.Is(err, ErrAutomaticCapture) {
		t.Fatal("The adapter accepted a corrupt error transcript.")
	}
}

func TestAutomaticHTTPReplayNeverCallsLiveAndReconstructsResponse(t *testing.T) {
	liveResponse := &http.Response{
		Status: "204 No Content", StatusCode: 204, Proto: "HTTP/2.0",
		ProtoMajor: 2, Header: http.Header{"X-Tag": {"first", "second"}},
		Body: http.NoBody, ContentLength: 0,
	}
	semantic, ok := makeAutomaticHTTPResponse(liveResponse, nil)
	if !ok {
		t.Fatal("The supported response could not be encoded.")
	}
	wire, err := makeSDKEngineDependencyResponse(semantic)
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	bridge := semanticDependencyBridge(t, "replay", [][]byte{record}, nil)
	defer bridge.close()
	operation := semanticTestOperation(bridge)
	transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
		func(*http.Request) (*http.Response, error) {
			t.Fatal("Replay called the live transport.")
			return nil, nil
		},
	)}
	transport.active.Store(true)
	request, _ := http.NewRequestWithContext(
		automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
	)
	response, gotErr := transport.RoundTrip(request)
	if gotErr != nil || response == nil || response.Request != request ||
		response.Status != liveResponse.Status || response.StatusCode != liveResponse.StatusCode ||
		response.Body != http.NoBody ||
		!reflect.DeepEqual(response.Header["X-Tag"], []string{"first", "second"}) {
		t.Fatal("Replay did not reconstruct the validated empty HTTP response.")
	}
}

func TestAutomaticHTTPReplaysThePreviousBodylessPayload(t *testing.T) {
	payload, err := CanonicalBytes(map[string]any{
		"body_kind": "no-body", "close": false, "content_length": int64(0),
		"proto": "HTTP/1.1", "proto_major": 1, "proto_minor": 1,
		"status": "204 No Content", "transfer_encoding": []any{}, "uncompressed": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	statusCode := uint16(204)
	request, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	response, err := reconstructAutomaticHTTPResponse(request, semanticDependencyResponse{
		Metadata: []semanticDependencyMetadata{}, Outcome: observationResponse,
		Payload: payload, HasPayload: true, StatusCode: &statusCode,
	})
	if err != nil || response.StatusCode != 204 || response.Body != http.NoBody {
		t.Fatal("The adapter rejected its previous bodyless response payload.")
	}
}

func TestAutomaticHTTPCaptureStreamsBodyAndTrailer(t *testing.T) {
	var capturedBody []byte
	finishCalls := 0
	bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
		if call["operation"] != sdkEngineDependencyFinish {
			return ""
		}
		finishCalls++
		capturedBody = automaticHTTPRecordedBody(t, call)
		return ""
	})
	defer bridge.close()
	operation := semanticTestOperation(bridge)
	closeError := errors.New("close sentinel")
	liveResponse := &http.Response{
		Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"X-Tag": {"first", "second"}},
		Body: &automaticHTTPTestBody{
			closeError: closeError, reader: strings.NewReader("response body"),
		},
		ContentLength: 13,
		Trailer:       http.Header{"X-Checksum": {"abc123"}},
	}
	transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
		func(*http.Request) (*http.Response, error) { return liveResponse, nil },
	)}
	transport.active.Store(true)
	request, _ := http.NewRequestWithContext(
		automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
	)
	response, err := transport.RoundTrip(request)
	if err != nil || response != liveResponse || finishCalls != 0 {
		t.Fatal("The stream capture changed the live response or finished before EOF.")
	}
	value, err := io.ReadAll(response.Body)
	if err != nil || string(value) != "response body" || string(capturedBody) != "response body" ||
		finishCalls != 1 {
		t.Fatal("The stream capture did not preserve and record the complete body.")
	}
	if err := response.Body.Close(); err != closeError {
		t.Fatal("The stream capture changed the exact Close error.")
	}
}

func TestAutomaticHTTPCapturesARealResponseStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Trailer", "X-Checksum")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("response body"))
		response.Header().Set("X-Checksum", "abc123")
	}))
	defer server.Close()
	var capturedBody []byte
	bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
		if call["operation"] == sdkEngineDependencyFinish {
			capturedBody = automaticHTTPRecordedBody(t, call)
		}
		return ""
	})
	defer bridge.close()
	operation := semanticTestOperation(bridge)
	transport := &automaticHTTPTransport{base: http.DefaultTransport}
	transport.active.Store(true)
	request, _ := http.NewRequestWithContext(
		automaticHTTPTestContext(operation), http.MethodGet, server.URL, nil,
	)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	value, err := io.ReadAll(response.Body)
	if err != nil || string(value) != "response body" || string(capturedBody) != "response body" ||
		response.Trailer.Get("X-Checksum") != "abc123" {
		t.Fatal("The adapter did not capture the real response body and trailer.")
	}
}

func TestAutomaticHTTPReplaysBodyAndTrailerWithoutLiveIO(t *testing.T) {
	liveResponse := &http.Response{
		Status: "200 OK", StatusCode: 200, Proto: "HTTP/2.0", ProtoMajor: 2,
		Header: http.Header{"X-Tag": {"first", "second"}},
		Body:   io.NopCloser(strings.NewReader("fixture")), ContentLength: 7,
		Trailer: http.Header{"X-Checksum": {"abc123"}},
	}
	semantic, ok := makeAutomaticHTTPResponseRecord(liveResponse, []byte("fixture"), "stream")
	if !ok {
		t.Fatal("The supported stream response could not be encoded.")
	}
	wire, err := makeSDKEngineDependencyResponse(semantic)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := json.Marshal(wire)
	bridge := semanticDependencyBridge(t, "replay", [][]byte{record}, nil)
	defer bridge.close()
	operation := semanticTestOperation(bridge)
	transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
		func(*http.Request) (*http.Response, error) {
			t.Fatal("Stream replay called the live transport.")
			return nil, nil
		},
	)}
	transport.active.Store(true)
	request, _ := http.NewRequestWithContext(
		automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
	)
	response, err := transport.RoundTrip(request)
	if err != nil || response == nil {
		t.Fatal("The stream replay did not reconstruct a response.")
	}
	body, readError := io.ReadAll(response.Body)
	if readError != nil || string(body) != "fixture" ||
		response.Trailer.Get("X-Checksum") != "abc123" {
		t.Fatal("The stream replay changed the body or trailer.")
	}
}

func TestAutomaticHTTPPartialAndOversizedStreamsFailClosed(t *testing.T) {
	t.Run("partial close", func(t *testing.T) {
		operations := make([]string, 0)
		bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
			operations = append(operations, call["operation"].(string))
			return ""
		})
		defer bridge.close()
		operation := semanticTestOperation(bridge)
		closeError := errors.New("close sentinel")
		response := &http.Response{
			Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
			Body: &automaticHTTPTestBody{
				closeError: closeError, reader: strings.NewReader("unread body"),
			},
			ContentLength: 11,
		}
		transport := automaticHTTPTestTransport(response)
		request, _ := http.NewRequestWithContext(
			automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
		)
		live, err := transport.RoundTrip(request)
		if err != nil || live.Body.Close() != closeError {
			t.Fatal("The partial stream changed the live Close result.")
		}
		joined := strings.Join(operations, ",")
		if !strings.Contains(joined, sdkEngineOperationUnowned) ||
			!strings.Contains(joined, sdkEngineObservationAbandon) ||
			strings.Contains(joined, sdkEngineDependencyFinish) {
			t.Fatal("The partial stream did not fail closed.")
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		operations := make([]string, 0)
		bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
			operations = append(operations, call["operation"].(string))
			return ""
		})
		defer bridge.close()
		operation := semanticTestOperation(bridge)
		value := bytes.Repeat([]byte{7}, automaticHTTPBodyBytes+1)
		response := &http.Response{
			Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
			Body: io.NopCloser(bytes.NewReader(value)), ContentLength: -1,
		}
		transport := automaticHTTPTestTransport(response)
		request, _ := http.NewRequestWithContext(
			automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
		)
		live, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		got, readError := io.ReadAll(live.Body)
		if readError != nil || !bytes.Equal(got, value) {
			t.Fatal("The oversized stream changed the live body.")
		}
		joined := strings.Join(operations, ",")
		if !strings.Contains(joined, sdkEngineOperationUnowned) ||
			strings.Contains(joined, sdkEngineDependencyFinish) {
			t.Fatal("The oversized stream did not fail closed.")
		}
	})
}

func TestAutomaticHTTPReadErrorPreservesIdentityAndFailsClosed(t *testing.T) {
	operations := make([]string, 0)
	bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
		operations = append(operations, call["operation"].(string))
		return ""
	})
	defer bridge.close()
	operation := semanticTestOperation(bridge)
	readError := errors.New("read sentinel")
	response := &http.Response{
		Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
		Body: &automaticHTTPTestBody{reader: &automaticHTTPErrorReader{
			error: readError, value: []byte("partial"),
		}},
		ContentLength: -1,
	}
	transport := automaticHTTPTestTransport(response)
	request, _ := http.NewRequestWithContext(
		automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
	)
	live, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	output := make([]byte, 16)
	count, gotError := live.Body.Read(output)
	if count != len("partial") || gotError != readError || string(output[:count]) != "partial" {
		t.Fatal("The stream capture changed the live Read result.")
	}
	joined := strings.Join(operations, ",")
	if !strings.Contains(joined, sdkEngineOperationUnowned) ||
		strings.Contains(joined, sdkEngineDependencyFinish) {
		t.Fatal("The read error did not fail closed.")
	}
}

func TestAutomaticHTTPConcurrentCloseUnblocksReadAndFailsClosed(t *testing.T) {
	operations := make([]string, 0)
	var operationsLock sync.Mutex
	bridge := semanticDependencyBridge(t, "capture", nil, func(call map[string]any) string {
		operationsLock.Lock()
		operations = append(operations, call["operation"].(string))
		operationsLock.Unlock()
		return ""
	})
	defer bridge.close()
	operation := semanticTestOperation(bridge)
	readError := errors.New("read sentinel")
	closeError := errors.New("close sentinel")
	body := &automaticHTTPBlockingBody{
		closeError: closeError, closed: make(chan struct{}), readError: readError,
		readStarted: make(chan struct{}),
	}
	response := &http.Response{
		Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1,
		Body: body, ContentLength: -1,
	}
	transport := automaticHTTPTestTransport(response)
	request, _ := http.NewRequestWithContext(
		automaticHTTPTestContext(operation), http.MethodGet, "https://example.test", nil,
	)
	live, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, readErr := live.Body.Read(make([]byte, 1))
		readResult <- readErr
	}()
	<-body.readStarted
	if got := live.Body.Close(); got != closeError {
		t.Fatal("Concurrent Close changed the exact source error.")
	}
	if got := <-readResult; got != readError {
		t.Fatal("Concurrent Close changed the exact Read error.")
	}
	operationsLock.Lock()
	joined := strings.Join(operations, ",")
	operationsLock.Unlock()
	if !strings.Contains(joined, sdkEngineOperationUnowned) ||
		strings.Contains(joined, sdkEngineDependencyFinish) {
		t.Fatal("Concurrent Read and Close did not fail closed.")
	}
}

func TestAutomaticHTTPStreamCountHasAnExactBound(t *testing.T) {
	base := automaticHTTPActiveStreams.Load()
	if base < 0 || base > automaticHTTPStreams {
		t.Fatal("The active stream count is invalid.")
	}
	reserved := int64(0)
	defer automaticHTTPActiveStreams.Add(-reserved)
	for base+reserved < automaticHTTPStreams {
		if !reserveAutomaticHTTPStream() {
			t.Fatal("The stream bound rejected an entry inside the limit.")
		}
		reserved++
	}
	if reserveAutomaticHTTPStream() {
		t.Fatal("The stream bound accepted one entry over the limit.")
	}
}

func TestAutomaticHTTPWithoutOperationContextDelegatesExactly(t *testing.T) {
	wantResponse := &http.Response{StatusCode: 200, Body: http.NoBody}
	wantError := errors.New("sentinel")
	transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
		func(*http.Request) (*http.Response, error) { return wantResponse, wantError },
	)}
	transport.active.Store(true)
	request, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	response, err := transport.RoundTrip(request)
	if response != wantResponse || err != wantError {
		t.Fatal("Context loss changed the exact live transport result.")
	}
}

func automaticHTTPTestContext(operation *AutomaticOperation) context.Context {
	binding := &automaticOperationBinding{operation: operation}
	return context.WithValue(context.Background(), automaticOperationContextKey{}, binding)
}

func automaticHTTPTestTransport(response *http.Response) *automaticHTTPTransport {
	transport := &automaticHTTPTransport{base: automaticHTTPRoundTripper(
		func(*http.Request) (*http.Response, error) { return response, nil },
	)}
	transport.active.Store(true)
	return transport
}

func automaticHTTPRecordedBody(t *testing.T, call map[string]any) []byte {
	t.Helper()
	response, ok := call["response"].(map[string]any)
	payloadText, payloadOK := response["payload"].(string)
	payload, payloadError := base64.RawURLEncoding.DecodeString(payloadText)
	var value map[string]any
	if !ok || !payloadOK || payloadError != nil || json.Unmarshal(payload, &value) != nil {
		t.Fatal("The captured HTTP response payload is invalid.")
	}
	bodyText, ok := value["body"].(string)
	body, err := base64.RawURLEncoding.DecodeString(bodyText)
	if !ok || err != nil {
		t.Fatal("The captured HTTP body is invalid.")
	}
	return body
}
