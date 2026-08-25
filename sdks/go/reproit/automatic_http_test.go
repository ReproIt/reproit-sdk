package reproit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

type automaticHTTPRoundTripper func(*http.Request) (*http.Response, error)

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
	first := acquireAutomaticHTTPAdapter()
	second := acquireAutomaticHTTPAdapter()
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

func TestAutomaticHTTPLeaseDoesNotOverwriteApplicationReplacement(t *testing.T) {
	originalClient := http.DefaultClient
	originalTransport := originalClient.Transport
	t.Cleanup(func() {
		originalClient.Transport = originalTransport
	})
	lease := acquireAutomaticHTTPAdapter()
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

func TestAutomaticHTTPLeaseRejectsOneOverItsBound(t *testing.T) {
	originalClient := http.DefaultClient
	originalTransport := originalClient.Transport
	t.Cleanup(func() {
		originalClient.Transport = originalTransport
	})
	leases := make([]*automaticHTTPAdapterLease, 0, automaticHTTPLeases)
	for index := 0; index < automaticHTTPLeases; index++ {
		lease := acquireAutomaticHTTPAdapter()
		if lease == nil {
			t.Fatalf("The adapter rejected lease %d inside its bound.", index)
		}
		leases = append(leases, lease)
	}
	if acquireAutomaticHTTPAdapter() != nil {
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
		bridge := semanticDependencyBridge(t, "replay", [][]byte{record}, func(call map[string]any) string {
			if call["operation"] == sdkEngineDependencyFinish {
				return sdkEngineSuccess(`{"outcome":"error"}`)
			}
			return ""
		})
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
