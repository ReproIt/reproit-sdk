package reproit

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	automaticHTTPAdapterID      = "go-net-http-default-client"
	automaticHTTPAdapterVersion = "1.0.0"
	automaticHTTPBodyBytes      = 16 * 1024
	automaticHTTPHeaderBytes    = 8 * 1024
	automaticHTTPHeaderFields   = 64
	automaticHTTPLeases         = 64
)

var automaticHTTPAdapter = installedObservationAdapter{
	adapterID:            automaticHTTPAdapterID,
	adapterVersion:       automaticHTTPAdapterVersion,
	class:                observationOutboundHTTP,
	implementationDigest: "sha256:97402c36e18fbb8783e51db8578a3ed0883dfa1e95860952800656a04dd4a65c",
}

type automaticHTTPAdapterLease struct {
	once      sync.Once
	transport *automaticHTTPTransport
}

type automaticHTTPLeaseState struct {
	mu         sync.Mutex
	original   http.RoundTripper
	references uint
	transport  *automaticHTTPTransport
}

type automaticHTTPTransport struct {
	active atomic.Bool
	base   http.RoundTripper
}

var automaticHTTPState automaticHTTPLeaseState

func acquireAutomaticHTTPAdapter() *automaticHTTPAdapterLease {
	automaticHTTPState.mu.Lock()
	defer automaticHTTPState.mu.Unlock()
	client := http.DefaultClient
	if client == nil {
		return nil
	}
	if current := automaticHTTPState.transport; current != nil {
		if client.Transport != current {
			current.active.Store(false)
			installedObservationAdapters.remove(automaticHTTPAdapter)
			automaticHTTPState.original = nil
			automaticHTTPState.references = 0
			automaticHTTPState.transport = nil
			return nil
		}
		if automaticHTTPState.references >= automaticHTTPLeases {
			return nil
		}
		automaticHTTPState.references++
		return &automaticHTTPAdapterLease{transport: current}
	}
	original := client.Transport
	base := original
	if base == nil {
		base = http.DefaultTransport
	}
	if base == nil {
		return nil
	}
	transport := &automaticHTTPTransport{base: base}
	transport.active.Store(true)
	client.Transport = transport
	if err := installedObservationAdapters.install(automaticHTTPAdapter); err != nil {
		if client.Transport == transport {
			client.Transport = original
		}
		transport.active.Store(false)
		return nil
	}
	automaticHTTPState.original = original
	automaticHTTPState.references = 1
	automaticHTTPState.transport = transport
	return &automaticHTTPAdapterLease{transport: transport}
}

func (lease *automaticHTTPAdapterLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() { lease.releaseOnce() })
}

func (lease *automaticHTTPAdapterLease) releaseOnce() {
	if lease.transport == nil {
		return
	}
	automaticHTTPState.mu.Lock()
	defer automaticHTTPState.mu.Unlock()
	if automaticHTTPState.transport != lease.transport || automaticHTTPState.references == 0 {
		return
	}
	automaticHTTPState.references--
	if automaticHTTPState.references != 0 {
		lease.transport = nil
		return
	}
	lease.transport.active.Store(false)
	if http.DefaultClient != nil && http.DefaultClient.Transport == lease.transport {
		http.DefaultClient.Transport = automaticHTTPState.original
	}
	installedObservationAdapters.remove(automaticHTTPAdapter)
	automaticHTTPState.original = nil
	automaticHTTPState.transport = nil
	lease.transport = nil
}

func (transport *automaticHTTPTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	if !transport.active.Load() || request == nil {
		return transport.base.RoundTrip(request)
	}
	operation, active := activeAutomaticOperation(request.Context())
	if !active {
		return transport.base.RoundTrip(request)
	}
	semanticRequest, supported := makeAutomaticHTTPRequest(request)
	if !supported {
		_ = operation.markUnowned(observationOutboundHTTP, nil, nil)
		return transport.base.RoundTrip(request)
	}
	calledLive := false
	var liveResponse *http.Response
	var liveError error
	semanticResponse, err := translateSemanticDependency(
		operation,
		semanticRequest,
		nil,
		func() (semanticDependencyResponse, error) {
			calledLive = true
			liveResponse, liveError = transport.base.RoundTrip(request)
			response, ok := makeAutomaticHTTPResponse(liveResponse, liveError)
			if !ok {
				_ = operation.markUnowned(observationOutboundHTTP, nil, nil)
			}
			return response, liveError
		},
	)
	if calledLive {
		return liveResponse, liveError
	}
	if err != nil {
		return nil, err
	}
	return reconstructAutomaticHTTPResponse(request, semanticResponse)
}

func makeAutomaticHTTPRequest(request *http.Request) (semanticDependencyRequest, bool) {
	if request.URL == nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") ||
		strings.EqualFold(request.Method, http.MethodConnect) || requestHasUpgrade(request) {
		return semanticDependencyRequest{}, false
	}
	body, bodyKind, ok := replayableAutomaticHTTPBody(request)
	if !ok {
		return semanticDependencyRequest{}, false
	}
	metadata, ok := automaticHTTPMetadata(request.Header)
	if !ok {
		return semanticDependencyRequest{}, false
	}
	payload, err := CanonicalBytes(map[string]any{
		"body":              base64.RawURLEncoding.EncodeToString(body),
		"body_kind":         bodyKind,
		"close":             request.Close,
		"content_length":    request.ContentLength,
		"host":              request.Host,
		"method":            request.Method,
		"proto":             request.Proto,
		"proto_major":       int(request.ProtoMajor),
		"proto_minor":       int(request.ProtoMinor),
		"transfer_encoding": stringList(request.TransferEncoding),
		"url":               request.URL.String(),
	})
	if err != nil || len(payload) > sdkEngineMaxSemanticDependencyRecordBytes {
		return semanticDependencyRequest{}, false
	}
	method := request.Method
	if method == "" {
		method = http.MethodGet
	}
	return semanticDependencyRequest{
		Encoding:         "go-net-http-v1",
		Metadata:         metadata,
		Method:           &method,
		ObservationClass: observationOutboundHTTP,
		Operation:        "outbound-http-request",
		Payload:          payload,
		Protocol:         request.URL.Scheme,
		Target:           request.URL.String(),
	}, true
}

func replayableAutomaticHTTPBody(request *http.Request) ([]byte, string, bool) {
	if request.Body == nil {
		return nil, "nil", true
	}
	if isAutomaticHTTPNoBody(request.Body) {
		return nil, "no-body", true
	}
	if request.GetBody == nil || request.ContentLength > automaticHTTPBodyBytes {
		return nil, "", false
	}
	body, err := request.GetBody()
	if err != nil || body == nil {
		return nil, "", false
	}
	value, readErr := io.ReadAll(io.LimitReader(body, automaticHTTPBodyBytes+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || len(value) > automaticHTTPBodyBytes {
		return nil, "", false
	}
	return value, "replayable", true
}

func makeAutomaticHTTPResponse(
	response *http.Response,
	liveError error,
) (semanticDependencyResponse, bool) {
	invalid := semanticDependencyResponse{Outcome: observationResponse}
	if liveError != nil {
		if response != nil {
			return invalid, false
		}
		code := "interrupted"
		var number uint32
		switch liveError {
		case context.Canceled:
			number = 1
		case context.DeadlineExceeded:
			number = 2
		default:
			return invalid, false
		}
		return semanticDependencyResponse{
			ErrorCode: &code, ErrorNumber: &number, Metadata: []semanticDependencyMetadata{},
			Outcome: observationError,
		}, true
	}
	if response == nil || response.StatusCode < 100 ||
		response.StatusCode > 599 || response.StatusCode == http.StatusSwitchingProtocols ||
		(response.Body != nil && !isAutomaticHTTPNoBody(response.Body)) || len(response.Trailer) != 0 {
		return invalid, false
	}
	metadata, ok := automaticHTTPMetadata(response.Header)
	if !ok {
		return invalid, false
	}
	bodyKind := "nil"
	if isAutomaticHTTPNoBody(response.Body) {
		bodyKind = "no-body"
	}
	payload, err := CanonicalBytes(map[string]any{
		"body_kind":         bodyKind,
		"close":             response.Close,
		"content_length":    response.ContentLength,
		"proto":             response.Proto,
		"proto_major":       int(response.ProtoMajor),
		"proto_minor":       int(response.ProtoMinor),
		"status":            response.Status,
		"transfer_encoding": stringList(response.TransferEncoding),
		"uncompressed":      response.Uncompressed,
	})
	if err != nil || len(payload) > sdkEngineMaxSemanticDependencyRecordBytes {
		return invalid, false
	}
	statusCode := uint16(response.StatusCode)
	return semanticDependencyResponse{
		Metadata: metadata, Outcome: observationResponse, Payload: payload,
		HasPayload: true, StatusCode: &statusCode,
	}, true
}

func automaticHTTPMetadata(header http.Header) ([]semanticDependencyMetadata, bool) {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]semanticDependencyMetadata, 0, len(header))
	total := 0
	for _, key := range keys {
		for _, value := range header[key] {
			if len(result) == automaticHTTPHeaderFields || len(key) > automaticHTTPHeaderBytes-total {
				return nil, false
			}
			total += len(key)
			if len(value) > automaticHTTPHeaderBytes-total {
				return nil, false
			}
			total += len(value)
			result = append(result, semanticDependencyMetadata{
				Name: []byte(key), Value: []byte(value),
			})
		}
	}
	return result, true
}

func requestHasUpgrade(request *http.Request) bool {
	return request.Header.Get("Upgrade") != "" ||
		headerContainsToken(request.Header, "Connection", "upgrade")
}

func isAutomaticHTTPNoBody(body io.ReadCloser) bool {
	return body != nil && reflect.TypeOf(body) == reflect.TypeOf(http.NoBody)
}

func headerContainsToken(header http.Header, name string, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func stringList(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func reconstructAutomaticHTTPResponse(
	request *http.Request,
	response semanticDependencyResponse,
) (*http.Response, error) {
	if response.Outcome == observationError {
		if response.ErrorCode == nil || *response.ErrorCode != "interrupted" ||
			response.ErrorNumber == nil || len(response.Metadata) != 0 || response.HasPayload ||
			response.Status != nil || response.StatusCode != nil {
			return nil, ErrAutomaticCapture
		}
		switch *response.ErrorNumber {
		case 1:
			return nil, context.Canceled
		case 2:
			return nil, context.DeadlineExceeded
		default:
			return nil, ErrAutomaticCapture
		}
	}
	if response.Outcome != observationResponse || !response.HasPayload ||
		response.StatusCode == nil || response.ErrorCode != nil || response.ErrorNumber != nil ||
		response.Status != nil {
		return nil, ErrAutomaticCapture
	}
	parsed, err := parseStrictJSON(response.Payload, sdkEngineMaxSemanticDependencyRecordBytes)
	object, ok := parsed.(map[string]any)
	if err != nil || !ok || !hasExactKeys(object,
		"body_kind", "close", "content_length", "proto", "proto_major", "proto_minor",
		"status", "transfer_encoding", "uncompressed",
	) {
		return nil, ErrAutomaticCapture
	}
	bodyKind, bodyOK := object["body_kind"].(string)
	closeValue, closeOK := object["close"].(bool)
	contentLength, contentOK := integerValue(object["content_length"])
	proto, protoOK := object["proto"].(string)
	protoMajor, majorOK := integerValue(object["proto_major"])
	protoMinor, minorOK := integerValue(object["proto_minor"])
	status, statusOK := object["status"].(string)
	transferEncoding, transferOK := automaticHTTPStringList(object["transfer_encoding"])
	uncompressed, uncompressedOK := object["uncompressed"].(bool)
	if !bodyOK || !closeOK || !contentOK || !protoOK || !majorOK || !minorOK ||
		!statusOK || !transferOK || !uncompressedOK || protoMajor < 0 || protoMajor > 255 ||
		protoMinor < 0 || protoMinor > 255 {
		return nil, ErrAutomaticCapture
	}
	var body io.ReadCloser
	switch bodyKind {
	case "nil":
	case "no-body":
		body = http.NoBody
	default:
		return nil, ErrAutomaticCapture
	}
	header := make(http.Header)
	for _, field := range response.Metadata {
		header[string(field.Name)] = append(header[string(field.Name)], string(field.Value))
	}
	return &http.Response{
		Status: status, StatusCode: int(*response.StatusCode), Proto: proto,
		ProtoMajor: int(protoMajor), ProtoMinor: int(protoMinor), Header: header,
		Body: body, ContentLength: contentLength, TransferEncoding: transferEncoding,
		Close: closeValue, Uncompressed: uncompressed, Request: request,
	}, nil
}

func automaticHTTPStringList(value any) ([]string, bool) {
	items, ok := anyList(value)
	if !ok {
		return nil, false
	}
	result := make([]string, len(items))
	for index, item := range items {
		entry, ok := item.(string)
		if !ok {
			return nil, false
		}
		result[index] = entry
	}
	return result, true
}

var _ http.RoundTripper = (*automaticHTTPTransport)(nil)
