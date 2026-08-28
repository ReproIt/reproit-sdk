package reproit

import (
	"bytes"
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
	automaticHTTPStreams        = 512
	automaticHTTPTargetBytes    = 16 * 1024
)

var automaticHTTPSensitiveHeaders = map[string]struct{}{
	"authorization": {}, "cookie": {}, "proxy-authenticate": {},
	"proxy-authorization": {}, "set-cookie": {}, "www-authenticate": {},
}

type automaticHTTPAdapterLease struct {
	once      sync.Once
	transport *automaticHTTPTransport
}

type automaticHTTPLeaseState struct {
	adapter    installedObservationAdapter
	mu         sync.Mutex
	original   http.RoundTripper
	references uint
	transport  *automaticHTTPTransport
}

type automaticHTTPTransport struct {
	active atomic.Bool
	base   http.RoundTripper
}

type automaticHTTPCaptureBody struct {
	body      []byte
	handle    sdkEngineDependencyHandle
	mu        sync.Mutex
	operation *AutomaticOperation
	response  *http.Response
	source    io.ReadCloser
	terminal  bool
}

type automaticHTTPReplayPayload struct {
	body             []byte
	bodyKind         string
	close            bool
	contentLength    int64
	proto            string
	protoMajor       int64
	protoMinor       int64
	status           string
	trailer          http.Header
	transferEncoding []string
	uncompressed     bool
}

var automaticHTTPState automaticHTTPLeaseState
var automaticHTTPActiveStreams atomic.Int64

func acquireAutomaticHTTPAdapter(implementationDigest string) *automaticHTTPAdapterLease {
	adapter := installedObservationAdapter{
		adapterID:            automaticHTTPAdapterID,
		adapterVersion:       automaticHTTPAdapterVersion,
		class:                observationOutboundHTTP,
		implementationDigest: implementationDigest,
	}
	automaticHTTPState.mu.Lock()
	defer automaticHTTPState.mu.Unlock()
	client := http.DefaultClient
	if client == nil {
		return nil
	}
	if current := automaticHTTPState.transport; current != nil {
		if client.Transport != current {
			current.active.Store(false)
			installedObservationAdapters.remove(automaticHTTPState.adapter)
			automaticHTTPState.adapter = installedObservationAdapter{}
			automaticHTTPState.original = nil
			automaticHTTPState.references = 0
			automaticHTTPState.transport = nil
			return nil
		}
		if automaticHTTPState.adapter != adapter {
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
	if err := installedObservationAdapters.install(adapter); err != nil {
		if client.Transport == transport {
			client.Transport = original
		}
		transport.active.Store(false)
		return nil
	}
	automaticHTTPState.original = original
	automaticHTTPState.adapter = adapter
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

func (lease *automaticHTTPAdapterLease) healthy() bool {
	if lease == nil || lease.transport == nil {
		return false
	}
	automaticHTTPState.mu.Lock()
	defer automaticHTTPState.mu.Unlock()
	return automaticHTTPState.transport == lease.transport &&
		automaticHTTPState.references > 0 && lease.transport.active.Load() &&
		http.DefaultClient != nil && http.DefaultClient.Transport == lease.transport
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
	installedObservationAdapters.remove(automaticHTTPState.adapter)
	automaticHTTPState.adapter = installedObservationAdapter{}
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
	return transport.roundTripObserved(operation, request, semanticRequest)
}

func (transport *automaticHTTPTransport) roundTripObserved(
	operation *AutomaticOperation,
	request *http.Request,
	semanticRequest semanticDependencyRequest,
) (*http.Response, error) {
	requestInput, err := makeSDKEngineDependencyRequest(semanticRequest)
	if err != nil {
		_ = operation.markUnowned(observationOutboundHTTP, nil, nil)
		return transport.base.RoundTrip(request)
	}
	started, err := operation.openSemanticDependency(requestInput, nil)
	if err != nil {
		return transport.base.RoundTrip(request)
	}
	if started.Action == string(observationReplay) {
		return replayAutomaticHTTP(operation, request, started.Handle)
	}
	response, liveError := transport.base.RoundTrip(request)
	if liveError != nil || response == nil || response.Body == nil ||
		isAutomaticHTTPNoBody(response.Body) {
		semanticResponse, supported := makeAutomaticHTTPResponse(response, liveError)
		finishAutomaticHTTPCapture(operation, started.Handle, semanticResponse, supported)
		return response, liveError
	}
	if !automaticHTTPResponseStreamSupported(response) || !reserveAutomaticHTTPStream() {
		failAutomaticHTTPCapture(operation, started.Handle)
		return response, liveError
	}
	response.Body = &automaticHTTPCaptureBody{
		handle: started.Handle, operation: operation, response: response, source: response.Body,
	}
	return response, liveError
}

func replayAutomaticHTTP(
	operation *AutomaticOperation,
	request *http.Request,
	handle sdkEngineDependencyHandle,
) (*http.Response, error) {
	finished := false
	defer func() {
		if !finished {
			_ = operation.project.bridge.abandonObservation(sdkEngineObservationHandle(handle))
		}
	}()
	record, err := readSDKEngineDependencyResponse(operation.project.bridge, handle)
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	outcome, err := operation.project.bridge.finishDependency(handle, nil)
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	finished = true
	semanticResponse, err := reconstructSemanticDependencyResponse(record, outcome)
	if err != nil {
		return nil, ErrAutomaticCapture
	}
	response, err := reconstructAutomaticHTTPResponse(request, semanticResponse)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func finishAutomaticHTTPCapture(
	operation *AutomaticOperation,
	handle sdkEngineDependencyHandle,
	response semanticDependencyResponse,
	supported bool,
) {
	if supported {
		wire, err := makeSDKEngineDependencyResponse(response)
		if err == nil {
			_, err = operation.project.bridge.finishDependency(handle, &wire)
		}
		if err == nil {
			return
		}
	}
	failAutomaticHTTPCapture(operation, handle)
}

func failAutomaticHTTPCapture(
	operation *AutomaticOperation,
	handle sdkEngineDependencyHandle,
) {
	_ = operation.markUnowned(observationOutboundHTTP, nil, nil)
	_ = operation.project.bridge.abandonObservation(sdkEngineObservationHandle(handle))
}

func makeAutomaticHTTPRequest(request *http.Request) (semanticDependencyRequest, bool) {
	if request.URL == nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") ||
		request.URL.User != nil || strings.EqualFold(request.Method, http.MethodConnect) ||
		requestHasUpgrade(request) || len(request.URL.String()) > automaticHTTPTargetBytes {
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
	if response == nil || (response.Body != nil && !isAutomaticHTTPNoBody(response.Body)) ||
		len(response.Trailer) != 0 {
		return invalid, false
	}
	bodyKind := "nil"
	if isAutomaticHTTPNoBody(response.Body) {
		bodyKind = "no-body"
	}
	return makeAutomaticHTTPResponseRecord(response, nil, bodyKind)
}

func automaticHTTPResponseStreamSupported(response *http.Response) bool {
	if response == nil || response.Body == nil || isAutomaticHTTPNoBody(response.Body) ||
		response.ContentLength < -1 || response.ContentLength > automaticHTTPBodyBytes {
		return false
	}
	_, supported := makeAutomaticHTTPResponseRecord(response, nil, "stream")
	return supported
}

func makeAutomaticHTTPResponseRecord(
	response *http.Response,
	body []byte,
	bodyKind string,
) (semanticDependencyResponse, bool) {
	invalid := semanticDependencyResponse{Outcome: observationResponse}
	if response == nil || response.StatusCode < 100 || response.StatusCode > 599 ||
		response.StatusCode == http.StatusSwitchingProtocols || len(body) > automaticHTTPBodyBytes {
		return invalid, false
	}
	metadata, ok := automaticHTTPMetadata(response.Header)
	if !ok {
		return invalid, false
	}
	trailer, ok := automaticHTTPMetadataPayload(response.Trailer)
	if !ok {
		return invalid, false
	}
	payload, err := CanonicalBytes(map[string]any{
		"body":              base64.RawURLEncoding.EncodeToString(body),
		"body_kind":         bodyKind,
		"close":             response.Close,
		"content_length":    response.ContentLength,
		"proto":             response.Proto,
		"proto_major":       int(response.ProtoMajor),
		"proto_minor":       int(response.ProtoMinor),
		"status":            response.Status,
		"trailer":           trailer,
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
		if _, sensitive := automaticHTTPSensitiveHeaders[strings.ToLower(key)]; sensitive {
			return nil, false
		}
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

func automaticHTTPMetadataPayload(header http.Header) ([]any, bool) {
	metadata, ok := automaticHTTPMetadata(header)
	if !ok {
		return nil, false
	}
	result := make([]any, len(metadata))
	for index, field := range metadata {
		result[index] = map[string]any{
			"name":  base64.RawURLEncoding.EncodeToString(field.Name),
			"value": base64.RawURLEncoding.EncodeToString(field.Value),
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

func reserveAutomaticHTTPStream() bool {
	for {
		active := automaticHTTPActiveStreams.Load()
		if active >= automaticHTTPStreams {
			return false
		}
		if automaticHTTPActiveStreams.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func (body *automaticHTTPCaptureBody) Read(output []byte) (count int, readError error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			body.fail()
			panic(recovered)
		}
	}()
	count, readError = body.source.Read(output)
	if count < 0 || count > len(output) {
		body.fail()
		return count, readError
	}
	if count > 0 && !body.append(output[:count]) {
		return count, readError
	}
	if readError == io.EOF {
		body.finish()
	} else if readError != nil {
		body.fail()
	}
	return count, readError
}

func (body *automaticHTTPCaptureBody) Close() (closeError error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			body.fail()
			panic(recovered)
		}
	}()
	closeError = body.source.Close()
	body.fail()
	return closeError
}

func (body *automaticHTTPCaptureBody) append(value []byte) bool {
	body.mu.Lock()
	if body.terminal {
		body.mu.Unlock()
		return false
	}
	if len(value) > automaticHTTPBodyBytes-len(body.body) {
		body.terminal = true
		automaticHTTPActiveStreams.Add(-1)
		body.mu.Unlock()
		failAutomaticHTTPCapture(body.operation, body.handle)
		return false
	}
	body.body = append(body.body, value...)
	body.mu.Unlock()
	return true
}

func (body *automaticHTTPCaptureBody) finish() {
	body.mu.Lock()
	if body.terminal {
		body.mu.Unlock()
		return
	}
	body.terminal = true
	captured := bytes.Clone(body.body)
	automaticHTTPActiveStreams.Add(-1)
	body.mu.Unlock()
	response, supported := makeAutomaticHTTPResponseRecord(body.response, captured, "stream")
	if supported && body.response.ContentLength >= 0 &&
		body.response.ContentLength != int64(len(captured)) {
		supported = false
	}
	finishAutomaticHTTPCapture(body.operation, body.handle, response, supported)
}

func (body *automaticHTTPCaptureBody) fail() {
	body.mu.Lock()
	if body.terminal {
		body.mu.Unlock()
		return
	}
	body.terminal = true
	automaticHTTPActiveStreams.Add(-1)
	body.mu.Unlock()
	failAutomaticHTTPCapture(body.operation, body.handle)
}

func reconstructAutomaticHTTPResponse(
	request *http.Request,
	response semanticDependencyResponse,
) (*http.Response, error) {
	if response.Outcome == observationError {
		return nil, reconstructAutomaticHTTPError(response)
	}
	if response.Outcome != observationResponse || !response.HasPayload ||
		response.StatusCode == nil || response.ErrorCode != nil || response.ErrorNumber != nil ||
		response.Status != nil {
		return nil, ErrAutomaticCapture
	}
	payload, err := decodeAutomaticHTTPReplayPayload(response.Payload)
	if err != nil {
		return nil, err
	}
	body, err := reconstructAutomaticHTTPBody(payload)
	if err != nil {
		return nil, err
	}
	header, headerOK := automaticHTTPHeaderFromMetadata(response.Metadata)
	if !headerOK {
		return nil, ErrAutomaticCapture
	}
	return &http.Response{
		Status: payload.status, StatusCode: int(*response.StatusCode), Proto: payload.proto,
		ProtoMajor: int(payload.protoMajor), ProtoMinor: int(payload.protoMinor), Header: header,
		Body: body, ContentLength: payload.contentLength,
		TransferEncoding: payload.transferEncoding, Close: payload.close,
		Uncompressed: payload.uncompressed, Trailer: payload.trailer, Request: request,
	}, nil
}

func reconstructAutomaticHTTPError(response semanticDependencyResponse) error {
	if response.ErrorCode == nil || *response.ErrorCode != "interrupted" ||
		response.ErrorNumber == nil || len(response.Metadata) != 0 || response.HasPayload ||
		response.Status != nil || response.StatusCode != nil {
		return ErrAutomaticCapture
	}
	switch *response.ErrorNumber {
	case 1:
		return context.Canceled
	case 2:
		return context.DeadlineExceeded
	default:
		return ErrAutomaticCapture
	}
}

func decodeAutomaticHTTPReplayPayload(value []byte) (automaticHTTPReplayPayload, error) {
	invalid := automaticHTTPReplayPayload{}
	parsed, err := parseStrictJSON(value, sdkEngineMaxSemanticDependencyRecordBytes)
	object, ok := parsed.(map[string]any)
	currentRecord := ok && hasExactKeys(object,
		"body", "body_kind", "close", "content_length", "proto", "proto_major", "proto_minor",
		"status", "trailer", "transfer_encoding", "uncompressed",
	)
	legacyRecord := ok && hasExactKeys(object,
		"body_kind", "close", "content_length", "proto", "proto_major", "proto_minor",
		"status", "transfer_encoding", "uncompressed",
	)
	if err != nil || (!currentRecord && !legacyRecord) {
		return invalid, ErrAutomaticCapture
	}
	bodyValue := ""
	bodyValueOK := legacyRecord
	trailer := make(http.Header)
	trailerOK := legacyRecord
	if currentRecord {
		bodyValue, bodyValueOK = object["body"].(string)
		trailer, trailerOK = automaticHTTPMetadataFromPayload(object["trailer"])
	}
	bodyKind, bodyKindOK := object["body_kind"].(string)
	closeValue, closeOK := object["close"].(bool)
	contentLength, contentOK := integerValue(object["content_length"])
	proto, protoOK := object["proto"].(string)
	protoMajor, majorOK := integerValue(object["proto_major"])
	protoMinor, minorOK := integerValue(object["proto_minor"])
	status, statusOK := object["status"].(string)
	transferEncoding, transferOK := automaticHTTPStringList(object["transfer_encoding"])
	uncompressed, uncompressedOK := object["uncompressed"].(bool)
	bodyBytes, bodyDecodeError := base64.RawURLEncoding.DecodeString(bodyValue)
	if !bodyValueOK || !bodyKindOK || bodyDecodeError != nil ||
		len(bodyBytes) > automaticHTTPBodyBytes ||
		!closeOK || !contentOK || !protoOK || !majorOK || !minorOK || !statusOK ||
		!trailerOK || !transferOK || !uncompressedOK || protoMajor < 0 || protoMajor > 255 ||
		protoMinor < 0 || protoMinor > 255 || contentLength < -1 {
		return invalid, ErrAutomaticCapture
	}
	return automaticHTTPReplayPayload{
		body: bodyBytes, bodyKind: bodyKind, close: closeValue, contentLength: contentLength,
		proto: proto, protoMajor: protoMajor, protoMinor: protoMinor, status: status,
		trailer: trailer, transferEncoding: transferEncoding, uncompressed: uncompressed,
	}, nil
}

func reconstructAutomaticHTTPBody(payload automaticHTTPReplayPayload) (io.ReadCloser, error) {
	var body io.ReadCloser
	switch payload.bodyKind {
	case "nil":
		if len(payload.body) != 0 || len(payload.trailer) != 0 {
			return nil, ErrAutomaticCapture
		}
	case "no-body":
		if len(payload.body) != 0 || len(payload.trailer) != 0 {
			return nil, ErrAutomaticCapture
		}
		body = http.NoBody
	case "stream":
		if payload.contentLength >= 0 && payload.contentLength != int64(len(payload.body)) {
			return nil, ErrAutomaticCapture
		}
		body = io.NopCloser(bytes.NewReader(payload.body))
	default:
		return nil, ErrAutomaticCapture
	}
	return body, nil
}

func automaticHTTPHeaderFromMetadata(
	metadata []semanticDependencyMetadata,
) (http.Header, bool) {
	if len(metadata) > automaticHTTPHeaderFields {
		return nil, false
	}
	header := make(http.Header)
	total := 0
	for _, field := range metadata {
		if len(field.Name) > automaticHTTPHeaderBytes-total {
			return nil, false
		}
		total += len(field.Name)
		if len(field.Value) > automaticHTTPHeaderBytes-total {
			return nil, false
		}
		total += len(field.Value)
		name := string(field.Name)
		if _, sensitive := automaticHTTPSensitiveHeaders[strings.ToLower(name)]; sensitive {
			return nil, false
		}
		header[name] = append(header[name], string(field.Value))
	}
	return header, true
}

func automaticHTTPMetadataFromPayload(value any) (http.Header, bool) {
	items, ok := anyList(value)
	if !ok || len(items) > automaticHTTPHeaderFields {
		return nil, false
	}
	header := make(http.Header)
	total := 0
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok || !hasExactKeys(entry, "name", "value") {
			return nil, false
		}
		nameText, nameOK := entry["name"].(string)
		valueText, valueOK := entry["value"].(string)
		name, nameError := base64.RawURLEncoding.DecodeString(nameText)
		fieldValue, valueError := base64.RawURLEncoding.DecodeString(valueText)
		if !nameOK || !valueOK || nameError != nil || valueError != nil ||
			len(name) > automaticHTTPHeaderBytes-total {
			return nil, false
		}
		total += len(name)
		if len(fieldValue) > automaticHTTPHeaderBytes-total {
			return nil, false
		}
		total += len(fieldValue)
		nameString := string(name)
		if _, sensitive := automaticHTTPSensitiveHeaders[strings.ToLower(nameString)]; sensitive {
			return nil, false
		}
		header[nameString] = append(header[nameString], string(fieldValue))
	}
	return header, true
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
