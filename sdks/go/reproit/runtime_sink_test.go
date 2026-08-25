package reproit

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

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
