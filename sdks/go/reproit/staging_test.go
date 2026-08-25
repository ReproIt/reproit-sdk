package reproit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const stagedCandidateContentType = "application/reproit-candidate-staging+json"

type unixStagedRuntimeSink struct{ *runtimeSink }

type tlsStagedRuntimeSink struct{ *runtimeSink }

func newunixStagedRuntimeSink(
	socketPath string,
	authorization func() string,
) (*unixStagedRuntimeSink, error) {
	if !strings.HasPrefix(socketPath, "/") || authorization == nil {
		return nil, errors.New("The Runtime socket path must be absolute.")
	}
	sink := &runtimeSink{
		authorization: authorization,
		candidatePath: "/v1/staged-candidates/{capture_id}",
		contentType:   stagedCandidateContentType,
		dial: func(timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, timeout)
		},
		host:  "reproit-runtime",
		queue: make(chan queuedCandidate, MaxQueuedCandidates),
	}
	go sink.worker()
	return &unixStagedRuntimeSink{runtimeSink: sink}, nil
}

func newtlsStagedRuntimeSink(
	address string,
	serverName string,
	caCertificatePath string,
	authorization func() string,
) (*tlsStagedRuntimeSink, error) {
	sink, err := newtlsRuntimeSink(address, serverName, caCertificatePath, authorization)
	if err != nil {
		return nil, err
	}
	sink.candidatePath = "/v1/staged-candidates/{capture_id}"
	sink.contentType = stagedCandidateContentType
	return &tlsStagedRuntimeSink{runtimeSink: sink.runtimeSink}, nil
}

type stagedDelivery interface {
	deliverBytes(captureID string, body []byte, timeout time.Duration) string
}

type stagedQueueItem struct {
	bytes     []byte
	captureID string
	enqueued  time.Time
}

type stagedCandidateSink struct {
	deferred    stagedDelivery
	key         []byte
	mu          sync.Mutex
	queue       chan stagedQueueItem
	queuedBytes int
	queuedCount int
	recall      RecallCounters
	runtime     stagedDelivery
}

func (sink *stagedCandidateSink) AllowsProcessingMode(mode string) bool { return mode == "private" }

func NewstagedCandidateSink(
	runtime stagedDelivery,
	deferred stagedDelivery,
	key []byte,
) (*stagedCandidateSink, error) {
	if runtime == nil || deferred == nil {
		return nil, errors.New("The candidate staging transport is invalid.")
	}
	if len(key) != 32 {
		return nil, errors.New("The candidate staging key must contain 32 bytes.")
	}
	sink := &stagedCandidateSink{
		deferred: deferred,
		key:      bytes.Clone(key),
		queue:    make(chan stagedQueueItem, MaxQueuedCandidates),
		runtime:  runtime,
	}
	go sink.worker()
	return sink, nil
}

func (sink *stagedCandidateSink) QueuedBytes() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.queuedBytes
}

func (sink *stagedCandidateSink) RecallCounters() RecallCounters {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.recall
}

func (sink *stagedCandidateSink) TrySend(captureID string, candidate []byte) bool {
	envelope, parsedCaptureID, err := sealStagedCandidate(candidate, sink.key)
	if err != nil || captureID != parsedCaptureID {
		sink.mu.Lock()
		increment(&sink.recall.CandidateIncomplete)
		sink.mu.Unlock()
		return false
	}
	sink.mu.Lock()
	if sink.queuedCount >= MaxQueuedCandidates || sink.queuedBytes+len(envelope) > MaxGlobalBytes {
		increment(&sink.recall.CandidateQueueFull)
		sink.mu.Unlock()
		return false
	}
	sink.queuedBytes += len(envelope)
	sink.queuedCount++
	sink.mu.Unlock()
	item := stagedQueueItem{bytes: envelope, captureID: captureID, enqueued: time.Now()}
	select {
	case sink.queue <- item:
		return true
	default:
		sink.release(len(envelope))
		sink.mu.Lock()
		increment(&sink.recall.CandidateQueueFull)
		sink.mu.Unlock()
		return false
	}
}

func (sink *stagedCandidateSink) worker() {
	for item := range sink.queue {
		outcome := sink.deliver(item)
		sink.mu.Lock()
		switch outcome {
		case "cloud_protected", "local_only":
			increment(&sink.recall.CandidateDurablyAccepted)
		case "reject":
			increment(&sink.recall.CandidateRejected)
		default:
			increment(&sink.recall.CandidateDeliveryExpired)
		}
		sink.mu.Unlock()
		sink.release(len(item.bytes))
	}
}

func (sink *stagedCandidateSink) release(size int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.queuedBytes = max(0, sink.queuedBytes-size)
	sink.queuedCount = max(0, sink.queuedCount-1)
}

func (sink *stagedCandidateSink) deliver(item stagedQueueItem) string {
	localOnly := false
	for _, offset := range []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond} {
		time.Sleep(max(0, item.enqueued.Add(offset).Sub(time.Now())))
		remaining := item.enqueued.Add(deliveryLifetime).Sub(time.Now())
		if remaining <= 0 {
			break
		}
		outcomes := make(chan string, 2)
		go func() { outcomes <- sink.runtime.deliverBytes(item.captureID, item.bytes, remaining) }()
		go func() { outcomes <- sink.deferred.deliverBytes(item.captureID, item.bytes, remaining) }()
		first, second := <-outcomes, <-outcomes
		if first == "cloud_protected" || second == "cloud_protected" {
			return "cloud_protected"
		}
		localOnly = localOnly || first == "local_only" || second == "local_only"
		if first == "reject" && second == "reject" ||
			first == "local_only" && (second == "local_only" || second == "reject") ||
			second == "local_only" && first == "reject" {
			if localOnly {
				return "local_only"
			}
			return "reject"
		}
	}
	if localOnly {
		return "local_only"
	}
	return "expired"
}

func sealStagedCandidate(candidateBytes, key []byte) ([]byte, string, error) {
	if len(candidateBytes) > MaxGlobalBytes {
		return nil, "", ErrCaptureLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(candidateBytes))
	decoder.UseNumber()
	var candidate map[string]any
	if err := decoder.Decode(&candidate); err != nil {
		return nil, "", ErrIncompleteCapture
	}
	canonical, err := CanonicalBytes(candidate)
	if err != nil || !bytes.Equal(canonical, candidateBytes) || !completeParsedCandidate(candidate) {
		return nil, "", ErrIncompleteCapture
	}
	identity, err := stagingIdentity(candidate)
	if err != nil {
		return nil, "", err
	}
	aad, err := CanonicalBytes(identity)
	if err != nil {
		return nil, "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", err
	}
	stored := append(bytes.Clone(nonce), gcm.Seal(nil, nonce, candidateBytes, aad)...)
	envelope := map[string]any{
		"cipher_digest": digestBytes(stored),
		"cipher_size":   len(stored),
		"ciphertext":    base64.RawURLEncoding.EncodeToString(stored),
		"format":        "reproit.candidate-staging-envelope.v1",
		"identity":      identity,
	}
	encoded, err := CanonicalBytes(envelope)
	captureID, _ := candidate["capture_id"].(string)
	return encoded, captureID, err
}

func completeParsedCandidate(candidate map[string]any) bool {
	return validateCandidate(candidate) == nil
}

func stagingIdentity(candidate map[string]any) (map[string]any, error) {
	deployment, ok := candidate["deployment"].(map[string]any)
	failure, failureOK := candidate["failure"].(map[string]any)
	subject, subjectOK := deployment["subject"].(map[string]any)
	failurePayload, payloadOK := parsedFailurePayload(candidate)
	failureIdentity, identityOK := failurePayload["identity"].(map[string]any)
	if !ok || !failureOK || !subjectOK || !payloadOK || !identityOK {
		return nil, ErrIncompleteCapture
	}
	if equal, err := canonicalEqual(failurePayload["failure"], failure); err != nil || !equal {
		return nil, ErrIncompleteCapture
	}
	storm := map[string]any{
		"failure_identity_digest": failure["identity"],
		"format":                  "reproit.failure-storm-identity.v1",
		"operation_kind":          failureIdentity["operation_kind"],
		"operation_name":          failureIdentity["operation_name"],
		"service_id":              deployment["service_id"],
		"source_revision":         deployment["source_revision"],
		"subject_artifact_digest": subject["artifact_digest"],
	}
	identity := map[string]any{
		"capture_id":           candidate["capture_id"],
		"deployment_digest":    digestValue(deployment),
		"expires_at":           time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05.000Z"),
		"failure_storm_digest": digestValue(storm),
		"format":               "reproit.candidate-staging-identity.v1",
		"organization_id":      deployment["organization_id"],
		"processing_mode":      deployment["processing_mode"],
		"project_id":           deployment["project_id"],
		"provider_lease_digest": digestValue(map[string]any{
			"format": "reproit.provider-lease-binding.v1", "organization_id": deployment["organization_id"],
			"service_id": deployment["service_id"], "world_id": candidate["world_id"],
		}),
		"request_digest": digestValue(candidate),
		"service_id":     deployment["service_id"],
		"world_id":       candidate["world_id"],
	}
	for _, value := range identity {
		if text, ok := value.(string); !ok || text == "" {
			return nil, ErrIncompleteCapture
		}
	}
	if identity["processing_mode"] != "private" {
		return nil, ErrIncompleteCapture
	}
	return identity, nil
}

func parsedFailurePayload(candidate map[string]any) (map[string]any, bool) {
	records, _ := candidate["records"].([]any)
	for _, value := range records {
		record, _ := value.(map[string]any)
		if record["kind"] != "failure" {
			continue
		}
		payload, ok := record["payload"].(string)
		decoded, err := base64.RawURLEncoding.DecodeString(payload)
		if !ok || err != nil {
			return nil, false
		}
		decoder := json.NewDecoder(bytes.NewReader(decoded))
		decoder.UseNumber()
		var result map[string]any
		return result, decoder.Decode(&result) == nil
	}
	return nil, false
}
