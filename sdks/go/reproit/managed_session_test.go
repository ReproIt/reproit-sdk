package reproit

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	loopbackProjectToken = "test-project-token"
	loopbackUploadToken  = "managed-upload-token-1"
)

func formatLoopbackTimestamp(value time.Time) string {
	return value.UTC().Format(timestampLayout)
}

// loopbackManagedService is one loopback HTTP double for the key service
// and the managed ingress. It validates every request body with the same
// canonical validators and records the exact request sequence.
type loopbackManagedService struct {
	t         *testing.T
	server    *httptest.Server
	authority string
	client    *ManagedTlsClient

	mu                         sync.Mutex
	requests                   [][2]string
	grantRequests              []map[string]any
	issuedGrants               []map[string]any
	expected                   map[string]bool
	uploaded                   map[string]bool
	uploadRequest              map[string]any
	registeredPublicKey        string
	registeredDeploymentDigest string
	grantFailureStatus         int
	limits                     map[string]any
}

func newLoopbackManagedService(t *testing.T) *loopbackManagedService {
	t.Helper()
	service := &loopbackManagedService{
		t:        t,
		expected: make(map[string]bool),
		uploaded: make(map[string]bool),
		limits:   positiveVector(t, loadCloudAPIVectors(t), "managed_candidate_limits"),
	}
	service.server = httptest.NewServer(http.HandlerFunc(service.handle))
	t.Cleanup(service.server.Close)
	service.authority = strings.TrimPrefix(service.server.URL, "http://")
	endpoint := &ManagedTlsEndpoint{
		authority: service.authority,
		origin:    "https://" + service.authority,
		dial: func(timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("tcp", service.authority, timeout)
		},
	}
	token, err := NewManagedProjectToken(loopbackProjectToken)
	if err != nil {
		t.Fatalf("project token: %v", err)
	}
	service.client = NewManagedTlsClient(endpoint, endpoint, token)
	return service
}

func (service *loopbackManagedService) requestLog() [][2]string {
	service.mu.Lock()
	defer service.mu.Unlock()
	return append([][2]string{}, service.requests...)
}

func (service *loopbackManagedService) reply(
	writer http.ResponseWriter, status int, value map[string]any,
) {
	body, err := CanonicalBytes(value)
	if err != nil {
		service.t.Errorf("loopback reply encode: %v", err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func (service *loopbackManagedService) reject(
	writer http.ResponseWriter, status int, code, message string,
) {
	service.reply(writer, status, map[string]any{
		"code": code, "message": message, "retryable": status == 429 || status == 503,
	})
}

func (service *loopbackManagedService) handle(
	writer http.ResponseWriter, request *http.Request,
) {
	path := request.URL.Path
	body, err := io.ReadAll(io.LimitReader(request.Body, managedMaxJSONResponseBytes+1))
	if err != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Unreadable request body.")
		return
	}
	service.mu.Lock()
	service.requests = append(service.requests, [2]string{request.Method, path})
	service.mu.Unlock()
	objectPrefix := "/v1/managed-candidates/" + fixtureUploadID + "/objects/"
	switch {
	case request.Method == "POST" && path == "/v1/workload-keys":
		service.registerWorkloadKey(writer, request, body)
	case request.Method == "POST" && path == "/v1/managed-candidate-encryption-grants":
		service.issueGrant(writer, request, body)
	case request.Method == "POST" && path == "/v1/managed-candidates":
		service.startUpload(writer, body)
	case request.Method == "POST" && path == "/v1/managed-candidates/"+fixtureUploadID+"/commit":
		service.commit(writer, request)
	case request.Method == "PUT" && strings.HasPrefix(path, objectPrefix):
		service.putObject(writer, request, path[len(objectPrefix):], body)
	case request.Method == "DELETE" && path == "/v1/managed-candidates/"+fixtureUploadID:
		service.cancel(writer)
	default:
		service.reject(writer, 404, "NOT_FOUND", "Unknown route.")
	}
}

func (service *loopbackManagedService) authorized(
	request *http.Request, expected string,
) bool {
	return request.Header.Get("Authorization") == expected
}

func (service *loopbackManagedService) registerWorkloadKey(
	writer http.ResponseWriter, request *http.Request, body []byte,
) {
	if !service.authorized(request, "Bearer "+loopbackProjectToken) {
		service.reject(writer, 401, "AUTHENTICATION_REQUIRED", "Missing project token.")
		return
	}
	parsed, err := parseStrictJSON(body, managedMaxJSONResponseBytes)
	if err != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid registration.")
		return
	}
	value, valueOK := parsed.(map[string]any)
	if !valueOK || !hasExactKeys(value, "algorithm", "deployment", "public_key", "service_id") ||
		value["algorithm"] != "Ed25519" || value["service_id"] != fixtureServiceID {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid registration.")
		return
	}
	publicKey, publicKeyOK := value["public_key"].(string)
	if !publicKeyOK {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid registration.")
		return
	}
	if _, err := decodeBase64URL(publicKey, 32); err != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid registration.")
		return
	}
	if err := validateWorkloadKeyRegistration(value); err != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid registration.")
		return
	}
	deployment := value["deployment"].(map[string]any)
	deploymentDigest, err := canonicalDigest(deployment)
	if err != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid registration.")
		return
	}
	service.mu.Lock()
	service.registeredPublicKey = publicKey
	service.registeredDeploymentDigest = deploymentDigest
	service.mu.Unlock()
	service.reply(writer, 200, map[string]any{
		"deployment_digest": deploymentDigest,
		"key_id":            fixtureWorkloadKeyID,
		"service_id":        fixtureServiceID,
	})
}

func (service *loopbackManagedService) issueGrant(
	writer http.ResponseWriter, request *http.Request, body []byte,
) {
	if request.Header.Get("Authorization") != "" {
		service.reject(writer, 403, "AUTHORIZATION_DENIED", "A project token cannot issue grants.")
		return
	}
	service.mu.Lock()
	failureStatus := service.grantFailureStatus
	service.mu.Unlock()
	if failureStatus != 0 {
		service.reject(writer, failureStatus, "SERVICE_UNAVAILABLE", "Grant unavailable.")
		return
	}
	parsed, err := parseStrictJSON(body, managedMaxJSONResponseBytes)
	if err != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid grant request.")
		return
	}
	grantRequest, grantRequestOK := parsed.(map[string]any)
	if !grantRequestOK || validateGrantRequest(grantRequest) != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid grant request.")
		return
	}
	service.mu.Lock()
	registeredPublicKey := service.registeredPublicKey
	registeredDeploymentDigest := service.registeredDeploymentDigest
	service.mu.Unlock()
	publicKey, err := decodeBase64URL(registeredPublicKey, 32)
	if err != nil || grantRequest["deployment_digest"] != registeredDeploymentDigest ||
		grantRequest["signer_key_id"] != fixtureWorkloadKeyID ||
		verifySignedValue(grantRequest, publicKey) != nil {
		service.reject(writer, 403, "ATTESTATION_SCOPE", "Invalid workload signature.")
		return
	}
	now := time.Now()
	grant := fixtureSignedCaptureGrant(
		service.t, grantRequest, fixtureKeyReference,
		formatLoopbackTimestamp(now.Add(-5*time.Minute)),
		formatLoopbackTimestamp(now.Add(5*time.Minute)),
		fixtureCaptureSignerSeed,
	)
	service.mu.Lock()
	service.grantRequests = append(service.grantRequests, grantRequest)
	service.issuedGrants = append(service.issuedGrants, grant)
	service.mu.Unlock()
	service.reply(writer, 200, map[string]any{
		"candidate_key": encodeBase64URL(fixtureCandidateKey),
		"capture_grant": grant,
	})
}

func (service *loopbackManagedService) startUpload(
	writer http.ResponseWriter, body []byte,
) {
	parsed, err := parseStrictJSON(body, managedMaxJSONResponseBytes)
	if err != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid upload request.")
		return
	}
	uploadRequest, uploadRequestOK := parsed.(map[string]any)
	if !uploadRequestOK || validateUploadRequest(uploadRequest) != nil {
		service.reject(writer, 400, "SCHEMA_INVALID", "Invalid upload request.")
		return
	}
	service.mu.Lock()
	issued := append([]map[string]any{}, service.issuedGrants...)
	service.mu.Unlock()
	grantKnown := false
	for _, grant := range issued {
		if equal, err := canonicalEqual(grant, uploadRequest["capture_grant"]); err == nil && equal {
			grantKnown = true
		}
	}
	if !grantKnown {
		service.reject(writer, 403, "ATTESTATION_SCOPE", "Unknown capture grant.")
		return
	}
	identity := uploadRequest["ciphertext_identity"].(map[string]any)
	expected := map[string]bool{
		identity["manifest_object"].(map[string]any)["cipher_digest"].(string): true,
	}
	objects, _ := candidateRecords(identity["objects"])
	for _, entry := range objects {
		chunks, _ := candidateRecords(entry["chunks"])
		for _, chunk := range chunks {
			expected[chunk["cipher_digest"].(string)] = true
		}
	}
	service.mu.Lock()
	service.uploadRequest = uploadRequest
	service.expected = expected
	service.uploaded = make(map[string]bool)
	service.mu.Unlock()
	digests := make([]string, 0, len(expected))
	for digest := range expected {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	missing := make([]any, 0, len(digests))
	origin := "https://" + service.authority
	for _, digest := range digests {
		missing = append(missing, map[string]any{
			"cipher_digest": digest,
			"expires_at":    formatLoopbackTimestamp(time.Now().Add(time.Minute)),
			"upload_url": origin + "/v1/managed-candidates/" + fixtureUploadID +
				"/objects/" + digest + "?token=up",
		})
	}
	service.reply(writer, 200, map[string]any{
		"expires_at":          formatLoopbackTimestamp(time.Now().Add(time.Minute)),
		"limits":              service.limits,
		"missing_objects":     missing,
		"next_missing_cursor": nil,
		"state":               "OPEN",
		"upload_id":           fixtureUploadID,
		"upload_token":        loopbackUploadToken,
	})
}

func (service *loopbackManagedService) putObject(
	writer http.ResponseWriter, request *http.Request, digest string, body []byte,
) {
	if request.URL.RawQuery != "token=up" {
		service.reject(writer, 404, "NOT_FOUND", "Unknown object route.")
		return
	}
	service.mu.Lock()
	known := service.expected[digest]
	service.mu.Unlock()
	if !known || digestBytes(body) != digest {
		service.reject(writer, 400, "OBJECT_DIGEST_MISMATCH", "Digest mismatch.")
		return
	}
	service.mu.Lock()
	service.uploaded[digest] = true
	service.mu.Unlock()
	writer.WriteHeader(204)
}

func (service *loopbackManagedService) commit(
	writer http.ResponseWriter, request *http.Request,
) {
	if !service.authorized(request, "Bearer "+loopbackUploadToken) {
		service.reject(writer, 401, "AUTHENTICATION_REQUIRED", "Missing upload token.")
		return
	}
	service.mu.Lock()
	complete := len(service.expected) == len(service.uploaded)
	uploadRequest := service.uploadRequest
	service.mu.Unlock()
	if !complete || uploadRequest == nil {
		service.reject(writer, 409, "UPLOAD_INCOMPLETE", "Objects are missing.")
		return
	}
	identity := uploadRequest["ciphertext_identity"].(map[string]any)
	service.reply(writer, 200, map[string]any{
		"candidate_identity_digest":  identity["candidate_identity_digest"],
		"candidate_key_reference":    identity["candidate_key_reference"],
		"capture_id":                 identity["capture_id"],
		"encrypted_candidate_digest": uploadRequest["encrypted_candidate_digest"],
		"state":                      "CLOUD_PROTECTED",
		"upload_id":                  fixtureUploadID,
	})
}

func (service *loopbackManagedService) cancel(writer http.ResponseWriter) {
	service.mu.Lock()
	uploadRequest := service.uploadRequest
	service.mu.Unlock()
	if uploadRequest == nil {
		service.reject(writer, 404, "NOT_FOUND", "Unknown upload.")
		return
	}
	identity := uploadRequest["ciphertext_identity"].(map[string]any)
	service.reply(writer, 200, map[string]any{
		"candidate_identity_digest":  identity["candidate_identity_digest"],
		"candidate_key_reference":    identity["candidate_key_reference"],
		"capture_id":                 identity["capture_id"],
		"encrypted_candidate_digest": uploadRequest["encrypted_candidate_digest"],
		"expires_at":                 nil,
		"missing_digests":            []any{},
		"state":                      "CANCELLED",
		"upload_id":                  fixtureUploadID,
	})
}

func loopbackSinkConfiguration(t *testing.T) ManagedSinkConfiguration {
	t.Helper()
	return loopbackSinkConfigurationAt(t, t.TempDir())
}

func loopbackSinkConfigurationAt(t *testing.T, stateRoot string) ManagedSinkConfiguration {
	t.Helper()
	publicKey, err := verificationKey(fixtureCaptureSignerSeed)
	if err != nil {
		t.Fatalf("verification key: %v", err)
	}
	return ManagedSinkConfiguration{
		CaptureSignerID:        fixtureCaptureSignerID,
		CaptureSignerPublicKey: publicKey,
		ServiceID:              fixtureServiceID,
		WorkloadStateRoot:      stateRoot,
		WorkloadSigningKey:     fixtureWorkloadSeed,
	}
}

type loopbackSessionFixture struct {
	service *loopbackManagedService
	sink    *ManagedCandidateSink
	subject *GoSubjectPackage
	world   map[string]any
	worldID string
}

func newLoopbackSessionFixture(t *testing.T) *loopbackSessionFixture {
	t.Helper()
	service := newLoopbackManagedService(t)
	subject := fixtureSubjectPackage(t)
	world := emptyWorld()
	worldID, err := canonicalDigest(world)
	if err != nil {
		t.Fatalf("world digest: %v", err)
	}
	sink, err := NewManagedCandidateSink(
		service.client,
		ManagedCaptureClosure{Artifacts: nil, Completion: "return", World: deepCopyMap(t, world)},
		loopbackSinkConfiguration(t),
		subject,
	)
	if err != nil {
		t.Fatalf("construct managed sink: %v", err)
	}
	return &loopbackSessionFixture{
		service: service, sink: sink, subject: subject, world: world, worldID: worldID,
	}
}

func (fixture *loopbackSessionFixture) boundDeployment(t *testing.T) map[string]any {
	t.Helper()
	deployment := unboundLoopbackDeployment("2026-01-01T00:00:00.000Z")
	if err := fixture.sink.BindDeployment(deployment); err != nil {
		t.Fatalf("bind deployment: %v", err)
	}
	return deployment
}

func unboundLoopbackDeployment(signedAt string) map[string]any {
	return map[string]any{
		"format":               "reproit.deployment.v1",
		"organization_id":      fixtureOrganizationID,
		"processing_mode":      "managed",
		"project_id":           fixtureProjectID,
		"repository_id":        "source.example/acme/commerce",
		"runtime_capabilities": []any{"runtime.go"},
		"runtime_endpoint":     "https://managed.reproit.example",
		"service_id":           fixtureServiceID,
		"service_path":         "services/orders",
		"signature":            "",
		"signed_at":            signedAt,
		"signer_key_id":        "",
		"source_revision":      "0123456789abcdef",
		"subject":              map[string]any{},
	}
}

func (fixture *loopbackSessionFixture) captureFailure(
	t *testing.T, deployment map[string]any, captureID, operationID, worldID string,
) {
	t.Helper()
	vectors := loadProtocolVectors(t)
	sdk := New(fixture.sink)
	start := CandidateStart{
		CaptureID: captureID, Deployment: deployment,
		OperationID: operationID, WorldID: worldID,
	}
	if err := sdk.Begin(start, positiveVector(t, vectors, "operation_begin_payload")); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := sdk.RecordInput(
		operationID, positiveVector(t, vectors, "operation_input_payload"),
	); err != nil {
		t.Fatalf("record input: %v", err)
	}
	if err := sdk.Fail(operationID, positiveVector(t, vectors, "failure_payload")); err != nil {
		t.Fatalf("fail: %v", err)
	}
}

func TestSignedDeploymentRegistrationUsesProjectTokenOnce(t *testing.T) {
	fixture := newLoopbackSessionFixture(t)
	deployment := fixture.boundDeployment(t)
	if fixture.sink.WorkloadKeyID() != fixtureWorkloadKeyID {
		t.Fatalf("workload key id %s", fixture.sink.WorkloadKeyID())
	}
	requests := fixture.service.requestLog()
	if len(requests) != 1 || requests[0] != [2]string{"POST", "/v1/workload-keys"} {
		t.Fatalf("registration requests %v", requests)
	}
	fixture.service.mu.Lock()
	registered := fixture.service.registeredPublicKey
	fixture.service.mu.Unlock()
	if registered != encodeBase64URL(fixture.sink.WorkloadPublicKey()) {
		t.Fatal("the registered public key does not match the workload key")
	}
	if err := verifySignedValue(deployment, fixture.sink.WorkloadPublicKey()); err != nil {
		t.Fatalf("verify signed deployment: %v", err)
	}
}

func TestExactRestartUsesProtectedReceiptWithoutRegistration(t *testing.T) {
	service := newLoopbackManagedService(t)
	stateRoot := t.TempDir()
	configuration := loopbackSinkConfigurationAt(t, stateRoot)
	subject := fixtureSubjectPackage(t)
	closure := ManagedCaptureClosure{Artifacts: nil, Completion: "return", World: emptyWorld()}
	first, err := NewManagedCandidateSink(service.client, closure, configuration, subject)
	if err != nil {
		t.Fatalf("construct first managed sink: %v", err)
	}
	firstDeployment := unboundLoopbackDeployment("2026-01-01T00:00:00.000Z")
	if err := first.BindDeployment(firstDeployment); err != nil {
		t.Fatalf("register first deployment: %v", err)
	}
	second, err := NewManagedCandidateSink(service.client, closure, configuration, subject)
	if err != nil {
		t.Fatalf("construct restarted managed sink: %v", err)
	}
	secondDeployment := unboundLoopbackDeployment("2026-01-02T00:00:00.000Z")
	if err := second.BindDeployment(secondDeployment); err != nil {
		t.Fatalf("bind restarted deployment: %v", err)
	}
	requests := service.requestLog()
	if len(requests) != 1 || requests[0] != [2]string{"POST", "/v1/workload-keys"} {
		t.Fatalf("restart registration requests %v", requests)
	}
	if firstDeployment["signed_at"] != secondDeployment["signed_at"] {
		t.Fatal("the restarted deployment did not reuse the first signed_at value")
	}
	firstDigest, _ := canonicalDigest(firstDeployment)
	secondDigest, _ := canonicalDigest(secondDeployment)
	if firstDigest != secondDigest || first.WorkloadKeyID() != second.WorkloadKeyID() {
		t.Fatal("the restarted workload did not reuse its exact registered identity")
	}
}

func TestSuccessfulOperationMakesNoCaptureRequest(t *testing.T) {
	fixture := newLoopbackSessionFixture(t)
	deployment := fixture.boundDeployment(t)
	requestsBefore := len(fixture.service.requestLog())
	vectors := loadProtocolVectors(t)
	sdk := New(fixture.sink)
	start := CandidateStart{
		CaptureID:   fixtureCaptureID,
		Deployment:  deployment,
		OperationID: fixtureOperationID,
		WorldID:     fixture.worldID,
	}
	if err := sdk.Begin(start, positiveVector(t, vectors, "operation_begin_payload")); err != nil {
		t.Fatalf("begin successful operation: %v", err)
	}
	sdk.Succeed(fixtureOperationID)
	if !fixture.sink.WaitUntilIdle(time.Second) {
		t.Fatal("the managed sink did not remain idle")
	}
	if len(fixture.service.requestLog()) != requestsBefore {
		t.Fatal("a successful operation made a capture request")
	}
}

func TestCompleteCandidateReachesCloudProtected(t *testing.T) {
	fixture := newLoopbackSessionFixture(t)
	deployment := fixture.boundDeployment(t)
	fixture.captureFailure(t, deployment, fixtureCaptureID, fixtureOperationID, fixture.worldID)
	if !fixture.sink.WaitUntilIdle(10 * time.Second) {
		t.Fatal("the managed sink did not drain")
	}
	counters := fixture.sink.RecallCounters()
	if counters.CandidateDurablyAccepted != 1 || counters.CandidateIncomplete != 0 ||
		counters.CandidateRejected != 0 {
		t.Fatalf("counters %+v", counters)
	}
	if fixture.sink.QueuedBytes() != 0 {
		t.Fatalf("queued bytes %d after idle", fixture.sink.QueuedBytes())
	}

	requests := fixture.service.requestLog()
	expectedPrefix := [][2]string{
		{"POST", "/v1/workload-keys"},
		{"POST", "/v1/managed-candidate-encryption-grants"},
		{"POST", "/v1/managed-candidate-encryption-grants"},
		{"POST", "/v1/managed-candidates"},
	}
	for index, expected := range expectedPrefix {
		if requests[index] != expected {
			t.Fatalf("request %d is %v, expected %v", index, requests[index], expected)
		}
	}
	fixture.service.mu.Lock()
	expectedCount := len(fixture.service.expected)
	uploadedCount := len(fixture.service.uploaded)
	grantRequests := append([]map[string]any{}, fixture.service.grantRequests...)
	uploadRequest := fixture.service.uploadRequest
	fixture.service.mu.Unlock()
	objectPuts := 0
	for _, request := range requests {
		if request[0] == "PUT" {
			objectPuts++
		}
	}
	if objectPuts != expectedCount || uploadedCount != expectedCount {
		t.Fatalf("uploaded %d of %d objects across %d PUTs", uploadedCount, expectedCount, objectPuts)
	}
	last := requests[len(requests)-1]
	if last != [2]string{"POST", "/v1/managed-candidates/" + fixtureUploadID + "/commit"} {
		t.Fatalf("last request %v", last)
	}
	if len(grantRequests) != 2 {
		t.Fatalf("expected two grant requests, found %d", len(grantRequests))
	}
	if equal, err := canonicalEqual(grantRequests[0], grantRequests[1]); err != nil || !equal {
		t.Fatal("the renewal grant request differs from the initial grant request")
	}
	identity := uploadRequest["ciphertext_identity"].(map[string]any)
	if grantRequests[0]["candidate_identity_digest"] != identity["candidate_identity_digest"] {
		t.Fatal("the grant request does not bind the uploaded ciphertext identity")
	}
	deploymentDigest, _ := canonicalDigest(deployment)
	for _, grantRequest := range grantRequests {
		if grantRequest["deployment_digest"] != deploymentDigest ||
			grantRequest["signer_key_id"] != fixture.sink.WorkloadKeyID() {
			t.Fatal("the grant request does not bind the registered Deployment")
		}
		if err := verifySignedValue(grantRequest, fixture.sink.WorkloadPublicKey()); err != nil {
			t.Fatalf("verify workload-signed grant request: %v", err)
		}
	}
}

func TestIncompleteCandidateStopsLocallyWithACounter(t *testing.T) {
	fixture := newLoopbackSessionFixture(t)
	deployment := fixture.boundDeployment(t)
	fixture.captureFailure(t, deployment, fixtureCaptureID, fixtureOperationID, fixture.worldID)
	if !fixture.sink.WaitUntilIdle(10 * time.Second) {
		t.Fatal("the managed sink did not drain")
	}
	requestsBefore := len(fixture.service.requestLog())

	fixture.captureFailure(
		t, deployment,
		"cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
		"op_01890f3e-7b1c-7cc0-8a1b-123456789ac4",
		"sha256:"+strings.Repeat("a", 64),
	)
	if !fixture.sink.WaitUntilIdle(10 * time.Second) {
		t.Fatal("the managed sink did not drain")
	}
	counters := fixture.sink.RecallCounters()
	if counters.CandidateIncomplete != 1 || counters.CandidateDurablyAccepted != 1 {
		t.Fatalf("counters %+v", counters)
	}
	if len(fixture.service.requestLog()) != requestsBefore {
		t.Fatal("an incomplete candidate must make zero network calls")
	}
}

func TestNonCanonicalCandidateIsRefusedWithoutEnqueue(t *testing.T) {
	fixture := newLoopbackSessionFixture(t)
	deployment := fixture.boundDeployment(t)
	candidate := fixtureCapturedCandidate(t, deployment, fixture.worldID)
	encoded, err := CanonicalBytes(candidate)
	if err != nil {
		t.Fatalf("canonical candidate: %v", err)
	}
	raw := append(encoded, ' ')
	if fixture.sink.TrySend(fixtureCaptureID, raw) {
		t.Fatal("a non-canonical candidate was queued")
	}
	if fixture.sink.RecallCounters().CandidateIncomplete != 1 {
		t.Fatal("the refusal must increment candidate_incomplete")
	}
}

func TestForeignWorkloadSignatureIsRefused(t *testing.T) {
	fixture := newLoopbackSessionFixture(t)
	deployment := fixtureBoundDeployment(
		t, fixture.subject, bytes.Repeat([]byte{0x55}, 32), fixtureWorkloadKeyID,
	)
	candidate := fixtureCapturedCandidate(t, deployment, fixture.worldID)
	encoded, err := CanonicalBytes(candidate)
	if err != nil {
		t.Fatalf("canonical candidate: %v", err)
	}
	if fixture.sink.TrySend(fixtureCaptureID, encoded) {
		t.Fatal("a foreign workload signature was accepted")
	}
	if fixture.sink.RecallCounters().CandidateIncomplete != 1 {
		t.Fatal("the refusal must increment candidate_incomplete")
	}
}

func TestGrantOutageIsFailOpenAndCountedAsRetryable(t *testing.T) {
	fixture := newLoopbackSessionFixture(t)
	fixture.service.mu.Lock()
	fixture.service.grantFailureStatus = 503
	fixture.service.mu.Unlock()
	deployment := fixture.boundDeployment(t)
	fixture.captureFailure(t, deployment, fixtureCaptureID, fixtureOperationID, fixture.worldID)
	if !fixture.sink.WaitUntilIdle(10 * time.Second) {
		t.Fatal("the managed sink did not drain")
	}
	counters := fixture.sink.RecallCounters()
	if counters.CandidateDurablyAccepted != 0 || counters.CandidateDeliveryExpired != 1 {
		t.Fatalf("counters %+v", counters)
	}
	for _, request := range fixture.service.requestLog() {
		if request == [2]string{"POST", "/v1/managed-candidates"} {
			t.Fatal("a grant outage must stop before the ingress")
		}
	}
}

// stubRegistrationClient registers immediately and then blocks grant
// delivery until released, always refusing the grant.
type stubRegistrationClient struct {
	release    chan struct{}
	mu         sync.Mutex
	grantCalls int
}

func newStubRegistrationClient() *stubRegistrationClient {
	return &stubRegistrationClient{release: make(chan struct{})}
}

func (client *stubRegistrationClient) RegisterWorkloadKey(
	request map[string]any, timeout time.Duration,
) (map[string]any, error) {
	deployment := request["deployment"].(map[string]any)
	deploymentDigest, _ := canonicalDigest(deployment)
	return map[string]any{
		"deployment_digest": deploymentDigest,
		"key_id":            request["deployment"].(map[string]any)["signer_key_id"],
		"service_id":        request["service_id"],
	}, nil
}

func (client *stubRegistrationClient) RequestEncryptionGrant(
	request map[string]any, timeout time.Duration,
) (EncryptionResponse, error) {
	client.mu.Lock()
	client.grantCalls++
	client.mu.Unlock()
	select {
	case <-client.release:
	case <-time.After(10 * time.Second):
	}
	return EncryptionResponse{}, newManagedError("SCHEMA_INVALID", "The double refuses grants.")
}

func (client *stubRegistrationClient) grantCallCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.grantCalls
}

func (client *stubRegistrationClient) Start(
	request map[string]any, timeout time.Duration,
) (map[string]any, error) {
	return nil, newManagedError("SCHEMA_INVALID", "The double has no ingress.")
}

func (client *stubRegistrationClient) Missing(
	uploadID string, uploadToken string, cursor string, timeout time.Duration,
) (map[string]any, error) {
	return nil, newManagedError("SCHEMA_INVALID", "The double has no ingress.")
}

func (client *stubRegistrationClient) UploadObject(
	uploadURL string, digest string, value []byte, timeout time.Duration,
) error {
	return newManagedError("SCHEMA_INVALID", "The double has no ingress.")
}

func (client *stubRegistrationClient) Commit(
	uploadID string, uploadToken string, timeout time.Duration,
) (map[string]any, error) {
	return nil, newManagedError("SCHEMA_INVALID", "The double has no ingress.")
}

func (client *stubRegistrationClient) Cancel(
	uploadID string, uploadToken string, timeout time.Duration,
) (map[string]any, error) {
	return nil, newManagedError("SCHEMA_INVALID", "The double has no ingress.")
}

func newStubSink(
	t *testing.T, client *stubRegistrationClient,
) (*ManagedCandidateSink, map[string]any) {
	t.Helper()
	sink, err := NewManagedCandidateSink(
		client,
		ManagedCaptureClosure{Artifacts: nil, Completion: "return", World: emptyWorld()},
		loopbackSinkConfiguration(t),
		fixtureSubjectPackage(t),
	)
	if err != nil {
		t.Fatalf("construct stub sink: %v", err)
	}
	fixture := &loopbackSessionFixture{sink: sink}
	return sink, fixture.boundDeployment(t)
}

func TestQueueBoundCountsQueueFullAndStaysFailOpen(t *testing.T) {
	client := newStubRegistrationClient()
	sink, deployment := newStubSink(t, client)
	world := emptyWorld()
	worldID, err := canonicalDigest(world)
	if err != nil {
		t.Fatalf("world digest: %v", err)
	}
	candidate := fixtureCapturedCandidate(t, deployment, worldID)
	raw, err := CanonicalBytes(candidate)
	if err != nil {
		t.Fatalf("canonical candidate: %v", err)
	}
	accepted := 0
	for attempt := 0; attempt < 17; attempt++ {
		if sink.TrySend(fixtureCaptureID, raw) {
			accepted++
		}
	}
	if accepted != 16 {
		t.Fatalf("accepted %d candidates, expected 16", accepted)
	}
	if sink.RecallCounters().CandidateQueueFull != 1 {
		t.Fatalf("queue-full counter %d", sink.RecallCounters().CandidateQueueFull)
	}
	close(client.release)
	if !sink.WaitUntilIdle(20 * time.Second) {
		t.Fatal("the managed sink did not drain")
	}
	counters := sink.RecallCounters()
	terminal := counters.CandidateRejected + counters.CandidateDeliveryExpired +
		counters.CandidateIncomplete + counters.CandidateDurablyAccepted
	if terminal != 16 || counters.CandidateDurablyAccepted != 0 {
		t.Fatalf("terminal counters %+v", counters)
	}
	if sink.QueuedBytes() != 0 {
		t.Fatalf("queued bytes %d after idle", sink.QueuedBytes())
	}
}

func TestProcessingModesAreManagedOnly(t *testing.T) {
	client := newStubRegistrationClient()
	sink, _ := newStubSink(t, client)
	if !sink.AllowsProcessingMode("managed") {
		t.Fatal("the managed sink must allow managed processing")
	}
	for _, mode := range []string{"private", "", "MANAGED"} {
		if sink.AllowsProcessingMode(mode) {
			t.Fatalf("the managed sink must refuse mode %q", mode)
		}
	}
}

func TestExpiredQueueEntriesAreCountedNotDelivered(t *testing.T) {
	client := newStubRegistrationClient()
	close(client.release)
	sink, deployment := newStubSink(t, client)
	sink.deliveryLifetime = 0
	world := emptyWorld()
	worldID, err := canonicalDigest(world)
	if err != nil {
		t.Fatalf("world digest: %v", err)
	}
	candidate := fixtureCapturedCandidate(t, deployment, worldID)
	raw, err := CanonicalBytes(candidate)
	if err != nil {
		t.Fatalf("canonical candidate: %v", err)
	}
	if !sink.TrySend(fixtureCaptureID, raw) {
		t.Fatal("the candidate was not queued")
	}
	deadline := time.Now().Add(5 * time.Second)
	for sink.RecallCounters().CandidateDeliveryExpired == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sink.RecallCounters().CandidateDeliveryExpired != 1 {
		t.Fatal("the expired entry was not counted")
	}
	if client.grantCallCount() != 0 {
		t.Fatal("an expired entry must not reach the network")
	}
}
