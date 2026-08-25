// Shared fixtures for the managed-mode capture client tests.
package reproit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fixtureCaptureID      = "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc"
	fixtureOperationID    = "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1"
	fixtureOrganizationID = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd"
	fixtureProjectID      = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"
	fixtureServiceID      = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
	fixtureUploadID       = "upl_01890f3e-7b1c-7cc0-8a1b-123456789ac1"

	fixtureCaptureSignerID = "managed-candidate-capture-test"

	grantVerificationTime = "2026-01-01T00:00:30.000Z"
)

var (
	fixtureCaptureSignerSeed = bytes.Repeat([]byte{0x83}, 32)
	fixtureWorkloadSeed      = bytes.Repeat([]byte{0x77}, 32)
	fixtureWorkloadKeyID     = fixtureManagedWorkloadKeyID()
	fixtureCandidateKey      = bytes.Repeat([]byte{0x42}, 32)
	fixtureKeyReference      = encodeBase64URL(bytes.Repeat([]byte{0x91}, 32))
	fixtureGrantID           = encodeBase64URL(bytes.Repeat([]byte{0x92}, 32))
)

func fixtureManagedWorkloadKeyID() string {
	publicKey, err := verificationKey(fixtureWorkloadSeed)
	if err != nil {
		panic(err)
	}
	return managedWorkloadKeyID(publicKey)
}

const specsV1Dir = "../../../.core/specs/v1"

// TestMain uses the exact Core checkout prepared from core-pin.json.
// An explicit environment value still wins.
func TestMain(m *testing.M) {
	defaults := map[string]string{
		"REPROIT_PROTOCOL_VECTORS":  "protocol-vectors.json",
		"REPROIT_CLOUD_API_VECTORS": "cloud-api-vectors.json",
		"REPROIT_PROCESSOR_CAPTURE": "processor-capture.json",
	}
	for environment, name := range defaults {
		if os.Getenv(environment) == "" {
			_ = os.Setenv(environment, filepath.Join(specsV1Dir, name))
		}
	}
	os.Exit(m.Run())
}

var (
	vectorCacheMu sync.Mutex
	vectorCache   = make(map[string]map[string]any)
)

func loadVectorFile(t *testing.T, name string) map[string]any {
	t.Helper()
	vectorCacheMu.Lock()
	defer vectorCacheMu.Unlock()
	if cached, present := vectorCache[name]; present {
		return cached
	}
	path := filepath.Join(specsV1Dir, name)
	if name == "protocol-vectors.json" {
		path = os.Getenv("REPROIT_PROTOCOL_VECTORS")
	} else if name == "cloud-api-vectors.json" {
		path = os.Getenv("REPROIT_CLOUD_API_VECTORS")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	parsed, parseErr := parseStrictJSON(raw, 1<<26)
	if parseErr != nil {
		t.Fatalf("parse %s: %v", name, parseErr)
	}
	value, ok := parsed.(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", name)
	}
	vectorCache[name] = value
	return value
}

func loadProtocolVectors(t *testing.T) map[string]any {
	return loadVectorFile(t, "protocol-vectors.json")
}

func loadCloudAPIVectors(t *testing.T) map[string]any {
	return loadVectorFile(t, "cloud-api-vectors.json")
}

func positiveVector(t *testing.T, vectors map[string]any, name string) map[string]any {
	t.Helper()
	positive, positiveOK := vectors["positive"].(map[string]any)
	if !positiveOK {
		t.Fatal("vectors have no positive section")
	}
	entry, entryOK := positive[name].(map[string]any)
	if !entryOK {
		t.Fatalf("missing positive vector %q", name)
	}
	value, valueOK := entry["value"].(map[string]any)
	if !valueOK {
		t.Fatalf("positive vector %q has no object value", name)
	}
	return value
}

func canonicalSHA256(t *testing.T, vectors map[string]any, name string) string {
	t.Helper()
	digests, digestsOK := vectors["canonical_sha256"].(map[string]any)
	if !digestsOK {
		t.Fatal("vectors have no canonical_sha256 section")
	}
	digest, digestOK := digests[name].(string)
	if !digestOK {
		t.Fatalf("missing canonical_sha256 entry %q", name)
	}
	return digest
}

func deepCopyValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := CanonicalBytes(value)
	if err != nil {
		t.Fatalf("canonical encode for copy: %v", err)
	}
	copied, copyErr := parseStrictJSON(encoded, 1<<26)
	if copyErr != nil {
		t.Fatalf("copy parse: %v", copyErr)
	}
	return copied
}

func deepCopyMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	return deepCopyValue(t, value).(map[string]any)
}

// applyMutation applies one negative-vector JSON-pointer replace mutation.
func applyMutation(t *testing.T, base map[string]any, mutation map[string]any) map[string]any {
	t.Helper()
	if mutation["operation"] != "replace" {
		t.Fatalf("unsupported mutation operation %v", mutation["operation"])
	}
	changed := deepCopyMap(t, base)
	path, _ := mutation["path"].(string)
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var target any = changed
	for _, part := range parts[:len(parts)-1] {
		switch typed := target.(type) {
		case map[string]any:
			target = typed[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil {
				t.Fatalf("invalid mutation path %q", path)
			}
			target = typed[index]
		default:
			t.Fatalf("invalid mutation path %q", path)
		}
	}
	leaf := parts[len(parts)-1]
	switch typed := target.(type) {
	case map[string]any:
		typed[leaf] = mutation["value"]
	case []any:
		index, err := strconv.Atoi(leaf)
		if err != nil {
			t.Fatalf("invalid mutation path %q", path)
		}
		typed[index] = mutation["value"]
	default:
		t.Fatalf("invalid mutation path %q", path)
	}
	return changed
}

// The subject fixture packages a freshly built probe binary. The test binary
// itself cannot be the subject because `go test` links test binaries without
// DWARF, and the managed gate requires the DWARF artifact.
var (
	fixtureSubjectOnce  sync.Once
	fixtureSubjectValue *GoSubjectPackage
	fixtureSubjectError error
)

func fixtureSubjectPackage(t *testing.T) *GoSubjectPackage {
	t.Helper()
	fixtureSubjectOnce.Do(func() {
		directory, err := os.MkdirTemp("", "reproit-go-subject-probe-")
		if err != nil {
			fixtureSubjectError = err
			return
		}
		source := "package main\n\nfunc main() { println(\"reproit subject probe\") }\n"
		module := "module reproit.dev/subjectprobe\n\ngo 1.26.0\n"
		if err := os.WriteFile(filepath.Join(directory, "main.go"), []byte(source), 0o600); err != nil {
			fixtureSubjectError = err
			return
		}
		if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte(module), 0o600); err != nil {
			fixtureSubjectError = err
			return
		}
		build := exec.Command("go", "build", "-o", "subjectprobe", ".")
		build.Dir = directory
		if output, err := build.CombinedOutput(); err != nil {
			fixtureSubjectError = err
			_ = output
			return
		}
		fixtureSubjectValue, fixtureSubjectError = PackageRunningGoSubject(
			filepath.Join(directory, "subjectprobe"),
		)
	})
	if fixtureSubjectError != nil {
		t.Fatalf("package fixture subject: %v", fixtureSubjectError)
	}
	return fixtureSubjectValue
}

func emptyWorld() map[string]any {
	return map[string]any{
		"created_at": "2026-01-01T00:00:00.000Z",
		"format":     "reproit.world-checkpoint.v1",
		"points":     []any{},
	}
}

func fixtureBoundDeployment(
	t *testing.T, subject *GoSubjectPackage, workloadSeed []byte, signerKeyID string,
) map[string]any {
	t.Helper()
	binding, err := subjectBinding(subject.Manifest)
	if err != nil {
		t.Fatalf("subject binding: %v", err)
	}
	capabilities := map[string]bool{
		"runtime.go": true,
		subject.Manifest["architecture"].(string):     true,
		subject.Manifest["operating_system"].(string): true,
	}
	names := make([]string, 0, len(capabilities))
	for name := range capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	sorted := make([]any, 0, len(names))
	for _, name := range names {
		sorted = append(sorted, name)
	}
	deployment := map[string]any{
		"format":               "reproit.deployment.v1",
		"organization_id":      fixtureOrganizationID,
		"processing_mode":      "managed",
		"project_id":           fixtureProjectID,
		"repository_id":        "source.example/acme/commerce",
		"runtime_capabilities": sorted,
		"runtime_endpoint":     "https://managed.reproit.example",
		"service_id":           fixtureServiceID,
		"service_path":         "services/orders",
		"signature":            "",
		"signed_at":            "2026-01-01T00:00:00.000Z",
		"signer_key_id":        signerKeyID,
		"source_revision":      "0123456789abcdef",
		"subject":              binding,
	}
	encoded, err := CanonicalBytes(deployment)
	if err != nil {
		t.Fatalf("canonical deployment: %v", err)
	}
	signature, err := signBytes(encoded, workloadSeed)
	if err != nil {
		t.Fatalf("sign deployment: %v", err)
	}
	deployment["signature"] = signature
	return deployment
}

// fixtureCapturedCandidate captures one complete managed candidate through
// the existing SDK.
func fixtureCapturedCandidate(
	t *testing.T, deployment map[string]any, worldID string,
) map[string]any {
	return fixtureCapturedCandidateWithIDs(
		t, deployment, worldID, fixtureCaptureID, fixtureOperationID,
	)
}

func fixtureCapturedCandidateWithIDs(
	t *testing.T, deployment map[string]any, worldID, captureID, operationID string,
) map[string]any {
	t.Helper()
	processResources = newSDKProcessResources()
	vectors := loadProtocolVectors(t)
	sink := &MemorySink{}
	sdk := New(sink)
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
	if len(sink.Candidates) != 1 {
		t.Fatalf("expected one captured candidate, found %d", len(sink.Candidates))
	}
	parsed, err := parseStrictJSON(sink.Candidates[0], MaxOperationBytes)
	if err != nil {
		t.Fatalf("parse captured candidate: %v", err)
	}
	return parsed.(map[string]any)
}

func fixtureSignedCaptureGrant(
	t *testing.T,
	request map[string]any,
	keyReference string,
	notBefore string,
	expiresAt string,
	signerSeed []byte,
) map[string]any {
	t.Helper()
	grant := map[string]any{
		"candidate_identity_digest": request["candidate_identity_digest"],
		"candidate_key_reference":   keyReference,
		"capture_id":                request["capture_id"],
		"cipher_suite":              managedCipherSuite,
		"expires_at":                expiresAt,
		"format":                    captureGrantFormat,
		"grant_id":                  fixtureGrantID,
		"not_before":                notBefore,
		"operation":                 "encrypt-and-upload-candidate",
		"organization_id":           request["organization_id"],
		"processing_mode":           "managed",
		"project_id":                request["project_id"],
		"service_id":                request["service_id"],
		"signature":                 "",
		"signer_key_id":             fixtureCaptureSignerID,
	}
	encoded, err := CanonicalBytes(grant)
	if err != nil {
		t.Fatalf("canonical grant: %v", err)
	}
	signature, err := signBytes(encoded, signerSeed)
	if err != nil {
		t.Fatalf("sign grant: %v", err)
	}
	grant["signature"] = signature
	return grant
}

// grantDeliverySpy records every grant request it receives and issues a
// freshly signed grant.
type grantDeliverySpy struct {
	t            *testing.T
	calls        []map[string]any
	candidateKey []byte
	keyReference string
}

func newGrantDeliverySpy(t *testing.T) *grantDeliverySpy {
	return &grantDeliverySpy{
		t: t, candidateKey: fixtureCandidateKey, keyReference: fixtureKeyReference,
	}
}

func (spy *grantDeliverySpy) RequestEncryptionGrant(
	request map[string]any, timeout time.Duration,
) (EncryptionResponse, error) {
	spy.calls = append(spy.calls, deepCopyMap(spy.t, request))
	grant := fixtureSignedCaptureGrant(
		spy.t, request, spy.keyReference,
		"2026-01-01T00:00:00.000Z", "2026-01-01T00:01:00.000Z", fixtureCaptureSignerSeed,
	)
	return EncryptionResponse{CandidateKey: spy.candidateKey, CaptureGrant: grant}, nil
}

// recordingIngress is an in-memory ingress double that verifies the upload
// session order.
type recordingIngress struct {
	t                 *testing.T
	sequence          []string
	expectedDigests   map[string]bool
	uploadedDigests   map[string]bool
	request           map[string]any
	failObjectUploads bool
	failCommit        bool
}

func newRecordingIngress(t *testing.T) *recordingIngress {
	return &recordingIngress{
		t:               t,
		expectedDigests: make(map[string]bool),
		uploadedDigests: make(map[string]bool),
	}
}

func (ingress *recordingIngress) Start(
	request map[string]any, timeout time.Duration,
) (map[string]any, error) {
	if err := validateUploadRequest(request); err != nil {
		return nil, err
	}
	ingress.sequence = append(ingress.sequence, "start")
	ingress.request = deepCopyMap(ingress.t, request)
	identity := request["ciphertext_identity"].(map[string]any)
	manifestObject := identity["manifest_object"].(map[string]any)
	ingress.expectedDigests = map[string]bool{
		manifestObject["cipher_digest"].(string): true,
	}
	objects, _ := candidateRecords(identity["objects"])
	for _, entry := range objects {
		chunks, _ := candidateRecords(entry["chunks"])
		for _, chunk := range chunks {
			ingress.expectedDigests[chunk["cipher_digest"].(string)] = true
		}
	}
	digests := make([]string, 0, len(ingress.expectedDigests))
	for digest := range ingress.expectedDigests {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	missing := make([]any, 0, len(digests))
	for _, digest := range digests {
		missing = append(missing, map[string]any{
			"cipher_digest": digest,
			"expires_at":    "2026-01-01T00:01:00.000Z",
			"upload_url":    "https://upload.reproit.example/" + digest,
		})
	}
	limits := positiveVector(
		ingress.t, loadCloudAPIVectors(ingress.t), "managed_candidate_limits",
	)
	return map[string]any{
		"expires_at":          "2026-01-01T00:01:00.000Z",
		"limits":              limits,
		"missing_objects":     missing,
		"next_missing_cursor": nil,
		"state":               "OPEN",
		"upload_id":           fixtureUploadID,
		"upload_token":        encodeBase64URL(bytes.Repeat([]byte{0x93}, 32)),
	}, nil
}

func (ingress *recordingIngress) Missing(
	uploadID string, uploadToken string, cursor string, timeout time.Duration,
) (map[string]any, error) {
	ingress.sequence = append(ingress.sequence, "missing")
	return nil, newManagedError("SCHEMA_INVALID", "one bounded page contains this fixture")
}

func (ingress *recordingIngress) UploadObject(
	uploadURL string, digest string, value []byte, timeout time.Duration,
) error {
	ingress.sequence = append(ingress.sequence, "upload_object")
	if ingress.failObjectUploads {
		return newManagedError("SCHEMA_INVALID", "the double rejects this object")
	}
	if digestBytes(value) != digest {
		ingress.t.Error("uploaded bytes do not match their digest")
	}
	if !ingress.expectedDigests[digest] {
		ingress.t.Errorf("unexpected uploaded digest %s", digest)
	}
	ingress.uploadedDigests[digest] = true
	return nil
}

func (ingress *recordingIngress) Commit(
	uploadID string, uploadToken string, timeout time.Duration,
) (map[string]any, error) {
	ingress.sequence = append(ingress.sequence, "commit")
	if ingress.failCommit {
		return nil, newManagedError("SCHEMA_INVALID", "the double rejects this commit")
	}
	if len(ingress.expectedDigests) != len(ingress.uploadedDigests) {
		ingress.t.Error("commit before every expected object was uploaded")
	}
	identity := ingress.request["ciphertext_identity"].(map[string]any)
	return map[string]any{
		"candidate_identity_digest":  identity["candidate_identity_digest"],
		"candidate_key_reference":    identity["candidate_key_reference"],
		"capture_id":                 identity["capture_id"],
		"encrypted_candidate_digest": ingress.request["encrypted_candidate_digest"],
		"state":                      "CLOUD_PROTECTED",
		"upload_id":                  uploadID,
	}, nil
}

func (ingress *recordingIngress) Cancel(
	uploadID string, uploadToken string, timeout time.Duration,
) (map[string]any, error) {
	ingress.sequence = append(ingress.sequence, "cancel")
	return map[string]any{"cancelled": true}, nil
}

func (ingress *recordingIngress) sequenceContains(step string) bool {
	for _, entry := range ingress.sequence {
		if entry == step {
			return true
		}
	}
	return false
}

// openSealedObjectBytes independently decrypts every sealed object and
// verifies plain digests.
func openSealedObjectBytes(
	t *testing.T, sealed *SealedManagedCandidate, candidateKey []byte,
) (map[string][]byte, error) {
	t.Helper()
	identity := sealed.Request()["ciphertext_identity"].(map[string]any)
	captureID := identity["capture_id"].(string)
	recovered := make(map[string][]byte)
	objects, _ := candidateRecords(identity["objects"])
	for _, entry := range objects {
		descriptor := entry["descriptor"].(map[string]any)
		context := objectKeyContext(
			identity, descriptor["object_id"].(string), descriptor["role"].(string),
		)
		objectKey, err := deriveObjectKey(candidateKey, captureID, context)
		if err != nil {
			return nil, err
		}
		contextDigest, err := canonicalDigest(context)
		if err != nil {
			return nil, err
		}
		chunks, _ := candidateRecords(entry["chunks"])
		content := make([]byte, 0)
		for _, chunk := range chunks {
			cipherSize, _ := integerValue(chunk["cipher_size"])
			index, _ := integerValue(chunk["index"])
			chunkContext := chunkKeyContext(
				contextDigest, int64(len(chunks)), index, cipherSize-28,
			)
			chunkKey, err := deriveChunkKey(objectKey, chunkContext)
			if err != nil {
				return nil, err
			}
			stored, err := os.ReadFile(sealed.CiphertextPath(chunk["cipher_digest"].(string)))
			if err != nil {
				return nil, err
			}
			plain, err := decryptChunk(chunkKey, stored, chunkContext)
			if err != nil {
				return nil, err
			}
			content = append(content, plain...)
		}
		if digestBytes(content) != descriptor["plain_digest"] {
			t.Fatal("decrypted object digest mismatch")
		}
		recovered[descriptor["object_id"].(string)] = content
	}
	return recovered, nil
}

func openSealedManifest(
	t *testing.T, sealed *SealedManagedCandidate, candidateKey []byte,
) map[string]any {
	t.Helper()
	identity := sealed.Request()["ciphertext_identity"].(map[string]any)
	manifestObject := identity["manifest_object"].(map[string]any)
	context := objectKeyContext(
		identity, manifestObject["object_id"].(string), "capture-batch-manifest",
	)
	captureID := identity["capture_id"].(string)
	objectKey, err := deriveObjectKey(candidateKey, captureID, context)
	if err != nil {
		t.Fatalf("derive manifest object key: %v", err)
	}
	contextDigest, err := canonicalDigest(context)
	if err != nil {
		t.Fatalf("manifest context digest: %v", err)
	}
	cipherSize, _ := integerValue(manifestObject["cipher_size"])
	chunkContext := chunkKeyContext(contextDigest, 1, 0, cipherSize-28)
	chunkKey, err := deriveChunkKey(objectKey, chunkContext)
	if err != nil {
		t.Fatalf("derive manifest chunk key: %v", err)
	}
	stored, err := os.ReadFile(sealed.CiphertextPath(manifestObject["cipher_digest"].(string)))
	if err != nil {
		t.Fatalf("read sealed manifest: %v", err)
	}
	plain, err := decryptChunk(chunkKey, stored, chunkContext)
	if err != nil {
		t.Fatalf("decrypt sealed manifest: %v", err)
	}
	parsed, err := parseStrictJSON(plain, managedMaxChunkBytes)
	if err != nil {
		t.Fatalf("parse sealed manifest: %v", err)
	}
	return parsed.(map[string]any)
}

func managedErrorCode(t *testing.T, err error) string {
	t.Helper()
	managedError, ok := err.(*ManagedError)
	if !ok {
		t.Fatalf("expected a ManagedError, found %T: %v", err, err)
	}
	return managedError.Code
}
