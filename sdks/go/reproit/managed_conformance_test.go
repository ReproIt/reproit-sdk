package reproit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCandidateIdentityDigestMatchesTheCanonicalVector(t *testing.T) {
	vectors := loadProtocolVectors(t)
	identity := positiveVector(t, vectors, "managed_candidate_identity")
	if err := validateManagedCandidateIdentity(identity); err != nil {
		t.Fatalf("identity vector rejected: %v", err)
	}
	digest, err := canonicalDigest(identity)
	if err != nil {
		t.Fatalf("identity digest: %v", err)
	}
	if expected := canonicalSHA256(t, vectors, "managed_candidate_identity"); digest != expected {
		t.Fatalf("identity digest %s, expected %s", digest, expected)
	}
}

func TestCiphertextIdentityDigestBindsTheCommitVector(t *testing.T) {
	vectors := loadProtocolVectors(t)
	identity := positiveVector(t, vectors, "managed_candidate_ciphertext_identity")
	if err := validateCiphertextIdentity(identity); err != nil {
		t.Fatalf("ciphertext identity vector rejected: %v", err)
	}
	digest, err := canonicalDigest(identity)
	if err != nil {
		t.Fatalf("ciphertext identity digest: %v", err)
	}
	expected := canonicalSHA256(t, vectors, "managed_candidate_ciphertext_identity")
	if digest != expected {
		t.Fatalf("ciphertext identity digest %s, expected %s", digest, expected)
	}
	commit := positiveVector(t, loadCloudAPIVectors(t), "managed_candidate_commit")
	if digest != commit["encrypted_candidate_digest"] {
		t.Fatal("ciphertext identity digest does not bind the commit vector")
	}
}

func publishedCaptureVerificationKey(t *testing.T, vectors map[string]any) []byte {
	t.Helper()
	keys, keysOK := vectors["verification_keys"].(map[string]any)
	if !keysOK {
		t.Fatal("vectors have no verification_keys section")
	}
	encoded, encodedOK := keys[fixtureCaptureSignerID].(string)
	if !encodedOK {
		t.Fatal("missing managed-candidate-capture-test verification key")
	}
	publicKey, err := decodeBase64URL(encoded, 32)
	if err != nil {
		t.Fatalf("decode verification key: %v", err)
	}
	return publicKey
}

func captureGrantExpectation(grant map[string]any) map[string]any {
	return map[string]any{
		"candidate_identity_digest": grant["candidate_identity_digest"],
		"candidate_key_reference":   grant["candidate_key_reference"],
		"capture_id":                grant["capture_id"],
		"organization_id":           grant["organization_id"],
		"project_id":                grant["project_id"],
		"service_id":                grant["service_id"],
		"signer_key_id":             grant["signer_key_id"],
	}
}

func TestCaptureGrantVerifiesWithThePublishedKey(t *testing.T) {
	vectors := loadProtocolVectors(t)
	grant := positiveVector(t, vectors, "managed_candidate_capture_grant")
	publicKey := publishedCaptureVerificationKey(t, vectors)
	err := verifyCaptureGrant(
		grant, captureGrantExpectation(grant), grantVerificationTime, publicKey,
	)
	if err != nil {
		t.Fatalf("capture grant vector rejected: %v", err)
	}
}

func TestCaptureGrantNegativeVectorsAreRejected(t *testing.T) {
	vectors := loadProtocolVectors(t)
	grant := positiveVector(t, vectors, "managed_candidate_capture_grant")
	publicKey := publishedCaptureVerificationKey(t, vectors)
	expectation := captureGrantExpectation(grant)
	negatives, _ := anyList(vectors["negative"])
	mutations := make([]map[string]any, 0)
	for _, entry := range negatives {
		mutation, mutationOK := entry.(map[string]any)
		if mutationOK && mutation["base"] == "managed_candidate_capture_grant" {
			mutations = append(mutations, mutation)
		}
	}
	if len(mutations) != 3 {
		t.Fatalf("expected 3 capture-grant mutations, found %d", len(mutations))
	}
	for _, mutation := range mutations {
		changed := applyMutation(t, grant, mutation)
		err := verifyCaptureGrant(changed, expectation, grantVerificationTime, publicKey)
		if err == nil {
			t.Fatalf("mutation %v was accepted", mutation["name"])
		}
		if code := managedErrorCode(t, err); code != mutation["expected"] {
			t.Fatalf(
				"mutation %v rejected with %s, expected %v",
				mutation["name"], code, mutation["expected"],
			)
		}
	}
}

func TestUploadRequestVectorValidates(t *testing.T) {
	request := positiveVector(t, loadCloudAPIVectors(t), "managed_candidate_upload_request")
	if err := validateUploadRequest(request); err != nil {
		t.Fatalf("upload request vector rejected: %v", err)
	}
}

func TestUploadRequestKeyReferenceMutationIsRejected(t *testing.T) {
	vectors := loadCloudAPIVectors(t)
	request := positiveVector(t, vectors, "managed_candidate_upload_request")
	negatives, _ := anyList(vectors["negative"])
	var mutation map[string]any
	for _, entry := range negatives {
		candidate, candidateOK := entry.(map[string]any)
		if candidateOK &&
			candidate["name"] == "managed-candidate-key-reference-differs-from-capture-grant" {
			mutation = candidate
			break
		}
	}
	if mutation == nil {
		t.Fatal("missing key-reference negative vector")
	}
	changed := applyMutation(t, request, mutation)
	err := validateUploadRequest(changed)
	if err == nil {
		t.Fatal("mutated upload request was accepted")
	}
	if code := managedErrorCode(t, err); code != "ATTESTATION_SCOPE" {
		t.Fatalf("mutated upload request rejected with %s, expected ATTESTATION_SCOPE", code)
	}
}

func TestEncryptionResponseVectorDecodes(t *testing.T) {
	vectors := loadCloudAPIVectors(t)
	response := positiveVector(t, vectors, "managed_candidate_encryption_response")
	if !hasExactKeys(response, "candidate_key", "capture_grant") {
		t.Fatal("encryption response vector has unexpected keys")
	}
	candidateKey, err := decodeBase64URL(response["candidate_key"].(string), 32)
	if err != nil || len(candidateKey) != 32 {
		t.Fatalf("candidate key decode: %v", err)
	}
	if err := validateCaptureGrant(response["capture_grant"]); err != nil {
		t.Fatalf("capture grant in encryption response rejected: %v", err)
	}
	grantRequest := positiveVector(t, vectors, "managed_candidate_encryption_grant_request")
	grant := response["capture_grant"].(map[string]any)
	if grantRequest["candidate_identity_digest"] != grant["candidate_identity_digest"] {
		t.Fatal("encryption response grant does not bind the grant request")
	}
}

func TestSignedWorkloadRegistrationVectorValidates(t *testing.T) {
	vectors := loadCloudAPIVectors(t)
	registration := positiveVector(t, vectors, "workload_key_registration")
	if err := validateWorkloadKeyRegistration(registration); err != nil {
		t.Fatalf("workload registration vector rejected: %v", err)
	}
	publicKey, err := decodeBase64URL(registration["public_key"].(string), 32)
	if err != nil {
		t.Fatalf("decode workload public key: %v", err)
	}
	deployment := registration["deployment"].(map[string]any)
	if deployment["signer_key_id"] != managedWorkloadKeyID(publicKey) {
		t.Fatal("the workload key identity does not match the canonical public key")
	}
	result := positiveVector(t, vectors, "workload_key_registration_result")
	deploymentDigest, err := canonicalDigest(deployment)
	if err != nil {
		t.Fatalf("deployment digest: %v", err)
	}
	if result["deployment_digest"] != deploymentDigest ||
		result["key_id"] != deployment["signer_key_id"] {
		t.Fatal("the registration result does not bind the signed Deployment")
	}
}

func TestSignedGrantRequestVectorValidates(t *testing.T) {
	vectors := loadCloudAPIVectors(t)
	request := positiveVector(t, vectors, "managed_candidate_encryption_grant_request")
	if err := validateGrantRequest(request); err != nil {
		t.Fatalf("signed grant request vector rejected: %v", err)
	}
	registration := positiveVector(t, vectors, "workload_key_registration")
	publicKey, err := decodeBase64URL(registration["public_key"].(string), 32)
	if err != nil {
		t.Fatalf("decode workload public key: %v", err)
	}
	if err := verifySignedValue(request, publicKey); err != nil {
		t.Fatalf("verify signed grant request: %v", err)
	}
	result := positiveVector(t, vectors, "workload_key_registration_result")
	if request["deployment_digest"] != result["deployment_digest"] ||
		request["signer_key_id"] != result["key_id"] {
		t.Fatal("the signed grant request does not bind the registered Deployment")
	}
}

func TestKeyContextVectorsMatchCanonicalDigests(t *testing.T) {
	vectors := loadProtocolVectors(t)
	for _, name := range []string{"object_key_context", "chunk_key_context"} {
		value := positiveVector(t, vectors, name)
		digest, err := canonicalDigest(value)
		if err != nil {
			t.Fatalf("%s digest: %v", name, err)
		}
		if expected := canonicalSHA256(t, vectors, name); digest != expected {
			t.Fatalf("%s digest %s, expected %s", name, digest, expected)
		}
	}
}

func TestSigningMatchesTheRustReferenceSignature(t *testing.T) {
	// The vector grant was signed by reproit-core with the test seed
	// 0x83 * 32. Deterministic Ed25519 over identical canonical bytes must
	// reproduce the exact signature.
	vectors := loadProtocolVectors(t)
	grant := positiveVector(t, vectors, "managed_candidate_capture_grant")
	publicKey, err := verificationKey(fixtureCaptureSignerSeed)
	if err != nil {
		t.Fatalf("verification key: %v", err)
	}
	published := publishedCaptureVerificationKey(t, vectors)
	if !bytes.Equal(publicKey, published) {
		t.Fatal("test seed does not reproduce the published verification key")
	}
	unsigned := deepCopyMap(t, grant)
	unsigned["signature"] = ""
	encoded, err := CanonicalBytes(unsigned)
	if err != nil {
		t.Fatalf("canonical unsigned grant: %v", err)
	}
	signature, err := signBytes(encoded, fixtureCaptureSignerSeed)
	if err != nil {
		t.Fatalf("sign grant: %v", err)
	}
	if signature != grant["signature"] {
		t.Fatal("deterministic signature does not match the reference vector")
	}
}

func TestSealMatchesTheRustReferenceCiphertext(t *testing.T) {
	// Pinned cross-implementation vector. The expected bytes were produced
	// by reproit-core (derive_object_key, derive_chunk_key, encrypt_chunk)
	// with these exact inputs, and the same constants are pinned in
	// sdks/python/tests/test_managed_conformance.py, so this test proves the
	// HKDF-SHA-256 and AES-256-GCM AAD contract byte for byte across the
	// Rust, Python, and Go implementations.
	context := map[string]any{
		"capture_batch_format": "reproit.capture-batch.v1",
		"capture_id":           "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc",
		"format":               "reproit.object-key-context.v1",
		"object_id":            "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4",
		"organization_id":      "org_01890f3e-7b1c-7cc0-8a1b-123456789abd",
		"processing_mode":      "managed",
		"project_id":           "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe",
		"role":                 "trigger",
		"service_id":           "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf",
	}
	candidateKey := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("cross-language managed seal vector")
	objectKey, err := deriveObjectKey(candidateKey, context["capture_id"].(string), context)
	if err != nil {
		t.Fatalf("derive object key: %v", err)
	}
	contextDigest, err := canonicalDigest(context)
	if err != nil {
		t.Fatalf("context digest: %v", err)
	}
	if contextDigest !=
		"sha256:06e6fa3d4a4185d0eff5cd92e01ed2d5aa3dc873f5b5cdead8313556855afa84" {
		t.Fatalf("object context digest drifted: %s", contextDigest)
	}
	chunkContext := chunkKeyContext(contextDigest, 1, 0, int64(len(plaintext)))
	chunkKey, err := deriveChunkKey(objectKey, chunkContext)
	if err != nil {
		t.Fatalf("derive chunk key: %v", err)
	}
	stored, err := encryptChunk(chunkKey, bytes.Repeat([]byte{0x07}, 12), plaintext, chunkContext)
	if err != nil {
		t.Fatalf("encrypt chunk: %v", err)
	}
	expected := "0707070707070707070707076feaeb515f76709f385b2542dff02ead97170a34" +
		"b32eba411bf935a7e778ce0dbb1b49d747d17d71f9b507a035d4647f312f"
	if hex.EncodeToString(stored) != expected {
		t.Fatalf("sealed bytes drifted: %s", hex.EncodeToString(stored))
	}
	recovered, err := decryptChunk(chunkKey, stored, chunkContext)
	if err != nil || !bytes.Equal(recovered, plaintext) {
		t.Fatalf("decrypt round trip failed: %v", err)
	}
}

func TestManagedCandidateManifestVectorBindsItsIdentity(t *testing.T) {
	vectors := loadProtocolVectors(t)
	manifest := positiveVector(t, vectors, "managed_candidate_manifest")
	if err := validateManagedCandidateIdentity(manifest["candidate_identity"]); err != nil {
		t.Fatalf("manifest candidate identity rejected: %v", err)
	}
	identityDigest, err := canonicalDigest(manifest["candidate_identity"])
	if err != nil {
		t.Fatalf("manifest identity digest: %v", err)
	}
	if identityDigest != manifest["candidate_identity_digest"] {
		t.Fatal("manifest does not bind its candidate identity digest")
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	expected := canonicalSHA256(t, vectors, "managed_candidate_manifest")
	if manifestDigest != expected {
		t.Fatalf("manifest digest %s, expected %s", manifestDigest, expected)
	}
}

func TestManagedCommitTimeoutScalesWithTheDeclaredClosure(t *testing.T) {
	if managedCommitTimeout(0) != commitTimeoutFloor {
		t.Fatal("empty closure must use the floor timeout")
	}
	if managedCommitTimeout(1) != commitTimeoutFloor+time.Second {
		t.Fatal("one byte must round up to one verification second")
	}
	if managedCommitTimeout(commitVerificationBytesPerSecond) != commitTimeoutFloor+time.Second {
		t.Fatal("one rate unit must cost one verification second")
	}
	if managedCommitTimeout(512*1024*1024) != commitTimeoutFloor+128*time.Second {
		t.Fatal("512 MiB must cost 128 verification seconds")
	}
	if managedCommitTimeout(managedMaxTotalCiphertextBytes) != commitTimeoutCap {
		t.Fatal("the maximum closure must be capped")
	}
}

func TestWorkloadKeyFileRoundTripAndRejections(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "workload.key")
	key, err := LoadOrCreateManagedWorkloadKey(path)
	if err != nil {
		t.Fatalf("create workload key: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("workload key has %d bytes", len(key))
	}
	metadata, err := os.Lstat(path)
	if err != nil || metadata.Mode().Perm() != 0o600 {
		t.Fatalf("workload key mode %v, expected 0600", metadata.Mode().Perm())
	}
	reloaded, err := LoadOrCreateManagedWorkloadKey(path)
	if err != nil || !bytes.Equal(reloaded, key) {
		t.Fatalf("reload workload key: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateManagedWorkloadKey(path); managedErrorCode(t, err) != "CONFIG_CONFLICT" {
		t.Fatal("world-readable key file must be rejected as CONFIG_CONFLICT")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	linked := filepath.Join(directory, "linked.key")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	_, linkedErr := LoadOrCreateManagedWorkloadKey(linked)
	if managedErrorCode(t, linkedErr) != "CONFIG_CONFLICT" {
		t.Fatal("symlinked key file must be rejected as CONFIG_CONFLICT")
	}

	short := filepath.Join(directory, "short.key")
	if err := os.WriteFile(short, bytes.Repeat([]byte{0x00}, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateManagedWorkloadKey(short); managedErrorCode(t, err) != "CONFIG_CONFLICT" {
		t.Fatal("wrong-size key file must be rejected as CONFIG_CONFLICT")
	}

	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(directory, 0o700) }()
	if _, err := LoadOrCreateManagedWorkloadKey(path); managedErrorCode(t, err) != "CONFIG_CONFLICT" {
		t.Fatal("group-writable parent must be rejected as CONFIG_CONFLICT")
	}
}

func TestRunningSubjectIsCompleteAndContentAddressed(t *testing.T) {
	subject := fixtureSubjectPackage(t)
	manifest := subject.Manifest
	if manifest["runtime_family"] != "go" ||
		manifest["format"] != "reproit.subject-closure.v1" {
		t.Fatal("subject manifest identity is wrong")
	}
	debugArtifacts, _ := candidateRecords(manifest["debug_artifacts"])
	if len(debugArtifacts) != 1 || debugArtifacts[0]["kind"] != "dwarf" {
		t.Fatal("subject manifest must carry the executable DWARF artifact")
	}
	launch := manifest["launch"].(map[string]any)
	files, _ := candidateRecords(manifest["files"])
	executableListed := false
	for _, file := range files {
		if file["path"] == launch["executable"] && file["executable"] == true {
			executableListed = true
		}
	}
	if !executableListed {
		t.Fatal("launch executable is not an executable subject file")
	}
	for _, packaged := range subject.Objects {
		content, err := os.ReadFile(packaged.Path)
		if err != nil {
			t.Fatalf("read packaged object: %v", err)
		}
		if digestBytes(content) != packaged.Digest || int64(len(content)) != packaged.Size {
			t.Fatal("packaged subject object is not content addressed")
		}
	}
	binding, err := subjectBinding(manifest)
	if err != nil {
		t.Fatalf("subject binding: %v", err)
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	if binding["artifact_digest"] != manifestDigest ||
		binding["executable"] != launch["executable"] ||
		binding["operating_system"] != manifest["operating_system"] {
		t.Fatal("subject binding does not match the manifest")
	}
}

type managedSealFixture struct {
	subject    *GoSubjectPackage
	world      map[string]any
	worldID    string
	deployment map[string]any
	candidate  map[string]any
}

func newManagedSealFixture(t *testing.T) *managedSealFixture {
	t.Helper()
	subject := fixtureSubjectPackage(t)
	world := emptyWorld()
	worldID, err := canonicalDigest(world)
	if err != nil {
		t.Fatalf("world digest: %v", err)
	}
	deployment := fixtureBoundDeployment(t, subject, fixtureWorkloadSeed, fixtureWorkloadKeyID)
	candidate := fixtureCapturedCandidate(t, deployment, worldID)
	return &managedSealFixture{
		subject: subject, world: world, worldID: worldID,
		deployment: deployment, candidate: candidate,
	}
}

func (fixture *managedSealFixture) closure(t *testing.T) *FrozenManagedCaptureClosure {
	t.Helper()
	frozen, err := FreezeManagedCaptureClosure(ManagedCaptureClosure{
		Artifacts: nil, Completion: "return", World: deepCopyMap(t, fixture.world),
	})
	if err != nil {
		t.Fatalf("freeze closure: %v", err)
	}
	return frozen
}

func (fixture *managedSealFixture) prepared(t *testing.T) *PreparedManagedCandidate {
	t.Helper()
	prepared, err := PrepareCompleteManagedCandidate(
		deepCopyMap(t, fixture.candidate), fixture.subject, fixture.closure(t),
	)
	if err != nil {
		t.Fatalf("prepare complete candidate: %v", err)
	}
	return prepared
}

func (fixture *managedSealFixture) sealed(t *testing.T) *SealedManagedCandidate {
	t.Helper()
	delivery := newGrantDeliverySpy(t)
	prepared := fixture.prepared(t)
	response, err := prepared.RequestEncryptionGrant(
		delivery, fixtureWorkloadKeyID, fixtureWorkloadSeed,
	)
	if err != nil {
		t.Fatalf("request encryption grant: %v", err)
	}
	publicKey, err := verificationKey(fixtureCaptureSignerSeed)
	if err != nil {
		t.Fatalf("verification key: %v", err)
	}
	sealed, err := prepared.Seal(response, grantVerificationTime, fixtureCaptureSignerID, publicKey)
	if err != nil {
		t.Fatalf("seal candidate: %v", err)
	}
	t.Cleanup(sealed.Close)
	return sealed
}

func TestKeyRequestOccursOnlyAfterExactLocalClosure(t *testing.T) {
	fixture := newManagedSealFixture(t)
	delivery := newGrantDeliverySpy(t)
	incomplete := deepCopyMap(t, fixture.candidate)
	incomplete["world_id"] = "sha256:" + strings.Repeat("a", 64)
	_, err := PrepareCompleteManagedCandidate(incomplete, fixture.subject, fixture.closure(t))
	if err == nil {
		t.Fatal("incomplete candidate was prepared")
	}
	if code := managedErrorCode(t, err); code != "INCOMPLETE_CANDIDATE" {
		t.Fatalf("incomplete candidate rejected with %s", code)
	}
	if len(delivery.calls) != 0 {
		t.Fatal("an incomplete candidate must make zero network calls")
	}

	prepared := fixture.prepared(t)
	if _, err := prepared.RequestEncryptionGrant(
		delivery, fixtureWorkloadKeyID, fixtureWorkloadSeed,
	); err != nil {
		t.Fatalf("request encryption grant: %v", err)
	}
	if len(delivery.calls) != 1 {
		t.Fatalf("expected exactly one grant call, found %d", len(delivery.calls))
	}
	identityDigest, err := canonicalDigest(prepared.Identity())
	if err != nil {
		t.Fatalf("identity digest: %v", err)
	}
	if delivery.calls[0]["candidate_identity_digest"] != identityDigest ||
		delivery.calls[0]["processing_mode"] != "managed" {
		t.Fatal("the grant request does not bind the exact local identity")
	}
}

func TestIncompleteRecordSequenceStopsBeforeAnyRequest(t *testing.T) {
	fixture := newManagedSealFixture(t)
	delivery := newGrantDeliverySpy(t)
	incomplete := deepCopyMap(t, fixture.candidate)
	records, _ := anyList(incomplete["records"])
	incomplete["records"] = records[:len(records)-1]
	_, err := PrepareCompleteManagedCandidate(incomplete, fixture.subject, fixture.closure(t))
	if err == nil {
		t.Fatal("truncated record sequence was prepared")
	}
	if code := managedErrorCode(t, err); code != "INCOMPLETE_CANDIDATE" {
		t.Fatalf("truncated record sequence rejected with %s", code)
	}
	if len(delivery.calls) != 0 {
		t.Fatal("a truncated candidate must make zero network calls")
	}
}

func TestSealRoundTripAndKeySecrecy(t *testing.T) {
	fixture := newManagedSealFixture(t)
	sealed := fixture.sealed(t)
	for _, digest := range sealed.CiphertextDigests() {
		stored, err := os.ReadFile(sealed.CiphertextPath(digest))
		if err != nil || digestBytes(stored) != digest {
			t.Fatalf("spooled ciphertext does not match its digest: %v", err)
		}
	}
	recovered, err := openSealedObjectBytes(t, sealed, fixtureCandidateKey)
	if err != nil {
		t.Fatalf("open sealed objects: %v", err)
	}
	identity := sealed.Request()["ciphertext_identity"].(map[string]any)
	objects, _ := candidateRecords(identity["objects"])
	candidateObjectID := ""
	for _, entry := range objects {
		descriptor := entry["descriptor"].(map[string]any)
		if descriptor["media_type"] == candidateMediaType {
			candidateObjectID = descriptor["object_id"].(string)
		}
	}
	candidateBytes, err := CanonicalBytes(fixture.candidate)
	if err != nil {
		t.Fatalf("canonical candidate: %v", err)
	}
	if !bytes.Equal(recovered[candidateObjectID], candidateBytes) {
		t.Fatal("the sealed candidate object does not decrypt to the candidate")
	}
	manifest := openSealedManifest(t, sealed, fixtureCandidateKey)
	if manifest["candidate_identity_digest"] != identity["candidate_identity_digest"] ||
		manifest["candidate_key_reference"] != identity["candidate_key_reference"] {
		t.Fatal("the sealed manifest does not bind the ciphertext identity")
	}
	requestBytes, err := CanonicalBytes(sealed.Request())
	if err != nil {
		t.Fatalf("canonical request: %v", err)
	}
	if bytes.Contains(requestBytes, []byte(encodeBase64URL(fixtureCandidateKey))) {
		t.Fatal("the candidate key leaked into the upload request")
	}
	if _, err := openSealedObjectBytes(t, sealed, bytes.Repeat([]byte{0x43}, 32)); err == nil {
		t.Fatal("a wrong candidate key must not decrypt the sealed objects")
	}
}

func TestSealRejectsIdentityDigestMismatch(t *testing.T) {
	fixture := newManagedSealFixture(t)
	prepared := fixture.prepared(t)
	delivery := newGrantDeliverySpy(t)
	if _, err := prepared.RequestEncryptionGrant(
		delivery, fixtureWorkloadKeyID, fixtureWorkloadSeed,
	); err != nil {
		t.Fatalf("request encryption grant: %v", err)
	}
	tamperedRequest := deepCopyMap(t, delivery.calls[0])
	tamperedRequest["candidate_identity_digest"] = "sha256:" + strings.Repeat("9", 64)
	tampered := newGrantDeliverySpy(t)
	tamperedResponse, err := tampered.RequestEncryptionGrant(tamperedRequest, grantTimeout)
	if err != nil {
		t.Fatalf("tampered grant request: %v", err)
	}
	publicKey, err := verificationKey(fixtureCaptureSignerSeed)
	if err != nil {
		t.Fatalf("verification key: %v", err)
	}
	_, err = prepared.Seal(
		tamperedResponse, grantVerificationTime, fixtureCaptureSignerID, publicKey,
	)
	if err == nil {
		t.Fatal("a grant for a different identity digest was accepted")
	}
	if code := managedErrorCode(t, err); code != "ATTESTATION_SCOPE" {
		t.Fatalf("identity digest mismatch rejected with %s", code)
	}
}

func TestRenewalCannotRotateKeyOrReference(t *testing.T) {
	fixture := newManagedSealFixture(t)
	sealed := fixture.sealed(t)
	ingress := newRecordingIngress(t)
	publicKey, err := verificationKey(fixtureCaptureSignerSeed)
	if err != nil {
		t.Fatalf("verification key: %v", err)
	}

	rotatedKey := newGrantDeliverySpy(t)
	rotatedKey.candidateKey = bytes.Repeat([]byte{0x43}, 32)
	renewal, err := sealed.RequestCaptureGrantRenewal(
		rotatedKey, fixtureWorkloadKeyID, fixtureWorkloadSeed,
	)
	if err != nil {
		t.Fatalf("request renewal: %v", err)
	}
	err = sealed.ApplyRenewedCaptureGrant(
		renewal, grantVerificationTime, fixtureCaptureSignerID, publicKey,
	)
	if code := managedErrorCode(t, err); code != "CAPTURE_ID_CONFLICT" {
		t.Fatalf("rotated candidate key rejected with %s", code)
	}

	rotatedReference := newGrantDeliverySpy(t)
	rotatedReference.keyReference = encodeBase64URL(bytes.Repeat([]byte{0x96}, 32))
	renewal, err = sealed.RequestCaptureGrantRenewal(
		rotatedReference, fixtureWorkloadKeyID, fixtureWorkloadSeed,
	)
	if err != nil {
		t.Fatalf("request renewal: %v", err)
	}
	err = sealed.ApplyRenewedCaptureGrant(
		renewal, grantVerificationTime, fixtureCaptureSignerID, publicKey,
	)
	if code := managedErrorCode(t, err); code != "CAPTURE_ID_CONFLICT" {
		t.Fatalf("rotated key reference rejected with %s", code)
	}
	if len(ingress.sequence) != 0 {
		t.Fatal("a rejected renewal must not reach the ingress")
	}
}

func TestValidRenewalIsAccepted(t *testing.T) {
	fixture := newManagedSealFixture(t)
	sealed := fixture.sealed(t)
	renewal, err := sealed.RequestCaptureGrantRenewal(
		newGrantDeliverySpy(t), fixtureWorkloadKeyID, fixtureWorkloadSeed,
	)
	if err != nil {
		t.Fatalf("request renewal: %v", err)
	}
	publicKey, err := verificationKey(fixtureCaptureSignerSeed)
	if err != nil {
		t.Fatalf("verification key: %v", err)
	}
	err = sealed.ApplyRenewedCaptureGrant(
		renewal, grantVerificationTime, fixtureCaptureSignerID, publicKey,
	)
	if err != nil {
		t.Fatalf("valid renewal rejected: %v", err)
	}
	if err := validateUploadRequest(sealed.Request()); err != nil {
		t.Fatalf("renewed upload request invalid: %v", err)
	}
}

func TestUploadSessionSuccess(t *testing.T) {
	fixture := newManagedSealFixture(t)
	sealed := fixture.sealed(t)
	ingress := newRecordingIngress(t)
	commit, err := sealed.Upload(ingress)
	if err != nil {
		t.Fatalf("upload session: %v", err)
	}
	if commit["state"] != "CLOUD_PROTECTED" {
		t.Fatalf("commit state %v", commit["state"])
	}
	expected := sealed.CiphertextDigests()
	if len(ingress.uploadedDigests) != len(expected) {
		t.Fatalf(
			"uploaded %d objects, expected %d", len(ingress.uploadedDigests), len(expected),
		)
	}
	for _, digest := range expected {
		if !ingress.uploadedDigests[digest] {
			t.Fatalf("digest %s was never uploaded", digest)
		}
	}
	if ingress.sequence[0] != "start" || ingress.sequence[len(ingress.sequence)-1] != "commit" {
		t.Fatalf("upload sequence %v", ingress.sequence)
	}
	uploads := 0
	for _, step := range ingress.sequence {
		if step == "upload_object" {
			uploads++
		}
	}
	if uploads != len(expected) || ingress.sequenceContains("cancel") {
		t.Fatalf("upload sequence %v", ingress.sequence)
	}
}

func TestUploadCancelsOnFailure(t *testing.T) {
	fixture := newManagedSealFixture(t)
	sealed := fixture.sealed(t)

	failingUploads := newRecordingIngress(t)
	failingUploads.failObjectUploads = true
	if _, err := sealed.Upload(failingUploads); err == nil {
		t.Fatal("a failing object upload must fail the session")
	}
	if !failingUploads.sequenceContains("cancel") || failingUploads.sequenceContains("commit") {
		t.Fatalf("failing upload sequence %v", failingUploads.sequence)
	}

	failingCommit := newRecordingIngress(t)
	failingCommit.failCommit = true
	if _, err := sealed.Upload(failingCommit); err == nil {
		t.Fatal("a failing commit must fail the session")
	}
	if failingCommit.sequence[len(failingCommit.sequence)-1] != "cancel" {
		t.Fatalf("failing commit sequence %v", failingCommit.sequence)
	}
}

func TestProjectTokenRules(t *testing.T) {
	if _, err := NewManagedProjectToken("a-valid-token"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	invalid := []string{"", "with space", "control\x01", strings.Repeat("x", 1_025)}
	for _, value := range invalid {
		if _, err := NewManagedProjectToken(value); err == nil {
			t.Fatalf("invalid token %q accepted", value)
		}
	}
}

var fixtureCAPath string

func selfSignedCAPath(t *testing.T) string {
	t.Helper()
	if fixtureCAPath != "" {
		if _, err := os.Lstat(fixtureCAPath); err == nil {
			return fixtureCAPath
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "reproit-managed-test-ca"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	directory, err := os.MkdirTemp("", "reproit-managed-ca-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	fixtureCAPath = path
	return path
}

func TestEndpointRequiresAValidCA(t *testing.T) {
	valid := selfSignedCAPath(t)
	_, err := NewManagedTlsEndpoint(
		"127.0.0.1", 443, "managed.reproit.example", "managed.reproit.example", valid,
	)
	if err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}

	directory := t.TempDir()
	empty := filepath.Join(directory, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(directory, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(directory, "linked.pem")
	if err := os.Symlink(valid, linked); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(directory, "absent.pem")
	for _, path := range []string{empty, garbage, linked, absent} {
		if _, err := NewManagedTlsEndpoint("127.0.0.1", 443, "example", "example", path); err == nil {
			t.Fatalf("invalid CA file %s accepted", path)
		}
	}
}

func TestEndpointRejectsInvalidAuthority(t *testing.T) {
	valid := selfSignedCAPath(t)
	invalid := []string{"", "bad/authority", "user@host", "with space", strings.Repeat("x", 513)}
	for _, authority := range invalid {
		if _, err := NewManagedTlsEndpoint("127.0.0.1", 443, "example", authority, valid); err == nil {
			t.Fatalf("invalid authority %q accepted", authority)
		}
	}
}

func TestResponseReaderRejectsInvalidResponses(t *testing.T) {
	cases := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n"),
		[]byte("garbage without terminator"),
	}
	for index, raw := range cases {
		if _, err := readManagedResponse(bytes.NewReader(raw)); err == nil {
			t.Fatalf("invalid response %d accepted", index)
		}
	}
}

func TestResponseReaderAcceptsABoundedBody(t *testing.T) {
	raw := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	response, err := readManagedResponse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("bounded response rejected: %v", err)
	}
	if response.status != 204 || len(response.body) != 0 {
		t.Fatalf("bounded response decoded as %d with %d body bytes", response.status, len(response.body))
	}
}
