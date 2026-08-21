// Managed-mode protocol primitives that mirror the Rust reference.
//
// This file is the Go mirror of the reproit-core pieces the managed capture
// client depends on: strict base64url and digest helpers, typed identifier
// validation, Ed25519 signing, the AES-256-GCM + HKDF-SHA-256 candidate
// seal, and the managed candidate schema validators. The Rust implementation
// in crates/reproit-core is normative. Every rule here has a direct
// counterpart there and in sdks/python/reproit_sdk/managed_protocol.py.
package reproit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unicode/utf8"
)

const (
	managedMaxChunkBytes               = 8 * 1024 * 1024
	managedMaxCandidateObjects         = 32_767
	managedMaxCandidatePlaintextBytes  = 1_048_576
	managedMaxCandidateCiphertextBytes = 1_048_604
	managedMaxTotalCiphertextBytes     = 274_878_824_448
	managedMaxStrictJSONDepth          = 512

	managedCipherSuite            = "AES-256-GCM+HKDF-SHA-256"
	captureGrantFormat            = "reproit.managed-candidate-capture-grant.v1"
	candidateIdentityFormat       = "reproit.managed-candidate-identity.v1"
	candidateManifestFormat       = "reproit.managed-candidate-manifest.v1"
	ciphertextIdentityFormat      = "reproit.managed-candidate-ciphertext-identity.v1"
	objectKeyContextFormat        = "reproit.object-key-context.v1"
	chunkKeyContextFormat         = "reproit.chunk-key-context.v1"
	captureBatchFormat            = "reproit.capture-batch.v1"
	timestampLayout               = "2006-01-02T15:04:05.000Z"
	candidateMediaType            = "application/vnd.reproit.candidate.v1+json"
	failureMediaType              = "application/vnd.reproit.failure.v1+json"
	subjectManifestMediaType      = "application/vnd.reproit.subject-closure.v1+json"
	triggerMediaType              = "application/vnd.reproit.trigger.v1+json"
	worldManifestMediaType        = "application/vnd.reproit.world-manifest.v1+json"
	dependencyTranscriptMediaType = "application/vnd.reproit.dependency-transcript.v1+json"
)

var managedRequiredRoles = []string{"candidate", "failure", "subject", "trigger", "world-manifest"}

var managedRoleMediaTypes = [][2]string{
	{"candidate", candidateMediaType},
	{"failure", failureMediaType},
	{"subject", subjectManifestMediaType},
	{"trigger", triggerMediaType},
	{"world-manifest", worldManifestMediaType},
}

var managedLogicalObjectRoles = map[string]bool{
	"admission-proof": true, "candidate": true, "debug-symbols": true,
	"dependency-transcript": true, "failure": true, "replay-capsule-manifest": true,
	"subject": true, "trigger": true, "world-manifest": true, "world-state": true,
}

// managedErrorCodes lists the wire values of reproit_core::ErrorCode. The
// transport rejects a server error whose code is not in this closed set.
var managedErrorCodes = map[string]bool{
	"ADMISSION_PROOF_BINDING": true, "ADMISSION_PROOF_COUNT": true,
	"ASSIGNEE_NOT_AUTHORIZED": true, "ARTIFACT_NOT_FOUND": true,
	"ATTESTATION_REVOKED": true, "ATTESTATION_SCOPE": true,
	"AUTHENTICATION_REQUIRED": true, "AUTHORIZATION_DENIED": true,
	"CAPTURE_ID_CONFLICT": true, "CONFIG_CONFLICT": true,
	"CROSS_TENANT_SCOPE": true, "DECRYPTION_AUTHENTICATION": true,
	"DEPENDENCY_TRANSCRIPT_MISMATCH": true, "DIFFERENT_FAILURE": true,
	"EVALUATION_ERROR": true, "FORBIDDEN": true,
	"INCOMPLETE_CANDIDATE": true, "INCOMPLETE_RECORD_SEQUENCE": true,
	"LIVE_EGRESS_BLOCKED": true, "KEY_PROVIDER_UNAVAILABLE": true,
	"KEY_UNWRAP_FAILED": true, "KEEP_DESTINATION_UNAVAILABLE": true,
	"LEGAL_DELETION_CONFLICT": true, "NONCE_REUSE": true,
	"NOT_FOUND": true, "OBJECT_DIGEST_MISMATCH": true,
	"PRIORITY_INVALID": true, "RATE_LIMITED": true,
	"RUNTIME_QUOTA": true, "SCHEMA_INVALID": true,
	"SERVICE_UNAVAILABLE": true, "SOURCE_ACCESS_DENIED": true,
	"SOURCE_CHECKOUT_FAILED": true, "SOURCE_DEPENDENCY_MISSING": true,
	"SOURCE_REVISION_MISSING": true, "STATE_SCOPE_VIOLATION": true,
	"SUBJECT_DIGEST_MISMATCH": true, "TRIAGE_CONFLICT": true,
	"UNSUPPORTED": true, "UNSUPPORTED_CAPABILITY_SET": true,
	"UPLOAD_EXPIRED": true, "UPLOAD_INCOMPLETE": true,
	"UPLOAD_LIMIT_EXCEEDED": true, "WORLD_NOT_CLOSED": true,
	"WORLD_POINT_EXPIRED": true, "WORLD_PROVIDER_MISSING": true,
}

var managedRetryableCodes = map[string]bool{
	"KEY_PROVIDER_UNAVAILABLE": true, "KEEP_DESTINATION_UNAVAILABLE": true,
	"RATE_LIMITED": true, "RUNTIME_QUOTA": true, "SERVICE_UNAVAILABLE": true,
	"SOURCE_CHECKOUT_FAILED": true, "UPLOAD_EXPIRED": true, "UPLOAD_INCOMPLETE": true,
}

var managedIDPrefixes = map[string]string{
	"capture_id": "cap_", "object_id": "obj_", "operation_id": "op_",
	"organization_id": "org_", "project_id": "prj_", "service_id": "svc_",
	"upload_id": "upl_",
}

// ManagedError reports a managed capture step that failed with a stable
// protocol error code.
type ManagedError struct {
	Code      string
	Message   string
	Retryable bool
}

func (managedError *ManagedError) Error() string {
	return managedError.Message
}

func newManagedError(code, message string) *ManagedError {
	return &ManagedError{Code: code, Message: message, Retryable: managedRetryableCodes[code]}
}

func errSchemaInvalid() *ManagedError {
	return newManagedError("SCHEMA_INVALID", "The value does not satisfy the schema.")
}

func errIncompleteCandidate() *ManagedError {
	return newManagedError(
		"INCOMPLETE_CANDIDATE", "The managed candidate is incomplete and cannot be uploaded.",
	)
}

func errAttestationScope() *ManagedError {
	return newManagedError("ATTESTATION_SCOPE", "The signature is invalid for this attestation.")
}

func errObjectDigestMismatch() *ManagedError {
	return newManagedError(
		"OBJECT_DIGEST_MISMATCH", "The object bytes do not match the bound digest.",
	)
}

func encodeBase64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// decodeBase64URL decodes strict unpadded base64url and rejects
// non-canonical encodings. expectedLength < 0 skips the length check.
func decodeBase64URL(value string, expectedLength int) ([]byte, error) {
	for index := 0; index < len(value); index++ {
		if !isBase64URLByte(value[index]) {
			return nil, errSchemaInvalid()
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, errSchemaInvalid()
	}
	if expectedLength >= 0 && len(decoded) != expectedLength {
		return nil, errSchemaInvalid()
	}
	return decoded, nil
}

func isBase64URLByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' || value == '-' || value == '_'
}

func canonicalDigest(value any) (string, error) {
	encoded, err := CanonicalBytes(value)
	if err != nil {
		return "", errSchemaInvalid()
	}
	return digestBytes(encoded), nil
}

func validTypedID(value any, kind string) bool {
	return validPrefixedUUIDv7(value, managedIDPrefixes[kind])
}

func requireTypedID(value any, kind string) (string, error) {
	text, ok := value.(string)
	if !ok || !validTypedID(text, kind) {
		return "", errSchemaInvalid()
	}
	return text, nil
}

func idUUIDBytes(value, kind string) ([]byte, error) {
	text, err := requireTypedID(value, kind)
	if err != nil {
		return nil, err
	}
	plain := text[len(managedIDPrefixes[kind]):]
	compact := plain[:8] + plain[9:13] + plain[14:18] + plain[19:23] + plain[24:]
	decoded, err := hex.DecodeString(compact)
	if err != nil {
		return nil, errSchemaInvalid()
	}
	return decoded, nil
}

func newObjectID() (string, error) {
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", newManagedError("SERVICE_UNAVAILABLE", "The local random source is unavailable.")
	}
	milliseconds := uint64(time.Now().UnixMilli())
	for index := 0; index < 6; index++ {
		random[index] = byte(milliseconds >> (40 - 8*index))
	}
	random[6] = 0x70 | random[6]&0x0f
	random[8] = 0x80 | random[8]&0x3f
	text := hex.EncodeToString(random[:])
	return fmt.Sprintf(
		"obj_%s-%s-%s-%s-%s", text[:8], text[8:12], text[12:16], text[16:20], text[20:],
	), nil
}

func validOpaqueReference(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) != 43 {
		return false
	}
	_, err := decodeBase64URL(text, 32)
	return err == nil
}

func validTimestamp(value any) bool {
	_, err := parseTimestamp(value)
	return err == nil
}

func parseTimestamp(value any) (time.Time, error) {
	text, ok := value.(string)
	if !ok || len(text) != 24 || text[len(text)-1] != 'Z' {
		return time.Time{}, errSchemaInvalid()
	}
	parsed, err := time.Parse(timestampLayout, text)
	if err != nil {
		return time.Time{}, errSchemaInvalid()
	}
	return parsed, nil
}

func nowTimestamp() string {
	return time.Now().UTC().Format(timestampLayout)
}

// validCapability matches the canonical capability shape:
// ^[a-z][a-z0-9.-]*$ with at most 128 bytes.
func validCapability(value any) bool {
	text, ok := value.(string)
	if !ok || text == "" || len(text) > 128 || text[0] < 'a' || text[0] > 'z' {
		return false
	}
	for index := 1; index < len(text); index++ {
		character := text[index]
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validateCapabilities(value any) error {
	values, ok := anyList(value)
	if !ok || len(values) > 64 {
		return errSchemaInvalid()
	}
	previous := ""
	for index, entry := range values {
		if !validCapability(entry) {
			return errSchemaInvalid()
		}
		text := entry.(string)
		if index > 0 && previous >= text {
			return errSchemaInvalid()
		}
		previous = text
	}
	return nil
}

func signBytes(value, signingKey []byte) (string, error) {
	if len(signingKey) != ed25519.SeedSize {
		return "", errSchemaInvalid()
	}
	privateKey := ed25519.NewKeyFromSeed(signingKey)
	return encodeBase64URL(ed25519.Sign(privateKey, value)), nil
}

func verificationKey(signingKey []byte) ([]byte, error) {
	if len(signingKey) != ed25519.SeedSize {
		return nil, errSchemaInvalid()
	}
	privateKey := ed25519.NewKeyFromSeed(signingKey)
	return bytes.Clone(privateKey.Public().(ed25519.PublicKey)), nil
}

func managedWorkloadKeyID(publicKey []byte) string {
	encoded := encodeBase64URL(publicKey)
	digest := sha256.Sum256([]byte(encoded))
	return "managed-workload-sha256:" + hex.EncodeToString(digest[:])
}

// verifySignedValue verifies the detached Ed25519 signature carried in the
// signature field of a canonical protocol value.
func verifySignedValue(value map[string]any, publicKey []byte) error {
	signatureText, ok := value["signature"].(string)
	if !ok {
		return errSchemaInvalid()
	}
	signature, err := decodeBase64URL(signatureText, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	unsigned := make(map[string]any, len(value))
	for key, entry := range value {
		unsigned[key] = entry
	}
	unsigned["signature"] = ""
	encoded, err := CanonicalBytes(unsigned)
	if err != nil {
		return errSchemaInvalid()
	}
	if len(publicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), encoded, signature) {
		return errAttestationScope()
	}
	return nil
}

// nonceRegistry rejects any nonce reuse within one sealed candidate.
type nonceRegistry struct {
	used map[string]bool
}

func newNonceRegistry() *nonceRegistry {
	return &nonceRegistry{used: make(map[string]bool)}
}

func (registry *nonceRegistry) register(nonce []byte) error {
	key := string(nonce)
	if len(nonce) != 12 || registry.used[key] {
		return newManagedError("NONCE_REUSE", "An occurrence cannot reuse an encryption nonce.")
	}
	registry.used[key] = true
	return nil
}

func objectKeyContext(identity map[string]any, objectID, role string) map[string]any {
	return map[string]any{
		"capture_batch_format": captureBatchFormat,
		"capture_id":           identity["capture_id"],
		"format":               objectKeyContextFormat,
		"object_id":            objectID,
		"organization_id":      identity["organization_id"],
		"processing_mode":      "managed",
		"project_id":           identity["project_id"],
		"role":                 role,
		"service_id":           identity["service_id"],
	}
}

func chunkKeyContext(
	objectContextDigest string, chunkCount, chunkIndex, plainSize int64,
) map[string]any {
	return map[string]any{
		"chunk_count":           chunkCount,
		"chunk_index":           chunkIndex,
		"format":                chunkKeyContextFormat,
		"object_context_digest": objectContextDigest,
		"plain_size":            plainSize,
	}
}

func hkdfExtract(salt, inputKeyMaterial []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(inputKeyMaterial)
	return mac.Sum(nil)
}

// hkdfExpand32 covers the full 32-byte output with one SHA-256 block.
func hkdfExpand32(pseudoRandomKey, info []byte) []byte {
	mac := hmac.New(sha256.New, pseudoRandomKey)
	mac.Write(info)
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

// deriveObjectKey runs HKDF-SHA-256: extract with the capture UUID salt,
// then expand with the canonical object context.
func deriveObjectKey(
	candidateKey []byte, captureID string, objectContext map[string]any,
) ([]byte, error) {
	if len(candidateKey) != 32 || captureID != objectContext["capture_id"] {
		return nil, errSchemaInvalid()
	}
	salt, err := idUUIDBytes(captureID, "capture_id")
	if err != nil {
		return nil, err
	}
	info, err := CanonicalBytes(objectContext)
	if err != nil {
		return nil, errSchemaInvalid()
	}
	return hkdfExpand32(hkdfExtract(salt, candidateKey), info), nil
}

func deriveChunkKey(objectKey []byte, context map[string]any) ([]byte, error) {
	if len(objectKey) != 32 {
		return nil, errSchemaInvalid()
	}
	info, err := CanonicalBytes(context)
	if err != nil {
		return nil, errSchemaInvalid()
	}
	return hkdfExpand32(objectKey, info), nil
}

// encryptChunk seals one chunk with AES-256-GCM using the canonical chunk
// context as associated data. The stored form is nonce || ciphertext || tag.
func encryptChunk(chunkKey, nonce, plaintext []byte, context map[string]any) ([]byte, error) {
	plainSize, plainSizeOK := integerValue(context["plain_size"])
	if len(chunkKey) != 32 || len(nonce) != 12 || len(plaintext) > managedMaxChunkBytes ||
		!plainSizeOK || plainSize != int64(len(plaintext)) {
		return nil, errSchemaInvalid()
	}
	sealer, associatedData, err := chunkSealer(chunkKey, context)
	if err != nil {
		return nil, err
	}
	return sealer.Seal(bytes.Clone(nonce), nonce, plaintext, associatedData), nil
}

func decryptChunk(chunkKey, stored []byte, context map[string]any) ([]byte, error) {
	authenticationFailed := newManagedError(
		"DECRYPTION_AUTHENTICATION", "Ciphertext authentication failed.",
	)
	plainSize, plainSizeOK := integerValue(context["plain_size"])
	if len(chunkKey) != 32 || len(stored) < 28 || len(stored) > managedMaxChunkBytes+28 ||
		!plainSizeOK || plainSize+28 != int64(len(stored)) {
		return nil, authenticationFailed
	}
	sealer, associatedData, err := chunkSealer(chunkKey, context)
	if err != nil {
		return nil, err
	}
	plaintext, err := sealer.Open(nil, stored[:12], stored[12:], associatedData)
	if err != nil {
		return nil, authenticationFailed
	}
	return plaintext, nil
}

func chunkSealer(chunkKey []byte, context map[string]any) (cipher.AEAD, []byte, error) {
	associatedData, err := CanonicalBytes(context)
	if err != nil {
		return nil, nil, errSchemaInvalid()
	}
	block, err := aes.NewCipher(chunkKey)
	if err != nil {
		return nil, nil, errSchemaInvalid()
	}
	sealer, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, errSchemaInvalid()
	}
	return sealer, associatedData, nil
}

func validateLogicalObject(value any) error {
	object, ok := value.(map[string]any)
	if !ok || !hasExactKeys(object, "media_type", "object_id", "plain_digest", "plain_size", "role") {
		return errSchemaInvalid()
	}
	mediaType, mediaTypeOK := object["media_type"].(string)
	plainSize, plainSizeOK := integerValue(object["plain_size"])
	role, roleOK := object["role"].(string)
	if !mediaTypeOK || mediaType == "" || len(mediaType) > 128 ||
		!validTypedID(object["object_id"], "object_id") ||
		!validDigest(object["plain_digest"]) ||
		!plainSizeOK || plainSize < 0 || plainSize > managedMaxTotalCiphertextBytes ||
		!roleOK || !managedLogicalObjectRoles[role] {
		return errSchemaInvalid()
	}
	return nil
}

func requireOneManifest(
	objects []map[string]any, role, mediaType string,
) (map[string]any, error) {
	var match map[string]any
	count := 0
	for _, object := range objects {
		if object["role"] == role && object["media_type"] == mediaType {
			match = object
			count++
		}
	}
	if count != 1 {
		return nil, errSchemaInvalid()
	}
	return match, nil
}

// validateManagedCandidateIdentity mirrors the reproit-core
// ManagedCandidateIdentity::validate rules exactly.
func validateManagedCandidateIdentity(value any) error {
	identity, ok := value.(map[string]any)
	if !ok || !hasExactKeys(identity,
		"candidate_digest", "capture_id", "deployment_digest", "format", "objects",
		"organization_id", "processing_mode", "project_id", "required_capabilities",
		"service_id", "subject_digest", "total_plaintext_bytes",
	) {
		return errSchemaInvalid()
	}
	objects, objectsOK := candidateRecords(identity["objects"])
	if identity["format"] != candidateIdentityFormat ||
		identity["processing_mode"] != "managed" ||
		!validDigest(identity["candidate_digest"]) ||
		!validDigest(identity["deployment_digest"]) ||
		!validDigest(identity["subject_digest"]) ||
		!validTypedID(identity["capture_id"], "capture_id") ||
		!validTypedID(identity["organization_id"], "organization_id") ||
		!validTypedID(identity["project_id"], "project_id") ||
		!validTypedID(identity["service_id"], "service_id") ||
		!objectsOK || len(objects) < 5 || len(objects) > managedMaxCandidateObjects {
		return errSchemaInvalid()
	}
	if err := validateCapabilities(identity["required_capabilities"]); err != nil {
		return err
	}
	totalPlaintextBytes := int64(0)
	roles := make(map[string]bool)
	for index, entry := range objects {
		if err := validateLogicalObject(entry); err != nil {
			return err
		}
		if index > 0 && objects[index-1]["object_id"].(string) >= entry["object_id"].(string) {
			return errSchemaInvalid()
		}
		roles[entry["role"].(string)] = true
		plainSize, _ := integerValue(entry["plain_size"])
		totalPlaintextBytes += plainSize
	}
	for _, role := range managedRequiredRoles {
		if !roles[role] {
			return errSchemaInvalid()
		}
	}
	for _, roleMediaType := range managedRoleMediaTypes {
		if _, err := requireOneManifest(objects, roleMediaType[0], roleMediaType[1]); err != nil {
			return err
		}
	}
	candidate, err := requireOneManifest(objects, "candidate", candidateMediaType)
	if err != nil {
		return err
	}
	subject, err := requireOneManifest(objects, "subject", subjectManifestMediaType)
	if err != nil {
		return err
	}
	candidateSize, _ := integerValue(candidate["plain_size"])
	declaredTotal, declaredTotalOK := integerValue(identity["total_plaintext_bytes"])
	if candidate["plain_digest"] != identity["candidate_digest"] ||
		candidateSize > managedMaxCandidatePlaintextBytes ||
		subject["plain_digest"] != identity["subject_digest"] ||
		!declaredTotalOK || totalPlaintextBytes != declaredTotal ||
		totalPlaintextBytes > managedMaxTotalCiphertextBytes {
		return errSchemaInvalid()
	}
	return nil
}

func validateChunkEntry(value any) error {
	chunk, ok := value.(map[string]any)
	if !ok || !hasExactKeys(chunk, "cipher_digest", "cipher_size", "index", "nonce") {
		return errSchemaInvalid()
	}
	cipherSize, cipherSizeOK := integerValue(chunk["cipher_size"])
	nonce, nonceOK := chunk["nonce"].(string)
	if _, indexOK := integerValue(chunk["index"]); !indexOK ||
		!validDigest(chunk["cipher_digest"]) ||
		!cipherSizeOK || cipherSize < 28 || cipherSize > managedMaxChunkBytes+28 ||
		!nonceOK || len(nonce) != 16 {
		return errSchemaInvalid()
	}
	_, err := decodeBase64URL(nonce, 12)
	return err
}

func validateManifestObject(value any) error {
	object, ok := value.(map[string]any)
	if !ok || !hasExactKeys(object, "cipher_digest", "cipher_size", "nonce", "object_id") {
		return errSchemaInvalid()
	}
	cipherSize, cipherSizeOK := integerValue(object["cipher_size"])
	nonce, nonceOK := object["nonce"].(string)
	if !validDigest(object["cipher_digest"]) ||
		!cipherSizeOK || cipherSize < 28 || cipherSize > managedMaxChunkBytes+28 ||
		!nonceOK || len(nonce) != 16 ||
		!validTypedID(object["object_id"], "object_id") {
		return errSchemaInvalid()
	}
	_, err := decodeBase64URL(nonce, 12)
	return err
}

// validateCiphertextIdentity mirrors the reproit-core
// ManagedCandidateCiphertextIdentity::validate rules exactly.
func validateCiphertextIdentity(value any) error {
	identity, ok := value.(map[string]any)
	if !ok || !hasExactKeys(identity,
		"candidate_identity_digest", "candidate_key_reference", "capture_id",
		"cipher_suite", "format", "manifest_object", "objects", "organization_id",
		"processing_mode", "project_id", "required_capabilities", "service_id",
		"total_ciphertext_bytes",
	) {
		return errSchemaInvalid()
	}
	objects, objectsOK := candidateRecords(identity["objects"])
	capabilities, capabilitiesOK := anyList(identity["required_capabilities"])
	if identity["format"] != ciphertextIdentityFormat ||
		identity["cipher_suite"] != managedCipherSuite ||
		identity["processing_mode"] != "managed" ||
		!validOpaqueReference(identity["candidate_key_reference"]) ||
		!validDigest(identity["candidate_identity_digest"]) ||
		!validTypedID(identity["capture_id"], "capture_id") ||
		!validTypedID(identity["organization_id"], "organization_id") ||
		!validTypedID(identity["project_id"], "project_id") ||
		!validTypedID(identity["service_id"], "service_id") ||
		!objectsOK || len(objects) < 5 || len(objects) > managedMaxCandidateObjects ||
		!capabilitiesOK || len(capabilities) == 0 {
		return errSchemaInvalid()
	}
	if err := validateCapabilities(identity["required_capabilities"]); err != nil {
		return err
	}
	if err := validateManifestObject(identity["manifest_object"]); err != nil {
		return err
	}
	manifestObject := identity["manifest_object"].(map[string]any)
	nonces := map[string]bool{manifestObject["nonce"].(string): true}
	chunkCount := int64(1)
	totalCiphertextBytes, _ := integerValue(manifestObject["cipher_size"])
	roles := make(map[string]bool)
	descriptors := make([]map[string]any, 0, len(objects))
	candidateCiphertextBytes := int64(0)
	candidateEntries := 0
	for index, entry := range objects {
		if !hasExactKeys(entry, "chunks", "descriptor") {
			return errSchemaInvalid()
		}
		if err := validateLogicalObject(entry["descriptor"]); err != nil {
			return err
		}
		descriptor := entry["descriptor"].(map[string]any)
		descriptors = append(descriptors, descriptor)
		if index > 0 {
			previous := objects[index-1]["descriptor"].(map[string]any)
			if previous["object_id"].(string) >= descriptor["object_id"].(string) {
				return errSchemaInvalid()
			}
		}
		chunks, chunksOK := candidateRecords(entry["chunks"])
		if !chunksOK || len(chunks) < 1 || len(chunks) > managedMaxCandidateObjects {
			return errSchemaInvalid()
		}
		roles[descriptor["role"].(string)] = true
		chunkCount += int64(len(chunks))
		objectCiphertextBytes := int64(0)
		for chunkIndex, chunk := range chunks {
			if err := validateChunkEntry(chunk); err != nil {
				return err
			}
			declaredIndex, _ := integerValue(chunk["index"])
			nonce := chunk["nonce"].(string)
			if declaredIndex != int64(chunkIndex) || nonces[nonce] {
				return errSchemaInvalid()
			}
			nonces[nonce] = true
			cipherSize, _ := integerValue(chunk["cipher_size"])
			totalCiphertextBytes += cipherSize
			objectCiphertextBytes += cipherSize
		}
		if descriptor["role"] == "candidate" && descriptor["media_type"] == candidateMediaType {
			candidateEntries++
			candidateCiphertextBytes = objectCiphertextBytes
		}
	}
	for _, role := range managedRequiredRoles {
		if !roles[role] {
			return errSchemaInvalid()
		}
	}
	for _, roleMediaType := range managedRoleMediaTypes {
		if _, err := requireOneManifest(descriptors, roleMediaType[0], roleMediaType[1]); err != nil {
			return err
		}
	}
	declaredTotal, declaredTotalOK := integerValue(identity["total_ciphertext_bytes"])
	if candidateEntries != 1 || chunkCount > 32_768 ||
		!declaredTotalOK || totalCiphertextBytes != declaredTotal ||
		totalCiphertextBytes > managedMaxTotalCiphertextBytes ||
		candidateCiphertextBytes > managedMaxCandidateCiphertextBytes {
		return errSchemaInvalid()
	}
	for _, descriptor := range descriptors {
		if descriptor["object_id"] == manifestObject["object_id"] {
			return errSchemaInvalid()
		}
	}
	return nil
}

// validateCaptureGrant mirrors ManagedCandidateCaptureGrant::validate exactly.
func validateCaptureGrant(value any) error {
	grant, ok := value.(map[string]any)
	if !ok || !hasExactKeys(grant,
		"candidate_identity_digest", "candidate_key_reference", "capture_id",
		"cipher_suite", "expires_at", "format", "grant_id", "not_before", "operation",
		"organization_id", "processing_mode", "project_id", "service_id", "signature",
		"signer_key_id",
	) {
		return errSchemaInvalid()
	}
	signerKeyID, signerKeyIDOK := grant["signer_key_id"].(string)
	signature, signatureOK := grant["signature"].(string)
	notBefore, notBeforeErr := parseTimestamp(grant["not_before"])
	expiresAt, expiresAtErr := parseTimestamp(grant["expires_at"])
	if grant["format"] != captureGrantFormat ||
		grant["cipher_suite"] != managedCipherSuite ||
		grant["operation"] != "encrypt-and-upload-candidate" ||
		grant["processing_mode"] != "managed" ||
		!validOpaqueReference(grant["candidate_key_reference"]) ||
		!validOpaqueReference(grant["grant_id"]) ||
		!validDigest(grant["candidate_identity_digest"]) ||
		!validTypedID(grant["capture_id"], "capture_id") ||
		!validTypedID(grant["organization_id"], "organization_id") ||
		!validTypedID(grant["project_id"], "project_id") ||
		!validTypedID(grant["service_id"], "service_id") ||
		!signerKeyIDOK || signerKeyID == "" || len(signerKeyID) > 256 ||
		!signatureOK || len(signature) != 86 ||
		notBeforeErr != nil || expiresAtErr != nil || !notBefore.Before(expiresAt) {
		return errSchemaInvalid()
	}
	_, err := decodeBase64URL(signature, 64)
	return err
}

// verifyCaptureGrant mirrors verify_managed_candidate_capture_grant exactly.
func verifyCaptureGrant(grant, expected map[string]any, now string, publicKey []byte) error {
	if err := validateCaptureGrant(grant); err != nil {
		return err
	}
	currentTime, err := parseTimestamp(now)
	if err != nil {
		return err
	}
	notBefore, _ := parseTimestamp(grant["not_before"])
	expiresAt, _ := parseTimestamp(grant["expires_at"])
	if grant["candidate_identity_digest"] != expected["candidate_identity_digest"] ||
		grant["candidate_key_reference"] != expected["candidate_key_reference"] ||
		grant["capture_id"] != expected["capture_id"] ||
		grant["organization_id"] != expected["organization_id"] ||
		grant["project_id"] != expected["project_id"] ||
		grant["service_id"] != expected["service_id"] ||
		grant["signer_key_id"] != expected["signer_key_id"] ||
		currentTime.Before(notBefore) || !currentTime.Before(expiresAt) {
		return newManagedError(
			"ATTESTATION_SCOPE",
			"The managed candidate capture grant does not match this capture.",
		)
	}
	return verifySignedValue(grant, publicKey)
}

// validateUploadRequest mirrors ManagedCandidateUploadRequest::validate exactly.
func validateUploadRequest(value any) error {
	request, ok := value.(map[string]any)
	if !ok || !hasExactKeys(request,
		"capture_grant", "ciphertext_identity", "encrypted_candidate_digest",
	) {
		return errSchemaInvalid()
	}
	if err := validateCaptureGrant(request["capture_grant"]); err != nil {
		return err
	}
	if err := validateCiphertextIdentity(request["ciphertext_identity"]); err != nil {
		return err
	}
	grant := request["capture_grant"].(map[string]any)
	identity := request["ciphertext_identity"].(map[string]any)
	if grant["candidate_identity_digest"] != identity["candidate_identity_digest"] ||
		grant["candidate_key_reference"] != identity["candidate_key_reference"] ||
		grant["capture_id"] != identity["capture_id"] ||
		grant["organization_id"] != identity["organization_id"] ||
		grant["project_id"] != identity["project_id"] ||
		grant["service_id"] != identity["service_id"] ||
		grant["processing_mode"] != identity["processing_mode"] ||
		grant["cipher_suite"] != identity["cipher_suite"] {
		return newManagedError(
			"ATTESTATION_SCOPE", "The capture grant does not cover this ciphertext identity.",
		)
	}
	identityDigest, err := canonicalDigest(identity)
	if err != nil {
		return err
	}
	if identityDigest != request["encrypted_candidate_digest"] {
		return errObjectDigestMismatch()
	}
	return nil
}

// parseStrictJSON parses bounded JSON and rejects duplicate keys, non-finite
// numbers, invalid UTF-8, and trailing data.
func parseStrictJSON(value []byte, maximumBytes int) (any, error) {
	if len(value) > maximumBytes || !utf8.Valid(value) {
		return nil, errSchemaInvalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	parsed, err := decodeStrictValue(decoder, 0)
	if err != nil {
		return nil, errSchemaInvalid()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errSchemaInvalid()
	}
	return parsed, nil
}

func decodeStrictValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > managedMaxStrictJSONDepth {
		return nil, errSchemaInvalid()
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errSchemaInvalid()
	}
	return decodeStrictToken(decoder, token, depth)
}

func decodeStrictToken(decoder *json.Decoder, token json.Token, depth int) (any, error) {
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, errSchemaInvalid()
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errSchemaInvalid()
			}
			if _, duplicate := object[key]; duplicate {
				return nil, errSchemaInvalid()
			}
			entry, err := decodeStrictValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = entry
		}
		if _, err := decoder.Token(); err != nil {
			return nil, errSchemaInvalid()
		}
		return object, nil
	case '[':
		values := make([]any, 0)
		for decoder.More() {
			entry, err := decodeStrictValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, entry)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, errSchemaInvalid()
		}
		return values, nil
	default:
		return nil, errSchemaInvalid()
	}
}

func hasExactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, present := value[key]; !present {
			return false
		}
	}
	return true
}

func anyList(value any) ([]any, bool) {
	values, ok := value.([]any)
	return values, ok
}
