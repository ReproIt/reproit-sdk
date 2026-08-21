// Managed candidate sealing and the bounded upload session.
//
// Split from managed_candidate.go to keep both files under the 1,000-line
// bound. Mirrors the seal and upload half of
// crates/reproit-sdk-rust/src/managed.rs, including the size-scaled bounded
// commit timeout.
package reproit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func (prepared *PreparedManagedCandidate) Seal(
	response EncryptionResponse,
	now string,
	captureSignerID string,
	captureSignerPublicKey []byte,
) (*SealedManagedCandidate, error) {
	identityDigest, err := canonicalDigest(prepared.identity)
	if err != nil {
		return nil, err
	}
	keyReference, _ := response.CaptureGrant["candidate_key_reference"].(string)
	err = verifyCaptureGrant(
		response.CaptureGrant,
		map[string]any{
			"candidate_identity_digest": identityDigest,
			"candidate_key_reference":   keyReference,
			"capture_id":                prepared.identity["capture_id"],
			"organization_id":           prepared.identity["organization_id"],
			"project_id":                prepared.identity["project_id"],
			"service_id":                prepared.identity["service_id"],
			"signer_key_id":             captureSignerID,
		},
		now,
		captureSignerPublicKey,
	)
	if err != nil {
		return nil, err
	}
	if err := verifyLocalClosure(prepared.objects); err != nil {
		return nil, err
	}

	spool, err := os.MkdirTemp("", "reproit-managed-candidate-")
	if err != nil {
		return nil, errManagedLocalStorage()
	}
	sealed, err := prepared.sealInto(response, identityDigest, keyReference, spool)
	if err != nil {
		_ = os.RemoveAll(spool)
		return nil, err
	}
	return sealed, nil
}

func (prepared *PreparedManagedCandidate) sealInto(
	response EncryptionResponse, identityDigest, keyReference, spool string,
) (*SealedManagedCandidate, error) {
	ciphertext := make(map[string]string)
	nonces := newNonceRegistry()
	encryptedObjects := make([]map[string]any, 0, len(prepared.objects))
	for _, object := range prepared.objects {
		encrypted, err := encryptPreparedObject(
			response.CandidateKey, prepared.identity, object, spool, ciphertext, nonces,
		)
		if err != nil {
			return nil, err
		}
		encryptedObjects = append(encryptedObjects, encrypted)
	}
	manifest := map[string]any{
		"candidate_identity":        prepared.identity,
		"candidate_identity_digest": identityDigest,
		"candidate_key_reference":   keyReference,
		"cipher_suite":              managedCipherSuite,
		"format":                    candidateManifestFormat,
	}
	manifestBytes, err := CanonicalBytes(manifest)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	manifestObjectID, err := newObjectID()
	if err != nil {
		return nil, err
	}
	manifestObject, err := encryptManifestObject(
		response.CandidateKey, prepared.identity, manifestObjectID, manifestBytes,
		spool, ciphertext, nonces,
	)
	if err != nil {
		return nil, err
	}
	totalCiphertextBytes, _ := integerValue(manifestObject["cipher_size"])
	for _, entry := range encryptedObjects {
		chunks, _ := candidateRecords(entry["chunks"])
		for _, chunk := range chunks {
			cipherSize, _ := integerValue(chunk["cipher_size"])
			totalCiphertextBytes += cipherSize
		}
	}
	capabilities, _ := anyList(prepared.identity["required_capabilities"])
	ciphertextIdentity := map[string]any{
		"candidate_identity_digest": identityDigest,
		"candidate_key_reference":   keyReference,
		"capture_id":                prepared.identity["capture_id"],
		"cipher_suite":              managedCipherSuite,
		"format":                    ciphertextIdentityFormat,
		"manifest_object":           manifestObject,
		"objects":                   encryptedObjects,
		"organization_id":           prepared.identity["organization_id"],
		"processing_mode":           "managed",
		"project_id":                prepared.identity["project_id"],
		"required_capabilities":     append([]any{}, capabilities...),
		"service_id":                prepared.identity["service_id"],
		"total_ciphertext_bytes":    totalCiphertextBytes,
	}
	if err := validateCiphertextIdentity(ciphertextIdentity); err != nil {
		return nil, err
	}
	encryptedCandidateDigest, err := canonicalDigest(ciphertextIdentity)
	if err != nil {
		return nil, err
	}
	request := map[string]any{
		"capture_grant":              response.CaptureGrant,
		"ciphertext_identity":        ciphertextIdentity,
		"encrypted_candidate_digest": encryptedCandidateDigest,
	}
	if err := validateUploadRequest(request); err != nil {
		return nil, err
	}
	return &SealedManagedCandidate{
		request:          request,
		candidateKey:     append([]byte{}, response.CandidateKey...),
		ciphertext:       ciphertext,
		deploymentDigest: prepared.identity["deployment_digest"].(string),
		spool:            spool,
	}, nil
}

// SealedManagedCandidate is the sealed upload request plus its private
// ciphertext spool.
type SealedManagedCandidate struct {
	request          map[string]any
	candidateKey     []byte
	ciphertext       map[string]string
	deploymentDigest string
	spool            string
}

func (sealed *SealedManagedCandidate) Request() map[string]any {
	return sealed.request
}

func (sealed *SealedManagedCandidate) CiphertextDigests() []string {
	digests := make([]string, 0, len(sealed.ciphertext))
	for digest := range sealed.ciphertext {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	return digests
}

func (sealed *SealedManagedCandidate) CiphertextPath(digest string) string {
	return sealed.ciphertext[digest]
}

// Close removes the private ciphertext spool.
func (sealed *SealedManagedCandidate) Close() {
	if sealed.spool != "" {
		_ = os.RemoveAll(sealed.spool)
	}
}

func (sealed *SealedManagedCandidate) RequestCaptureGrantRenewal(
	delivery ManagedCandidateGrantDelivery,
	workloadKeyID string,
	workloadSigningKey []byte,
) (EncryptionResponse, error) {
	identity := sealed.request["ciphertext_identity"].(map[string]any)
	request := map[string]any{
		"candidate_identity_digest": identity["candidate_identity_digest"],
		"capture_id":                identity["capture_id"],
		"cipher_suite":              managedCipherSuite,
		"deployment_digest":         sealed.deploymentDigest,
		"organization_id":           identity["organization_id"],
		"processing_mode":           "managed",
		"project_id":                identity["project_id"],
		"service_id":                identity["service_id"],
		"signature":                 "",
		"signer_key_id":             workloadKeyID,
	}
	encoded, err := CanonicalBytes(request)
	if err != nil {
		return EncryptionResponse{}, errSchemaInvalid()
	}
	request["signature"], err = signBytes(encoded, workloadSigningKey)
	if err != nil {
		return EncryptionResponse{}, err
	}
	return delivery.RequestEncryptionGrant(request, grantTimeout)
}

func (sealed *SealedManagedCandidate) ApplyRenewedCaptureGrant(
	response EncryptionResponse,
	now string,
	captureSignerID string,
	captureSignerPublicKey []byte,
) error {
	identity := sealed.request["ciphertext_identity"].(map[string]any)
	if !bytesEqualConstantLength(response.CandidateKey, sealed.candidateKey) ||
		response.CaptureGrant["candidate_key_reference"] != identity["candidate_key_reference"] {
		return newManagedError(
			"CAPTURE_ID_CONFLICT",
			"The renewed managed capture grant does not match the live candidate key.",
		)
	}
	err := verifyCaptureGrant(
		response.CaptureGrant,
		map[string]any{
			"candidate_identity_digest": identity["candidate_identity_digest"],
			"candidate_key_reference":   identity["candidate_key_reference"],
			"capture_id":                identity["capture_id"],
			"organization_id":           identity["organization_id"],
			"project_id":                identity["project_id"],
			"service_id":                identity["service_id"],
			"signer_key_id":             captureSignerID,
		},
		now,
		captureSignerPublicKey,
	)
	if err != nil {
		return err
	}
	sealed.request["capture_grant"] = response.CaptureGrant
	return validateUploadRequest(sealed.request)
}

func (sealed *SealedManagedCandidate) Upload(
	delivery ManagedCandidateIngressDelivery,
) (map[string]any, error) {
	identity := sealed.request["ciphertext_identity"].(map[string]any)
	totalCiphertextBytes, _ := integerValue(identity["total_ciphertext_bytes"])
	commitTimeout := managedCommitTimeout(totalCiphertextBytes)
	start, err := delivery.Start(sealed.request, grantTimeout)
	if err != nil {
		return nil, err
	}
	uploadID, _ := start["upload_id"].(string)
	uploadToken, _ := start["upload_token"].(string)
	if start["state"] == "COMMITTED" {
		commit, err := delivery.Commit(uploadID, uploadToken, commitTimeout)
		if err != nil {
			return nil, err
		}
		return sealed.verifiedCommit(commit)
	}
	if start["state"] != "OPEN" && start["state"] != "UPLOADING" {
		return nil, errUploadState()
	}
	if err := sealed.uploadMissing(delivery, start); err != nil {
		sealed.cancelQuietly(delivery, uploadID, uploadToken)
		return nil, err
	}
	commit, err := delivery.Commit(uploadID, uploadToken, commitTimeout)
	if err != nil {
		sealed.cancelQuietly(delivery, uploadID, uploadToken)
		return nil, err
	}
	return sealed.verifiedCommit(commit)
}

func (sealed *SealedManagedCandidate) verifiedCommit(
	commit map[string]any,
) (map[string]any, error) {
	identity := sealed.request["ciphertext_identity"].(map[string]any)
	grant := sealed.request["capture_grant"].(map[string]any)
	if commit["capture_id"] != grant["capture_id"] ||
		commit["candidate_identity_digest"] != identity["candidate_identity_digest"] ||
		commit["candidate_key_reference"] != identity["candidate_key_reference"] ||
		commit["encrypted_candidate_digest"] != sealed.request["encrypted_candidate_digest"] ||
		commit["state"] != "CLOUD_PROTECTED" {
		return nil, errUploadState()
	}
	return commit, nil
}

func (sealed *SealedManagedCandidate) uploadMissing(
	delivery ManagedCandidateIngressDelivery, start map[string]any,
) error {
	limits, _ := start["limits"].(map[string]any)
	attempts, attemptsOK := integerValue(limits["object_attempts"])
	uploadID, _ := start["upload_id"].(string)
	uploadToken, _ := start["upload_token"].(string)
	missingObjects, _ := anyList(start["missing_objects"])
	cursor := start["next_missing_cursor"]
	seen := make(map[string]bool)
	maximumPages := (len(sealed.ciphertext)+99)/100 + 1
	for page := 0; page < maximumPages; page++ {
		if len(missingObjects) > 100 {
			return errUploadState()
		}
		for _, missingValue := range missingObjects {
			missing := missingValue.(map[string]any)
			digest := missing["cipher_digest"].(string)
			if seen[digest] || sealed.ciphertext[digest] == "" {
				return errUploadState()
			}
			seen[digest] = true
		}
		for _, missingValue := range missingObjects {
			missing := missingValue.(map[string]any)
			if err := sealed.uploadOne(delivery, missing, attempts, attemptsOK); err != nil {
				return err
			}
		}
		if cursor == nil {
			return nil
		}
		cursorText, _ := cursor.(string)
		nextPage, err := delivery.Missing(uploadID, uploadToken, cursorText, grantTimeout)
		if err != nil {
			return err
		}
		missingObjects, _ = anyList(nextPage["missing_objects"])
		cursor = nextPage["next_missing_cursor"]
	}
	return errUploadState()
}

func (sealed *SealedManagedCandidate) uploadOne(
	delivery ManagedCandidateIngressDelivery,
	missing map[string]any,
	attempts int64,
	attemptsOK bool,
) error {
	if !attemptsOK || attempts == 0 || attempts > 5 {
		return errUploadState()
	}
	digest := missing["cipher_digest"].(string)
	uploadURL, _ := missing["upload_url"].(string)
	value, err := readCiphertextObject(sealed.ciphertext[digest])
	if err != nil {
		return err
	}
	if digestBytes(value) != digest {
		return errObjectDigestMismatch()
	}
	var lastError error
	for attempt := int64(0); attempt < attempts; attempt++ {
		err := delivery.UploadObject(uploadURL, digest, value, grantTimeout)
		if err == nil {
			return nil
		}
		managedError, isManaged := err.(*ManagedError)
		if !isManaged || !managedError.Retryable {
			return err
		}
		lastError = err
	}
	if lastError != nil {
		return lastError
	}
	return errUploadState()
}

func (sealed *SealedManagedCandidate) cancelQuietly(
	delivery ManagedCandidateIngressDelivery, uploadID, uploadToken string,
) {
	_, _ = delivery.Cancel(uploadID, uploadToken, grantTimeout)
}

func readCiphertextObject(path string) ([]byte, error) {
	if path == "" {
		return nil, errManagedLocalStorage()
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errManagedLocalStorage()
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, managedMaxChunkBytes+29))
	if err != nil {
		return nil, errManagedLocalStorage()
	}
	return value, nil
}
func encryptPreparedObject(
	candidateKey []byte,
	identity map[string]any,
	object *preparedObject,
	spoolPath string,
	ciphertext map[string]string,
	nonces *nonceRegistry,
) (map[string]any, error) {
	descriptor := object.descriptor
	plainSize, _ := integerValue(descriptor["plain_size"])
	chunkCount := (max(plainSize, 1) + managedMaxChunkBytes - 1) / managedMaxChunkBytes
	if chunkCount > managedMaxCandidateObjects {
		return nil, errIncompleteCandidate()
	}
	context := objectKeyContext(
		identity, descriptor["object_id"].(string), descriptor["role"].(string),
	)
	contextDigest, err := canonicalDigest(context)
	if err != nil {
		return nil, err
	}
	captureID := identity["capture_id"].(string)
	objectKey, err := deriveObjectKey(candidateKey, captureID, context)
	if err != nil {
		return nil, err
	}
	reader, err := newPreparedObjectReader(object)
	if err != nil {
		return nil, err
	}
	defer reader.close()
	plainHasher := sha256.New()
	chunks := make([]map[string]any, 0, chunkCount)
	remaining := plainSize
	for index := int64(0); index < chunkCount; index++ {
		chunkPlainSize := min(remaining, int64(managedMaxChunkBytes))
		plaintext, err := reader.readExact(chunkPlainSize)
		if err != nil {
			return nil, err
		}
		plainHasher.Write(plaintext)
		chunkContext := chunkKeyContext(contextDigest, chunkCount, index, chunkPlainSize)
		chunkKey, err := deriveChunkKey(objectKey, chunkContext)
		if err != nil {
			return nil, err
		}
		nonce, err := randomNonce(nonces)
		if err != nil {
			return nil, err
		}
		stored, err := encryptChunk(chunkKey, nonce, plaintext, chunkContext)
		if err != nil {
			return nil, err
		}
		chunk, err := storeCiphertext(spoolPath, ciphertext, index, nonce, stored)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)
		remaining -= chunkPlainSize
	}
	plainDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(plainHasher.Sum(nil)))
	atEnd, err := reader.atEnd()
	if err != nil || remaining != 0 || !atEnd || plainDigest != descriptor["plain_digest"] {
		return nil, errIncompleteCandidate()
	}
	return map[string]any{"chunks": chunks, "descriptor": cloneDescriptor(descriptor)}, nil
}

// preparedObjectReader performs bounded chunked reads over an in-memory or
// spooled prepared object.
type preparedObjectReader struct {
	content []byte
	offset  int64
	source  *os.File
}

func newPreparedObjectReader(object *preparedObject) (*preparedObjectReader, error) {
	if object.content != nil {
		return &preparedObjectReader{content: object.content}, nil
	}
	source, err := os.Open(object.path)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	return &preparedObjectReader{source: source}, nil
}

func (reader *preparedObjectReader) readExact(size int64) ([]byte, error) {
	if reader.source == nil {
		if reader.offset+size > int64(len(reader.content)) {
			return nil, errIncompleteCandidate()
		}
		value := reader.content[reader.offset : reader.offset+size]
		reader.offset += size
		return value, nil
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader.source, value); err != nil {
		return nil, errIncompleteCandidate()
	}
	return value, nil
}

func (reader *preparedObjectReader) atEnd() (bool, error) {
	if reader.source == nil {
		return reader.offset >= int64(len(reader.content)), nil
	}
	trailing := make([]byte, 1)
	count, err := reader.source.Read(trailing)
	if count != 0 {
		return false, nil
	}
	if err != io.EOF && err != nil {
		return false, nil
	}
	return true, nil
}

func (reader *preparedObjectReader) close() {
	if reader.source != nil {
		_ = reader.source.Close()
	}
}

func encryptManifestObject(
	candidateKey []byte,
	identity map[string]any,
	objectID string,
	plaintext []byte,
	spoolPath string,
	ciphertext map[string]string,
	nonces *nonceRegistry,
) (map[string]any, error) {
	if len(plaintext) > managedMaxChunkBytes {
		return nil, errIncompleteCandidate()
	}
	context := objectKeyContext(identity, objectID, "capture-batch-manifest")
	contextDigest, err := canonicalDigest(context)
	if err != nil {
		return nil, err
	}
	chunkContext := chunkKeyContext(contextDigest, 1, 0, int64(len(plaintext)))
	captureID := identity["capture_id"].(string)
	objectKey, err := deriveObjectKey(candidateKey, captureID, context)
	if err != nil {
		return nil, err
	}
	chunkKey, err := deriveChunkKey(objectKey, chunkContext)
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce(nonces)
	if err != nil {
		return nil, err
	}
	stored, err := encryptChunk(chunkKey, nonce, plaintext, chunkContext)
	if err != nil {
		return nil, err
	}
	chunk, err := storeCiphertext(spoolPath, ciphertext, 0, nonce, stored)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"cipher_digest": chunk["cipher_digest"],
		"cipher_size":   chunk["cipher_size"],
		"nonce":         chunk["nonce"],
		"object_id":     objectID,
	}, nil
}

func storeCiphertext(
	spoolPath string,
	ciphertext map[string]string,
	index int64,
	nonce []byte,
	stored []byte,
) (map[string]any, error) {
	digest := digestBytes(stored)
	path := filepath.Join(spoolPath, digestName(digest))
	if _, err := os.Lstat(path); err != nil {
		if err := os.WriteFile(path, stored, 0o600); err != nil {
			return nil, errManagedLocalStorage()
		}
	}
	if existing, present := ciphertext[digest]; present && existing != path {
		return nil, errObjectDigestMismatch()
	}
	ciphertext[digest] = path
	return map[string]any{
		"cipher_digest": digest,
		"cipher_size":   int64(len(stored)),
		"index":         index,
		"nonce":         encodeBase64URL(nonce),
	}, nil
}

func randomNonce(nonces *nonceRegistry) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errManagedLocalStorage()
	}
	if err := nonces.register(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func cloneDescriptor(descriptor map[string]any) map[string]any {
	clone := make(map[string]any, len(descriptor))
	for key, value := range descriptor {
		clone[key] = value
	}
	return clone
}

func bytesEqualConstantLength(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	difference := byte(0)
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func errUploadState() *ManagedError {
	return newManagedError(
		"SERVICE_UNAVAILABLE",
		"The managed candidate upload did not reach a valid durable state.",
	)
}
