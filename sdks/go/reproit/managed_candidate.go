// Managed candidate preparation, sealing, and bounded upload.
//
// Mirrors crates/reproit-sdk-rust/src/managed.rs: the SDK proves local
// completeness first, then requests one managed candidate encryption grant,
// seals every object with AES-256-GCM keyed through HKDF-SHA-256, and drives
// the start, missing, object-PUT, commit, and cancel upload session. An
// incomplete candidate stops before any network request.
package reproit

import (
	"sort"
	"time"
)

const grantTimeout = 5 * time.Second

// The ingress verifies the digest and size of every declared ciphertext byte
// before it commits, so the commit wait scales with the declared closure.
// The floor covers control latency, the rate is a conservative verification
// throughput, and the cap bounds the wait for the maximum closure.
const (
	commitTimeoutFloor               = 5 * time.Second
	commitVerificationBytesPerSecond = 4 * 1024 * 1024
	commitTimeoutCap                 = 180 * time.Second
)

func managedCommitTimeout(totalCiphertextBytes int64) time.Duration {
	verificationSeconds := (totalCiphertextBytes + commitVerificationBytesPerSecond - 1) /
		commitVerificationBytesPerSecond
	timeout := commitTimeoutFloor + time.Duration(verificationSeconds)*time.Second
	if timeout > commitTimeoutCap {
		return commitTimeoutCap
	}
	return timeout
}

var managedCompletionsByKind = map[string]map[string]bool{
	"request-response": {"return": true},
	"stream":           {"stream-end": true},
	"delivered-work":   {"acknowledgment": true, "task-end": true},
}

// ManagedCandidateGrantDelivery issues managed candidate encryption grants.
type ManagedCandidateGrantDelivery interface {
	RequestEncryptionGrant(
		request map[string]any, timeout time.Duration,
	) (EncryptionResponse, error)
}

// ManagedCandidateIngressDelivery drives the bounded managed upload session.
type ManagedCandidateIngressDelivery interface {
	Start(request map[string]any, timeout time.Duration) (map[string]any, error)
	Missing(
		uploadID string, uploadToken string, cursor string, timeout time.Duration,
	) (map[string]any, error)
	UploadObject(uploadURL string, digest string, value []byte, timeout time.Duration) error
	Commit(uploadID string, uploadToken string, timeout time.Duration) (map[string]any, error)
	Cancel(uploadID string, uploadToken string, timeout time.Duration) (map[string]any, error)
}

type preparedObject struct {
	descriptor map[string]any
	content    []byte
	path       string
}

func (object *preparedObject) read() ([]byte, error) {
	plainSize, _ := integerValue(object.descriptor["plain_size"])
	if plainSize > managedMaxChunkBytes {
		return nil, errIncompleteCandidate()
	}
	if object.content != nil {
		return object.content, nil
	}
	return readBounded(object.path, plainSize)
}

// PreparedManagedCandidate is one locally complete candidate whose closure
// is proved before upload.
type PreparedManagedCandidate struct {
	identity map[string]any
	objects  []*preparedObject
	subject  *GoSubjectPackage
	// The frozen closure owns the artifact spool the objects reference.
	closure *FrozenManagedCaptureClosure
}

func PrepareCompleteManagedCandidate(
	candidate map[string]any,
	subject *GoSubjectPackage,
	closure *FrozenManagedCaptureClosure,
) (*PreparedManagedCandidate, error) {
	if err := managedValidateCandidate(candidate); err != nil {
		return nil, err
	}
	if err := validateSubjectClosureManifest(subject.Manifest); err != nil {
		return nil, err
	}
	if candidate["processing_mode"] != "managed" {
		return nil, newManagedError(
			"SCHEMA_INVALID", "Managed capture requires a managed deployment.",
		)
	}
	if err := validateSubjectBinding(candidate, subject.Manifest); err != nil {
		return nil, err
	}
	worldID, err := closure.worldID()
	if err != nil {
		return nil, err
	}
	if worldID != candidate["world_id"] {
		return nil, errIncompleteCandidate()
	}

	deployment := candidate["deployment"].(map[string]any)
	var objects []*preparedObject
	candidateBytes, err := CanonicalBytes(candidate)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	if objects, err = pushGeneratedObject(
		objects, "candidate", candidateMediaType, candidateBytes,
	); err != nil {
		return nil, err
	}
	if objects, err = pushSubjectObjects(objects, subject); err != nil {
		return nil, err
	}
	if objects, err = pushTriggerAndInputs(
		objects, candidate, closure.closure.Completion,
	); err != nil {
		return nil, err
	}
	if objects, err = pushFailureObject(objects, candidate); err != nil {
		return nil, err
	}
	worldBytes, err := CanonicalBytes(closure.closure.World)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	if objects, err = pushGeneratedObject(
		objects, "world-manifest", worldManifestMediaType, worldBytes,
	); err != nil {
		return nil, err
	}
	if objects, err = pushCaptureArtifacts(
		objects, candidate, closure.closure.World, closure.closure.Artifacts,
	); err != nil {
		return nil, err
	}
	sort.Slice(objects, func(left, right int) bool {
		return objects[left].descriptor["object_id"].(string) <
			objects[right].descriptor["object_id"].(string)
	})
	if err := verifyLocalClosure(objects); err != nil {
		return nil, err
	}

	descriptors := make([]map[string]any, 0, len(objects))
	totalPlaintextBytes := int64(0)
	for _, object := range objects {
		descriptor := cloneDescriptor(object.descriptor)
		descriptors = append(descriptors, descriptor)
		plainSize, _ := integerValue(descriptor["plain_size"])
		totalPlaintextBytes += plainSize
	}
	if totalPlaintextBytes > maxProcessLogicalBytes {
		return nil, errIncompleteCandidate()
	}
	candidateDigest, err := canonicalDigest(candidate)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	deploymentDigest, err := canonicalDigest(deployment)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	subjectDigest, err := canonicalDigest(subject.Manifest)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	capabilities, _ := anyList(deployment["runtime_capabilities"])
	identity := map[string]any{
		"candidate_digest":      candidateDigest,
		"capture_id":            candidate["capture_id"],
		"deployment_digest":     deploymentDigest,
		"format":                candidateIdentityFormat,
		"objects":               descriptors,
		"organization_id":       deployment["organization_id"],
		"processing_mode":       "managed",
		"project_id":            deployment["project_id"],
		"required_capabilities": append([]any{}, capabilities...),
		"service_id":            deployment["service_id"],
		"subject_digest":        subjectDigest,
		"total_plaintext_bytes": totalPlaintextBytes,
	}
	if err := validateManagedCandidateIdentity(identity); err != nil {
		return nil, err
	}
	return &PreparedManagedCandidate{
		identity: identity, objects: objects, subject: subject, closure: closure,
	}, nil
}

func (prepared *PreparedManagedCandidate) Identity() map[string]any {
	return prepared.identity
}

func (prepared *PreparedManagedCandidate) RequestEncryptionGrant(
	delivery ManagedCandidateGrantDelivery,
	workloadKeyID string,
	workloadSigningKey []byte,
) (EncryptionResponse, error) {
	if err := validateManagedCandidateIdentity(prepared.identity); err != nil {
		return EncryptionResponse{}, err
	}
	if err := verifyLocalClosure(prepared.objects); err != nil {
		return EncryptionResponse{}, err
	}
	identityDigest, err := canonicalDigest(prepared.identity)
	if err != nil {
		return EncryptionResponse{}, err
	}
	request := map[string]any{
		"candidate_identity_digest": identityDigest,
		"capture_id":                prepared.identity["capture_id"],
		"cipher_suite":              managedCipherSuite,
		"deployment_digest":         prepared.identity["deployment_digest"],
		"organization_id":           prepared.identity["organization_id"],
		"processing_mode":           "managed",
		"project_id":                prepared.identity["project_id"],
		"service_id":                prepared.identity["service_id"],
		"signature":                 "",
		"signer_key_id":             workloadKeyID,
	}
	if !validManagedWorkloadKeyID(workloadKeyID) || len(workloadSigningKey) != 32 {
		return EncryptionResponse{}, errSchemaInvalid()
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

// validateSubjectBinding proves the deployment subject matches the running
// subject package.
func validateSubjectBinding(candidate map[string]any, manifest map[string]any) error {
	deployment, deploymentOK := candidate["deployment"].(map[string]any)
	if !deploymentOK {
		return errIncompleteCandidate()
	}
	subject, subjectOK := deployment["subject"].(map[string]any)
	if !subjectOK {
		return errIncompleteCandidate()
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		return errIncompleteCandidate()
	}
	launch, launchOK := manifest["launch"].(map[string]any)
	if !launchOK {
		return errIncompleteCandidate()
	}
	capabilities, capabilitiesOK := anyList(deployment["runtime_capabilities"])
	argumentsEqual, argumentsErr := canonicalEqual(subject["arguments"], launch["arguments"])
	namesEqual, namesErr := canonicalEqual(
		subject["environment_names"], launch["environment_names"],
	)
	architecture, _ := manifest["architecture"].(string)
	operatingSystem, _ := manifest["operating_system"].(string)
	if subject["artifact_digest"] != manifestDigest ||
		subject["artifact_media_type"] != subjectManifestMediaType ||
		subject["architecture"] != manifest["architecture"] ||
		subject["operating_system"] != manifest["operating_system"] ||
		argumentsErr != nil || !argumentsEqual || namesErr != nil || !namesEqual ||
		subject["executable"] != launch["executable"] ||
		subject["working_directory"] != launch["working_directory"] ||
		!capabilitiesOK || !containsCapability(capabilities, architecture) ||
		!containsCapability(capabilities, operatingSystem) {
		return newManagedError(
			"SUBJECT_DIGEST_MISMATCH",
			"The managed deployment does not match the running subject package.",
		)
	}
	return nil
}

func containsCapability(capabilities []any, value string) bool {
	for _, capability := range capabilities {
		if capability == value {
			return true
		}
	}
	return false
}

// managedValidateCandidate proves the candidate record closure locally,
// mirroring the Rust gate.
func managedValidateCandidate(candidate map[string]any) error {
	_, recordsOK := anyList(candidate["records"])
	deployment, deploymentOK := candidate["deployment"].(map[string]any)
	if candidate["format"] != "reproit.candidate.v1" ||
		!validTypedID(candidate["capture_id"], "capture_id") ||
		!validTypedID(candidate["operation_id"], "operation_id") ||
		!validDigest(candidate["world_id"]) ||
		!recordsOK || !deploymentOK ||
		!validTypedID(deployment["organization_id"], "organization_id") ||
		!validTypedID(deployment["project_id"], "project_id") ||
		!validTypedID(deployment["service_id"], "service_id") ||
		candidate["processing_mode"] != deployment["processing_mode"] {
		return errIncompleteCandidate()
	}
	signature, signatureOK := deployment["signature"].(string)
	if !signatureOK {
		return errIncompleteCandidate()
	}
	if _, err := decodeBase64URL(signature, 64); err != nil {
		return errIncompleteCandidate()
	}
	if validateCandidate(candidate) != nil {
		return errIncompleteCandidate()
	}
	return nil
}

func decodeRecordPayload(record any) (map[string]any, error) {
	mapped, ok := record.(map[string]any)
	if !ok {
		return nil, errIncompleteCandidate()
	}
	payload, payloadOK := mapped["payload"].(string)
	if !payloadOK {
		return nil, errIncompleteCandidate()
	}
	decoded, err := decodeBase64URL(payload, -1)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	parsed, err := parseStrictJSON(decoded, managedMaxChunkBytes)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	value, valueOK := parsed.(map[string]any)
	if !valueOK {
		return nil, errIncompleteCandidate()
	}
	return value, nil
}

func pushGeneratedObject(
	objects []*preparedObject, role, mediaType string, content []byte,
) ([]*preparedObject, error) {
	objectID, err := newObjectID()
	if err != nil {
		return nil, err
	}
	return pushContentObject(objects, objectID, role, mediaType, content), nil
}

func pushContentObject(
	objects []*preparedObject, objectID, role, mediaType string, content []byte,
) []*preparedObject {
	descriptor := map[string]any{
		"media_type":   mediaType,
		"object_id":    objectID,
		"plain_digest": digestBytes(content),
		"plain_size":   int64(len(content)),
		"role":         role,
	}
	return append(objects, &preparedObject{descriptor: descriptor, content: content})
}

func pushFileObject(
	objects []*preparedObject,
	objectID, mediaType, digest string,
	size int64,
	path, role string,
) []*preparedObject {
	descriptor := map[string]any{
		"media_type":   mediaType,
		"object_id":    objectID,
		"plain_digest": digest,
		"plain_size":   size,
		"role":         role,
	}
	return append(objects, &preparedObject{descriptor: descriptor, path: path})
}

func pushSubjectObjects(
	objects []*preparedObject, subject *GoSubjectPackage,
) ([]*preparedObject, error) {
	manifestBytes, err := CanonicalBytes(subject.Manifest)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	if objects, err = pushGeneratedObject(
		objects, "subject", subjectManifestMediaType, manifestBytes,
	); err != nil {
		return nil, err
	}
	declared := make(map[string][2]any)
	declaredObjects, _ := candidateRecords(subject.Manifest["objects"])
	for _, entry := range declaredObjects {
		digest, _ := entry["digest"].(string)
		size, _ := integerValue(entry["size"])
		mediaType, _ := entry["media_type"].(string)
		declared[digest] = [2]any{mediaType, size}
	}
	if len(declared) != len(subject.Objects) {
		return nil, errIncompleteCandidate()
	}
	for _, packaged := range subject.Objects {
		entry, present := declared[packaged.Digest]
		if !present || entry[1].(int64) != packaged.Size {
			return nil, errIncompleteCandidate()
		}
		objectID, err := newObjectID()
		if err != nil {
			return nil, err
		}
		objects = pushFileObject(
			objects, objectID, entry[0].(string), packaged.Digest, packaged.Size,
			packaged.Path, "subject",
		)
	}
	return objects, nil
}

func pushTriggerAndInputs(
	objects []*preparedObject, candidate map[string]any, completion string,
) ([]*preparedObject, error) {
	records, _ := anyList(candidate["records"])
	if len(records) == 0 {
		return nil, errIncompleteCandidate()
	}
	begin, err := decodeRecordPayload(records[0])
	if err != nil {
		return nil, err
	}
	inputs := make([]map[string]any, 0)
	for _, recordValue := range records {
		record, recordOK := recordValue.(map[string]any)
		if !recordOK {
			return nil, errIncompleteCandidate()
		}
		if record["kind"] != "input" {
			continue
		}
		payload, err := decodeRecordPayload(record)
		if err != nil {
			return nil, err
		}
		valueText, valueTextOK := payload["value"].(string)
		if !valueTextOK {
			return nil, errIncompleteCandidate()
		}
		content, err := decodeBase64URL(valueText, -1)
		if err != nil {
			return nil, errIncompleteCandidate()
		}
		objectID, err := newObjectID()
		if err != nil {
			return nil, err
		}
		contentType, contentTypeOK := payload["content_type"].(string)
		if !contentTypeOK {
			return nil, errIncompleteCandidate()
		}
		inputs = append(inputs, map[string]any{
			"channel":      payload["channel"],
			"object_id":    objectID,
			"plain_digest": payload["value_digest"],
			"sequence":     int64(len(inputs)),
		})
		objects = pushContentObject(objects, objectID, "trigger", contentType, content)
	}
	operationKind, _ := begin["operation_kind"].(string)
	allowed := managedCompletionsByKind[operationKind]
	adapterID, adapterIDOK := begin["adapter_id"].(string)
	adapterVersion, adapterVersionOK := begin["adapter_version"].(string)
	operationName, operationNameOK := begin["operation_name"].(string)
	causalParents, causalParentsOK := anyList(begin["causal_parent_ids"])
	if len(inputs) == 0 || len(inputs) > 1_024 || !allowed[completion] ||
		!adapterIDOK || adapterID == "" || len(adapterID) > 128 ||
		!adapterVersionOK || adapterVersion == "" || len(adapterVersion) > 64 ||
		!operationNameOK || operationName == "" || len(operationName) > 128 ||
		!causalParentsOK || len(causalParents) > 32 {
		return nil, errIncompleteCandidate()
	}
	seenParents := make(map[string]bool)
	for _, parent := range causalParents {
		text, textOK := parent.(string)
		if !textOK || !validTypedID(text, "operation_id") || seenParents[text] {
			return nil, errIncompleteCandidate()
		}
		seenParents[text] = true
	}
	trigger := map[string]any{
		"adapter_id":        begin["adapter_id"],
		"adapter_version":   begin["adapter_version"],
		"causal_parent_ids": begin["causal_parent_ids"],
		"completion":        completion,
		"format":            "reproit.trigger.v1",
		"inputs":            inputs,
		"operation_id":      candidate["operation_id"],
		"operation_kind":    operationKind,
		"operation_name":    begin["operation_name"],
	}
	triggerBytes, err := CanonicalBytes(trigger)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	return pushGeneratedObject(objects, "trigger", triggerMediaType, triggerBytes)
}

func pushFailureObject(
	objects []*preparedObject, candidate map[string]any,
) ([]*preparedObject, error) {
	records, _ := anyList(candidate["records"])
	var failureRecord map[string]any
	for _, recordValue := range records {
		record, recordOK := recordValue.(map[string]any)
		if recordOK && record["kind"] == "failure" {
			failureRecord = record
			break
		}
	}
	if failureRecord == nil {
		return nil, errIncompleteCandidate()
	}
	payload, err := decodeRecordPayload(failureRecord)
	if err != nil {
		return nil, err
	}
	failure, failureOK := payload["failure"].(map[string]any)
	if !failureOK || !validTypedID(failure["object_id"], "object_id") {
		return nil, errIncompleteCandidate()
	}
	payloadBytes, err := CanonicalBytes(payload)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	return pushContentObject(
		objects, failure["object_id"].(string), "failure", failureMediaType, payloadBytes,
	), nil
}

func pushCaptureArtifacts(
	objects []*preparedObject,
	candidate map[string]any,
	world map[string]any,
	artifacts []ManagedCandidateArtifact,
) ([]*preparedObject, error) {
	records, _ := anyList(candidate["records"])
	dependencyRecords := make([]map[string]any, 0)
	for _, recordValue := range records {
		record, recordOK := recordValue.(map[string]any)
		if recordOK && record["kind"] == "dependency" {
			dependencyRecords = append(dependencyRecords, record)
		}
	}
	requiresArtifacts := len(expectedWorldArtifacts(world)) > 0 || len(dependencyRecords) > 0
	if len(artifacts) == 0 && requiresArtifacts {
		return nil, errIncompleteCandidate()
	}
	for _, artifact := range artifacts {
		size, digest, err := hashFile(artifact.Path)
		if err != nil {
			return nil, err
		}
		objects = pushFileObject(
			objects, artifact.ObjectID, artifact.MediaType, digest, size,
			artifact.Path, artifact.Role,
		)
	}
	if err := validateDependencyClosure(candidate, objects, dependencyRecords); err != nil {
		return nil, err
	}
	return objects, nil
}

func validateDependencyClosure(
	candidate map[string]any,
	objects []*preparedObject,
	dependencyRecords []map[string]any,
) error {
	cursors := make([]map[string]any, 0, len(dependencyRecords))
	for _, record := range dependencyRecords {
		cursor, err := decodeRecordPayload(record)
		if err != nil {
			return err
		}
		cursors = append(cursors, cursor)
	}
	descriptors := make(map[string]map[string]any)
	for _, object := range objects {
		descriptors[object.descriptor["object_id"].(string)] = object.descriptor
	}
	transcripts := make([]map[string]any, 0)
	for _, object := range objects {
		descriptor := object.descriptor
		if descriptor["role"] != "dependency-transcript" ||
			descriptor["media_type"] != dependencyTranscriptMediaType {
			continue
		}
		content, err := object.read()
		if err != nil {
			return err
		}
		transcript, err := validateTranscriptBytes(content)
		if err != nil {
			return err
		}
		interactions, _ := anyList(transcript["interactions"])
		for _, interactionValue := range interactions {
			interaction := interactionValue.(map[string]any)
			operationMatches := interaction["operation_id"] == candidate["operation_id"] ||
				interaction["causal_parent_id"] == candidate["operation_id"]
			if !operationMatches ||
				!descriptorMatches(
					descriptors, interaction["request_object_id"], interaction["request_digest"],
				) ||
				!descriptorMatches(
					descriptors, interaction["response_object_id"], interaction["response_digest"],
				) {
				return errIncompleteCandidate()
			}
		}
		transcripts = append(transcripts, transcript)
	}
	if len(cursors) != len(transcripts) {
		return errIncompleteCandidate()
	}
	for _, cursor := range cursors {
		matches := 0
		for _, transcript := range transcripts {
			if transcript["adapter_id"] == cursor["adapter_id"] &&
				transcript["adapter_version"] == cursor["adapter_version"] {
				matches++
			}
		}
		if matches != 1 {
			return errIncompleteCandidate()
		}
	}
	return nil
}

func descriptorMatches(
	descriptors map[string]map[string]any, objectID any, digest any,
) bool {
	text, ok := objectID.(string)
	if !ok {
		return false
	}
	descriptor := descriptors[text]
	return descriptor != nil && descriptor["plain_digest"] == digest
}

func verifyLocalClosure(objects []*preparedObject) error {
	if len(objects) < 5 || len(objects) > managedMaxCandidateObjects {
		return errIncompleteCandidate()
	}
	objectIDs := make(map[string]bool)
	for _, object := range objects {
		descriptor := object.descriptor
		objectID := descriptor["object_id"].(string)
		if objectIDs[objectID] {
			return errIncompleteCandidate()
		}
		objectIDs[objectID] = true
		var actualSize int64
		var actualDigest string
		if object.content != nil {
			actualSize = int64(len(object.content))
			actualDigest = digestBytes(object.content)
		} else {
			size, digest, err := hashFile(object.path)
			if err != nil {
				return err
			}
			actualSize, actualDigest = size, digest
		}
		plainSize, _ := integerValue(descriptor["plain_size"])
		if actualSize != plainSize || actualDigest != descriptor["plain_digest"] {
			return errIncompleteCandidate()
		}
	}
	return nil
}
