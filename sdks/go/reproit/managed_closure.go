// The static managed capture closure: world binding and frozen artifacts.
//
// Mirrors the closure half of crates/reproit-sdk-rust/src/managed.rs: the
// world checkpoint shape the SDK consumes, the static artifact set proof,
// dependency-transcript validation, and freezing artifact bytes into a
// private spool so they cannot change between proof and upload.
package reproit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	managedMaxCaptureArtifactBytes = int64(1024 * 1024 * 1024)
	managedMaxWorldArtifactBytes   = int64(2 * 1024 * 1024 * 1024)
	managedMaxWorldManifestBytes   = 262_144
	managedCopyBufferBytes         = 64 * 1024
)

var managedArtifactRoles = map[string]bool{"dependency-transcript": true, "world-state": true}

// ManagedCandidateArtifact is one static local file the capture closure
// binds by content digest.
type ManagedCandidateArtifact struct {
	MediaType string
	ObjectID  string
	Path      string
	Role      string
	URI       string
}

// ManagedCaptureClosure is the static capture closure the application proves
// before upload.
type ManagedCaptureClosure struct {
	Artifacts  []ManagedCandidateArtifact
	Completion string
	World      map[string]any
}

// FrozenManagedCaptureClosure is a capture closure whose artifact bytes are
// frozen in a private spool.
type FrozenManagedCaptureClosure struct {
	closure       ManagedCaptureClosure
	reservedBytes int64
	spool         string
}

func FreezeManagedCaptureClosure(
	closure ManagedCaptureClosure,
) (*FrozenManagedCaptureClosure, error) {
	if err := validateWorldCheckpoint(closure.World); err != nil {
		return nil, err
	}
	if err := validateStaticArtifactSet(closure.World, closure.Artifacts); err != nil {
		return nil, err
	}
	spool := ""
	artifacts := closure.Artifacts
	reservedBytes, err := captureArtifactBytes(artifacts)
	if err != nil || !processResources.reserveLogical(reservedBytes) {
		return nil, errIncompleteCandidate()
	}
	reserved := true
	defer func() {
		if reserved {
			processResources.releaseLogical(reservedBytes)
		}
	}()
	if len(artifacts) > 0 {
		created, err := os.MkdirTemp("", "reproit-managed-world-")
		if err != nil {
			return nil, errManagedLocalStorage()
		}
		spool = created
		artifacts = make([]ManagedCandidateArtifact, 0, len(closure.Artifacts))
		for _, artifact := range closure.Artifacts {
			frozen, err := freezeArtifact(artifact, spool)
			if err != nil {
				_ = os.RemoveAll(spool)
				return nil, err
			}
			artifacts = append(artifacts, frozen)
		}
		if err := validateStaticArtifactSet(closure.World, artifacts); err != nil {
			_ = os.RemoveAll(spool)
			return nil, err
		}
	}
	result := &FrozenManagedCaptureClosure{
		closure: ManagedCaptureClosure{
			Artifacts: artifacts, Completion: closure.Completion, World: closure.World,
		},
		reservedBytes: reservedBytes, spool: spool,
	}
	reserved = false
	return result, nil
}

func (frozen *FrozenManagedCaptureClosure) worldID() (string, error) {
	if err := validateWorldCheckpoint(frozen.closure.World); err != nil {
		return "", err
	}
	return canonicalDigest(frozen.closure.World)
}

// Close removes the private artifact spool.
func (frozen *FrozenManagedCaptureClosure) Close() {
	if frozen.spool != "" {
		_ = os.RemoveAll(frozen.spool)
	}
	if frozen.reservedBytes > 0 {
		processResources.releaseLogical(frozen.reservedBytes)
		frozen.reservedBytes = 0
	}
}

func captureArtifactBytes(artifacts []ManagedCandidateArtifact) (int64, error) {
	total := int64(0)
	for _, artifact := range artifacts {
		metadata, err := os.Lstat(artifact.Path)
		if err != nil || !metadata.Mode().IsRegular() || metadata.Size() <= 0 ||
			metadata.Size() > managedMaxCaptureArtifactBytes ||
			total > managedMaxWorldArtifactBytes-metadata.Size() {
			return 0, errIncompleteCandidate()
		}
		total += metadata.Size()
	}
	return total, nil
}

// validateWorldCheckpoint validates the bounded world checkpoint shape the
// SDK consumes.
func validateWorldCheckpoint(value any) error {
	checkpoint, ok := value.(map[string]any)
	if !ok || !hasExactKeys(checkpoint, "created_at", "format", "points") {
		return errSchemaInvalid()
	}
	points, pointsOK := anyList(checkpoint["points"])
	if checkpoint["format"] != "reproit.world-checkpoint.v1" ||
		!validTimestamp(checkpoint["created_at"]) || !pointsOK || len(points) > 64 {
		return errSchemaInvalid()
	}
	providers := make(map[string]bool)
	for _, pointValue := range points {
		point, pointOK := pointValue.(map[string]any)
		if !pointOK || point["format"] != "reproit.recoverable-point.v1" {
			return errSchemaInvalid()
		}
		providerID, providerIDOK := point["provider_id"].(string)
		artifacts, artifactsOK := anyList(point["artifacts"])
		if !providerIDOK || !artifactsOK || len(artifacts) > managedMaxCandidateObjects ||
			providers[providerID] {
			return errSchemaInvalid()
		}
		providers[providerID] = true
		for _, artifactValue := range artifacts {
			artifact, artifactOK := artifactValue.(map[string]any)
			if !artifactOK {
				return errSchemaInvalid()
			}
			size, sizeOK := integerValue(artifact["size"])
			uri, uriOK := artifact["uri"].(string)
			if _, mediaTypeOK := artifact["media_type"].(string); !mediaTypeOK ||
				!validDigest(artifact["digest"]) || !sizeOK || size < 0 ||
				!uriOK || uri == "" || len(uri) > 2_048 {
				return errSchemaInvalid()
			}
		}
	}
	encoded, err := CanonicalBytes(checkpoint)
	if err != nil || len(encoded) > managedMaxWorldManifestBytes {
		return errSchemaInvalid()
	}
	return nil
}

type worldArtifactIdentity struct {
	uri       string
	digest    string
	size      int64
	mediaType string
}

func expectedWorldArtifacts(world map[string]any) map[worldArtifactIdentity]bool {
	expected := make(map[worldArtifactIdentity]bool)
	points, _ := anyList(world["points"])
	for _, pointValue := range points {
		point := pointValue.(map[string]any)
		artifacts, _ := anyList(point["artifacts"])
		for _, artifactValue := range artifacts {
			artifact := artifactValue.(map[string]any)
			size, _ := integerValue(artifact["size"])
			expected[worldArtifactIdentity{
				uri:       artifact["uri"].(string),
				digest:    artifact["digest"].(string),
				size:      size,
				mediaType: artifact["media_type"].(string),
			}] = true
		}
	}
	return expected
}

func validateStaticArtifactSet(
	world map[string]any, artifacts []ManagedCandidateArtifact,
) error {
	if len(artifacts) > managedMaxCandidateObjects {
		return errIncompleteCandidate()
	}
	expectedWorld := expectedWorldArtifacts(world)
	suppliedWorld := make(map[string]bool)
	for _, artifact := range artifacts {
		if artifact.Role == "world-state" {
			suppliedWorld[artifact.URI] = true
		}
	}
	if len(expectedWorld) != len(suppliedWorld) {
		return errIncompleteCandidate()
	}
	for expected := range expectedWorld {
		if !suppliedWorld[expected.uri] {
			return errIncompleteCandidate()
		}
	}
	objectIDs := make(map[string]bool)
	uris := make(map[string]bool)
	for _, artifact := range artifacts {
		if !managedArtifactRoles[artifact.Role] || artifact.URI == "" ||
			len(artifact.URI) > 2_048 || artifact.MediaType == "" ||
			len(artifact.MediaType) > 256 || objectIDs[artifact.ObjectID] ||
			uris[artifact.URI] {
			return errIncompleteCandidate()
		}
		objectIDs[artifact.ObjectID] = true
		uris[artifact.URI] = true
		size, digest, err := hashFile(artifact.Path)
		if err != nil {
			return err
		}
		if artifact.Role == "world-state" && !expectedWorld[worldArtifactIdentity{
			uri: artifact.URI, digest: digest, size: size, mediaType: artifact.MediaType,
		}] {
			return errIncompleteCandidate()
		}
		if artifact.Role == "dependency-transcript" &&
			artifact.MediaType == dependencyTranscriptMediaType {
			if size > managedMaxChunkBytes {
				return errIncompleteCandidate()
			}
			content, err := readBounded(artifact.Path, size)
			if err != nil {
				return err
			}
			if _, err := validateTranscriptBytes(content); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateTranscriptBytes mirrors the DependencyTranscript strict parse and
// validation.
func validateTranscriptBytes(value []byte) (map[string]any, error) {
	parsedValue, err := parseStrictJSON(value, managedMaxChunkBytes)
	if err != nil {
		return nil, err
	}
	parsed, ok := parsedValue.(map[string]any)
	if !ok {
		return nil, errSchemaInvalid()
	}
	canonical, err := CanonicalBytes(parsed)
	if err != nil || !bytes.Equal(canonical, value) ||
		!hasExactKeys(parsed, "adapter_id", "adapter_version", "format", "interactions") ||
		parsed["format"] != "reproit.dependency-transcript.v1" {
		return nil, errSchemaInvalid()
	}
	adapterID, adapterIDOK := parsed["adapter_id"].(string)
	adapterVersion, adapterVersionOK := parsed["adapter_version"].(string)
	interactions, interactionsOK := anyList(parsed["interactions"])
	if !adapterIDOK || adapterID == "" || len(adapterID) > 128 ||
		!adapterVersionOK || adapterVersion == "" || len(adapterVersion) > 64 ||
		!interactionsOK || len(interactions) < 1 || len(interactions) > 1_024 {
		return nil, errSchemaInvalid()
	}
	for index, interaction := range interactions {
		if err := validateTranscriptInteraction(interaction, index); err != nil {
			return nil, err
		}
	}
	return parsed, nil
}

func validateTranscriptInteraction(value any, index int) error {
	interaction, ok := value.(map[string]any)
	if !ok || !hasExactKeys(interaction,
		"causal_parent_id", "operation_id", "outcome", "request_digest",
		"request_object_id", "response_digest", "response_object_id", "sequence",
		"session_position",
	) {
		return errSchemaInvalid()
	}
	sequence, sequenceOK := integerValue(interaction["sequence"])
	sessionPosition, sessionPositionOK := integerValue(interaction["session_position"])
	if !sequenceOK || sequence != int64(index) ||
		!validTypedID(interaction["operation_id"], "operation_id") ||
		interaction["causal_parent_id"] != nil &&
			!validTypedID(interaction["causal_parent_id"], "operation_id") ||
		!validDigest(interaction["request_digest"]) ||
		!validDigest(interaction["response_digest"]) ||
		!validTypedID(interaction["request_object_id"], "object_id") ||
		!validTypedID(interaction["response_object_id"], "object_id") ||
		!sessionPositionOK || sessionPosition < 0 || sessionPosition > 9_007_199_254_740_991 {
		return errSchemaInvalid()
	}
	return nil
}

func freezeArtifact(
	artifact ManagedCandidateArtifact, spoolPath string,
) (ManagedCandidateArtifact, error) {
	size, err := artifactSize(artifact.Path)
	if err != nil {
		return ManagedCandidateArtifact{}, err
	}
	objectID, err := newObjectID()
	if err != nil {
		return ManagedCandidateArtifact{}, err
	}
	temporary := filepath.Join(spoolPath, "artifact-"+objectID)
	firstDigest, copied, err := copyAndDigest(artifact.Path, temporary, size)
	if err != nil {
		return ManagedCandidateArtifact{}, err
	}
	secondDigest, verified, err := digestFile(artifact.Path, size)
	if err != nil {
		return ManagedCandidateArtifact{}, err
	}
	if firstDigest != secondDigest || copied != verified {
		return ManagedCandidateArtifact{}, errIncompleteCandidate()
	}
	frozenPath := filepath.Join(spoolPath, digestName(firstDigest))
	if _, statErr := os.Lstat(frozenPath); statErr == nil {
		storedDigest, storedSize, err := digestFile(frozenPath, copied)
		if err != nil || storedDigest != firstDigest || storedSize != copied {
			return ManagedCandidateArtifact{}, errObjectDigestMismatch()
		}
		_ = os.Remove(temporary)
	} else if err := os.Rename(temporary, frozenPath); err != nil {
		return ManagedCandidateArtifact{}, errManagedLocalStorage()
	}
	return ManagedCandidateArtifact{
		MediaType: artifact.MediaType,
		ObjectID:  artifact.ObjectID,
		Path:      frozenPath,
		Role:      artifact.Role,
		URI:       artifact.URI,
	}, nil
}

func artifactSize(path string) (int64, error) {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Size() == 0 || metadata.Size() > managedMaxCaptureArtifactBytes {
		return 0, errIncompleteCandidate()
	}
	return metadata.Size(), nil
}

func copyAndDigest(source, target string, expected int64) (string, int64, error) {
	reader, err := os.Open(source)
	if err != nil {
		return "", 0, errManagedLocalStorage()
	}
	defer reader.Close()
	writer, err := os.Create(target)
	if err != nil {
		return "", 0, errManagedLocalStorage()
	}
	defer writer.Close()
	hasher := sha256.New()
	total := int64(0)
	buffer := make([]byte, managedCopyBufferBytes)
	for {
		count, readErr := reader.Read(buffer)
		if count > 0 {
			total += int64(count)
			if total > expected {
				return "", 0, errIncompleteCandidate()
			}
			hasher.Write(buffer[:count])
			if _, writeErr := writer.Write(buffer[:count]); writeErr != nil {
				return "", 0, errManagedLocalStorage()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, errManagedLocalStorage()
		}
	}
	if err := writer.Sync(); err != nil {
		return "", 0, errManagedLocalStorage()
	}
	if total != expected {
		return "", 0, errIncompleteCandidate()
	}
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(hasher.Sum(nil))), total, nil
}

func digestFile(path string, expected int64) (string, int64, error) {
	reader, err := os.Open(path)
	if err != nil {
		return "", 0, errIncompleteCandidate()
	}
	defer reader.Close()
	hasher := sha256.New()
	total := int64(0)
	buffer := make([]byte, managedCopyBufferBytes)
	for {
		count, readErr := reader.Read(buffer)
		if count > 0 {
			total += int64(count)
			if total > expected {
				return "", 0, errIncompleteCandidate()
			}
			hasher.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, errIncompleteCandidate()
		}
	}
	if total != expected {
		return "", 0, errIncompleteCandidate()
	}
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(hasher.Sum(nil))), total, nil
}

func readBounded(path string, expected int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errIncompleteCandidate()
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, expected+1))
	if err != nil || int64(len(value)) != expected {
		return nil, errIncompleteCandidate()
	}
	return value, nil
}

// hashFile hashes a stable regular file, failing closed if it changes
// underneath.
func hashFile(path string) (int64, string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return 0, "", errIncompleteCandidate()
	}
	if _, err := artifactSize(path); err != nil {
		return 0, "", err
	}
	digest, size, err := digestFile(path, before.Size())
	if err != nil {
		return 0, "", err
	}
	after, err := os.Lstat(path)
	if err != nil || after.Size() != size || !after.ModTime().Equal(before.ModTime()) {
		return 0, "", errIncompleteCandidate()
	}
	return size, digest, nil
}

func digestName(digest string) string {
	return strings.TrimPrefix(digest, "sha256:")
}

func errManagedLocalStorage() *ManagedError {
	return newManagedError(
		"SERVICE_UNAVAILABLE",
		"Repro It could not create the bounded local ciphertext staging area.",
	)
}
