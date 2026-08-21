package reproit

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"syscall"
)

const (
	managedDeploymentMetadataBytes  = 256
	managedRegistrationReceiptBytes = 512
)

// ManagedWorkloadRegistrationReceipt is the non-secret registration state.
type ManagedWorkloadRegistrationReceipt struct {
	DeploymentDigest string
	ServiceID        string
	WorkloadKeyID    string
}

// ManagedWorkloadIdentityState owns one deployment-bound workload identity.
type ManagedWorkloadIdentityState struct {
	directory string
}

func newManagedWorkloadIdentityState(
	stateRoot string, bindingDigest string,
) (*ManagedWorkloadIdentityState, error) {
	if !validDigest(bindingDigest) {
		return nil, errStateRootInvalid()
	}
	root, err := managedStateRoot(stateRoot)
	if err != nil {
		return nil, err
	}
	if err := ensureStateRoot(root); err != nil {
		return nil, err
	}
	reproitDirectory := filepath.Join(root, "reproit")
	if err := ensurePrivateDirectory(reproitDirectory); err != nil {
		return nil, err
	}
	workloadsDirectory := filepath.Join(reproitDirectory, "workloads")
	if err := ensurePrivateDirectory(workloadsDirectory); err != nil {
		return nil, err
	}
	directory := filepath.Join(workloadsDirectory, bindingDigest)
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &ManagedWorkloadIdentityState{directory: directory}, nil
}

func managedStateRoot(configured string) (string, error) {
	if configured != "" {
		if !filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
			return "", errStateRootInvalid()
		}
		return configured, nil
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		if !filepath.IsAbs(xdg) || filepath.Clean(xdg) != xdg {
			return "", errStateRootInvalid()
		}
		return xdg, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", errStateRootInvalid()
	}
	return filepath.Join(home, ".local", "state"), nil
}

func ensureStateRoot(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return errStateRootUnavailable()
	}
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.IsDir() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Mode().Perm()&0o022 != 0 {
		return errStateRootInvalid()
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return errStateRootUnavailable()
	}
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.IsDir() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Mode().Perm()&0o077 != 0 {
		return errStateRootInvalid()
	}
	return nil
}

func (state *ManagedWorkloadIdentityState) loadOrCreateKey(proposed []byte) ([]byte, error) {
	if err := validateKeyParent(state.directory); err != nil {
		return nil, err
	}
	path := filepath.Join(state.directory, "workload.key")
	if existing, err := readWorkloadKey(path, state.directory); err == nil {
		if len(proposed) != 0 && !bytes.Equal(existing, proposed) {
			return nil, errKeyStoreInvalid()
		}
		return existing, nil
	} else if _, statErr := os.Lstat(path); statErr == nil || !os.IsNotExist(statErr) {
		return nil, err
	}
	key := proposed
	if len(key) == 0 {
		key = make([]byte, workloadKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return nil, errKeyStoreUnavailable()
		}
	}
	if len(key) != workloadKeyBytes {
		return nil, errKeyStoreInvalid()
	}
	if err := atomicCreateManagedState(path, key, managedRegistrationReceiptBytes); err != nil {
		if os.IsExist(err) {
			return state.loadOrCreateKey(proposed)
		}
		return nil, err
	}
	return bytes.Clone(key), nil
}

func (state *ManagedWorkloadIdentityState) loadOrCreateSignedAt(
	bindingDigest string, proposedSignedAt string,
) (string, error) {
	if !validDigest(bindingDigest) || !validTimestamp(proposedSignedAt) {
		return "", errDeploymentMetadataInvalid()
	}
	path := filepath.Join(state.directory, "deployment.json")
	if metadata, found, err := readDeploymentMetadata(path); err != nil {
		return "", err
	} else if found {
		if metadata["binding_digest"] != bindingDigest {
			return "", errDeploymentMetadataScope()
		}
		return metadata["signed_at"].(string), nil
	}
	metadata := map[string]any{
		"binding_digest": bindingDigest,
		"format":         1,
		"signed_at":      proposedSignedAt,
	}
	encoded, err := CanonicalBytes(metadata)
	if err != nil || len(encoded) > managedDeploymentMetadataBytes {
		return "", errDeploymentMetadataInvalid()
	}
	if err := atomicCreateManagedState(path, encoded, managedDeploymentMetadataBytes); err != nil {
		if os.IsExist(err) {
			return state.loadOrCreateSignedAt(bindingDigest, proposedSignedAt)
		}
		return "", err
	}
	return proposedSignedAt, nil
}

func (state *ManagedWorkloadIdentityState) loadRegistrationReceipt(
	expected ManagedWorkloadRegistrationReceipt,
) (bool, error) {
	if err := validateRegistrationReceipt(expected); err != nil {
		return false, err
	}
	path := filepath.Join(state.directory, "registration.json")
	value, found, err := readCanonicalState(path, managedRegistrationReceiptBytes)
	if err != nil || !found {
		return false, err
	}
	receipt, err := registrationReceiptFromValue(value)
	if err != nil {
		return false, err
	}
	if receipt != expected {
		return false, errRegistrationReceiptScope()
	}
	return true, nil
}

func (state *ManagedWorkloadIdentityState) persistRegistrationReceipt(
	receipt ManagedWorkloadRegistrationReceipt,
) error {
	if err := validateRegistrationReceipt(receipt); err != nil {
		return err
	}
	value := map[string]any{
		"deployment_digest": receipt.DeploymentDigest,
		"service_id":        receipt.ServiceID,
		"workload_key_id":   receipt.WorkloadKeyID,
	}
	encoded, err := CanonicalBytes(value)
	if err != nil || len(encoded) > managedRegistrationReceiptBytes {
		return errRegistrationReceiptInvalid()
	}
	path := filepath.Join(state.directory, "registration.json")
	if err := atomicCreateManagedState(path, encoded, managedRegistrationReceiptBytes); err != nil {
		if os.IsExist(err) {
			matched, loadErr := state.loadRegistrationReceipt(receipt)
			if loadErr != nil {
				return loadErr
			}
			if matched {
				return nil
			}
		}
		return err
	}
	return nil
}

func readDeploymentMetadata(path string) (map[string]any, bool, error) {
	value, found, err := readCanonicalState(path, managedDeploymentMetadataBytes)
	if err != nil || !found {
		return nil, found, err
	}
	metadata, ok := value.(map[string]any)
	format, formatOK := integerValue(metadataValue(metadata, "format"))
	if !ok || !hasExactKeys(metadata, "binding_digest", "format", "signed_at") ||
		!formatOK || format != 1 || !validDigest(metadata["binding_digest"]) ||
		!validTimestamp(metadata["signed_at"]) {
		return nil, false, errDeploymentMetadataInvalid()
	}
	return metadata, true, nil
}

func readCanonicalState(path string, maximumBytes int) (any, bool, error) {
	metadata, err := os.Lstat(path)
	parentMetadata, parentErr := os.Stat(filepath.Dir(path))
	fileStat, fileStatOK := metadataStat(metadata)
	parentStat, parentStatOK := metadataStat(parentMetadata)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil || !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Mode().Perm()&0o077 != 0 || metadata.Size() <= 0 ||
		metadata.Size() > int64(maximumBytes) || parentErr != nil ||
		!fileStatOK || !parentStatOK || fileStat.Uid != parentStat.Uid {
		return nil, false, errRegistrationReceiptInvalid()
	}
	encoded, err := os.ReadFile(path)
	if err != nil || int64(len(encoded)) != metadata.Size() {
		return nil, false, errRegistrationReceiptInvalid()
	}
	value, err := parseStrictJSON(encoded, maximumBytes)
	if err != nil {
		return nil, false, errRegistrationReceiptInvalid()
	}
	canonical, err := CanonicalBytes(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, false, errRegistrationReceiptInvalid()
	}
	return value, true, nil
}

func metadataStat(metadata os.FileInfo) (*syscall.Stat_t, bool) {
	if metadata == nil {
		return nil, false
	}
	value, ok := metadata.Sys().(*syscall.Stat_t)
	return value, ok
}

func registrationReceiptFromValue(value any) (ManagedWorkloadRegistrationReceipt, error) {
	receipt, ok := value.(map[string]any)
	if !ok || !hasExactKeys(receipt, "deployment_digest", "service_id", "workload_key_id") {
		return ManagedWorkloadRegistrationReceipt{}, errRegistrationReceiptInvalid()
	}
	deploymentDigest, deploymentDigestOK := receipt["deployment_digest"].(string)
	serviceID, serviceIDOK := receipt["service_id"].(string)
	workloadKeyID, workloadKeyIDOK := receipt["workload_key_id"].(string)
	if !deploymentDigestOK || !serviceIDOK || !workloadKeyIDOK {
		return ManagedWorkloadRegistrationReceipt{}, errRegistrationReceiptInvalid()
	}
	result := ManagedWorkloadRegistrationReceipt{
		DeploymentDigest: deploymentDigest,
		ServiceID:        serviceID,
		WorkloadKeyID:    workloadKeyID,
	}
	if err := validateRegistrationReceipt(result); err != nil {
		return ManagedWorkloadRegistrationReceipt{}, err
	}
	return result, nil
}

func metadataValue(metadata map[string]any, key string) any {
	if metadata == nil {
		return nil
	}
	return metadata[key]
}

func validateRegistrationReceipt(receipt ManagedWorkloadRegistrationReceipt) error {
	if !validDigest(receipt.DeploymentDigest) ||
		!validTypedID(receipt.ServiceID, "service_id") ||
		!validManagedWorkloadKeyID(receipt.WorkloadKeyID) {
		return errRegistrationReceiptInvalid()
	}
	return nil
}

func atomicCreateManagedState(path string, value []byte, maximumBytes int) error {
	if len(value) == 0 || len(value) > maximumBytes {
		return errRegistrationReceiptInvalid()
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(value); err != nil {
		return errStateRootUnavailable()
	}
	if err := file.Sync(); err != nil {
		return errStateRootUnavailable()
	}
	if err := file.Close(); err != nil {
		return errStateRootUnavailable()
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errStateRootUnavailable()
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return errStateRootUnavailable()
	}
	if err := directory.Close(); err != nil {
		return errStateRootUnavailable()
	}
	remove = false
	return nil
}

func errStateRootInvalid() *ManagedError {
	return newManagedError("CONFIG_CONFLICT", "The managed workload state directory is invalid.")
}

func errStateRootUnavailable() *ManagedError {
	return newManagedError("SERVICE_UNAVAILABLE", "The managed workload state is unavailable.")
}

func errDeploymentMetadataInvalid() *ManagedError {
	return newManagedError("CONFIG_CONFLICT", "The managed deployment state is invalid.")
}

func errDeploymentMetadataScope() *ManagedError {
	return newManagedError("AUTHORIZATION_DENIED", "The managed deployment state has another scope.")
}

func errRegistrationReceiptInvalid() *ManagedError {
	return newManagedError("CONFIG_CONFLICT", "The managed workload registration state is invalid.")
}

func errRegistrationReceiptScope() *ManagedError {
	return newManagedError(
		"AUTHORIZATION_DENIED", "The managed workload registration has another scope.",
	)
}
