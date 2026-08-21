// Managed workload identity: a protected local Ed25519 key file.
//
// Mirrors crates/reproit-sdk-rust/src/managed_identity.rs. The key file holds
// exactly 32 secret bytes with mode 0600 inside a directory that group and
// other users cannot write. Every deviation fails closed.
package reproit

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const workloadKeyBytes = 32

// LoadOrCreateManagedWorkloadKey creates or loads the 32-byte managed
// workload signing key at path.
func LoadOrCreateManagedWorkloadKey(path string) ([]byte, error) {
	parent := filepath.Dir(path)
	if parent == "" || parent == "." {
		return nil, errKeyStoreInvalid()
	}
	if err := validateKeyParent(parent); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return readWorkloadKey(path, parent)
		}
		return nil, errKeyStoreUnavailable()
	}
	key := make([]byte, workloadKeyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		_ = file.Close()
		return nil, errKeyStoreUnavailable()
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return nil, errKeyStoreUnavailable()
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, errKeyStoreUnavailable()
	}
	if err := file.Close(); err != nil {
		return nil, errKeyStoreUnavailable()
	}
	if err := validateKeyFile(path, parent); err != nil {
		return nil, err
	}
	return key, nil
}

func readWorkloadKey(path, parent string) ([]byte, error) {
	if err := validateKeyFile(path, parent); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errKeyStoreUnavailable()
	}
	defer file.Close()
	key := make([]byte, workloadKeyBytes)
	if _, err := io.ReadFull(file, key); err != nil {
		return nil, errKeyStoreInvalid()
	}
	trailing := make([]byte, 1)
	if count, _ := file.Read(trailing); count != 0 {
		return nil, errKeyStoreInvalid()
	}
	return key, nil
}

func validateKeyParent(parent string) error {
	metadata, err := os.Lstat(parent)
	if err != nil {
		return errKeyStoreInvalid()
	}
	if !metadata.IsDir() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Mode().Perm()&0o022 != 0 {
		return errKeyStoreInvalid()
	}
	return nil
}

func validateKeyFile(path, parent string) error {
	metadata, err := os.Lstat(path)
	if err != nil {
		return errKeyStoreInvalid()
	}
	parentMetadata, err := os.Stat(parent)
	if err != nil {
		return errKeyStoreInvalid()
	}
	fileStat, fileStatOK := metadata.Sys().(*syscall.Stat_t)
	parentStat, parentStatOK := parentMetadata.Sys().(*syscall.Stat_t)
	if !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Size() != workloadKeyBytes ||
		metadata.Mode().Perm()&0o077 != 0 ||
		!fileStatOK || !parentStatOK || fileStat.Uid != parentStat.Uid {
		return errKeyStoreInvalid()
	}
	return nil
}

func errKeyStoreInvalid() *ManagedError {
	return newManagedError(
		"CONFIG_CONFLICT", "The managed workload key file is not private or valid.",
	)
}

func errKeyStoreUnavailable() *ManagedError {
	return newManagedError(
		"SERVICE_UNAVAILABLE", "The managed workload key file is unavailable.",
	)
}
