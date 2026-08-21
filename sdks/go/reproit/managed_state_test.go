package reproit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedWorkloadStatePersistsIdentityMetadataAndReceipt(t *testing.T) {
	root := t.TempDir()
	bindingDigest := digestBytes([]byte("go-deployment-binding"))
	state, err := newManagedWorkloadIdentityState(root, bindingDigest)
	if err != nil {
		t.Fatalf("create workload state: %v", err)
	}
	key, err := state.loadOrCreateKey(fixtureWorkloadSeed)
	if err != nil {
		t.Fatalf("persist workload key: %v", err)
	}
	restarted, err := newManagedWorkloadIdentityState(root, bindingDigest)
	if err != nil {
		t.Fatalf("open workload state after restart: %v", err)
	}
	reloaded, err := restarted.loadOrCreateKey(nil)
	if err != nil || string(reloaded) != string(key) {
		t.Fatalf("reload workload key: %v", err)
	}
	firstSignedAt := "2026-01-01T00:00:00.000Z"
	signedAt, err := state.loadOrCreateSignedAt(bindingDigest, firstSignedAt)
	if err != nil || signedAt != firstSignedAt {
		t.Fatalf("persist signed_at: %s, %v", signedAt, err)
	}
	signedAt, err = restarted.loadOrCreateSignedAt(
		bindingDigest, "2026-01-02T00:00:00.000Z",
	)
	if err != nil || signedAt != firstSignedAt {
		t.Fatalf("reuse signed_at: %s, %v", signedAt, err)
	}
	receipt := ManagedWorkloadRegistrationReceipt{
		DeploymentDigest: digestBytes([]byte("signed-go-deployment")),
		ServiceID:        fixtureServiceID,
		WorkloadKeyID:    fixtureWorkloadKeyID,
	}
	if found, err := state.loadRegistrationReceipt(receipt); err != nil || found {
		t.Fatalf("unexpected registration receipt: %t, %v", found, err)
	}
	if err := state.persistRegistrationReceipt(receipt); err != nil {
		t.Fatalf("persist registration receipt: %v", err)
	}
	if found, err := restarted.loadRegistrationReceipt(receipt); err != nil || !found {
		t.Fatalf("reload registration receipt: %t, %v", found, err)
	}
	for _, name := range []string{"workload.key", "deployment.json", "registration.json"} {
		metadata, err := os.Stat(filepath.Join(state.directory, name))
		if err != nil || metadata.Mode().Perm() != 0o600 {
			t.Fatalf("state file %s permissions %v, %v", name, metadata.Mode().Perm(), err)
		}
	}
}

func TestManagedWorkloadStateRejectsCorruptionScopeDriftAndBounds(t *testing.T) {
	root := t.TempDir()
	bindingDigest := digestBytes([]byte("go-deployment-binding"))
	state, err := newManagedWorkloadIdentityState(root, bindingDigest)
	if err != nil {
		t.Fatalf("create workload state: %v", err)
	}
	receipt := ManagedWorkloadRegistrationReceipt{
		DeploymentDigest: digestBytes([]byte("signed-go-deployment")),
		ServiceID:        fixtureServiceID,
		WorkloadKeyID:    fixtureWorkloadKeyID,
	}
	if err := state.persistRegistrationReceipt(receipt); err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	mismatch := receipt
	mismatch.DeploymentDigest = digestBytes([]byte("other-deployment"))
	if _, err := state.loadRegistrationReceipt(mismatch); managedErrorCode(t, err) !=
		"AUTHORIZATION_DENIED" {
		t.Fatalf("scope mismatch: %v", err)
	}
	receiptPath := filepath.Join(state.directory, "registration.json")
	if err := os.WriteFile(
		receiptPath, []byte(strings.Repeat("a", managedRegistrationReceiptBytes+1)), 0o600,
	); err != nil {
		t.Fatalf("write oversized receipt: %v", err)
	}
	if _, err := state.loadRegistrationReceipt(receipt); managedErrorCode(t, err) !=
		"CONFIG_CONFLICT" {
		t.Fatalf("oversized receipt: %v", err)
	}
}

func TestManagedWorkloadStateRejectsLinksAndOpenPermissions(t *testing.T) {
	root := t.TempDir()
	bindingDigest := digestBytes([]byte("go-deployment-binding"))
	state, err := newManagedWorkloadIdentityState(root, bindingDigest)
	if err != nil {
		t.Fatalf("create workload state: %v", err)
	}
	if _, err := state.loadOrCreateKey(fixtureWorkloadSeed); err != nil {
		t.Fatalf("persist workload key: %v", err)
	}
	keyPath := filepath.Join(state.directory, "workload.key")
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatalf("open workload key permissions: %v", err)
	}
	if _, err := state.loadOrCreateKey(nil); managedErrorCode(t, err) != "CONFIG_CONFLICT" {
		t.Fatalf("open workload key: %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove workload key: %v", err)
	}
	target := filepath.Join(state.directory, "target.key")
	if err := os.WriteFile(target, fixtureWorkloadSeed, 0o600); err != nil {
		t.Fatalf("write workload key target: %v", err)
	}
	if err := os.Symlink(target, keyPath); err != nil {
		t.Fatalf("link workload key: %v", err)
	}
	if _, err := state.loadOrCreateKey(nil); managedErrorCode(t, err) != "CONFIG_CONFLICT" {
		t.Fatalf("linked workload key: %v", err)
	}
}
