package reproit

import (
	"strings"
	"testing"
)

func TestAutomaticNativeGuardsInstallEveryUnownedClassOnce(t *testing.T) {
	first := acquireAutomaticNativeGuards(automaticRandomTestDigest)
	second := acquireAutomaticNativeGuards(automaticRandomTestDigest)
	if first == nil || second == nil || !first.healthy() || !second.healthy() {
		t.Fatal("The native guards did not install one shared adapter group.")
	}
	registrations := installedObservationAdapters.snapshot()
	if len(registrations) != len(automaticNativeGuardClasses) {
		t.Fatal("The native guards did not register every guarded class.")
	}
	for _, class := range automaticNativeGuardClasses {
		found := false
		for _, registration := range registrations {
			if registration.Class == string(class) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("The native guards did not register %s.", class)
		}
	}
	first.release()
	if !second.healthy() {
		t.Fatal("The first native guard lease removed the shared adapters.")
	}
	second.release()
	if len(installedObservationAdapters.snapshot()) != 0 {
		t.Fatal("The final native guard lease retained registrations.")
	}
}

func TestAutomaticNativeGuardsRejectChangedIdentityAndRegistryDrift(t *testing.T) {
	lease := acquireAutomaticNativeGuards(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The native guard lease was not installed.")
	}
	defer lease.release()
	if acquireAutomaticNativeGuards("sha256:"+strings.Repeat("b", 64)) != nil {
		t.Fatal("The native guards accepted a changed implementation identity.")
	}
	installedObservationAdapters.remove(automaticNativeGuards.adapters[0])
	if lease.healthy() {
		t.Fatal("The native guards accepted a missing class registration.")
	}
}
