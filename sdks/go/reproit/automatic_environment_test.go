package reproit

import (
	"errors"
	"testing"
)

func TestAutomaticEnvironmentLeaseRequiresInstalledHooks(t *testing.T) {
	restoreAutomaticEnvironmentState(t)
	if acquireAutomaticEnvironmentAdapter(automaticRandomTestDigest) != nil {
		t.Fatal("The environment adapter accepted missing build hooks.")
	}
}

func TestAutomaticEnvironmentLeaseInstallsNestsAndReleases(t *testing.T) {
	installAutomaticEnvironmentTestHooks(t, nil, nil, nil)
	first := acquireAutomaticEnvironmentAdapter(automaticRandomTestDigest)
	second := acquireAutomaticEnvironmentAdapter(automaticRandomTestDigest)
	if first == nil || second == nil || !first.healthy() || !second.healthy() {
		t.Fatal("The environment adapter did not install verified hooks.")
	}
	registrations := installedObservationAdapters.snapshot()
	if len(registrations) != 1 || registrations[0].Class != string(observationEnvironment) {
		t.Fatal("The environment adapter did not register its observation class.")
	}
	first.release()
	if !second.healthy() {
		t.Fatal("The first environment lease removed the shared hooks.")
	}
	second.release()
	if len(installedObservationAdapters.snapshot()) != 0 {
		t.Fatal("The final environment lease retained its registration.")
	}
}

func TestAutomaticEnvironmentMutationPreservesResultsAndMarksOperations(t *testing.T) {
	wantError := errors.New("invalid environment name")
	setCalls := 0
	unsetCalls := 0
	clearCalls := 0
	installAutomaticEnvironmentTestHooks(
		t,
		func(string, string) error {
			setCalls++
			return nil
		},
		func(string) error {
			unsetCalls++
			return wantError
		},
		func() { clearCalls++ },
	)
	lease := acquireAutomaticEnvironmentAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The environment adapter lease was not installed.")
	}
	unowned := 0
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		if request["operation"] == sdkEngineOperationUnowned {
			unowned++
		}
		return `{}`
	})
	project.automaticAdapters = &automaticAdapterLeases{environment: lease}
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	if err := instrumentedSetenv("REGION", "west"); err != nil {
		t.Fatal("The environment adapter changed a successful set result.")
	}
	if err := instrumentedUnsetenv("INVALID"); !errors.Is(err, wantError) {
		t.Fatal("The environment adapter changed an unsuccessful unset result.")
	}
	instrumentedClearenv()
	if setCalls != 1 || unsetCalls != 1 || clearCalls != 1 || unowned != 2 {
		t.Fatal("The environment adapter did not mark each successful mutation.")
	}
}

func installAutomaticEnvironmentTestHooks(
	t *testing.T,
	setenv func(string, string) error,
	unsetenv func(string) error,
	clearenv func(),
) {
	t.Helper()
	restoreAutomaticEnvironmentState(t)
	if setenv == nil {
		setenv = func(string, string) error { return nil }
	}
	if unsetenv == nil {
		unsetenv = func(string) error { return nil }
	}
	if clearenv == nil {
		clearenv = func() {}
	}
	registerAutomaticEnvironmentInstrumentationV1(setenv, unsetenv, clearenv)
}

func restoreAutomaticEnvironmentState(t *testing.T) {
	t.Helper()
	automaticEnvironmentState.mu.Lock()
	if automaticEnvironmentState.references != 0 {
		automaticEnvironmentState.mu.Unlock()
		t.Fatal("An environment adapter lease leaked from another test.")
	}
	previousInvalid := automaticEnvironmentState.hookInvalid
	previousSetenv := automaticEnvironmentState.setenv
	previousUnsetenv := automaticEnvironmentState.unsetenv
	previousClearenv := automaticEnvironmentState.clearenv
	automaticEnvironmentState.hookInvalid = false
	automaticEnvironmentState.setenv = nil
	automaticEnvironmentState.unsetenv = nil
	automaticEnvironmentState.clearenv = nil
	automaticEnvironmentState.mu.Unlock()
	t.Cleanup(func() {
		automaticEnvironmentState.mu.Lock()
		defer automaticEnvironmentState.mu.Unlock()
		automaticEnvironmentState.hookInvalid = previousInvalid
		automaticEnvironmentState.setenv = previousSetenv
		automaticEnvironmentState.unsetenv = previousUnsetenv
		automaticEnvironmentState.clearenv = previousClearenv
	})
}
