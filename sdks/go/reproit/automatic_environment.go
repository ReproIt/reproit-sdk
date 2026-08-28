package reproit

import "sync"

const (
	automaticEnvironmentAdapterID      = "go-syscall-build-instrumentation"
	automaticEnvironmentAdapterVersion = "1.0.0"
	automaticEnvironmentLeases         = 64
)

var automaticEnvironmentUnsupportedEvidence = []byte("go-environment-mutation-v1")

type automaticEnvironmentAdapterLease struct {
	once sync.Once
}

type automaticEnvironmentLeaseState struct {
	adapter     installedObservationAdapter
	clearenv    func()
	hookInvalid bool
	mu          sync.Mutex
	references  int
	setenv      func(string, string) error
	unsetenv    func(string) error
}

var automaticEnvironmentState automaticEnvironmentLeaseState

// The instrumented standard package calls this function during package initialization.
func registerAutomaticEnvironmentInstrumentationV1(
	setenv func(string, string) error,
	unsetenv func(string) error,
	clearenv func(),
) {
	automaticEnvironmentState.mu.Lock()
	defer automaticEnvironmentState.mu.Unlock()
	if setenv == nil || unsetenv == nil || clearenv == nil ||
		automaticEnvironmentState.setenv != nil {
		automaticEnvironmentState.hookInvalid = true
		return
	}
	automaticEnvironmentState.setenv = setenv
	automaticEnvironmentState.unsetenv = unsetenv
	automaticEnvironmentState.clearenv = clearenv
}

func acquireAutomaticEnvironmentAdapter(
	implementationDigest string,
) *automaticEnvironmentAdapterLease {
	adapter := installedObservationAdapter{
		adapterID:            automaticEnvironmentAdapterID,
		adapterVersion:       automaticEnvironmentAdapterVersion,
		class:                observationEnvironment,
		implementationDigest: implementationDigest,
	}
	automaticEnvironmentState.mu.Lock()
	defer automaticEnvironmentState.mu.Unlock()
	if !automaticEnvironmentHookHealthyLocked() ||
		automaticEnvironmentState.references >= automaticEnvironmentLeases {
		return nil
	}
	if automaticEnvironmentState.references == 0 {
		if installedObservationAdapters.install(adapter) != nil {
			return nil
		}
		automaticEnvironmentState.adapter = adapter
	} else if automaticEnvironmentState.adapter != adapter {
		return nil
	}
	automaticEnvironmentState.references++
	return &automaticEnvironmentAdapterLease{}
}

func (lease *automaticEnvironmentAdapterLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		automaticEnvironmentState.mu.Lock()
		defer automaticEnvironmentState.mu.Unlock()
		if automaticEnvironmentState.references == 0 {
			return
		}
		automaticEnvironmentState.references--
		if automaticEnvironmentState.references == 0 {
			installedObservationAdapters.remove(automaticEnvironmentState.adapter)
			automaticEnvironmentState.adapter = installedObservationAdapter{}
		}
	})
}

func (lease *automaticEnvironmentAdapterLease) healthy() bool {
	if lease == nil {
		return false
	}
	automaticEnvironmentState.mu.Lock()
	defer automaticEnvironmentState.mu.Unlock()
	return automaticEnvironmentState.references > 0 &&
		automaticEnvironmentHookHealthyLocked()
}

func automaticEnvironmentHookHealthyLocked() bool {
	return !automaticEnvironmentState.hookInvalid &&
		automaticEnvironmentState.setenv != nil &&
		automaticEnvironmentState.unsetenv != nil &&
		automaticEnvironmentState.clearenv != nil
}

func instrumentedSetenv(key string, value string) error {
	setenv, _, _ := automaticEnvironmentFunctions()
	if setenv == nil {
		panic(ErrAutomaticCapture)
	}
	err := setenv(key, value)
	if err == nil {
		markAutomaticEnvironmentMutation()
	}
	return err
}

func instrumentedUnsetenv(key string) error {
	_, unsetenv, _ := automaticEnvironmentFunctions()
	if unsetenv == nil {
		panic(ErrAutomaticCapture)
	}
	err := unsetenv(key)
	if err == nil {
		markAutomaticEnvironmentMutation()
	}
	return err
}

func instrumentedClearenv() {
	_, _, clearenv := automaticEnvironmentFunctions()
	if clearenv == nil {
		panic(ErrAutomaticCapture)
	}
	clearenv()
	markAutomaticEnvironmentMutation()
}

func automaticEnvironmentFunctions() (
	func(string, string) error,
	func(string) error,
	func(),
) {
	automaticEnvironmentState.mu.Lock()
	defer automaticEnvironmentState.mu.Unlock()
	if !automaticEnvironmentHookHealthyLocked() {
		return nil, nil, nil
	}
	return automaticEnvironmentState.setenv,
		automaticEnvironmentState.unsetenv,
		automaticEnvironmentState.clearenv
}

func markAutomaticEnvironmentMutation() {
	for _, operation := range snapshotAutomaticOperations() {
		_ = operation.markUnowned(
			observationEnvironment,
			nil,
			automaticEnvironmentUnsupportedEvidence,
		)
	}
}
