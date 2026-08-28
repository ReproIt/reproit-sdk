package reproit

import "sync"

const (
	automaticNativeGuardAdapterID      = "go-native-sentinel-guard"
	automaticNativeGuardAdapterVersion = "1.0.0"
	automaticNativeGuardLeases         = 64
)

var automaticNativeGuardClasses = [...]automaticObservationClass{
	observationDatabase,
	observationFilesystem,
	observationQueue,
}

type automaticNativeGuardLease struct {
	once sync.Once
}

type automaticNativeGuardState struct {
	adapters   []installedObservationAdapter
	mu         sync.Mutex
	references int
}

var automaticNativeGuards automaticNativeGuardState

func acquireAutomaticNativeGuards(implementationDigest string) *automaticNativeGuardLease {
	automaticNativeGuards.mu.Lock()
	defer automaticNativeGuards.mu.Unlock()
	if automaticNativeGuards.references >= automaticNativeGuardLeases {
		return nil
	}
	if automaticNativeGuards.references > 0 {
		if !automaticNativeGuardsHealthyLocked(implementationDigest) {
			return nil
		}
		automaticNativeGuards.references++
		return &automaticNativeGuardLease{}
	}
	adapters := make([]installedObservationAdapter, 0, len(automaticNativeGuardClasses))
	for _, class := range automaticNativeGuardClasses {
		adapter := installedObservationAdapter{
			adapterID:            automaticNativeGuardAdapterID,
			adapterVersion:       automaticNativeGuardAdapterVersion,
			class:                class,
			implementationDigest: implementationDigest,
		}
		if installedObservationAdapters.install(adapter) != nil {
			for _, installed := range adapters {
				installedObservationAdapters.remove(installed)
			}
			return nil
		}
		adapters = append(adapters, adapter)
	}
	automaticNativeGuards.adapters = adapters
	automaticNativeGuards.references = 1
	return &automaticNativeGuardLease{}
}

func (lease *automaticNativeGuardLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		automaticNativeGuards.mu.Lock()
		defer automaticNativeGuards.mu.Unlock()
		if automaticNativeGuards.references == 0 {
			return
		}
		automaticNativeGuards.references--
		if automaticNativeGuards.references != 0 {
			return
		}
		for _, adapter := range automaticNativeGuards.adapters {
			installedObservationAdapters.remove(adapter)
		}
		automaticNativeGuards.adapters = nil
	})
}

func (lease *automaticNativeGuardLease) healthy() bool {
	if lease == nil {
		return false
	}
	automaticNativeGuards.mu.Lock()
	defer automaticNativeGuards.mu.Unlock()
	if automaticNativeGuards.references == 0 || len(automaticNativeGuards.adapters) == 0 {
		return false
	}
	return automaticNativeGuardsHealthyLocked(
		automaticNativeGuards.adapters[0].implementationDigest,
	)
}

func automaticNativeGuardsHealthyLocked(implementationDigest string) bool {
	if len(automaticNativeGuards.adapters) != len(automaticNativeGuardClasses) {
		return false
	}
	registrations := installedObservationAdapters.snapshot()
	for index, class := range automaticNativeGuardClasses {
		adapter := automaticNativeGuards.adapters[index]
		if adapter.adapterID != automaticNativeGuardAdapterID ||
			adapter.adapterVersion != automaticNativeGuardAdapterVersion ||
			adapter.class != class || adapter.implementationDigest != implementationDigest {
			return false
		}
		found := false
		for _, registration := range registrations {
			if registration.AdapterID == adapter.adapterID &&
				registration.AdapterVersion == adapter.adapterVersion &&
				registration.Class == string(adapter.class) &&
				registration.ImplementationDigest == adapter.implementationDigest {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
