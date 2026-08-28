package reproit

type automaticAdapterLeases struct {
	clock        *automaticClockAdapterLease
	environment  *automaticEnvironmentAdapterLease
	http         *automaticHTTPAdapterLease
	nativeGuards *automaticNativeGuardLease
	random       *automaticRandomAdapterLease
}

type automaticAdapterHealth struct {
	class   automaticObservationClass
	healthy bool
}

func acquireAutomaticAdapters(implementationDigest string) *automaticAdapterLeases {
	leases := &automaticAdapterLeases{}
	leases.http = acquireAutomaticHTTPAdapter(implementationDigest)
	if leases.http == nil {
		return nil
	}
	leases.random = acquireAutomaticRandomAdapter(implementationDigest)
	if leases.random == nil {
		leases.release()
		return nil
	}
	leases.clock = acquireAutomaticClockAdapter(implementationDigest)
	if leases.clock == nil {
		leases.release()
		return nil
	}
	leases.environment = acquireAutomaticEnvironmentAdapter(implementationDigest)
	if leases.environment == nil {
		leases.release()
		return nil
	}
	leases.nativeGuards = acquireAutomaticNativeGuards(implementationDigest)
	if leases.nativeGuards == nil {
		leases.release()
		return nil
	}
	return leases
}

func (leases *automaticAdapterLeases) release() {
	if leases == nil {
		return
	}
	leases.nativeGuards.release()
	leases.nativeGuards = nil
	leases.environment.release()
	leases.environment = nil
	leases.clock.release()
	leases.clock = nil
	leases.random.release()
	leases.random = nil
	leases.http.release()
	leases.http = nil
}

func (leases *automaticAdapterLeases) health() [7]automaticAdapterHealth {
	if leases == nil {
		return [7]automaticAdapterHealth{
			{class: observationClock, healthy: true},
			{class: observationDatabase, healthy: true},
			{class: observationEnvironment, healthy: true},
			{class: observationFilesystem, healthy: true},
			{class: observationOutboundHTTP, healthy: true},
			{class: observationQueue, healthy: true},
			{class: observationRandomness, healthy: true},
		}
	}
	guardsHealthy := leases.nativeGuards == nil || leases.nativeGuards.healthy()
	return [7]automaticAdapterHealth{
		{observationClock, leases.clock == nil || leases.clock.healthy()},
		{observationDatabase, guardsHealthy},
		{observationEnvironment, leases.environment == nil || leases.environment.healthy()},
		{observationFilesystem, guardsHealthy},
		{observationOutboundHTTP, leases.http == nil || leases.http.healthy()},
		{observationQueue, guardsHealthy},
		{observationRandomness, leases.random == nil || leases.random.healthy()},
	}
}
