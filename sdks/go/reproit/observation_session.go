package reproit

import "sync"

type observationAction string
type observationOutcome string
type observationSessionState uint8

const (
	observationCapture observationAction = "capture"
	observationReplay  observationAction = "replay"

	observationError    observationOutcome = "error"
	observationResponse observationOutcome = "response"

	observationRequestState observationSessionState = iota
	observationCaptureState
	observationReplayState
	observationReplayEOFState
	observationFinishedState
)

type installedObservationAdapter struct {
	adapterID            string
	adapterVersion       string
	class                automaticObservationClass
	implementationDigest string
}

type observationAdapterRegistry struct {
	mu       sync.RWMutex
	adapters map[automaticObservationClass]installedObservationAdapter
}

var installedObservationAdapters observationAdapterRegistry

func (registry *observationAdapterRegistry) install(adapter installedObservationAdapter) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if adapter.adapterID == "" || adapter.adapterVersion == "" || adapter.implementationDigest == "" ||
		len(registry.adapters) >= sdkEngineMaxObservationAdapters {
		return ErrAutomaticCapture
	}
	if registry.adapters == nil {
		registry.adapters = make(map[automaticObservationClass]installedObservationAdapter)
	}
	if _, exists := registry.adapters[adapter.class]; exists {
		return ErrAutomaticCapture
	}
	registry.adapters[adapter.class] = adapter
	return nil
}

func (registry *observationAdapterRegistry) remove(adapter installedObservationAdapter) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if installed, exists := registry.adapters[adapter.class]; exists && installed == adapter {
		delete(registry.adapters, adapter.class)
	}
}

func (registry *observationAdapterRegistry) snapshot() []sdkEngineObservationAdapter {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	result := make([]sdkEngineObservationAdapter, 0, len(registry.adapters))
	for _, class := range sdkEngineRequiredObservationClasses {
		adapter, exists := registry.adapters[class]
		if !exists {
			continue
		}
		result = append(result, sdkEngineObservationAdapter{
			AdapterID: adapter.adapterID, AdapterVersion: adapter.adapterVersion,
			Class: string(adapter.class), ImplementationDigest: adapter.implementationDigest,
		})
	}
	return result
}

type observationSession struct {
	bridge          *sdkEngineBridge
	handle          sdkEngineObservationHandle
	mu              sync.Mutex
	requestBytes    uint64
	responseBytes   uint64
	sessionPosition uint64
	state           observationSessionState
}

func (operation *AutomaticOperation) openObservationSession(
	class automaticObservationClass,
	causalParentID *string,
) (*observationSession, error) {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.finished || operation.worldComplete {
		return nil, ErrAutomaticCapture
	}
	started, err := operation.project.bridge.openObservation(
		operation.handle, string(class), causalParentID,
	)
	if err != nil {
		operation.abandonLocked()
		return nil, ErrAutomaticCapture
	}
	return &observationSession{
		bridge: operation.project.bridge, handle: started.Handle,
		sessionPosition: started.SessionPosition, state: observationRequestState,
	}, nil
}

func (session *observationSession) writeRequest(chunk []byte) error {
	return session.write("request", chunk, observationRequestState)
}

func (session *observationSession) writeResponse(chunk []byte) error {
	return session.write("response", chunk, observationCaptureState)
}

func (session *observationSession) write(
	stream string, chunk []byte, required observationSessionState,
) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state != required || len(chunk) == 0 || len(chunk) > sdkEngineMaxObservationChunkBytes {
		return ErrAutomaticCapture
	}
	if session.bridge.writeObservation(session.handle, stream, chunk) != nil {
		session.abandonLocked()
		return ErrAutomaticCapture
	}
	if stream == "request" {
		session.requestBytes += uint64(len(chunk))
	} else {
		session.responseBytes += uint64(len(chunk))
	}
	return nil
}

func (session *observationSession) dispatch() (observationAction, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state != observationRequestState || session.requestBytes == 0 {
		return "", ErrAutomaticCapture
	}
	action, err := session.bridge.dispatchObservation(session.handle)
	if err != nil {
		session.abandonLocked()
		return "", ErrAutomaticCapture
	}
	switch observationAction(action) {
	case observationCapture:
		session.state = observationCaptureState
	case observationReplay:
		session.state = observationReplayState
	default:
		session.abandonLocked()
		return "", ErrAutomaticCapture
	}
	return observationAction(action), nil
}

func (session *observationSession) readResponse() ([]byte, bool, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state != observationReplayState {
		return nil, false, ErrAutomaticCapture
	}
	result, err := session.bridge.readObservation(session.handle)
	if err != nil {
		session.abandonLocked()
		return nil, false, ErrAutomaticCapture
	}
	if result.EOF {
		session.state = observationReplayEOFState
	}
	return result.Chunk, result.EOF, nil
}

func (session *observationSession) finish(outcome observationOutcome) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	valid := session.state == observationCaptureState && session.responseBytes > 0
	valid = valid || session.state == observationReplayEOFState
	if !valid || (outcome != observationError && outcome != observationResponse) {
		return ErrAutomaticCapture
	}
	if session.bridge.finishObservation(
		session.handle, string(outcome), session.sessionPosition,
	) != nil {
		session.abandonLocked()
		return ErrAutomaticCapture
	}
	session.state = observationFinishedState
	return nil
}

func (session *observationSession) abandon() {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.abandonLocked()
}

func (session *observationSession) abandonLocked() {
	if session.state == observationFinishedState {
		return
	}
	_ = session.bridge.abandonObservation(session.handle)
	session.state = observationFinishedState
}
