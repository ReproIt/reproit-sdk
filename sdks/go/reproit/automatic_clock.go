package reproit

import (
	"encoding/binary"
	"runtime"
	"sync"
	"time"
)

const (
	automaticClockAdapterID      = "go-time-build-instrumentation"
	automaticClockAdapterVersion = "1.0.0"
	automaticClockLeases         = 64
	automaticClockValueBytes     = 8
)

var automaticClockUnsupportedEvidence = []byte("go-clock-unsupported-v1")

type automaticClockAdapterLease struct {
	once sync.Once
}

type automaticClockLeaseState struct {
	adapter     installedObservationAdapter
	hookInvalid bool
	mu          sync.Mutex
	originalNow func() time.Time
	references  int
}

var automaticClockState automaticClockLeaseState

// The instrumented standard package calls this function during package initialization.
func registerAutomaticClockInstrumentationV1(originalNow func() time.Time) {
	automaticClockState.mu.Lock()
	defer automaticClockState.mu.Unlock()
	if originalNow == nil || automaticClockState.originalNow != nil {
		automaticClockState.hookInvalid = true
		return
	}
	automaticClockState.originalNow = originalNow
}

func acquireAutomaticClockAdapter(
	implementationDigest string,
) *automaticClockAdapterLease {
	adapter := installedObservationAdapter{
		adapterID:            automaticClockAdapterID,
		adapterVersion:       automaticClockAdapterVersion,
		class:                observationClock,
		implementationDigest: implementationDigest,
	}
	automaticClockState.mu.Lock()
	defer automaticClockState.mu.Unlock()
	if !automaticClockHookHealthyLocked() ||
		automaticClockState.references >= automaticClockLeases {
		return nil
	}
	if automaticClockState.references == 0 {
		if installedObservationAdapters.install(adapter) != nil {
			return nil
		}
		automaticClockState.adapter = adapter
	} else if automaticClockState.adapter != adapter {
		return nil
	}
	automaticClockState.references++
	return &automaticClockAdapterLease{}
}

func (lease *automaticClockAdapterLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		automaticClockState.mu.Lock()
		defer automaticClockState.mu.Unlock()
		if automaticClockState.references == 0 {
			return
		}
		automaticClockState.references--
		if automaticClockState.references == 0 {
			installedObservationAdapters.remove(automaticClockState.adapter)
			automaticClockState.adapter = installedObservationAdapter{}
		}
	})
}

func (lease *automaticClockAdapterLease) healthy() bool {
	if lease == nil {
		return false
	}
	automaticClockState.mu.Lock()
	defer automaticClockState.mu.Unlock()
	return automaticClockState.references > 0 && automaticClockHookHealthyLocked()
}

func automaticClockHookHealthyLocked() bool {
	return !automaticClockState.hookInvalid &&
		automaticClockState.originalNow != nil && runtime.Version() != ""
}

func instrumentedTimeNow() time.Time {
	originalNow := automaticClockOriginalNow()
	if originalNow == nil {
		panic(ErrAutomaticCapture)
	}
	operations := snapshotAutomaticOperations()
	if len(operations) == 0 {
		return originalNow()
	}
	if operation := currentAutomaticOperation(); operation != nil {
		return readAutomaticClock(operation, originalNow)
	}
	value := originalNow()
	markAutomaticClockUnowned(operations)
	return value
}

func automaticClockOriginalNow() func() time.Time {
	automaticClockState.mu.Lock()
	defer automaticClockState.mu.Unlock()
	if !automaticClockHookHealthyLocked() {
		return nil
	}
	return automaticClockState.originalNow
}

func readAutomaticClock(
	operation *AutomaticOperation,
	originalNow func() time.Time,
) time.Time {
	request, err := makeSemanticObservationRequest(semanticObservationRequest{
		operation: "clock-wall-time",
	})
	if err != nil {
		return captureClockFallback(operation, originalNow)
	}
	session, err := operation.openObservationSession(observationClock, nil)
	if err != nil || session.writeRequest(request) != nil {
		if session != nil {
			session.abandon()
		}
		return captureClockFallback(operation, originalNow)
	}
	action, err := session.dispatch()
	if err != nil {
		session.abandon()
		return captureClockFallback(operation, originalNow)
	}
	if action == observationReplay {
		return replayAutomaticClock(session, request)
	}
	return captureAutomaticClock(operation, session, originalNow(), request)
}

func captureAutomaticClock(
	operation *AutomaticOperation,
	session *observationSession,
	value time.Time,
	request []byte,
) time.Time {
	encoded := make([]byte, automaticClockValueBytes)
	binary.BigEndian.PutUint64(encoded, uint64(value.UnixNano()))
	response, err := makeSemanticObservationResponse("clock-wall-time", request, encoded)
	if err != nil || writeSemanticObservationResponse(session, response) != nil ||
		session.finish(observationResponse) != nil {
		session.abandon()
		markAutomaticClockUnowned([]*AutomaticOperation{operation})
	}
	return value
}

func replayAutomaticClock(session *observationSession, request []byte) time.Time {
	response, err := readSemanticObservationResponse(session)
	if err == nil {
		response, err = decodeSemanticObservationResponse(
			response, request, "clock-wall-time", automaticClockValueBytes,
		)
	}
	if err != nil || session.finish(observationResponse) != nil {
		session.abandon()
		panic(ErrAutomaticCapture)
	}
	nanoseconds := int64(binary.BigEndian.Uint64(response))
	return time.Unix(0, nanoseconds).Local()
}

func captureClockFallback(
	operation *AutomaticOperation,
	originalNow func() time.Time,
) time.Time {
	value := originalNow()
	markAutomaticClockUnowned([]*AutomaticOperation{operation})
	return value
}

func markAutomaticClockUnowned(operations []*AutomaticOperation) {
	for _, operation := range operations {
		_ = operation.markUnowned(
			observationClock,
			nil,
			automaticClockUnsupportedEvidence,
		)
	}
}
