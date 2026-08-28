package reproit

import (
	cryptorand "crypto/rand"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
)

const (
	automaticRandomAdapterID      = "go-crypto-rand-reader"
	automaticRandomAdapterVersion = "1.0.0"
	automaticRandomLeases         = 64
	automaticRandomValueBytes     = 32 * 1024
)

var automaticRandomUnsupportedEvidence = []byte("go-crypto-rand-unsupported-v1")

type automaticRandomAdapterLease struct {
	once   sync.Once
	reader *automaticRandomReader
}

type automaticRandomLeaseState struct {
	adapter    installedObservationAdapter
	mu         sync.Mutex
	original   io.Reader
	reader     *automaticRandomReader
	references int
}

type automaticRandomReader struct {
	active atomic.Bool
	base   io.Reader
}

var automaticRandomState automaticRandomLeaseState

func acquireAutomaticRandomAdapter(
	implementationDigest string,
) *automaticRandomAdapterLease {
	adapter := installedObservationAdapter{
		adapterID:            automaticRandomAdapterID,
		adapterVersion:       automaticRandomAdapterVersion,
		class:                observationRandomness,
		implementationDigest: implementationDigest,
	}
	automaticRandomState.mu.Lock()
	defer automaticRandomState.mu.Unlock()
	if current := automaticRandomState.reader; current != nil {
		if !sameAutomaticRandomReader(cryptorand.Reader, current) {
			current.active.Store(false)
			resetAutomaticRandomState()
			return nil
		}
		if automaticRandomState.adapter != adapter ||
			automaticRandomState.references >= automaticRandomLeases {
			return nil
		}
		automaticRandomState.references++
		return &automaticRandomAdapterLease{reader: current}
	}
	original := cryptorand.Reader
	if original == nil {
		return nil
	}
	reader := &automaticRandomReader{base: original}
	reader.active.Store(true)
	cryptorand.Reader = reader
	if err := installedObservationAdapters.install(adapter); err != nil {
		if sameAutomaticRandomReader(cryptorand.Reader, reader) {
			cryptorand.Reader = original
		}
		reader.active.Store(false)
		return nil
	}
	automaticRandomState.adapter = adapter
	automaticRandomState.original = original
	automaticRandomState.reader = reader
	automaticRandomState.references = 1
	return &automaticRandomAdapterLease{reader: reader}
}

func (lease *automaticRandomAdapterLease) release() {
	if lease == nil {
		return
	}
	lease.once.Do(lease.releaseOnce)
}

func (lease *automaticRandomAdapterLease) healthy() bool {
	if lease == nil || lease.reader == nil {
		return false
	}
	automaticRandomState.mu.Lock()
	defer automaticRandomState.mu.Unlock()
	return automaticRandomState.reader == lease.reader &&
		automaticRandomState.references > 0 && lease.reader.active.Load() &&
		sameAutomaticRandomReader(cryptorand.Reader, lease.reader)
}

func (lease *automaticRandomAdapterLease) releaseOnce() {
	automaticRandomState.mu.Lock()
	defer automaticRandomState.mu.Unlock()
	if lease.reader == nil || automaticRandomState.reader != lease.reader ||
		automaticRandomState.references == 0 {
		return
	}
	automaticRandomState.references--
	if automaticRandomState.references != 0 {
		lease.reader = nil
		return
	}
	lease.reader.active.Store(false)
	if sameAutomaticRandomReader(cryptorand.Reader, lease.reader) {
		cryptorand.Reader = automaticRandomState.original
	}
	resetAutomaticRandomState()
	lease.reader = nil
}

func resetAutomaticRandomState() {
	installedObservationAdapters.remove(automaticRandomState.adapter)
	automaticRandomState.adapter = installedObservationAdapter{}
	automaticRandomState.original = nil
	automaticRandomState.reader = nil
	automaticRandomState.references = 0
}

func sameAutomaticRandomReader(left io.Reader, right io.Reader) bool {
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	return leftValue.IsValid() && rightValue.IsValid() &&
		leftValue.Type() == rightValue.Type() && leftValue.Comparable() &&
		leftValue.Equal(rightValue)
}

func (reader *automaticRandomReader) Read(output []byte) (int, error) {
	if !reader.active.Load() {
		return reader.base.Read(output)
	}
	operations := snapshotAutomaticOperations()
	if len(operations) == 0 || len(output) == 0 {
		return reader.base.Read(output)
	}
	operation := currentAutomaticOperation()
	if operation == nil || len(output) > automaticRandomValueBytes {
		count, err := reader.base.Read(output)
		markAutomaticRandomUnowned(operations)
		return count, err
	}
	return readAutomaticRandom(operation, reader.base, output)
}

func readAutomaticRandom(
	operation *AutomaticOperation,
	base io.Reader,
	output []byte,
) (int, error) {
	request, err := automaticRandomRequest(len(output))
	if err != nil {
		count, readErr := base.Read(output)
		markAutomaticRandomUnowned([]*AutomaticOperation{operation})
		return count, readErr
	}
	session, err := operation.openObservationSession(observationRandomness, nil)
	if err != nil || session.writeRequest(request) != nil {
		if session != nil {
			session.abandon()
		}
		return base.Read(output)
	}
	action, err := session.dispatch()
	if err != nil {
		session.abandon()
		return base.Read(output)
	}
	if action == observationReplay {
		return replayAutomaticRandom(session, request, output)
	}
	return captureAutomaticRandom(operation, session, base, request, output)
}

func captureAutomaticRandom(
	operation *AutomaticOperation,
	session *observationSession,
	base io.Reader,
	request []byte,
	output []byte,
) (int, error) {
	count, readErr := base.Read(output)
	if readErr != nil || count != len(output) || count < 0 || count > len(output) {
		session.abandon()
		markAutomaticRandomUnowned([]*AutomaticOperation{operation})
		return count, readErr
	}
	response, err := automaticRandomResponse(request, output)
	if err != nil || writeAutomaticRandomResponse(session, response) != nil ||
		session.finish(observationResponse) != nil {
		session.abandon()
		markAutomaticRandomUnowned([]*AutomaticOperation{operation})
	}
	return count, readErr
}

func replayAutomaticRandom(
	session *observationSession,
	request []byte,
	output []byte,
) (int, error) {
	response, err := readAutomaticRandomResponse(session)
	if err == nil {
		response, err = decodeAutomaticRandomResponse(response, request, len(output))
	}
	if err != nil || session.finish(observationResponse) != nil {
		session.abandon()
		return 0, ErrAutomaticCapture
	}
	copy(output, response)
	return len(output), nil
}

func automaticRandomRequest(length int) ([]byte, error) {
	value := length
	return makeSemanticObservationRequest(semanticObservationRequest{
		length: &value, operation: "random-bytes",
	})
}

func automaticRandomResponse(request []byte, value []byte) ([]byte, error) {
	return makeSemanticObservationResponse("random-bytes", request, value)
}

func writeAutomaticRandomResponse(session *observationSession, value []byte) error {
	return writeSemanticObservationResponse(session, value)
}

func readAutomaticRandomResponse(session *observationSession) ([]byte, error) {
	return readSemanticObservationResponse(session)
}

func decodeAutomaticRandomResponse(
	value []byte,
	request []byte,
	length int,
) ([]byte, error) {
	return decodeSemanticObservationResponse(value, request, "random-bytes", length)
}

func markAutomaticRandomUnowned(operations []*AutomaticOperation) {
	for _, operation := range operations {
		_ = operation.markUnowned(
			observationRandomness,
			nil,
			automaticRandomUnsupportedEvidence,
		)
	}
}

var _ io.Reader = (*automaticRandomReader)(nil)
