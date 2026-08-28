package reproit

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestAutomaticGoInstrumentedBuild(t *testing.T) {
	if os.Getenv("REPROIT_TEST_GO_INSTRUMENTATION") != "1" {
		t.Skip("This check requires the Repro It Go build instrumentor.")
	}
	lease := acquireAutomaticClockAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The instrumented Go build did not install the clock hook.")
	}
	defer lease.release()
	environmentLease := acquireAutomaticEnvironmentAdapter(automaticRandomTestDigest)
	if environmentLease == nil {
		t.Fatal("The instrumented Go build did not install the environment hooks.")
	}
	defer environmentLease.release()
	nativeGuards := acquireAutomaticNativeGuards(automaticRandomTestDigest)
	if nativeGuards == nil {
		t.Fatal("The instrumented Go build did not install the native sentinel guards.")
	}
	defer nativeGuards.release()
	httpLease := acquireAutomaticHTTPAdapter(automaticRandomTestDigest)
	if httpLease == nil {
		t.Fatal("The instrumented Go build did not install the HTTP adapter.")
	}
	defer httpLease.release()
	randomLease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if randomLease == nil {
		t.Fatal("The instrumented Go build did not install the random adapter.")
	}
	defer randomLease.release()
	if len(installedObservationAdapters.snapshot()) != sdkEngineMaxObservationAdapters {
		t.Fatal("The instrumented Go build did not register all observation classes.")
	}
	if time.Now().IsZero() {
		t.Fatal("The instrumented Go clock did not return the live value outside an operation.")
	}
}

func TestAutomaticClockLeaseRequiresOneInstalledHook(t *testing.T) {
	restoreAutomaticClockState(t)
	if acquireAutomaticClockAdapter(automaticRandomTestDigest) != nil {
		t.Fatal("The clock adapter accepted a missing build hook.")
	}
}

func TestAutomaticClockLeaseInstallsNestsAndReleases(t *testing.T) {
	restoreAutomaticClockState(t)
	registerAutomaticClockInstrumentationV1(time.Now)
	first := acquireAutomaticClockAdapter(automaticRandomTestDigest)
	second := acquireAutomaticClockAdapter(automaticRandomTestDigest)
	if first == nil || second == nil || !first.healthy() || !second.healthy() {
		t.Fatal("The clock adapter did not install one verified hook.")
	}
	registrations := installedObservationAdapters.snapshot()
	if len(registrations) != 1 || registrations[0].Class != string(observationClock) {
		t.Fatal("The clock adapter did not register its observation class.")
	}
	first.release()
	if !second.healthy() {
		t.Fatal("The first clock lease removed the shared hook.")
	}
	second.release()
	if len(installedObservationAdapters.snapshot()) != 0 {
		t.Fatal("The final clock lease retained its registration.")
	}
}

func TestAutomaticClockCaptureRecordsWallTimeAndPreservesResult(t *testing.T) {
	want := time.Unix(1_700_000_000, 123_456_789).Local()
	installAutomaticClockTestHook(t, func() time.Time { return want })
	lease := acquireAutomaticClockAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The clock adapter lease was not installed.")
	}
	var requestRecord []byte
	var responseRecord []byte
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		switch request["operation"] {
		case sdkEngineObservationOpen:
			return `{"observation_handle":101,"session_position":0}`
		case sdkEngineObservationDispatch:
			return `{"action":"capture"}`
		case sdkEngineObservationWrite:
			chunk, err := base64.RawURLEncoding.DecodeString(request["chunk"].(string))
			if err != nil {
				t.Fatal("The clock adapter wrote an invalid chunk.")
			}
			if request["stream"] == "request" {
				requestRecord = append(requestRecord, chunk...)
			} else {
				responseRecord = append(responseRecord, chunk...)
			}
		}
		return `{}`
	})
	project.automaticAdapters = &automaticAdapterLeases{clock: lease}
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	if got := instrumentedTimeNow(); !got.Equal(want) || got.Location() != want.Location() {
		t.Fatal("The clock adapter changed the live wall time.")
	}
	wantRequest, _ := makeSemanticObservationRequest(semanticObservationRequest{
		operation: "clock-wall-time",
	})
	value := make([]byte, automaticClockValueBytes)
	binary.BigEndian.PutUint64(value, uint64(want.UnixNano()))
	wantResponse, _ := makeSemanticObservationResponse("clock-wall-time", wantRequest, value)
	if string(requestRecord) != string(wantRequest) || string(responseRecord) != string(wantResponse) {
		t.Fatal("The clock adapter changed the semantic record.")
	}
}

func TestAutomaticClockReplayUsesNoLiveClock(t *testing.T) {
	liveCalls := 0
	installAutomaticClockTestHook(t, func() time.Time {
		liveCalls++
		return time.Unix(1, 0)
	})
	lease := acquireAutomaticClockAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The clock adapter lease was not installed.")
	}
	wantNanoseconds := int64(1_700_000_000_123_456_789)
	request, _ := makeSemanticObservationRequest(semanticObservationRequest{
		operation: "clock-wall-time",
	})
	value := make([]byte, automaticClockValueBytes)
	binary.BigEndian.PutUint64(value, uint64(wantNanoseconds))
	response, _ := makeSemanticObservationResponse("clock-wall-time", request, value)
	project := automaticRandomReplayProject(t, response)
	project.automaticAdapters = &automaticAdapterLeases{clock: lease}
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	got := instrumentedTimeNow()
	if got.UnixNano() != wantNanoseconds || liveCalls != 0 {
		t.Fatal("Clock replay read the live clock or changed the recorded value.")
	}
}

func TestAutomaticClockAmbiguityPreservesTimeAndMarksEveryOperation(t *testing.T) {
	want := time.Unix(1_700_000_000, 1).Local()
	installAutomaticClockTestHook(t, func() time.Time { return want })
	lease := acquireAutomaticClockAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The clock adapter lease was not installed.")
	}
	unowned := 0
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		if request["operation"] == sdkEngineOperationUnowned {
			unowned++
		}
		return `{}`
	})
	project.automaticAdapters = &automaticAdapterLeases{clock: lease}
	defer project.Close()
	startAutomaticTestOperationOnGoroutine(t, project)
	startAutomaticTestOperationOnGoroutine(t, project)

	if got := instrumentedTimeNow(); !got.Equal(want) || unowned != 2 {
		t.Fatal("An ambiguous clock read changed the result or retained the operations.")
	}
}

func TestAutomaticClockRejectsChangedReplayBytes(t *testing.T) {
	installAutomaticClockTestHook(t, time.Now)
	lease := acquireAutomaticClockAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The clock adapter lease was not installed.")
	}
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		switch request["operation"] {
		case sdkEngineObservationOpen:
			return `{"observation_handle":102,"session_position":0}`
		case sdkEngineObservationDispatch:
			return `{"action":"replay"}`
		case sdkEngineObservationRead:
			return fmt.Sprintf(
				`{"chunk":"%s","eof":true}`,
				base64.RawURLEncoding.EncodeToString([]byte(`{"changed":true}`)),
			)
		}
		return `{}`
	})
	project.automaticAdapters = &automaticAdapterLeases{clock: lease}
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	defer func() {
		if recover() != ErrAutomaticCapture {
			t.Fatal("Changed clock replay bytes did not stop replay.")
		}
	}()
	_ = instrumentedTimeNow()
}

func installAutomaticClockTestHook(t *testing.T, originalNow func() time.Time) {
	t.Helper()
	restoreAutomaticClockState(t)
	registerAutomaticClockInstrumentationV1(originalNow)
}

func restoreAutomaticClockState(t *testing.T) {
	t.Helper()
	automaticClockState.mu.Lock()
	if automaticClockState.references != 0 {
		automaticClockState.mu.Unlock()
		t.Fatal("A clock adapter lease leaked from another test.")
	}
	previousInvalid := automaticClockState.hookInvalid
	previousNow := automaticClockState.originalNow
	automaticClockState.hookInvalid = false
	automaticClockState.originalNow = nil
	automaticClockState.mu.Unlock()
	t.Cleanup(func() {
		automaticClockState.mu.Lock()
		defer automaticClockState.mu.Unlock()
		automaticClockState.hookInvalid = previousInvalid
		automaticClockState.originalNow = previousNow
	})
}
