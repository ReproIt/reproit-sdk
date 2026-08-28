package reproit

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

const automaticRandomTestDigest = "sha256:" +
	"d1f1ce8f05ef1fab38a4f959f83a6a7897c7d32317784a41c3fcf0df40384ba8"

type automaticRandomReaderFunc func([]byte) (int, error)

func (read automaticRandomReaderFunc) Read(output []byte) (int, error) {
	return read(output)
}

func TestAutomaticRandomLeaseInstallsNestsAndRestores(t *testing.T) {
	original := cryptorand.Reader
	base := bytes.NewReader([]byte("entropy"))
	cryptorand.Reader = base
	t.Cleanup(func() { cryptorand.Reader = original })

	first := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	second := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if first == nil || second == nil || first.reader != second.reader ||
		!sameAutomaticRandomReader(cryptorand.Reader, first.reader) {
		t.Fatal("The random adapter did not install one shared reader.")
	}
	registrations := installedObservationAdapters.snapshot()
	if len(registrations) != 1 || registrations[0].Class != string(observationRandomness) {
		t.Fatal("The random adapter did not register its observation class.")
	}
	first.release()
	if !sameAutomaticRandomReader(cryptorand.Reader, second.reader) {
		t.Fatal("The nested random lease restored the reader too early.")
	}
	second.release()
	if !sameAutomaticRandomReader(cryptorand.Reader, base) {
		t.Fatal("The final random lease did not restore the original reader.")
	}
}

func TestAutomaticRandomLeasePreservesApplicationReplacement(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = bytes.NewReader([]byte("original"))
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	replacement := bytes.NewBufferString("replacement")
	cryptorand.Reader = replacement
	lease.release()
	if !sameAutomaticRandomReader(cryptorand.Reader, replacement) {
		t.Fatal("The random lease overwrote the application replacement.")
	}
}

func TestAutomaticRandomLeaseHasAnExactBound(t *testing.T) {
	original := cryptorand.Reader
	base := bytes.NewReader([]byte("entropy"))
	cryptorand.Reader = base
	t.Cleanup(func() { cryptorand.Reader = original })
	leases := make([]*automaticRandomAdapterLease, 0, automaticRandomLeases)
	for index := 0; index < automaticRandomLeases; index++ {
		lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
		if lease == nil {
			t.Fatalf("The random adapter rejected lease %d inside its bound.", index)
		}
		leases = append(leases, lease)
	}
	if acquireAutomaticRandomAdapter(automaticRandomTestDigest) != nil {
		t.Fatal("The random adapter accepted one lease over its bound.")
	}
	for _, lease := range leases {
		lease.release()
	}
	if !sameAutomaticRandomReader(cryptorand.Reader, base) {
		t.Fatal("The bounded random leases did not restore the original reader.")
	}
}

func TestAutomaticRandomLeaseRejectsAChangedImplementationIdentity(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = bytes.NewReader([]byte("entropy"))
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	defer lease.release()
	changed := "sha256:" + strings.Repeat("b", 64)
	if acquireAutomaticRandomAdapter(changed) != nil || !lease.healthy() {
		t.Fatal("The random adapter accepted a changed implementation identity.")
	}
}

func TestAutomaticRandomCaptureRecordsExactBytes(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = bytes.NewReader([]byte("abcdefgh"))
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	defer lease.release()

	requests := make([]map[string]any, 0)
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		requests = append(requests, request)
		switch request["operation"] {
		case sdkEngineObservationOpen:
			return `{"observation_handle":91,"session_position":0}`
		case sdkEngineObservationDispatch:
			return `{"action":"capture"}`
		default:
			return `{}`
		}
	})
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	output := make([]byte, 8)
	count, err := cryptorand.Read(output)
	if err != nil || count != len(output) || string(output) != "abcdefgh" {
		t.Fatal("The random adapter changed the live read.")
	}
	var requestRecord []byte
	var responseRecord []byte
	for _, request := range requests {
		if request["operation"] != sdkEngineObservationWrite {
			continue
		}
		chunk, decodeErr := base64.RawURLEncoding.DecodeString(request["chunk"].(string))
		if decodeErr != nil {
			t.Fatal("The random adapter wrote an invalid chunk.")
		}
		if request["stream"] == "request" {
			requestRecord = append(requestRecord, chunk...)
		} else {
			responseRecord = append(responseRecord, chunk...)
		}
	}
	wantRequest, _ := automaticRandomRequest(8)
	wantResponse, _ := automaticRandomResponse(wantRequest, []byte("abcdefgh"))
	if !bytes.Equal(requestRecord, wantRequest) || !bytes.Equal(responseRecord, wantResponse) {
		t.Fatal("The random adapter changed the semantic record.")
	}
}

func TestAutomaticRandomReplayUsesNoLiveEntropy(t *testing.T) {
	original := cryptorand.Reader
	liveCalls := 0
	cryptorand.Reader = automaticRandomReaderFunc(func([]byte) (int, error) {
		liveCalls++
		return 0, errors.New("live entropy was called")
	})
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	defer lease.release()
	request, _ := automaticRandomRequest(4)
	response, _ := automaticRandomResponse(request, []byte("seed"))
	project := automaticRandomReplayProject(t, response)
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	output := make([]byte, 4)
	count, err := cryptorand.Read(output)
	if err != nil || count != len(output) || string(output) != "seed" || liveCalls != 0 {
		t.Fatal("Random replay used live entropy or changed the result.")
	}
}

func TestAutomaticRandomAmbiguityPreservesLiveReadAndMarksEveryOperation(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = bytes.NewReader([]byte("live"))
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	defer lease.release()
	unowned := 0
	opened := 0
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		switch request["operation"] {
		case sdkEngineOperationUnowned:
			unowned++
		case sdkEngineObservationOpen:
			opened++
		}
		return `{}`
	})
	defer project.Close()
	startAutomaticTestOperationOnGoroutine(t, project)
	startAutomaticTestOperationOnGoroutine(t, project)

	output := make([]byte, 4)
	count, err := cryptorand.Reader.Read(output)
	if err != nil || count != len(output) || string(output) != "live" {
		t.Fatal("An ambiguous random read changed the live result.")
	}
	if unowned != 2 || opened != 0 {
		t.Fatal("An ambiguous random read did not keep both operations local.")
	}
}

func TestAutomaticRandomPartialReadPreservesResultAndStaysLocal(t *testing.T) {
	original := cryptorand.Reader
	wantError := errors.New("random source failed")
	cryptorand.Reader = automaticRandomReaderFunc(func(output []byte) (int, error) {
		copy(output, "ab")
		return 2, wantError
	})
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	defer lease.release()
	unowned := 0
	project := automaticRandomCaptureProject(t, &unowned)
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	output := make([]byte, 4)
	count, err := cryptorand.Reader.Read(output)
	if count != 2 || err != wantError || string(output[:2]) != "ab" || unowned != 1 {
		t.Fatal("A partial random read changed its result or left the operation owned.")
	}
}

func TestAutomaticRandomOneByteOverLimitPreservesLiveReadAndStaysLocal(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = automaticRandomReaderFunc(func(output []byte) (int, error) {
		for index := range output {
			output[index] = byte(index)
		}
		return len(output), nil
	})
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	defer lease.release()
	unowned := 0
	project := automaticRandomCaptureProject(t, &unowned)
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	output := make([]byte, automaticRandomValueBytes+1)
	count, err := cryptorand.Reader.Read(output)
	if err != nil || count != len(output) || unowned != 1 {
		t.Fatal("An oversized random read changed its result or remained owned.")
	}
}

func TestAutomaticRandomCorruptReplayStopsWithoutLiveEntropy(t *testing.T) {
	original := cryptorand.Reader
	liveCalls := 0
	cryptorand.Reader = automaticRandomReaderFunc(func([]byte) (int, error) {
		liveCalls++
		return 0, nil
	})
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	defer lease.release()
	project := automaticRandomReplayProject(t, []byte(`{"format":"invalid"}`))
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	defer operation.Close()

	output := make([]byte, 4)
	count, err := cryptorand.Reader.Read(output)
	if count != 0 || !errors.Is(err, ErrAutomaticCapture) || liveCalls != 0 {
		t.Fatal("A corrupt random replay used live entropy or returned data.")
	}
}

func TestAutomaticRandomReplacementMarksWorldUnownedAtClose(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = bytes.NewReader([]byte("entropy"))
	t.Cleanup(func() { cryptorand.Reader = original })
	lease := acquireAutomaticRandomAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The random adapter lease was not installed.")
	}
	unowned := 0
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		if request["operation"] == sdkEngineOperationUnowned {
			unowned++
		}
		return `{}`
	})
	project.automaticAdapters = &automaticAdapterLeases{random: lease}
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	cryptorand.Reader = bytes.NewReader([]byte("replacement"))

	if err := operation.closeWorld(CompletionReturn); err != nil {
		t.Fatal("The fake engine rejected the World close.")
	}
	if unowned != 1 {
		t.Fatal("A replaced random reader did not mark the World unowned.")
	}
}

func TestAutomaticHTTPReplacementMarksWorldUnownedAtClose(t *testing.T) {
	originalClient := http.DefaultClient
	originalTransport := originalClient.Transport
	t.Cleanup(func() { originalClient.Transport = originalTransport })
	lease := acquireAutomaticHTTPAdapter(automaticRandomTestDigest)
	if lease == nil {
		t.Fatal("The HTTP adapter lease was not installed.")
	}
	unowned := 0
	project := automaticRandomTestProject(t, func(request map[string]any) string {
		if request["operation"] == sdkEngineOperationUnowned {
			unowned++
		}
		return `{}`
	})
	project.automaticAdapters = &automaticAdapterLeases{http: lease}
	defer project.Close()
	operation := automaticRandomTestOperation(t, project)
	originalClient.Transport = automaticHTTPRoundTripper(
		func(*http.Request) (*http.Response, error) { return nil, nil },
	)

	if err := operation.closeWorld(CompletionReturn); err != nil {
		t.Fatal("The fake engine rejected the World close.")
	}
	if unowned != 1 {
		t.Fatal("A replaced HTTP transport did not mark the World unowned.")
	}
}

func TestAutomaticProjectCloseRemovesActiveRandomOwnership(t *testing.T) {
	project := automaticRandomTestProject(t, func(map[string]any) string { return `{}` })
	operation := automaticRandomTestOperation(t, project)
	if len(snapshotAutomaticOperations()) != 1 {
		t.Fatal("The operation registry did not track the active operation.")
	}
	project.Close()
	if operation.isActive() || len(snapshotAutomaticOperations()) != 0 {
		t.Fatal("Project close retained automatic operation ownership.")
	}
}

func TestAutomaticRandomOwnershipIgnoresAWorldClosedOperation(t *testing.T) {
	project := automaticRandomTestProject(t, func(map[string]any) string { return `{}` })
	defer project.Close()
	closed := automaticRandomTestOperation(t, project)
	active := automaticRandomTestOperation(t, project)
	defer active.Close()
	if err := closed.closeWorld(CompletionReturn); err != nil {
		t.Fatal("The fake engine rejected the World close.")
	}
	operations := snapshotAutomaticOperations()
	if len(operations) != 1 || operations[0] != active {
		t.Fatal("A World-closed operation remained a random observation owner.")
	}
}

func TestAutomaticOperationRegistryHasAnExactBound(t *testing.T) {
	if len(snapshotAutomaticOperations()) != 0 {
		t.Fatal("The operation registry was not empty before its boundary test.")
	}
	project := &AutomaticProject{}
	operations := make([]*AutomaticOperation, 0, automaticMaxActiveOperations)
	for index := 0; index < automaticMaxActiveOperations; index++ {
		operation := &AutomaticOperation{project: project}
		if !registerAutomaticOperation(operation) {
			t.Fatalf("The operation registry rejected entry %d inside its bound.", index)
		}
		operations = append(operations, operation)
	}
	if registerAutomaticOperation(&AutomaticOperation{project: project}) {
		t.Fatal("The operation registry accepted one entry over its bound.")
	}
	for _, operation := range operations {
		unregisterAutomaticOperation(operation)
	}
	if len(snapshotAutomaticOperations()) != 0 {
		t.Fatal("The operation registry retained its boundary fixtures.")
	}
}

func automaticRandomCaptureProject(t *testing.T, unowned *int) *AutomaticProject {
	t.Helper()
	return automaticRandomTestProject(t, func(request map[string]any) string {
		switch request["operation"] {
		case sdkEngineObservationOpen:
			return `{"observation_handle":93,"session_position":0}`
		case sdkEngineObservationDispatch:
			return `{"action":"capture"}`
		case sdkEngineOperationUnowned:
			*unowned++
		}
		return `{}`
	})
}

func automaticRandomReplayProject(t *testing.T, response []byte) *AutomaticProject {
	t.Helper()
	return automaticRandomTestProject(t, func(request map[string]any) string {
		switch request["operation"] {
		case sdkEngineObservationOpen:
			return `{"observation_handle":92,"session_position":0}`
		case sdkEngineObservationDispatch:
			return `{"action":"replay"}`
		case sdkEngineObservationRead:
			return fmt.Sprintf(
				`{"chunk":"%s","eof":true}`,
				base64.RawURLEncoding.EncodeToString(response),
			)
		}
		return `{}`
	})
}

func automaticRandomTestProject(
	t *testing.T,
	handle func(map[string]any) string,
) *AutomaticProject {
	t.Helper()
	operationIndex := 0
	bridge := automaticTestBridge(t, func(input []byte, output []byte) int64 {
		var request map[string]any
		if json.Unmarshal(input, &request) != nil {
			t.Fatal("The random adapter request is not JSON.")
		}
		result := `{}`
		switch request["operation"] {
		case sdkEngineOperationOpenEngine:
			result = `{"engine_handle":81}`
		case sdkEngineOperationBegin:
			operationIndex++
			result = fmt.Sprintf(
				`{"operation_handle":%d,"operation_id":"op_random_%d"}`,
				81+operationIndex,
				operationIndex,
			)
		default:
			result = handle(request)
		}
		return int64(copy(output, sdkEngineSuccess(result)))
	})
	project, err := openAutomaticProjectWith(
		AutomaticProjectOptions{},
		bridge,
		&GoSubjectPackage{Manifest: map[string]any{}, Objects: []PackagedSubjectObject{{
			Digest: "sha256:" + strings.Repeat("a", 64), Path: "/subject", Size: 1,
		}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func automaticRandomTestOperation(
	t *testing.T,
	project *AutomaticProject,
) *AutomaticOperation {
	t.Helper()
	operation, err := project.StartOperation(AutomaticOperationStart{
		AdapterID: "random-test", AdapterVersion: "1.0.0",
		Kind: OperationRequestResponse, Name: "random-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func startAutomaticTestOperationOnGoroutine(
	t *testing.T,
	project *AutomaticProject,
) *AutomaticOperation {
	t.Helper()
	started := make(chan *AutomaticOperation, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		operation, err := project.StartOperation(AutomaticOperationStart{
			AdapterID: "random-test", AdapterVersion: "1.0.0",
			Kind: OperationRequestResponse, Name: "random-test",
		})
		if err != nil {
			started <- nil
			return
		}
		started <- operation
		<-release
		operation.Close()
	}()
	operation := <-started
	if operation == nil {
		t.Fatal("The test goroutine could not start an operation.")
	}
	t.Cleanup(func() {
		close(release)
		<-done
	})
	return operation
}

var _ io.Reader = automaticRandomReaderFunc(nil)
