// Bounded managed candidate sink with fail-open delivery.
//
// Mirrors crates/reproit-sdk-rust/src/managed_sink.rs: a bounded in-process
// queue, one background delivery worker, recall counters without customer
// values, and fail-open semantics. A managed SDK failure never changes the
// application's behavior.
package reproit

import (
	"bytes"
	"sort"
	"strings"
	"sync"
	"time"
)

const managedRegistrationTimeout = 5 * time.Second

// ManagedCaptureClient is the full managed key-service and ingress surface
// the sink drives. ManagedTlsClient implements it.
type ManagedCaptureClient interface {
	ManagedCandidateGrantDelivery
	ManagedCandidateIngressDelivery
}

type managedWorkloadRegistrationClient interface {
	RegisterWorkloadKey(
		request map[string]any, timeout time.Duration,
	) (map[string]any, error)
}

type ManagedSinkConfiguration struct {
	CaptureSignerID        string
	CaptureSignerPublicKey []byte
	ServiceID              string
	WorkloadStateRoot      string
	WorkloadSigningKey     []byte
}

type queuedManagedCandidate struct {
	value    map[string]any
	size     int
	queuedAt time.Time
}

// ManagedCandidateSink delivers complete managed candidates through the
// bounded upload session.
type ManagedCandidateSink struct {
	client             ManagedCaptureClient
	closure            *FrozenManagedCaptureClosure
	configuration      ManagedSinkConfiguration
	subject            *GoSubjectPackage
	worldID            string
	workloadKeyID      string
	workloadPublicKey  []byte
	workloadSigningKey []byte
	deploymentDigest   string
	// deliveryLifetime is the bounded queue-to-delivery budget. Tests may
	// shorten it before the first send.
	deliveryLifetime time.Duration

	mu             sync.Mutex
	registrationMu sync.Mutex
	active         bool
	queuedBytes    int
	queuedCount    int
	recall         RecallCounters

	queue chan queuedManagedCandidate
}

// NewManagedCandidateSink freezes the capture closure and packages the running
// subject when subject is nil. BindDeployment registers the signed Deployment.
func NewManagedCandidateSink(
	client ManagedCaptureClient,
	closure ManagedCaptureClosure,
	configuration ManagedSinkConfiguration,
	subject *GoSubjectPackage,
) (*ManagedCandidateSink, error) {
	if err := validateManagedSinkConfiguration(configuration); err != nil {
		return nil, err
	}
	frozen, err := FreezeManagedCaptureClosure(closure)
	if err != nil {
		return nil, err
	}
	if subject == nil {
		subject, err = PackageRunningGoSubject("")
		if err != nil {
			return nil, err
		}
	}
	worldID, err := frozen.worldID()
	if err != nil {
		return nil, err
	}
	sink := &ManagedCandidateSink{
		client:           client,
		closure:          frozen,
		configuration:    configuration,
		subject:          subject,
		worldID:          worldID,
		deliveryLifetime: deliveryLifetime,
		queue:            make(chan queuedManagedCandidate, MaxQueuedCandidates),
	}
	go sink.worker()
	return sink, nil
}

// AllowsProcessingMode advertises the managed processing mode only.
func (sink *ManagedCandidateSink) AllowsProcessingMode(mode string) bool {
	return mode == "managed"
}

func (sink *ManagedCandidateSink) QueuedBytes() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.queuedBytes
}

// RecallCounters returns bounded counters that contain no customer values.
func (sink *ManagedCandidateSink) RecallCounters() RecallCounters {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.recall
}

func (sink *ManagedCandidateSink) SubjectManifest() map[string]any {
	return sink.subject.Manifest
}

func (sink *ManagedCandidateSink) WorkloadKeyID() string {
	sink.registrationMu.Lock()
	defer sink.registrationMu.Unlock()
	return sink.workloadKeyID
}

func (sink *ManagedCandidateSink) WorkloadPublicKey() []byte {
	sink.registrationMu.Lock()
	defer sink.registrationMu.Unlock()
	return bytes.Clone(sink.workloadPublicKey)
}

func (sink *ManagedCandidateSink) WorldID() string {
	return sink.worldID
}

// BindDeployment binds the deployment to this subject and signs it as this
// workload.
func (sink *ManagedCandidateSink) BindDeployment(deployment map[string]any) error {
	sink.registrationMu.Lock()
	defer sink.registrationMu.Unlock()
	if deployment["service_id"] != sink.configuration.ServiceID {
		return newManagedError(
			"AUTHORIZATION_DENIED", "The managed deployment belongs to a different service.",
		)
	}
	binding, err := subjectBinding(sink.subject.Manifest)
	if err != nil {
		return err
	}
	deployment["processing_mode"] = "managed"
	deployment["subject"] = binding
	capabilities, _ := anyList(deployment["runtime_capabilities"])
	merged := make(map[string]bool)
	for _, capability := range capabilities {
		text, textOK := capability.(string)
		if !textOK {
			return errSchemaInvalid()
		}
		merged[text] = true
	}
	merged[sink.subject.Manifest["architecture"].(string)] = true
	merged[sink.subject.Manifest["operating_system"].(string)] = true
	// The captured World's process-visible processor view travels with the
	// candidate so admission starts from the complete observation
	// (spec 7.8.1).
	for _, capability := range CaptureProcessorCapabilities() {
		merged[capability] = true
	}
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	sorted := make([]any, 0, len(names))
	for _, name := range names {
		sorted = append(sorted, name)
	}
	deployment["runtime_capabilities"] = sorted
	bindingDigest, err := managedDeploymentBindingDigest(deployment)
	if err != nil {
		return err
	}
	state, err := newManagedWorkloadIdentityState(
		sink.configuration.WorkloadStateRoot, bindingDigest,
	)
	if err != nil {
		return err
	}
	workloadSigningKey, err := state.loadOrCreateKey(sink.configuration.WorkloadSigningKey)
	if err != nil {
		return err
	}
	publicKey, err := verificationKey(workloadSigningKey)
	if err != nil {
		return err
	}
	workloadKeyID := managedWorkloadKeyID(publicKey)
	signedAt, _ := deployment["signed_at"].(string)
	signedAt, err = state.loadOrCreateSignedAt(bindingDigest, signedAt)
	if err != nil {
		return err
	}
	deployment["signed_at"] = signedAt
	deployment["signer_key_id"] = workloadKeyID
	deployment["signature"] = ""
	encoded, err := CanonicalBytes(deployment)
	if err != nil {
		return errSchemaInvalid()
	}
	signature, err := signBytes(encoded, workloadSigningKey)
	if err != nil {
		return err
	}
	deployment["signature"] = signature
	if err := validateManagedDeployment(deployment); err != nil {
		return err
	}
	if err := sink.registerDeployment(
		state, deployment, workloadKeyID, publicKey,
	); err != nil {
		return err
	}
	sink.workloadKeyID = workloadKeyID
	sink.workloadPublicKey = publicKey
	sink.workloadSigningKey = workloadSigningKey
	sink.deploymentDigest, _ = canonicalDigest(deployment)
	return nil
}

func (sink *ManagedCandidateSink) registerDeployment(
	state *ManagedWorkloadIdentityState,
	deployment map[string]any,
	workloadKeyID string,
	publicKey []byte,
) error {
	deploymentDigest, err := canonicalDigest(deployment)
	if err != nil {
		return errSchemaInvalid()
	}
	receipt := ManagedWorkloadRegistrationReceipt{
		DeploymentDigest: deploymentDigest,
		ServiceID:        sink.configuration.ServiceID,
		WorkloadKeyID:    workloadKeyID,
	}
	found, err := state.loadRegistrationReceipt(receipt)
	if err != nil || found {
		return err
	}
	request := map[string]any{
		"algorithm":  "Ed25519",
		"deployment": deployment,
		"public_key": encodeBase64URL(publicKey),
		"service_id": sink.configuration.ServiceID,
	}
	registrar, ok := sink.client.(managedWorkloadRegistrationClient)
	if !ok {
		return newManagedError(
			"CONFIG_CONFLICT", "The managed capture client cannot register a signed Deployment.",
		)
	}
	registration, err := registrar.RegisterWorkloadKey(request, managedRegistrationTimeout)
	if err != nil {
		return newManagedError(errCode(err), "Repro It could not register this workload key.")
	}
	if registration["deployment_digest"] != deploymentDigest ||
		registration["key_id"] != workloadKeyID ||
		registration["service_id"] != sink.configuration.ServiceID {
		return newManagedError(
			"ATTESTATION_SCOPE", "The managed workload registration does not match this deployment.",
		)
	}
	return state.persistRegistrationReceipt(receipt)
}

// WaitUntilIdle reports whether the queue drained within timeout.
func (sink *ManagedCandidateSink) WaitUntilIdle(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		sink.mu.Lock()
		idle := !sink.active && sink.queuedCount == 0
		sink.mu.Unlock()
		if idle {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TrySend queues one complete candidate. It never fails into the
// application: every refusal only increments a recall counter.
func (sink *ManagedCandidateSink) TrySend(captureID string, candidate []byte) bool {
	value, err := sink.authorizedCandidate(captureID, candidate)
	if err != nil {
		sink.increment(func(recall *RecallCounters) *uint64 {
			return &recall.CandidateIncomplete
		})
		return false
	}
	sink.mu.Lock()
	if sink.queuedCount >= MaxQueuedCandidates ||
		sink.queuedBytes+len(candidate) > MaxGlobalBytes {
		increment(&sink.recall.CandidateQueueFull)
		sink.mu.Unlock()
		return false
	}
	sink.queuedBytes += len(candidate)
	sink.queuedCount++
	sink.mu.Unlock()
	queued := queuedManagedCandidate{value: value, size: len(candidate), queuedAt: time.Now()}
	select {
	case sink.queue <- queued:
		return true
	default:
		sink.mu.Lock()
		sink.queuedBytes -= len(candidate)
		sink.queuedCount--
		increment(&sink.recall.CandidateQueueFull)
		sink.mu.Unlock()
		return false
	}
}

func (sink *ManagedCandidateSink) authorizedCandidate(
	captureID string, candidate []byte,
) (map[string]any, error) {
	if len(candidate) > MaxOperationBytes {
		return nil, errSchemaInvalid()
	}
	parsed, err := parseStrictJSON(candidate, MaxOperationBytes)
	if err != nil {
		return nil, err
	}
	value, valueOK := parsed.(map[string]any)
	if !valueOK {
		return nil, errSchemaInvalid()
	}
	canonical, err := CanonicalBytes(value)
	if err != nil || !bytes.Equal(canonical, candidate) ||
		value["capture_id"] != captureID || value["processing_mode"] != "managed" {
		return nil, errSchemaInvalid()
	}
	deployment, deploymentOK := value["deployment"].(map[string]any)
	if !deploymentOK || deployment["processing_mode"] != "managed" ||
		deployment["service_id"] != sink.configuration.ServiceID ||
		sink.workloadKeyID == "" || deployment["signer_key_id"] != sink.workloadKeyID {
		return nil, newManagedError(
			"AUTHORIZATION_DENIED",
			"The managed deployment does not use the registered workload key.",
		)
	}
	if err := verifySignedValue(deployment, sink.workloadPublicKey); err != nil {
		return nil, err
	}
	deploymentDigest, err := canonicalDigest(deployment)
	if err != nil || deploymentDigest != sink.deploymentDigest {
		return nil, newManagedError(
			"AUTHORIZATION_DENIED", "The managed deployment is not registered for this workload.",
		)
	}
	return value, nil
}

func (sink *ManagedCandidateSink) worker() {
	for queued := range sink.queue {
		if time.Since(queued.queuedAt) >= sink.deliveryLifetime {
			sink.increment(func(recall *RecallCounters) *uint64 {
				return &recall.CandidateDeliveryExpired
			})
			sink.finishQueued(queued.size)
			continue
		}
		sink.mu.Lock()
		sink.active = true
		sink.mu.Unlock()
		err := sink.deliver(queued.value)
		sink.recordDeliveryResult(err)
		sink.finishQueued(queued.size)
	}
}

func (sink *ManagedCandidateSink) finishQueued(size int) {
	sink.mu.Lock()
	sink.active = false
	sink.queuedBytes = max(0, sink.queuedBytes-size)
	sink.queuedCount = max(0, sink.queuedCount-1)
	sink.mu.Unlock()
}

func (sink *ManagedCandidateSink) deliver(candidate map[string]any) error {
	prepared, err := PrepareCompleteManagedCandidate(candidate, sink.subject, sink.closure)
	if err != nil {
		return err
	}
	grant, err := prepared.RequestEncryptionGrant(
		sink.client, sink.workloadKeyID, sink.workloadSigningKey,
	)
	if err != nil {
		return err
	}
	sealed, err := prepared.Seal(
		grant,
		nowTimestamp(),
		sink.configuration.CaptureSignerID,
		sink.configuration.CaptureSignerPublicKey,
	)
	if err != nil {
		return err
	}
	defer sealed.Close()
	renewal, err := sealed.RequestCaptureGrantRenewal(
		sink.client, sink.workloadKeyID, sink.workloadSigningKey,
	)
	if err != nil {
		return err
	}
	err = sealed.ApplyRenewedCaptureGrant(
		renewal,
		nowTimestamp(),
		sink.configuration.CaptureSignerID,
		sink.configuration.CaptureSignerPublicKey,
	)
	if err != nil {
		return err
	}
	_, err = sealed.Upload(sink.client)
	return err
}

func (sink *ManagedCandidateSink) recordDeliveryResult(err error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if err == nil {
		increment(&sink.recall.CandidateDurablyAccepted)
		return
	}
	managedError, isManaged := err.(*ManagedError)
	switch {
	case isManaged && managedError.Code == "INCOMPLETE_CANDIDATE":
		increment(&sink.recall.CandidateIncomplete)
	case isManaged && managedError.Retryable:
		increment(&sink.recall.CandidateDeliveryExpired)
	default:
		increment(&sink.recall.CandidateRejected)
	}
}

func (sink *ManagedCandidateSink) increment(
	selectCounter func(*RecallCounters) *uint64,
) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	increment(selectCounter(&sink.recall))
}

func validateManagedSinkConfiguration(configuration ManagedSinkConfiguration) error {
	if configuration.CaptureSignerID == "" || len(configuration.CaptureSignerID) > 256 ||
		len(configuration.CaptureSignerPublicKey) != 32 ||
		(len(configuration.WorkloadSigningKey) != 0 &&
			len(configuration.WorkloadSigningKey) != 32) {
		return errSchemaInvalid()
	}
	_, err := requireTypedID(configuration.ServiceID, "service_id")
	return err
}

func managedDeploymentBindingDigest(deployment map[string]any) (string, error) {
	stable := make(map[string]any, len(deployment)-3)
	for key, value := range deployment {
		if key != "signature" && key != "signed_at" && key != "signer_key_id" {
			stable[key] = value
		}
	}
	return canonicalDigest(stable)
}

func errCode(err error) string {
	if managed, ok := err.(*ManagedError); ok {
		return managed.Code
	}
	return "SERVICE_UNAVAILABLE"
}

// validateManagedDeployment mirrors the reproit-core Deployment::validate
// checks the SDK can prove.
func validateManagedDeployment(deployment map[string]any) error {
	repositoryID, repositoryIDOK := deployment["repository_id"].(string)
	runtimeEndpoint, runtimeEndpointOK := deployment["runtime_endpoint"].(string)
	servicePath, servicePathOK := deployment["service_path"].(string)
	signerKeyID, signerKeyIDOK := deployment["signer_key_id"].(string)
	sourceRevision, sourceRevisionOK := deployment["source_revision"].(string)
	signature, signatureOK := deployment["signature"].(string)
	if deployment["format"] != "reproit.deployment.v1" ||
		!repositoryIDOK || repositoryID == "" || len(repositoryID) > 256 ||
		!runtimeEndpointOK || runtimeEndpoint == "" || len(runtimeEndpoint) > 2_048 ||
		!servicePathOK || servicePath == "" || strings.HasPrefix(servicePath, "/") ||
		servicePathContainsParent(servicePath) ||
		!signerKeyIDOK || signerKeyID == "" || len(signerKeyID) > 256 ||
		!sourceRevisionOK || sourceRevision == "" || len(sourceRevision) > 256 ||
		!validTimestamp(deployment["signed_at"]) || !signatureOK {
		return errSchemaInvalid()
	}
	if err := validateCapabilities(deployment["runtime_capabilities"]); err != nil {
		return err
	}
	_, err := decodeBase64URL(signature, 64)
	return err
}

func servicePathContainsParent(servicePath string) bool {
	for _, part := range strings.Split(servicePath, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
