use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

use reproit_cloud_api::{WorkloadKeyRegistration, managed_workload_key_id};
use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::{SecretKey, encode_base64url, sign_bytes, verification_key, verify_signed_value},
    identity::{OperationId, ServiceId, Timestamp},
    model::{
        Candidate, Deployment, EventKind, NativeObservationFenceReceipt, ProcessingMode, Subject,
        SubjectClosureManifest, SubjectFormat, Validate as _,
    },
};
use time::OffsetDateTime;

use crate::{
    CandidateSink, MAX_GLOBAL_BYTES, MAX_QUEUED_CANDIDATES, ManagedProjectToken,
    ManagedRustCaptureClosure, ManagedRustOperationClosure, ManagedTlsClient,
    ManagedWorkloadIdentityState, ManagedWorkloadRegistrationReceipt, PreparedManagedRustCandidate,
    RustSubjectPackage, SdkRecallCounters, managed::FrozenManagedRustCaptureClosure,
    managed_deployment::managed_deployment_binding_digest,
    official_managed::official_managed_configuration, package_running_rust_subject,
};

const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5);
const CANDIDATE_DELIVERY_LIFETIME: Duration =
    Duration::from_millis(crate::CANDIDATE_DELIVERY_LIFETIME_MS);

pub struct ManagedRustSinkConfiguration {
    pub capture_signer_id: String,
    pub capture_signer_public_key: [u8; 32],
    pub project_token: Option<ManagedProjectToken>,
    pub service_id: ServiceId,
    pub workload_state_root: PathBuf,
}

pub struct ManagedRustCandidateSink {
    idle: Arc<Condvar>,
    operation_id: Option<OperationId>,
    queue: SyncSender<QueuedCandidate>,
    recall: Arc<Mutex<SdkRecallCounters>>,
    service_id: ServiceId,
    state: Arc<Mutex<QueueState>>,
    subject_manifest: SubjectClosureManifest,
    world_id: reproit_core::identity::Digest,
    workload_key_id: String,
    workload_public_key: [u8; 32],
    workload_signing_key: Arc<SecretKey>,
}

pub struct ManagedRustLocalRecorder {
    operation_id: OperationId,
    state: Mutex<LocalRecorderState>,
    subject: Arc<RustSubjectPackage>,
}

#[derive(Default)]
struct LocalRecorderState {
    bytes: usize,
    candidate: Option<Candidate>,
    incomplete: u64,
}

pub struct ManagedRustRecordedFailure {
    candidate: Candidate,
    operation_id: OperationId,
    subject: Arc<RustSubjectPackage>,
}

struct QueuedCandidate {
    bytes: usize,
    candidate: Candidate,
    capture_id: reproit_core::identity::CaptureId,
    queued_at: Instant,
}

struct WorkloadGrantSigner {
    key_id: String,
    signing_key: Arc<SecretKey>,
}

struct RegisteredWorkload {
    key_id: String,
    public_key: [u8; 32],
    signing_key: Arc<SecretKey>,
}

#[derive(Clone, Copy)]
enum WorkloadStateLocation<'a> {
    Protected,
    Root(&'a std::path::Path),
}

struct ManagedSinkConnection<'a> {
    capture_signer_id: String,
    capture_signer_public_key: [u8; 32],
    client: Arc<ManagedTlsClient>,
    service_id: ServiceId,
    workload_state: WorkloadStateLocation<'a>,
}

#[derive(Default)]
struct QueueState {
    active: bool,
    bytes: usize,
    candidates: usize,
}

impl ManagedRustCandidateSink {
    pub fn new(
        client: Arc<ManagedTlsClient>,
        closure: ManagedRustCaptureClosure,
        configuration: ManagedRustSinkConfiguration,
        deployment: &mut Deployment,
    ) -> Result<Self, Error> {
        validate_configuration(&configuration)?;
        let closure = FrozenManagedRustCaptureClosure::freeze(closure)?;
        Self::new_with_frozen_closure(client, closure, None, configuration, deployment)
    }

    pub fn new_for_operation(
        client: Arc<ManagedTlsClient>,
        operation_closure: ManagedRustOperationClosure,
        configuration: ManagedRustSinkConfiguration,
        deployment: &mut Deployment,
    ) -> Result<Self, Error> {
        validate_configuration(&configuration)?;
        let (operation_id, closure) = operation_closure.into_parts();
        Self::new_with_frozen_closure(
            client,
            closure,
            Some(operation_id),
            configuration,
            deployment,
        )
    }

    fn new_with_frozen_closure(
        client: Arc<ManagedTlsClient>,
        closure: FrozenManagedRustCaptureClosure,
        operation_id: Option<OperationId>,
        configuration: ManagedRustSinkConfiguration,
        deployment: &mut Deployment,
    ) -> Result<Self, Error> {
        let subject = Arc::new(package_running_rust_subject().map_err(|error| {
            Error::new(
                error.code,
                "Repro It could not package the complete running Rust application.",
            )
        })?);
        Self::new_with_subject(
            client,
            closure,
            operation_id,
            configuration,
            subject,
            deployment,
        )
    }

    fn new_with_subject(
        client: Arc<ManagedTlsClient>,
        closure: FrozenManagedRustCaptureClosure,
        operation_id: Option<OperationId>,
        configuration: ManagedRustSinkConfiguration,
        subject: Arc<RustSubjectPackage>,
        deployment: &mut Deployment,
    ) -> Result<Self, Error> {
        let ManagedRustSinkConfiguration {
            capture_signer_id,
            capture_signer_public_key,
            project_token,
            service_id,
            workload_state_root,
        } = configuration;
        let connection = ManagedSinkConnection {
            capture_signer_id,
            capture_signer_public_key,
            client,
            service_id,
            workload_state: WorkloadStateLocation::Root(&workload_state_root),
        };
        Self::new_with_subject_connection(
            connection,
            closure,
            operation_id,
            move || project_token.ok_or_else(registration_token_required),
            subject,
            deployment,
        )
    }

    fn new_with_official_subject<F>(
        closure: FrozenManagedRustCaptureClosure,
        operation_id: Option<OperationId>,
        project_token_provider: F,
        subject: Arc<RustSubjectPackage>,
        deployment: &mut Deployment,
    ) -> Result<Self, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        let configuration = official_managed_configuration()?;
        configuration
            .managed_origin
            .clone_into(&mut deployment.runtime_endpoint);
        let service_id = deployment.service_id;
        let connection = ManagedSinkConnection {
            capture_signer_id: configuration.capture_signer_id.to_owned(),
            capture_signer_public_key: configuration.capture_signer_public_key,
            client: configuration.client,
            service_id,
            workload_state: WorkloadStateLocation::Protected,
        };
        Self::new_with_subject_connection(
            connection,
            closure,
            operation_id,
            project_token_provider,
            subject,
            deployment,
        )
    }

    fn new_with_subject_connection<F>(
        connection: ManagedSinkConnection<'_>,
        closure: FrozenManagedRustCaptureClosure,
        operation_id: Option<OperationId>,
        project_token_provider: F,
        subject: Arc<RustSubjectPackage>,
        deployment: &mut Deployment,
    ) -> Result<Self, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        let ManagedSinkConnection {
            capture_signer_id,
            capture_signer_public_key,
            client,
            service_id,
            workload_state,
        } = connection;
        let closure = closure.into_worker_owner();
        let subject_manifest = subject.manifest.clone();
        let world_id = closure.closure.world.world_id()?;
        let registered = register_managed_workload(
            client.as_ref(),
            deployment,
            &subject_manifest,
            service_id,
            workload_state,
            project_token_provider,
        )?;
        let workload_key_id = registered.key_id;
        let workload_public_key = registered.public_key;
        let workload_signing_key = registered.signing_key.clone();
        let worker_workload_signer = WorkloadGrantSigner {
            key_id: workload_key_id.clone(),
            signing_key: registered.signing_key,
        };
        let (queue, receiver) = sync_channel::<QueuedCandidate>(MAX_QUEUED_CANDIDATES);
        let state = Arc::new(Mutex::new(QueueState::default()));
        let recall = Arc::new(Mutex::new(SdkRecallCounters::default()));
        let idle = Arc::new(Condvar::new());
        let worker_state = state.clone();
        let worker_recall = recall.clone();
        let worker_idle = idle.clone();
        let (ready_sender, ready_receiver) = sync_channel(0);
        thread::Builder::new()
            .name("reproit-managed-rust-capture".to_owned())
            .spawn(move || {
                if ready_sender.send(()).is_err() {
                    return;
                }
                while let Ok(queued) = receiver.recv() {
                    if delivery_expired(queued.queued_at, Instant::now()) {
                        record_delivery_expired(&worker_recall);
                        finish_queued(&worker_state, &worker_idle, queued.capture_id, queued.bytes);
                        continue;
                    }
                    set_active(&worker_state, true);
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        deliver_candidate(
                            &queued.candidate,
                            subject.clone(),
                            &closure,
                            CandidateDeliveryContext {
                                capture_signer_id: &capture_signer_id,
                                capture_signer_public_key: &capture_signer_public_key,
                                client: client.as_ref(),
                                queued_at: queued.queued_at,
                                workload_signer: &worker_workload_signer,
                            },
                        )
                    }))
                    .unwrap_or_else(|_| Err(local_unavailable()));
                    record_result(&worker_recall, &result);
                    finish_queued(&worker_state, &worker_idle, queued.capture_id, queued.bytes);
                }
            })
            .map_err(|_| local_unavailable())?;
        ready_receiver
            .recv_timeout(REGISTRATION_TIMEOUT)
            .map_err(|_| local_unavailable())?;
        Ok(Self {
            idle,
            operation_id,
            queue,
            recall,
            service_id,
            state,
            subject_manifest,
            world_id,
            workload_key_id,
            workload_public_key,
            workload_signing_key,
        })
    }

    #[must_use]
    pub fn subject_manifest(&self) -> &SubjectClosureManifest {
        &self.subject_manifest
    }

    #[must_use]
    pub fn workload_key_id(&self) -> &str {
        &self.workload_key_id
    }

    #[must_use]
    pub const fn workload_public_key(&self) -> &[u8; 32] {
        &self.workload_public_key
    }

    #[must_use]
    pub const fn world_id(&self) -> reproit_core::identity::Digest {
        self.world_id
    }

    fn finalize_automatic_fence(&self, candidate: &mut Candidate) -> Result<(), Error> {
        let fence_records = candidate
            .records
            .iter_mut()
            .filter(|record| record.kind == EventKind::ObservationFence)
            .collect::<Vec<_>>();
        if fence_records.is_empty() {
            return Ok(());
        }
        if fence_records.len() != 1 {
            return Err(incomplete_candidate());
        }
        let record = fence_records
            .into_iter()
            .next()
            .ok_or_else(incomplete_candidate)?;
        let bytes = reproit_core::crypto::decode_base64url_bytes(&record.payload)?;
        let mut fence: NativeObservationFenceReceipt = canonical::parse_strict(&bytes)?;
        fence.deployment_digest = canonical::digest(&candidate.deployment)?;
        fence.subject_digest = canonical::digest(&candidate.deployment.subject)?;
        self.workload_key_id.clone_into(&mut fence.signer_key_id);
        fence.signature.clear();
        fence.signature = sign_bytes(
            &canonical::canonical_bytes(&fence)?,
            &self.workload_signing_key,
        );
        fence.validate()?;
        record.payload = encode_base64url(&canonical::canonical_bytes(&fence)?);
        candidate.validate()
    }

    pub fn wait_until_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while state.active || state.candidates != 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let result = self.idle.wait_timeout(state, deadline - now);
            let (next, _) = result.unwrap_or_else(PoisonError::into_inner);
            state = next;
        }
        true
    }

    fn authorize_candidate(&self, candidate: &Candidate) -> Result<(), Error> {
        candidate.validate()?;
        if self
            .operation_id
            .is_some_and(|operation_id| operation_id != candidate.operation_id)
            || candidate.deployment.service_id != self.service_id
            || candidate.deployment.signer_key_id != self.workload_key_id
        {
            return Err(Error::new(
                ErrorCode::AuthorizationDenied,
                "The managed deployment does not use the registered workload key.",
            ));
        }
        verify_signed_value(
            &serde_json::to_value(&candidate.deployment).map_err(|_| Error::schema_invalid())?,
            &self.workload_public_key,
        )
    }
}

impl ManagedRustLocalRecorder {
    pub fn new(operation_id: OperationId) -> Result<Self, Error> {
        let subject = package_running_rust_subject().map_err(|error| {
            Error::new(
                error.code,
                "Repro It could not package the complete running Rust application.",
            )
        })?;
        Self::new_with_shared_subject(operation_id, Arc::new(subject))
    }

    pub fn new_with_shared_subject(
        operation_id: OperationId,
        subject: Arc<RustSubjectPackage>,
    ) -> Result<Self, Error> {
        subject.manifest.validate()?;
        Ok(Self {
            operation_id,
            state: Mutex::new(LocalRecorderState::default()),
            subject,
        })
    }

    pub fn bind_deployment(&self, deployment: &mut Deployment) -> Result<(), Error> {
        bind_subject(deployment, &self.subject.manifest)?;
        "pending-managed-registration".clone_into(&mut deployment.signer_key_id);
        deployment.signature = encode_base64url(&[0_u8; 64]);
        deployment.validate()
    }

    pub fn take_failed_candidate(&self) -> Option<ManagedRustRecordedFailure> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let candidate = state.candidate.take();
        state.bytes = 0;
        drop(state);
        if let Some(candidate) = &candidate {
            crate::resources::release_candidate(candidate.capture_id);
        }
        candidate.map(|candidate| ManagedRustRecordedFailure {
            candidate,
            operation_id: self.operation_id,
            subject: self.subject.clone(),
        })
    }
}

impl Drop for ManagedRustLocalRecorder {
    fn drop(&mut self) {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(candidate) = &state.candidate {
            crate::resources::release_candidate(candidate.capture_id);
        }
    }
}

impl CandidateSink for ManagedRustLocalRecorder {
    fn queued_bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
    }

    fn recall_counters(&self) -> SdkRecallCounters {
        let incomplete = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .incomplete;
        SdkRecallCounters {
            candidate_incomplete: incomplete,
            ..SdkRecallCounters::default()
        }
    }

    fn retains_queued_candidates(&self) -> bool {
        true
    }

    fn try_send(&self, candidate: Candidate) -> bool {
        let candidate_bytes = canonical::canonical_bytes(&candidate).map(|bytes| bytes.len());
        let Ok(candidate_bytes) = candidate_bytes else {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.incomplete = state.incomplete.saturating_add(1);
            return false;
        };
        let capture_id = candidate.capture_id;
        if !crate::resources::claim_candidate(capture_id, candidate_bytes) {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.incomplete = state.incomplete.saturating_add(1);
            return false;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if candidate.operation_id != self.operation_id
            || candidate_bytes > crate::MAX_OPERATION_BYTES
            || state.candidate.is_some()
        {
            state.incomplete = state.incomplete.saturating_add(1);
            drop(state);
            crate::resources::release_candidate(capture_id);
            return false;
        }
        state.bytes = candidate_bytes;
        state.candidate = Some(candidate);
        true
    }
}

impl ManagedRustRecordedFailure {
    pub fn finalize<F>(
        self,
        operation_closure: ManagedRustOperationClosure,
        connect: F,
    ) -> Result<ManagedRustCandidateSink, Error>
    where
        F: FnOnce() -> Result<(Arc<ManagedTlsClient>, ManagedRustSinkConfiguration), Error>,
    {
        let (mut recorded, operation_id, closure) = self.prepare(operation_closure)?;
        let (client, configuration) = connect()?;
        validate_configuration(&configuration)?;
        if recorded.candidate.deployment.service_id != configuration.service_id {
            return Err(Error::new(
                ErrorCode::AuthorizationDenied,
                "The managed deployment belongs to a different service.",
            ));
        }
        let sink = ManagedRustCandidateSink::new_with_subject(
            client,
            closure,
            Some(operation_id),
            configuration,
            recorded.subject,
            &mut recorded.candidate.deployment,
        )?;
        sink.finalize_automatic_fence(&mut recorded.candidate)?;
        recorded.candidate.processing_mode = recorded.candidate.deployment.processing_mode;
        if !sink.try_send(recorded.candidate) {
            return Err(incomplete_candidate());
        }
        Ok(sink)
    }

    pub fn finalize_official<F>(
        self,
        operation_closure: ManagedRustOperationClosure,
        project_token_provider: F,
    ) -> Result<ManagedRustCandidateSink, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        let (mut recorded, operation_id, closure) = self.prepare(operation_closure)?;
        let sink = ManagedRustCandidateSink::new_with_official_subject(
            closure,
            Some(operation_id),
            project_token_provider,
            recorded.subject,
            &mut recorded.candidate.deployment,
        )?;
        sink.finalize_automatic_fence(&mut recorded.candidate)?;
        recorded.candidate.processing_mode = recorded.candidate.deployment.processing_mode;
        if !sink.try_send(recorded.candidate) {
            return Err(incomplete_candidate());
        }
        Ok(sink)
    }

    fn prepare(
        self,
        operation_closure: ManagedRustOperationClosure,
    ) -> Result<(Self, OperationId, FrozenManagedRustCaptureClosure), Error> {
        let (operation_id, closure) = operation_closure.into_parts();
        if operation_id != self.operation_id || self.candidate.operation_id != operation_id {
            return Err(incomplete_candidate());
        }
        let preflight = PreparedManagedRustCandidate::prepare_frozen_shared(
            &self.candidate,
            self.subject.clone(),
            &closure,
        )?;
        drop(preflight);
        Ok((self, operation_id, closure))
    }
}

fn bind_subject(
    deployment: &mut Deployment,
    manifest: &SubjectClosureManifest,
) -> Result<(), Error> {
    let platform = reproit_sdk_platform::host_platform().map_err(|_| {
        Error::new(
            ErrorCode::Unsupported,
            "This host does not have a supported Backend platform descriptor.",
        )
    })?;
    if manifest.architecture != platform.architecture
        || manifest.operating_system != platform.operating_system
    {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "The subject platform does not match the capture host.",
        ));
    }
    deployment.processing_mode = ProcessingMode::Managed;
    deployment.subject = Subject {
        architecture: manifest.architecture.clone(),
        arguments: manifest.launch.arguments.clone(),
        artifact_digest: canonical::digest(manifest)?,
        artifact_media_type: "application/vnd.reproit.subject-closure.v1+json".to_owned(),
        artifact_uri: format!("reproit-managed://{}", canonical::digest(manifest)?),
        environment_names: manifest.launch.environment_names.clone(),
        executable: manifest.launch.executable.clone(),
        format: SubjectFormat::V1,
        operating_system: manifest.operating_system.clone(),
        working_directory: manifest.launch.working_directory.clone(),
    };
    deployment.runtime_capabilities.extend([
        platform.runtime_abi.to_owned(),
        manifest.architecture.clone(),
        manifest.operating_system.clone(),
    ]);
    // The captured World's process-visible processor view travels with the
    // candidate so admission starts from the complete observation
    // (spec 7.8.1).
    deployment
        .runtime_capabilities
        .extend(crate::processor_capture::capture_processor_capabilities());
    deployment.runtime_capabilities.sort();
    deployment.runtime_capabilities.dedup();
    Ok(())
}

fn register_managed_workload<F>(
    client: &ManagedTlsClient,
    deployment: &mut Deployment,
    manifest: &SubjectClosureManifest,
    service_id: ServiceId,
    workload_state: WorkloadStateLocation<'_>,
    project_token_provider: F,
) -> Result<RegisteredWorkload, Error>
where
    F: FnOnce() -> Result<ManagedProjectToken, Error>,
{
    prepare_managed_deployment(deployment, manifest, service_id)?;
    let binding_digest = managed_deployment_binding_digest(deployment)?;
    let workload_identity = match workload_state {
        WorkloadStateLocation::Protected => {
            ManagedWorkloadIdentityState::from_environment(binding_digest)?
        }
        WorkloadStateLocation::Root(state_root) => {
            ManagedWorkloadIdentityState::from_state_root(state_root, binding_digest)?
        }
    };
    let signing_key = workload_identity.load_or_create_key()?;
    deployment.signed_at =
        workload_identity.load_or_create_deployment_signed_at(binding_digest, &now()?)?;
    let public_key = verification_key(&signing_key);
    let public_key_text = encode_base64url(&public_key);
    let key_id = managed_workload_key_id(&public_key_text)?;
    sign_managed_deployment(deployment, &key_id, &signing_key)?;
    let request = WorkloadKeyRegistration {
        algorithm: "Ed25519".to_owned(),
        deployment: deployment.clone(),
        public_key: public_key_text,
        service_id,
    };
    let receipt = ManagedWorkloadRegistrationReceipt {
        deployment_digest: request.deployment_digest()?,
        service_id,
        workload_key_id: key_id.clone(),
    };
    if workload_identity
        .load_registration_receipt(&receipt)?
        .is_none()
    {
        let project_token = project_token_provider()?;
        let registration = client
            .register_workload_key(project_token, &request, REGISTRATION_TIMEOUT)
            .map_err(|error| {
                Error::new(error.code, "Repro It could not register this workload key.")
            })?;
        if registration.key_id != key_id {
            return Err(Error::new(
                ErrorCode::AttestationScope,
                "The managed workload registration does not match this deployment.",
            ));
        }
        workload_identity.persist_registration_receipt(&receipt)?;
    }
    Ok(RegisteredWorkload {
        key_id,
        public_key,
        signing_key: Arc::new(signing_key),
    })
}

fn prepare_managed_deployment(
    deployment: &mut Deployment,
    manifest: &SubjectClosureManifest,
    service_id: ServiceId,
) -> Result<(), Error> {
    if deployment.service_id != service_id {
        return Err(Error::new(
            ErrorCode::AuthorizationDenied,
            "The managed deployment belongs to a different service.",
        ));
    }
    bind_subject(deployment, manifest)?;
    deployment.validate()?;
    deployment.signer_key_id.clear();
    deployment.signature.clear();
    Ok(())
}

fn sign_managed_deployment(
    deployment: &mut Deployment,
    workload_key_id: &str,
    workload_signing_key: &SecretKey,
) -> Result<(), Error> {
    workload_key_id.clone_into(&mut deployment.signer_key_id);
    deployment.signature.clear();
    deployment.signature = sign_bytes(
        &canonical::canonical_bytes(deployment)?,
        workload_signing_key,
    );
    deployment.validate()
}

impl CandidateSink for ManagedRustCandidateSink {
    fn queued_bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes
    }

    fn recall_counters(&self) -> SdkRecallCounters {
        self.recall
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn retains_queued_candidates(&self) -> bool {
        true
    }

    fn try_send(&self, candidate: Candidate) -> bool {
        if self.authorize_candidate(&candidate).is_err() {
            record_incomplete(&self.recall);
            return false;
        }
        let Ok(bytes) = canonical::canonical_bytes(&candidate).map(|value| value.len()) else {
            record_incomplete(&self.recall);
            return false;
        };
        let capture_id = candidate.capture_id;
        if !crate::resources::claim_candidate(capture_id, bytes) {
            record_queue_full(&self.recall);
            return false;
        }
        let full = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.candidates >= MAX_QUEUED_CANDIDATES
                || state
                    .bytes
                    .checked_add(bytes)
                    .is_none_or(|total| total > MAX_GLOBAL_BYTES)
            {
                true
            } else {
                state.bytes += bytes;
                state.candidates += 1;
                false
            }
        };
        if full {
            crate::resources::release_candidate(capture_id);
            record_queue_full(&self.recall);
            return false;
        }
        let queued = QueuedCandidate {
            bytes,
            candidate,
            capture_id,
            queued_at: Instant::now(),
        };
        match self.queue.try_send(queued) {
            Ok(()) => true,
            Err(TrySendError::Full(queued) | TrySendError::Disconnected(queued)) => {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.bytes = state.bytes.saturating_sub(queued.bytes);
                state.candidates = state.candidates.saturating_sub(1);
                drop(state);
                crate::resources::release_candidate(queued.capture_id);
                record_queue_full(&self.recall);
                false
            }
        }
    }
}

#[derive(Clone, Copy)]
struct CandidateDeliveryContext<'a> {
    capture_signer_id: &'a str,
    capture_signer_public_key: &'a [u8; 32],
    client: &'a ManagedTlsClient,
    queued_at: Instant,
    workload_signer: &'a WorkloadGrantSigner,
}

fn deliver_candidate(
    candidate: &Candidate,
    subject: Arc<RustSubjectPackage>,
    closure: &FrozenManagedRustCaptureClosure,
    context: CandidateDeliveryContext<'_>,
) -> Result<(), Error> {
    let deadline = crate::managed::ManagedDeliveryDeadline::from_queued_at(context.queued_at);
    deadline.check()?;
    let prepared =
        PreparedManagedRustCandidate::prepare_frozen_shared(candidate, subject, closure)?;
    deadline.check()?;
    let grant = prepared.request_encryption_grant_before(
        context.client,
        &context.workload_signer.key_id,
        context.workload_signer.signing_key.as_ref(),
        deadline,
    )?;
    deadline.check()?;
    let mut sealed = prepared.seal(
        grant,
        &now()?,
        context.capture_signer_id,
        context.capture_signer_public_key,
    )?;
    deadline.check()?;
    let renewal = sealed.request_capture_grant_renewal_before(
        context.client,
        &context.workload_signer.key_id,
        context.workload_signer.signing_key.as_ref(),
        deadline,
    )?;
    sealed.apply_renewed_capture_grant(
        renewal,
        &now()?,
        context.capture_signer_id,
        context.capture_signer_public_key,
    )?;
    deadline.check()?;
    sealed.upload_before(context.client, deadline)?;
    Ok(())
}

fn validate_configuration(configuration: &ManagedRustSinkConfiguration) -> Result<(), Error> {
    if configuration.capture_signer_id.is_empty() || configuration.capture_signer_id.len() > 256 {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn set_active(state: &Mutex<QueueState>, active: bool) {
    state.lock().unwrap_or_else(PoisonError::into_inner).active = active;
}

fn delivery_expired(queued_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(queued_at) >= CANDIDATE_DELIVERY_LIFETIME
}

fn finish_queued(
    state: &Mutex<QueueState>,
    idle: &Condvar,
    capture_id: reproit_core::identity::CaptureId,
    bytes: usize,
) {
    crate::resources::release_candidate(capture_id);
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    state.active = false;
    state.bytes = state.bytes.saturating_sub(bytes);
    state.candidates = state.candidates.saturating_sub(1);
    idle.notify_all();
}

fn record_result(recall: &Mutex<SdkRecallCounters>, result: &Result<(), Error>) {
    let mut recall = recall.lock().unwrap_or_else(PoisonError::into_inner);
    match result {
        Ok(()) => {
            recall.candidate_durably_accepted = recall.candidate_durably_accepted.saturating_add(1);
        }
        Err(error) if error.code == ErrorCode::IncompleteCandidate => {
            recall.candidate_incomplete = recall.candidate_incomplete.saturating_add(1);
        }
        Err(error) if error.retryable => {
            recall.candidate_delivery_expired = recall.candidate_delivery_expired.saturating_add(1);
        }
        Err(_) => {
            recall.candidate_rejected = recall.candidate_rejected.saturating_add(1);
        }
    }
}

fn record_incomplete(recall: &Mutex<SdkRecallCounters>) {
    let mut recall = recall.lock().unwrap_or_else(PoisonError::into_inner);
    recall.candidate_incomplete = recall.candidate_incomplete.saturating_add(1);
}

fn record_queue_full(recall: &Mutex<SdkRecallCounters>) {
    let mut recall = recall.lock().unwrap_or_else(PoisonError::into_inner);
    recall.candidate_queue_full = recall.candidate_queue_full.saturating_add(1);
}

fn record_delivery_expired(recall: &Mutex<SdkRecallCounters>) {
    let mut recall = recall.lock().unwrap_or_else(PoisonError::into_inner);
    recall.candidate_delivery_expired = recall.candidate_delivery_expired.saturating_add(1);
}

fn now() -> Result<Timestamp, Error> {
    let value = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year(),
        value.month() as u8,
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.millisecond(),
    )
    .parse()
}

fn local_unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The managed capture worker could not start.",
    )
}

fn registration_token_required() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed project token is required for first registration.",
    )
}

fn incomplete_candidate() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The managed candidate is incomplete and cannot be uploaded.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_delivery_lifetime_has_an_exact_boundary() {
        let queued_at = Instant::now();
        let almost_expired = (queued_at + CANDIDATE_DELIVERY_LIFETIME)
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert!(!delivery_expired(queued_at, almost_expired));
        assert!(delivery_expired(
            queued_at,
            queued_at + CANDIDATE_DELIVERY_LIFETIME
        ));
    }
}
