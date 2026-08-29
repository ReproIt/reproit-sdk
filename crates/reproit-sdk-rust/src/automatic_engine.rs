use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use reproit_core::{
    Error, ErrorCode,
    identity::{CaptureId, Digest, OperationId},
    model::{
        AutomaticObservationClass, DependencyOutcome, FailureIdentity, OperationBeginPayload,
        OperationInputPayload,
    },
};
use uuid::Uuid;

use reproit_sdk_sentinel::{self as native_sentinel, OperationCoverage};

use crate::{
    AutomaticCandidateStart, ManagedProjectToken, ManagedRustCandidateSink,
    ManagedRustCaptureClosure, ManagedRustLocalRecorder, ManagedRustOperationClosure,
    OfficialManagedProject, Sdk, SubjectPackage,
    automatic_context::{AutomaticOperationContext, AutomaticOperationShared},
    automatic_world::{
        AutomaticObservationRegistration, AutomaticObservationStream, AutomaticWorldCapture,
        AutomaticWorldCoordinator, MAX_AUTOMATIC_OBSERVATION_CHUNK_BYTES,
        MAX_AUTOMATIC_OBSERVATION_RESPONSE_READ_BYTES,
        MAX_AUTOMATIC_OBSERVATION_SESSIONS_PER_OPERATION,
        MAX_NATIVE_SENTINEL_EVIDENCE_BYTES as MAX_NATIVE_SENTINEL_EVIDENCE_BOUND,
    },
    official_operation::{
        ManagedProjectTokenProvider, RustOperation, RustOperationFactory, failure_payload,
        validate_completion,
    },
};

#[derive(Clone)]
pub struct AutomaticManagedEngine {
    observation_registrations:
        BTreeMap<AutomaticObservationClass, AutomaticObservationRegistration>,
    project: OfficialManagedProject,
    sentinel: Option<Arc<NativeSentinelLease>>,
    subject: Arc<SubjectPackage>,
}

const RUST_NATIVE_GUARD_ADAPTER_ID: &str = "rust-native-coverage-sentinel";
const RUST_NATIVE_GUARD_ADAPTER_VERSION: &str = "1.0.0";
static NEXT_NATIVE_OPERATION_HANDLE: AtomicU64 = AtomicU64::new(1);

struct NativeSentinelLease;

impl NativeSentinelLease {
    fn acquire() -> Arc<Self> {
        native_sentinel::engine_opened();
        Arc::new(Self)
    }
}

impl Drop for NativeSentinelLease {
    fn drop(&mut self) {
        native_sentinel::engine_closed();
    }
}

impl AutomaticManagedEngine {
    #[must_use]
    pub fn new(project: OfficialManagedProject, subject: SubjectPackage) -> Self {
        let mut engine = Self {
            observation_registrations: BTreeMap::new(),
            project,
            sentinel: Some(NativeSentinelLease::acquire()),
            subject: Arc::new(subject),
        };
        engine.install_native_guard_adapters();
        engine
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_unregistered(project: OfficialManagedProject, subject: SubjectPackage) -> Self {
        Self {
            observation_registrations: BTreeMap::new(),
            project,
            sentinel: None,
            subject: Arc::new(subject),
        }
    }

    fn install_native_guard_adapters(&mut self) {
        let Some(implementation_digest) = self.subject.manifest.modules.iter().find_map(|module| {
            (module.path == self.subject.manifest.launch.executable).then_some(module.module_digest)
        }) else {
            return;
        };
        for class in AutomaticObservationClass::ALL {
            let Ok(registration) = AutomaticObservationRegistration::new(
                class,
                RUST_NATIVE_GUARD_ADAPTER_ID.to_owned(),
                RUST_NATIVE_GUARD_ADAPTER_VERSION.to_owned(),
                implementation_digest,
            ) else {
                self.observation_registrations.clear();
                return;
            };
            self.observation_registrations.insert(class, registration);
        }
    }

    pub fn register_observation_adapter(
        &mut self,
        class: AutomaticObservationClass,
        adapter_id: String,
        adapter_version: String,
        implementation_digest: Digest,
    ) -> Result<(), Error> {
        let registration = AutomaticObservationRegistration::new(
            class,
            adapter_id,
            adapter_version,
            implementation_digest,
        )?;
        if self
            .observation_registrations
            .insert(class, registration)
            .is_some()
        {
            return Err(Error::schema_invalid());
        }
        Ok(())
    }

    pub fn start(&self, begin: &OperationBeginPayload) -> Result<AutomaticManagedOperation, Error> {
        let capture_id = new_capture_id()?;
        let operation_id = new_operation_id()?;
        let recorder = Arc::new(ManagedRustLocalRecorder::new_with_shared_subject(
            operation_id,
            self.subject.clone(),
        )?);
        let mut deployment = self.project.deployment()?;
        recorder.bind_deployment(&mut deployment)?;
        let sdk = Sdk::new(recorder.clone());
        sdk.begin_automatic(
            AutomaticCandidateStart {
                capture_id,
                deployment,
                operation_id,
            },
            begin,
        )?;
        let mut coordinator = match AutomaticWorldCoordinator::new_with_registrations(
            sdk.clone(),
            operation_id,
            self.observation_registrations.clone(),
        ) {
            Ok(coordinator) => coordinator,
            Err(error) => {
                sdk.abandon_incomplete(operation_id);
                return Err(error);
            }
        };
        if let Err(error) = coordinator.capture_ambient() {
            sdk.abandon_incomplete(operation_id);
            return Err(error);
        }
        let shared = match AutomaticOperationShared::new(operation_id, coordinator) {
            Ok(shared) => shared,
            Err(error) => {
                sdk.abandon_incomplete(operation_id);
                return Err(error);
            }
        };
        let sentinel_handle = if self.sentinel.is_some() {
            let handle = next_native_operation_handle()?;
            let _engine_call_guard = native_sentinel::engine_call_scope();
            native_sentinel::operation_started(handle);
            Some(handle)
        } else {
            None
        };
        Ok(AutomaticManagedOperation {
            closure: None,
            finished: false,
            operation_id,
            operation_kind: begin.operation_kind,
            operation_name: begin.operation_name.clone(),
            recorder,
            sdk,
            sentinel_handle,
            shared,
        })
    }
}

pub struct AutomaticManagedOperation {
    closure: Option<ManagedRustOperationClosure>,
    finished: bool,
    operation_id: OperationId,
    operation_kind: reproit_core::model::OperationKind,
    operation_name: String,
    recorder: Arc<ManagedRustLocalRecorder>,
    sdk: Sdk,
    sentinel_handle: Option<u64>,
    shared: Arc<AutomaticOperationShared>,
}

impl AutomaticManagedOperation {
    pub const MAX_OBSERVATION_CHUNK_BYTES: usize = MAX_AUTOMATIC_OBSERVATION_CHUNK_BYTES;
    pub const MAX_OBSERVATION_RESPONSE_READ_BYTES: usize =
        MAX_AUTOMATIC_OBSERVATION_RESPONSE_READ_BYTES;
    pub const MAX_OBSERVATION_SESSIONS: usize = MAX_AUTOMATIC_OBSERVATION_SESSIONS_PER_OPERATION;
    pub const MAX_NATIVE_SENTINEL_EVIDENCE_BYTES: usize = MAX_NATIVE_SENTINEL_EVIDENCE_BOUND;

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[doc(hidden)]
    #[must_use]
    pub fn ambient_context(&self) -> AutomaticOperationContext {
        AutomaticOperationContext::new(self.operation_id, self.shared.clone())
    }

    pub fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.sdk.record_input(self.operation_id, input)
    }

    pub fn open_observation(
        &mut self,
        session_id: u64,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
    ) -> Result<u64, Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared.with_coordinator(|coordinator| {
            coordinator.open_observation(session_id, class, causal_parent_id)
        })
    }

    pub fn write_observation_request(
        &mut self,
        session_id: u64,
        chunk: &[u8],
    ) -> Result<(), Error> {
        self.write_observation(session_id, AutomaticObservationStream::Request, chunk)
    }

    pub fn write_observation_response(
        &mut self,
        session_id: u64,
        chunk: &[u8],
    ) -> Result<(), Error> {
        self.write_observation(session_id, AutomaticObservationStream::Response, chunk)
    }

    pub fn dispatch_observation(&mut self, session_id: u64) -> Result<&'static str, Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared.with_coordinator(|coordinator| {
            coordinator
                .dispatch_observation(session_id)
                .map(super::automatic_world::AutomaticObservationAction::as_str)
        })
    }

    pub fn read_observation_response(&mut self, session_id: u64) -> Result<(Vec<u8>, bool), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared
            .with_coordinator(|coordinator| coordinator.read_observation_response(session_id))
    }

    pub fn finish_observation(
        &mut self,
        session_id: u64,
        outcome: DependencyOutcome,
        session_position: u64,
    ) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared.with_coordinator(|coordinator| {
            coordinator.finish_observation(session_id, outcome, session_position)
        })
    }

    pub fn abandon_observation(&mut self, session_id: u64) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared
            .with_coordinator(|coordinator| coordinator.abandon_observation(session_id))
    }

    pub fn mark_unowned(
        &mut self,
        class: reproit_core::model::AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
        evidence: &[u8],
    ) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared.with_coordinator(|coordinator| {
            coordinator.mark_unowned(class, causal_parent_id, evidence)
        })
    }

    #[doc(hidden)]
    pub fn bind_native_sentinel_coverage(&mut self, evidence: &[u8]) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared
            .with_coordinator(|coordinator| coordinator.bind_native_sentinel_coverage(evidence))
    }

    fn write_observation(
        &mut self,
        session_id: u64,
        stream: AutomaticObservationStream,
        chunk: &[u8],
    ) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        self.shared.with_coordinator(|coordinator| {
            coordinator.write_observation(session_id, stream, chunk)
        })
    }

    pub fn close_world(
        &mut self,
        completion: reproit_core::model::TriggerCompletion,
    ) -> Result<(), Error> {
        let _engine_call_guard = native_sentinel::engine_call_scope();
        if let Some(handle) = self.sentinel_handle.take()
            && let OperationCoverage::CleanKernelTrace(evidence) =
                native_sentinel::operation_finished(handle)
        {
            self.bind_native_sentinel_coverage(&evidence.encode())?;
        }
        let coordinator = self.shared.take_for_close()?;
        let capture = coordinator.close(completion)?;
        self.bind_automatic_world(capture)
    }

    fn bind_automatic_world(&mut self, capture: AutomaticWorldCapture) -> Result<(), Error> {
        self.sdk
            .record_observation_fence(self.operation_id, &capture.fence)?;
        self.bind_world(capture.closure)
    }

    fn bind_world(&mut self, closure: ManagedRustCaptureClosure) -> Result<(), Error> {
        if self.closure.is_some() {
            return Err(Error::schema_invalid());
        }
        let shared = Mutex::new(Some(closure));
        let operation_closure =
            ManagedRustOperationClosure::capture(self.operation_id, &move |_| {
                shared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                    .ok_or_else(incomplete_operation)
            })?;
        let world_id = operation_closure.world_id()?;
        self.sdk.bind_automatic_world(self.operation_id, world_id)?;
        self.closure = Some(operation_closure);
        Ok(())
    }

    pub fn succeed(mut self) {
        self.remove_native_sentinel_operation();
        self.shared.deactivate();
        self.sdk.succeed(self.operation_id);
        self.finished = true;
    }

    pub fn abandon_incomplete(mut self) {
        self.remove_native_sentinel_operation();
        self.shared.deactivate();
        self.sdk.abandon_incomplete(self.operation_id);
        self.finished = true;
    }

    pub fn fail(
        mut self,
        identity: FailureIdentity,
        project_token: ManagedProjectToken,
    ) -> Result<ManagedRustCandidateSink, Error> {
        let closure = self.closure.take().ok_or_else(incomplete_operation)?;
        let failure = failure_payload(identity, self.operation_kind, &self.operation_name)?;
        self.sdk.fail(self.operation_id, &failure)?;
        let recorded = self
            .recorder
            .take_failed_candidate()
            .ok_or_else(incomplete_operation)?;
        self.finished = true;
        recorded.finalize_official(closure, move || Ok(project_token))
    }

    fn remove_native_sentinel_operation(&mut self) {
        if let Some(handle) = self.sentinel_handle.take() {
            let _engine_call_guard = native_sentinel::engine_call_scope();
            native_sentinel::operation_removed(handle);
        }
    }
}

pub struct AutomaticManagedRustOperationFactory {
    engine: AutomaticManagedEngine,
    token_provider: Arc<dyn ManagedProjectTokenProvider>,
}

impl AutomaticManagedRustOperationFactory {
    pub fn new<T>(engine: AutomaticManagedEngine, token_provider: T) -> Self
    where
        T: ManagedProjectTokenProvider,
    {
        Self {
            engine,
            token_provider: Arc::new(token_provider),
        }
    }
}

impl RustOperationFactory for AutomaticManagedRustOperationFactory {
    fn start(&self, begin: &OperationBeginPayload) -> Result<Box<dyn RustOperation>, Error> {
        Ok(Box::new(AutomaticFactoryOperation {
            operation: self.engine.start(begin)?,
            token_provider: self.token_provider.clone(),
        }))
    }
}

struct AutomaticFactoryOperation {
    operation: AutomaticManagedOperation,
    token_provider: Arc<dyn ManagedProjectTokenProvider>,
}

impl RustOperation for AutomaticFactoryOperation {
    fn operation_id(&self) -> OperationId {
        self.operation.operation_id()
    }

    fn automatic_context(&self) -> Option<AutomaticOperationContext> {
        Some(self.operation.ambient_context())
    }

    fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error> {
        self.operation.record_input(input)
    }

    fn succeed(self: Box<Self>) {
        self.operation.succeed();
    }

    fn abandon_incomplete(self: Box<Self>) {
        self.operation.abandon_incomplete();
    }

    fn fail(
        mut self: Box<Self>,
        identity: FailureIdentity,
        completion: reproit_core::model::TriggerCompletion,
    ) -> Result<(), Error> {
        validate_completion(self.operation.operation_kind, completion)?;
        self.operation.close_world(completion)?;
        let token_provider = self.token_provider;
        self.operation
            .fail(identity, token_provider.project_token()?)?;
        Ok(())
    }
}

impl Drop for AutomaticManagedOperation {
    fn drop(&mut self) {
        if !self.finished {
            self.remove_native_sentinel_operation();
            self.shared.deactivate();
            self.sdk.abandon_incomplete(self.operation_id);
        }
    }
}

fn new_capture_id() -> Result<CaptureId, Error> {
    format!("cap_{}", Uuid::now_v7()).parse()
}

fn new_operation_id() -> Result<OperationId, Error> {
    format!("op_{}", Uuid::now_v7()).parse()
}

fn next_native_operation_handle() -> Result<u64, Error> {
    NEXT_NATIVE_OPERATION_HANDLE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |handle| {
            handle.checked_add(1)
        })
        .map_err(|_| {
            Error::new(
                ErrorCode::RuntimeQuota,
                "The native operation limit was reached.",
            )
        })
}

fn incomplete_operation() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The automatic operation capture is incomplete.",
    )
}
