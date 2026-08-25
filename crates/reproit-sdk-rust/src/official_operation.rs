use std::sync::{Arc, Mutex, PoisonError};

use reproit_core::{
    Error, ErrorCode,
    identity::{CaptureId, OperationId},
    model::{
        DependencyCursorPayload, FailureIdentity, FailurePayload, FailurePayloadFormat,
        FailureReference, OperationBeginPayload, OperationInputPayload, OperationKind,
        TriggerCompletion, Validate,
    },
};
use uuid::Uuid;

use crate::{
    CandidateStart, ManagedProjectToken, ManagedRustCandidateSink, ManagedRustCaptureClosure,
    ManagedRustCaptureClosureProvider, ManagedRustLocalRecorder, ManagedRustOperationClosure,
    OfficialManagedProject, Sdk, SdkRecallCounters,
};

pub trait RustOperation: Send {
    fn operation_id(&self) -> OperationId;
    fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error>;
    fn succeed(self: Box<Self>);
    fn abandon_incomplete(self: Box<Self>);
    fn fail(
        self: Box<Self>,
        identity: FailureIdentity,
        completion: TriggerCompletion,
    ) -> Result<(), Error>;
}

pub trait RustOperationFactory: Send + Sync + 'static {
    fn start(&self, begin: &OperationBeginPayload) -> Result<Box<dyn RustOperation>, Error>;
}

pub trait ManagedProjectTokenProvider: Send + Sync + 'static {
    fn project_token(&self) -> Result<ManagedProjectToken, Error>;
}

impl<F> ManagedProjectTokenProvider for F
where
    F: Fn() -> Result<ManagedProjectToken, Error> + Send + Sync + 'static,
{
    fn project_token(&self) -> Result<ManagedProjectToken, Error> {
        self()
    }
}

pub struct OfficialManagedRustOperationFactory {
    closure_coordinator: Arc<dyn ManagedRustCaptureClosureProvider>,
    project: OfficialManagedProject,
    token_provider: Arc<dyn ManagedProjectTokenProvider>,
}

impl OfficialManagedRustOperationFactory {
    pub fn new<C, T>(
        project: OfficialManagedProject,
        closure_coordinator: C,
        token_provider: T,
    ) -> Self
    where
        C: ManagedRustCaptureClosureProvider,
        T: ManagedProjectTokenProvider,
    {
        Self {
            closure_coordinator: Arc::new(closure_coordinator),
            project,
            token_provider: Arc::new(token_provider),
        }
    }
}

impl RustOperationFactory for OfficialManagedRustOperationFactory {
    fn start(&self, begin: &OperationBeginPayload) -> Result<Box<dyn RustOperation>, Error> {
        let operation = OfficialManagedRustOperation::start_coordinated(
            &self.project,
            self.closure_coordinator.as_ref(),
            begin,
        )?;
        Ok(Box::new(FactoryOperation {
            operation,
            operation_kind: begin.operation_kind,
            token_provider: self.token_provider.clone(),
        }))
    }
}

struct FactoryOperation {
    operation: OfficialManagedRustOperation,
    operation_kind: OperationKind,
    token_provider: Arc<dyn ManagedProjectTokenProvider>,
}

impl RustOperation for FactoryOperation {
    fn operation_id(&self) -> OperationId {
        self.operation.operation_id()
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
        self: Box<Self>,
        identity: FailureIdentity,
        completion: TriggerCompletion,
    ) -> Result<(), Error> {
        validate_completion(self.operation_kind, completion)?;
        let token_provider = self.token_provider;
        self.operation
            .fail_identity(&identity, move || token_provider.project_token())?;
        Ok(())
    }
}

pub(crate) fn validate_completion(
    operation_kind: OperationKind,
    completion: TriggerCompletion,
) -> Result<(), Error> {
    if matches!(
        (operation_kind, completion),
        (OperationKind::RequestResponse, TriggerCompletion::Return)
            | (OperationKind::Stream, TriggerCompletion::StreamEnd)
            | (
                OperationKind::DeliveredWork,
                TriggerCompletion::Acknowledgment | TriggerCompletion::TaskEnd
            )
    ) {
        Ok(())
    } else {
        Err(Error::schema_invalid())
    }
}

pub struct OfficialManagedRustOperation {
    capture_id: CaptureId,
    closure: Option<ManagedRustCaptureClosure>,
    finished: bool,
    operation_id: OperationId,
    operation_kind: OperationKind,
    operation_name: String,
    recorder: Arc<ManagedRustLocalRecorder>,
    sdk: Sdk,
}

impl OfficialManagedRustOperation {
    pub fn start(
        project: &OfficialManagedProject,
        closure: ManagedRustCaptureClosure,
        begin: &OperationBeginPayload,
    ) -> Result<Self, Error> {
        let capture_id = new_capture_id()?;
        let operation_id = new_operation_id()?;
        let world_id = closure.world.world_id()?;
        Self::start_inner(
            project,
            capture_id,
            operation_id,
            world_id,
            Some(closure),
            begin,
        )
    }

    pub fn start_coordinated<P>(
        project: &OfficialManagedProject,
        closure_coordinator: &P,
        begin: &OperationBeginPayload,
    ) -> Result<Self, Error>
    where
        P: ManagedRustCaptureClosureProvider + ?Sized,
    {
        let capture_id = new_capture_id()?;
        let operation_id = new_operation_id()?;
        let closure = closure_coordinator.capture_closure(operation_id)?;
        let world_id = closure.world.world_id()?;
        Self::start_inner(
            project,
            capture_id,
            operation_id,
            world_id,
            Some(closure),
            begin,
        )
    }

    pub fn start_open(
        project: &OfficialManagedProject,
        world_id: reproit_core::identity::Digest,
        begin: &OperationBeginPayload,
    ) -> Result<Self, Error> {
        Self::start_inner(
            project,
            new_capture_id()?,
            new_operation_id()?,
            world_id,
            None,
            begin,
        )
    }

    fn start_inner(
        project: &OfficialManagedProject,
        capture_id: CaptureId,
        operation_id: OperationId,
        world_id: reproit_core::identity::Digest,
        closure: Option<ManagedRustCaptureClosure>,
        begin: &OperationBeginPayload,
    ) -> Result<Self, Error> {
        let recorder = Arc::new(ManagedRustLocalRecorder::new(operation_id)?);
        let mut deployment = project.deployment()?;
        recorder.bind_deployment(&mut deployment)?;
        let sdk = Sdk::new(recorder.clone());
        sdk.begin(
            CandidateStart {
                capture_id,
                deployment,
                operation_id,
                world_id,
            },
            begin,
        )?;
        Ok(Self {
            capture_id,
            closure,
            finished: false,
            operation_id,
            operation_kind: begin.operation_kind,
            operation_name: begin.operation_name.clone(),
            recorder,
            sdk,
        })
    }

    #[must_use]
    pub const fn capture_id(&self) -> CaptureId {
        self.capture_id
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error> {
        self.sdk.record_input(self.operation_id, input)
    }

    pub fn record_dependency(&self, dependency: &DependencyCursorPayload) -> Result<(), Error> {
        self.sdk.record_dependency(self.operation_id, dependency)
    }

    pub fn succeed(mut self) -> SdkRecallCounters {
        self.sdk.succeed(self.operation_id);
        self.finished = true;
        self.sdk.recall_counters()
    }

    pub fn abandon_incomplete(mut self) -> SdkRecallCounters {
        self.sdk.abandon_incomplete(self.operation_id);
        self.finished = true;
        self.sdk.recall_counters()
    }

    pub fn fail<F>(
        mut self,
        failure: &FailurePayload,
        project_token_provider: F,
    ) -> Result<ManagedRustCandidateSink, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        let closure = self.closure.take().ok_or_else(incomplete_operation)?;
        self.fail_inner(failure, closure, project_token_provider)
    }

    pub fn fail_identity<F>(
        self,
        identity: &FailureIdentity,
        project_token_provider: F,
    ) -> Result<ManagedRustCandidateSink, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        let failure = self.failure_payload(identity.clone())?;
        self.fail(&failure, project_token_provider)
    }

    pub fn fail_with_closure<F>(
        self,
        failure: &FailurePayload,
        closure: ManagedRustCaptureClosure,
        project_token_provider: F,
    ) -> Result<ManagedRustCandidateSink, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        if self.closure.is_some() {
            return Err(incomplete_operation());
        }
        self.fail_inner(failure, closure, project_token_provider)
    }

    pub fn fail_with_operation_closure<F>(
        mut self,
        failure: &FailurePayload,
        operation_closure: ManagedRustOperationClosure,
        project_token_provider: F,
    ) -> Result<ManagedRustCandidateSink, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        if self.closure.is_some() || operation_closure.operation_id() != self.operation_id {
            return Err(incomplete_operation());
        }
        self.sdk.fail(self.operation_id, failure)?;
        let recorded = self
            .recorder
            .take_failed_candidate()
            .ok_or_else(incomplete_operation)?;
        self.finished = true;
        recorded.finalize_official(operation_closure, project_token_provider)
    }

    fn fail_inner<F>(
        mut self,
        failure: &FailurePayload,
        closure: ManagedRustCaptureClosure,
        project_token_provider: F,
    ) -> Result<ManagedRustCandidateSink, Error>
    where
        F: FnOnce() -> Result<ManagedProjectToken, Error>,
    {
        self.sdk.fail(self.operation_id, failure)?;
        let recorded = self
            .recorder
            .take_failed_candidate()
            .ok_or_else(incomplete_operation)?;
        let shared = Mutex::new(Some(closure));
        let operation_closure =
            ManagedRustOperationClosure::capture(self.operation_id, &move |_| {
                shared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                    .ok_or_else(incomplete_operation)
            })?;
        self.finished = true;
        recorded.finalize_official(operation_closure, project_token_provider)
    }

    fn failure_payload(&self, identity: FailureIdentity) -> Result<FailurePayload, Error> {
        failure_payload(identity, self.operation_kind, &self.operation_name)
    }
}

pub(crate) fn failure_payload(
    identity: FailureIdentity,
    expected_operation_kind: OperationKind,
    expected_operation_name: &str,
) -> Result<FailurePayload, Error> {
    identity.validate()?;
    let (operation_kind, operation_name) = identity.operation();
    if operation_kind != expected_operation_kind || operation_name != expected_operation_name {
        return Err(Error::schema_invalid());
    }
    let grouping = identity.grouping()?;
    Ok(FailurePayload {
        failure: FailureReference {
            category: grouping.category,
            identity: grouping.identity_digest,
            matcher: grouping.matcher,
            object_id: format!("obj_{}", Uuid::now_v7()).parse()?,
            schema: "reproit.failure.v1".to_owned(),
        },
        format: FailurePayloadFormat::V1,
        identity,
    })
}

impl Drop for OfficialManagedRustOperation {
    fn drop(&mut self) {
        if !self.finished {
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

fn incomplete_operation() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The managed operation capture is incomplete.",
    )
}

#[cfg(test)]
mod completion_tests {
    use super::*;

    #[test]
    fn every_backend_kind_accepts_only_its_declared_completion() {
        assert!(
            validate_completion(OperationKind::RequestResponse, TriggerCompletion::Return).is_ok()
        );
        assert!(validate_completion(OperationKind::Stream, TriggerCompletion::StreamEnd).is_ok());
        assert!(
            validate_completion(
                OperationKind::DeliveredWork,
                TriggerCompletion::Acknowledgment,
            )
            .is_ok()
        );
        assert!(
            validate_completion(OperationKind::DeliveredWork, TriggerCompletion::TaskEnd).is_ok()
        );
        assert!(validate_completion(OperationKind::Stream, TriggerCompletion::Return).is_err());
    }
}
