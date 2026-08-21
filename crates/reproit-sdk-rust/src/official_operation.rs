use std::sync::{Arc, Mutex, PoisonError};

use reproit_core::{
    Error, ErrorCode,
    identity::{CaptureId, OperationId},
    model::{
        DependencyCursorPayload, FailurePayload, OperationBeginPayload, OperationInputPayload,
    },
};
use uuid::Uuid;

use crate::{
    CandidateStart, ManagedProjectToken, ManagedRustCandidateSink, ManagedRustCaptureClosure,
    ManagedRustLocalRecorder, ManagedRustOperationClosure, OfficialManagedProject, Sdk,
    SdkRecallCounters,
};

pub struct OfficialManagedRustOperation {
    capture_id: CaptureId,
    closure: Option<ManagedRustCaptureClosure>,
    finished: bool,
    operation_id: OperationId,
    recorder: Arc<ManagedRustLocalRecorder>,
    sdk: Sdk,
}

impl OfficialManagedRustOperation {
    pub fn start(
        project: &OfficialManagedProject,
        closure: ManagedRustCaptureClosure,
        begin: &OperationBeginPayload,
    ) -> Result<Self, Error> {
        let world_id = closure.world.world_id()?;
        Self::start_inner(project, world_id, Some(closure), begin)
    }

    pub fn start_open(
        project: &OfficialManagedProject,
        world_id: reproit_core::identity::Digest,
        begin: &OperationBeginPayload,
    ) -> Result<Self, Error> {
        Self::start_inner(project, world_id, None, begin)
    }

    fn start_inner(
        project: &OfficialManagedProject,
        world_id: reproit_core::identity::Digest,
        closure: Option<ManagedRustCaptureClosure>,
        begin: &OperationBeginPayload,
    ) -> Result<Self, Error> {
        let capture_id = new_capture_id()?;
        let operation_id = new_operation_id()?;
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
