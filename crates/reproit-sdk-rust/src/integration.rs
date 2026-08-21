use std::{
    future::Future,
    str::FromStr as _,
    sync::{Arc, Mutex, PoisonError},
};

use reproit_core::{
    Error, ErrorCode,
    crypto::encode_base64url,
    identity::{Digest, ObjectId, OperationId},
    model::{
        DependencyCursorPayload, FailureIdentity, FailurePayload, FailurePayloadFormat,
        FailureReference, InputChannel, OperationBeginFormat, OperationBeginPayload,
        OperationInputFormat, OperationInputPayload, OperationKind, Validate as _,
    },
};
use uuid::Uuid;

use crate::{
    ManagedProjectToken, ManagedRustCaptureClosureProvider, ManagedRustOperationClosure,
    OfficialManagedProject, OfficialManagedRustOperation,
};

const ADAPTER_ID: &str = "sdk";
const ADAPTER_VERSION: &str = "1.0.0";
const MANAGED_PROJECT_TOKEN_ENVIRONMENT: &str = "REPROIT_MANAGED_PROJECT_TOKEN";
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_INPUT_BYTES: usize = 32 * 1_024;
const MAX_OPERATION_NAME_BYTES: usize = 128;

type ProjectTokenProvider =
    Arc<dyn Fn() -> Result<ManagedProjectToken, Error> + Send + Sync + 'static>;
type WorldCaptureProvider =
    Arc<dyn Fn() -> Result<ManagedWorldCapture, Error> + Send + Sync + 'static>;

/// A complete World capture for one application operation.
pub struct ManagedWorldCapture {
    closure: Arc<dyn ManagedRustCaptureClosureProvider>,
    world_id: Digest,
}

impl ManagedWorldCapture {
    pub fn new<C>(world_id: Digest, closure: C) -> Self
    where
        C: ManagedRustCaptureClosureProvider,
    {
        Self {
            closure: Arc::new(closure),
            world_id,
        }
    }
}

/// The Repro It capture entry for a Rust application.
#[derive(Clone)]
pub struct ReproIt {
    project: OfficialManagedProject,
    project_token: ProjectTokenProvider,
    world_capture: WorldCaptureProvider,
}

impl ReproIt {
    pub fn from_build<W>(
        project_toml: &str,
        build_repository_id: &str,
        source_revision: &str,
        world_capture: W,
    ) -> Result<Self, Error>
    where
        W: Fn() -> Result<ManagedWorldCapture, Error> + Send + Sync + 'static,
    {
        Ok(Self {
            project: OfficialManagedProject::from_build(
                project_toml,
                build_repository_id,
                source_revision,
            )?,
            project_token: Arc::new(managed_project_token_from_environment),
            world_capture: Arc::new(world_capture),
        })
    }

    #[must_use]
    pub fn with_project_token_provider<T>(mut self, provider: T) -> Self
    where
        T: Fn() -> Result<ManagedProjectToken, Error> + Send + Sync + 'static,
    {
        self.project_token = Arc::new(provider);
        self
    }

    pub async fn run<T, E, O, F, C>(
        &self,
        operation_name: &str,
        content_type: &str,
        input: &[u8],
        operation: O,
        classify_failure: C,
    ) -> Result<T, E>
    where
        O: FnOnce(OperationCapture) -> F,
        F: Future<Output = Result<T, E>>,
        C: FnOnce(&E) -> Option<FailureIdentity>,
    {
        self.run_kind(
            OperationKind::RequestResponse,
            operation_name,
            content_type,
            input,
            operation,
            classify_failure,
        )
        .await
    }

    pub async fn run_stream<T, E, O, F, C>(
        &self,
        operation_name: &str,
        content_type: &str,
        input: &[u8],
        operation: O,
        classify_failure: C,
    ) -> Result<T, E>
    where
        O: FnOnce(OperationCapture) -> F,
        F: Future<Output = Result<T, E>>,
        C: FnOnce(&E) -> Option<FailureIdentity>,
    {
        self.run_kind(
            OperationKind::Stream,
            operation_name,
            content_type,
            input,
            operation,
            classify_failure,
        )
        .await
    }

    pub async fn run_delivered_work<T, E, O, F, C>(
        &self,
        operation_name: &str,
        content_type: &str,
        input: &[u8],
        operation: O,
        classify_failure: C,
    ) -> Result<T, E>
    where
        O: FnOnce(OperationCapture) -> F,
        F: Future<Output = Result<T, E>>,
        C: FnOnce(&E) -> Option<FailureIdentity>,
    {
        self.run_kind(
            OperationKind::DeliveredWork,
            operation_name,
            content_type,
            input,
            operation,
            classify_failure,
        )
        .await
    }

    async fn run_kind<T, E, O, F, C>(
        &self,
        operation_kind: OperationKind,
        operation_name: &str,
        content_type: &str,
        input: &[u8],
        operation: O,
        classify_failure: C,
    ) -> Result<T, E>
    where
        O: FnOnce(OperationCapture) -> F,
        F: Future<Output = Result<T, E>>,
        C: FnOnce(&E) -> Option<FailureIdentity>,
    {
        let active = self.start_operation(operation_kind, operation_name, content_type, input);
        let context = active
            .as_ref()
            .map_or_else(OperationCapture::inactive, ActiveOperation::context);
        let result = operation(context).await;
        match result {
            Ok(value) => {
                if let Some(active) = active {
                    active.succeed();
                }
                Ok(value)
            }
            Err(error) => {
                if let (Some(active), Some(identity)) = (active, classify_failure(&error)) {
                    active.fail(identity);
                }
                Err(error)
            }
        }
    }

    fn start_operation(
        &self,
        operation_kind: OperationKind,
        operation_name: &str,
        content_type: &str,
        input: &[u8],
    ) -> Option<ActiveOperation> {
        let capture = validate_boundary(operation_name, content_type, input)
            .and_then(|()| (self.world_capture)())
            .and_then(|world| {
                ActiveOperation::start(
                    &self.project,
                    self.project_token.clone(),
                    world,
                    operation_kind,
                    operation_name,
                    content_type,
                    input,
                )
            });
        capture.ok()
    }
}

#[derive(Clone)]
pub struct OperationCapture {
    operation: Option<Arc<OperationState>>,
}

impl OperationCapture {
    fn inactive() -> Self {
        Self { operation: None }
    }

    pub fn operation_id(&self) -> Option<OperationId> {
        self.operation
            .as_ref()
            .and_then(|operation| operation.operation_id().ok())
    }

    pub fn record_dependency(&self, dependency: &DependencyCursorPayload) {
        if let Some(operation) = &self.operation {
            let _ = operation.record_dependency(dependency);
        }
    }
}

struct ActiveOperation {
    operation_kind: OperationKind,
    operation_name: String,
    state: Arc<OperationState>,
}

impl ActiveOperation {
    fn start(
        project: &OfficialManagedProject,
        project_token: ProjectTokenProvider,
        world: ManagedWorldCapture,
        operation_kind: OperationKind,
        operation_name: &str,
        content_type: &str,
        input: &[u8],
    ) -> Result<Self, Error> {
        let begin = operation_begin(operation_kind, operation_name);
        let operation = OfficialManagedRustOperation::start_open(project, world.world_id, &begin)?;
        operation.record_input(&operation_input(content_type, input))?;
        Ok(Self {
            operation_kind,
            operation_name: operation_name.to_owned(),
            state: Arc::new(OperationState {
                operation: Mutex::new(Some(operation)),
                project_token,
                world_capture: world.closure,
            }),
        })
    }

    fn context(&self) -> OperationCapture {
        OperationCapture {
            operation: Some(self.state.clone()),
        }
    }

    fn succeed(self) {
        if let Ok(operation) = self.state.take() {
            operation.succeed();
        }
    }

    fn fail(self, identity: FailureIdentity) {
        let result = failure_payload(identity, self.operation_kind, &self.operation_name)
            .and_then(|failure| self.state.fail(&failure));
        if result.is_err() {
            self.state.abandon();
        }
    }
}

struct OperationState {
    operation: Mutex<Option<OfficialManagedRustOperation>>,
    project_token: ProjectTokenProvider,
    world_capture: Arc<dyn ManagedRustCaptureClosureProvider>,
}

impl OperationState {
    fn operation_id(&self) -> Result<OperationId, Error> {
        self.operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(OfficialManagedRustOperation::operation_id)
            .ok_or_else(incomplete_operation)
    }

    fn record_dependency(&self, dependency: &DependencyCursorPayload) -> Result<(), Error> {
        self.operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .ok_or_else(incomplete_operation)?
            .record_dependency(dependency)
    }

    fn take(&self) -> Result<OfficialManagedRustOperation, Error> {
        self.operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(incomplete_operation)
    }

    fn fail(&self, failure: &FailurePayload) -> Result<(), Error> {
        let operation_id = self.operation_id()?;
        let closure =
            ManagedRustOperationClosure::capture(operation_id, self.world_capture.as_ref())?;
        let project_token = self.project_token.clone();
        self.take()?
            .fail_with_operation_closure(failure, closure, move || project_token())
            .map(|_sink| ())
    }

    fn abandon(&self) {
        if let Ok(operation) = self.take() {
            operation.abandon_incomplete();
        }
    }
}

impl Drop for OperationState {
    fn drop(&mut self) {
        if let Some(operation) = self
            .operation
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            operation.abandon_incomplete();
        }
    }
}

fn validate_boundary(operation_name: &str, content_type: &str, input: &[u8]) -> Result<(), Error> {
    if operation_name.is_empty()
        || operation_name.len() > MAX_OPERATION_NAME_BYTES
        || content_type.is_empty()
        || content_type.len() > MAX_CONTENT_TYPE_BYTES
        || input.len() > MAX_INPUT_BYTES
    {
        return Err(Error::schema_invalid());
    }
    Ok(())
}

fn operation_begin(operation_kind: OperationKind, operation_name: &str) -> OperationBeginPayload {
    OperationBeginPayload {
        adapter_id: ADAPTER_ID.to_owned(),
        adapter_version: ADAPTER_VERSION.to_owned(),
        causal_parent_ids: Vec::new(),
        format: OperationBeginFormat::V1,
        operation_kind,
        operation_name: operation_name.to_owned(),
    }
}

fn operation_input(content_type: &str, input: &[u8]) -> OperationInputPayload {
    OperationInputPayload {
        channel: InputChannel::Input,
        content_type: content_type.to_owned(),
        format: OperationInputFormat::V1,
        input_index: 0,
        value: encode_base64url(input),
        value_digest: Digest::of(input),
    }
}

fn failure_payload(
    identity: FailureIdentity,
    expected_operation_kind: OperationKind,
    operation_name: &str,
) -> Result<FailurePayload, Error> {
    identity.validate()?;
    let (operation_kind, identity_operation_name) = identity.operation();
    if operation_kind != expected_operation_kind || identity_operation_name != operation_name {
        return Err(Error::schema_invalid());
    }
    let grouping = identity.grouping()?;
    Ok(FailurePayload {
        failure: FailureReference {
            category: grouping.category,
            identity: grouping.identity_digest,
            matcher: grouping.matcher,
            object_id: new_object_id()?,
            schema: "reproit.failure.v1".to_owned(),
        },
        format: FailurePayloadFormat::V1,
        identity,
    })
}

fn managed_project_token_from_environment() -> Result<ManagedProjectToken, Error> {
    let token = std::env::var(MANAGED_PROJECT_TOKEN_ENVIRONMENT).map_err(|_| {
        Error::new(
            ErrorCode::AuthenticationRequired,
            "The managed project token is unavailable.",
        )
    })?;
    ManagedProjectToken::new(token)
}

fn incomplete_operation() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The managed operation capture is incomplete.",
    )
}

fn new_object_id() -> Result<ObjectId, Error> {
    ObjectId::from_str(&format!("obj_{}", Uuid::now_v7()))
}
