use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr as _,
    sync::{Arc, Mutex, PoisonError},
    thread,
    time::{Duration, Instant},
};

use reproit_core::{
    Error, ErrorCode,
    crypto::encode_base64url,
    identity::{Digest, ObjectId, OperationId},
    model::{
        DependencyCursorPayload, ExceptionCategory, ExceptionFailureIdentity, FailureIdentity,
        FailurePayload, FailurePayloadFormat, FailureReference, InputChannel, OperationBeginFormat,
        OperationBeginPayload, OperationInputFormat, OperationInputPayload, OperationKind,
        Validate as _,
    },
};
use time::OffsetDateTime;
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
const MAX_PROJECT_CONFIG_BYTES: u64 = 65_536;
const MAX_PROJECT_SEARCH_DEPTH: usize = 64;

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
    project: Option<OfficialManagedProject>,
    project_token: ProjectTokenProvider,
    world_capture: WorldCaptureProvider,
}

impl ReproIt {
    /// Loads the reviewed project binding and prepares automatic capture.
    #[must_use]
    pub fn init() -> Self {
        Self::try_init().unwrap_or_else(|_| Self::inactive())
    }

    /// Runs one framework-neutral operation and preserves its exact result.
    pub async fn operation<T, E, O, F>(
        &self,
        operation_name: &str,
        input: &[u8],
        operation: O,
    ) -> Result<T, E>
    where
        O: FnOnce() -> F,
        F: Future<Output = Result<T, E>>,
    {
        self.run(
            operation_name,
            "application/octet-stream",
            input,
            |_| operation(),
            |_| Some(automatic_failure_identity::<E>(operation_name)),
        )
        .await
    }

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
            project: Some(OfficialManagedProject::from_build(
                project_toml,
                build_repository_id,
                source_revision,
            )?),
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
        let project = self.project.as_ref()?;
        let capture = validate_boundary(operation_name, content_type, input)
            .and_then(|()| (self.world_capture)())
            .and_then(|world| {
                ActiveOperation::start(
                    project,
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

    fn try_init() -> Result<Self, Error> {
        let project_file = find_project_file(&std::env::current_dir().map_err(|_| init_error())?)?;
        let metadata = fs::symlink_metadata(&project_file).map_err(|_| init_error())?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_PROJECT_CONFIG_BYTES
        {
            return Err(init_error());
        }
        let project_toml = fs::read_to_string(&project_file).map_err(|_| init_error())?;
        let repository_id = project_repository_id(&project_toml)?;
        let project_root = project_file
            .parent()
            .and_then(Path::parent)
            .ok_or_else(init_error)?;
        let source_revision = git_source_revision(project_root)?;
        Self::from_build(
            &project_toml,
            &repository_id,
            &source_revision,
            automatic_world_capture,
        )
    }

    fn inactive() -> Self {
        Self {
            project: None,
            project_token: Arc::new(managed_project_token_from_environment),
            world_capture: Arc::new(automatic_world_capture),
        }
    }
}

fn automatic_failure_identity<E>(operation_name: &str) -> FailureIdentity {
    let rust_type = std::any::type_name::<E>();
    let type_name = if rust_type.len() <= 256 {
        rust_type.to_owned()
    } else {
        "RustError".to_owned()
    };
    FailureIdentity::Exception(ExceptionFailureIdentity {
        category: ExceptionCategory::Exception,
        cause_types: Vec::new(),
        frames: Vec::new(),
        operation_kind: OperationKind::RequestResponse,
        operation_name: operation_name.to_owned(),
        runtime_family: "rust".to_owned(),
        schema: "reproit.failure.v1".to_owned(),
        stable_code: Some(Digest::of(rust_type.as_bytes()).to_string()),
        type_name,
    })
}

fn find_project_file(start: &Path) -> Result<PathBuf, Error> {
    start
        .ancestors()
        .take(MAX_PROJECT_SEARCH_DEPTH)
        .find_map(|directory| {
            let configuration_directory = directory.join(".reproit");
            let directory_metadata = fs::symlink_metadata(&configuration_directory).ok()?;
            if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
                return None;
            }
            let candidate = configuration_directory.join("project.toml");
            let metadata = fs::symlink_metadata(&candidate).ok()?;
            (metadata.is_file() && !metadata.file_type().is_symlink()).then_some(candidate)
        })
        .ok_or_else(init_error)
}

fn project_repository_id(project_toml: &str) -> Result<String, Error> {
    let project: toml::Value = toml::from_str(project_toml).map_err(|_| init_error())?;
    project
        .get("repository_id")
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .map(str::to_owned)
        .ok_or_else(init_error)
}

fn git_source_revision(project_root: &Path) -> Result<String, Error> {
    let mut child = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(project_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| init_error())?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().map_err(|_| init_error())?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(init_error());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().map_err(|_| init_error())?;
    if !output.status.success() || output.stdout.len() > 65 {
        return Err(init_error());
    }
    let revision = String::from_utf8(output.stdout).map_err(|_| init_error())?;
    let revision = revision.trim();
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(init_error());
    }
    Ok(revision.to_owned())
}

fn automatic_world_capture() -> Result<ManagedWorldCapture, Error> {
    let world = crate::WorldCheckpoint {
        created_at: now_timestamp()?,
        format: crate::WorldCheckpointFormat::V1,
        points: Vec::new(),
    };
    let world_id = world.world_id()?;
    Ok(ManagedWorldCapture::new(world_id, move |_| {
        Ok(crate::ManagedRustCaptureClosure {
            artifacts: Vec::new(),
            completion: crate::TriggerCompletion::Return,
            world: world.clone(),
        })
    }))
}

fn now_timestamp() -> Result<reproit_core::identity::Timestamp, Error> {
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

fn init_error() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "Repro It could not load the reviewed project configuration.",
    )
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
