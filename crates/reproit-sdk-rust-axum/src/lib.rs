#![forbid(unsafe_code)]

use std::{
    pin::Pin,
    str::FromStr as _,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::Response,
};
use http_body::{Body as HttpBody, Frame};
use reproit_core::{
    Error, ErrorCode,
    crypto::encode_base64url,
    identity::{CaptureId, Digest, ObjectId, OperationId},
    model::{
        DependencyCursorPayload, Deployment, FailureIdentity, FailurePayload, FailurePayloadFormat,
        FailureReference, InputChannel, OperationBeginFormat, OperationBeginPayload,
        OperationInputFormat, OperationInputPayload, OperationKind, Validate as _,
    },
};
use reproit_sdk_rust::{
    CandidateStart, ManagedProjectToken, ManagedRustCaptureClosureProvider,
    ManagedRustOperationClosure, OfficialManagedProject, OfficialManagedRustOperation, Sdk,
};
use uuid::Uuid;

const ADAPTER_ID: &str = "axum";
const ADAPTER_VERSION: &str = "0.8.9";
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";
const MAX_CAPTURED_INPUT_BYTES: usize = 32 * 1_024;
const MAX_CAPTURED_OUTPUT_BYTES: usize = 32 * 1_024;
const MAX_CAPTURED_RESPONSE_HEADER_BYTES: usize = 16 * 1_024;
const MAX_CAPTURED_RESPONSE_HEADERS: usize = 128;
const MANAGED_PROJECT_TOKEN_ENVIRONMENT: &str = "REPROIT_MANAGED_PROJECT_TOKEN";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationContext {
    pub causal_parent_id: Option<OperationId>,
    pub operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AxumRequestIdentity {
    pub capture_id: CaptureId,
    pub operation_id: OperationId,
}

impl AxumRequestIdentity {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            capture_id: new_capture_id().ok_or_else(Error::schema_invalid)?,
            operation_id: new_operation_id().ok_or_else(Error::schema_invalid)?,
        })
    }
}

pub struct AxumResponseObservation<'a> {
    body: &'a [u8],
    headers: &'a HeaderMap,
    status: StatusCode,
}

impl AxumResponseObservation<'_> {
    #[must_use]
    pub const fn body(&self) -> &[u8] {
        self.body
    }

    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        self.headers
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }
}

pub trait AxumFailureClassifier: Send + Sync + 'static {
    fn classify(
        &self,
        context: &OperationContext,
        response: &AxumResponseObservation<'_>,
    ) -> Option<FailureIdentity>;
}

impl<F> AxumFailureClassifier for F
where
    F: for<'a> Fn(&OperationContext, &AxumResponseObservation<'a>) -> Option<FailureIdentity>
        + Send
        + Sync
        + 'static,
{
    fn classify(
        &self,
        context: &OperationContext,
        response: &AxumResponseObservation<'_>,
    ) -> Option<FailureIdentity> {
        self(context, response)
    }
}

#[derive(Clone)]
pub struct AxumRequestCapture {
    classifier: Arc<dyn AxumFailureClassifier>,
    deployment: Deployment,
    operation_name: String,
    request_identity: RequestIdentitySource,
    sdk: Sdk,
    world_id: Digest,
}

#[derive(Clone)]
enum RequestIdentitySource {
    Fresh,
    Prepared(Arc<Mutex<Option<AxumRequestIdentity>>>),
}

impl RequestIdentitySource {
    fn next(&self) -> Option<AxumRequestIdentity> {
        match self {
            Self::Fresh => AxumRequestIdentity::new().ok(),
            Self::Prepared(identity) => identity
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        }
    }
}

impl AxumRequestCapture {
    pub fn new(
        sdk: Sdk,
        deployment: Deployment,
        world_id: Digest,
        operation_name: impl Into<String>,
        classifier: Arc<dyn AxumFailureClassifier>,
    ) -> Result<Self, Error> {
        deployment.validate()?;
        let operation_name = valid_operation_name(operation_name.into())?;
        Ok(Self {
            classifier,
            deployment,
            operation_name,
            request_identity: RequestIdentitySource::Fresh,
            sdk,
            world_id,
        })
    }

    pub fn new_for_request(
        sdk: Sdk,
        deployment: Deployment,
        world_id: Digest,
        operation_name: impl Into<String>,
        classifier: Arc<dyn AxumFailureClassifier>,
        identity: AxumRequestIdentity,
    ) -> Result<Self, Error> {
        let mut capture = Self::new(sdk, deployment, world_id, operation_name, classifier)?;
        capture.request_identity =
            RequestIdentitySource::Prepared(Arc::new(Mutex::new(Some(identity))));
        Ok(capture)
    }
}

/// Captures an Axum request through the official managed SDK entry.
#[derive(Clone)]
pub struct OfficialAxumRequestCapture {
    classifier: Arc<dyn AxumFailureClassifier>,
    operation_name: String,
    project: OfficialManagedProject,
    project_token: ProjectTokenProvider,
    world_capture: WorldCaptureProvider,
}

type ProjectTokenProvider =
    Arc<dyn Fn() -> Result<ManagedProjectToken, Error> + Send + Sync + 'static>;
type WorldCaptureProvider =
    Arc<dyn Fn() -> Result<OfficialAxumWorldCapture, Error> + Send + Sync + 'static>;

pub struct OfficialAxumWorldCapture {
    closure: Arc<dyn ManagedRustCaptureClosureProvider>,
    world_id: Digest,
}

impl OfficialAxumWorldCapture {
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

#[derive(Clone)]
pub struct OfficialAxumOperationContext {
    operation: Arc<OfficialAxumOperation>,
}

impl OfficialAxumOperationContext {
    pub fn operation_id(&self) -> Result<OperationId, Error> {
        self.operation.operation_id()
    }

    pub fn record_dependency(&self, dependency: &DependencyCursorPayload) -> Result<(), Error> {
        self.operation.record_dependency(dependency)
    }
}

impl OfficialAxumRequestCapture {
    pub fn new<W, C>(
        project: OfficialManagedProject,
        operation_name: impl Into<String>,
        world_capture: W,
        classifier: C,
    ) -> Result<Self, Error>
    where
        W: Fn() -> Result<OfficialAxumWorldCapture, Error> + Send + Sync + 'static,
        C: AxumFailureClassifier,
    {
        let operation_name = valid_operation_name(operation_name.into())?;
        Ok(Self {
            classifier: Arc::new(classifier),
            operation_name,
            project,
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
}

pub async fn capture_axum_request(
    State(capture): State<AxumRequestCapture>,
    request: Request,
    next: Next,
) -> Response {
    let parent = request.extensions().get::<OperationContext>().cloned();
    let Some(identity) = capture.request_identity.next() else {
        return next.run(request).await;
    };
    let operation_id = identity.operation_id;
    let context = OperationContext {
        causal_parent_id: parent.map(|context| context.operation_id),
        operation_id,
    };
    let start = CandidateStart {
        capture_id: identity.capture_id,
        deployment: capture.deployment.clone(),
        operation_id,
        world_id: capture.world_id,
    };
    let begin = operation_begin(&capture.operation_name, context.causal_parent_id);
    if capture.sdk.begin(start, &begin).is_err() {
        return next.run(request).await;
    }
    let operation: Arc<dyn ActiveAxumOperation> = Arc::new(SdkAxumOperation {
        finished: AtomicBool::new(false),
        operation_id,
        sdk: capture.sdk,
    });
    capture_request(
        request,
        next,
        capture.classifier,
        capture.operation_name,
        context,
        operation,
    )
    .await
}

pub async fn capture_official_axum_request(
    State(capture): State<OfficialAxumRequestCapture>,
    mut request: Request,
    next: Next,
) -> Response {
    let parent = request
        .extensions()
        .get::<OperationContext>()
        .map(|context| context.operation_id);
    let begin = operation_begin(&capture.operation_name, parent);
    let Ok(world_capture) = (capture.world_capture)() else {
        return next.run(request).await;
    };
    let Ok(operation) =
        OfficialManagedRustOperation::start_open(&capture.project, world_capture.world_id, &begin)
    else {
        return next.run(request).await;
    };
    let context = OperationContext {
        causal_parent_id: parent,
        operation_id: operation.operation_id(),
    };
    let operation = Arc::new(OfficialAxumOperation {
        operation: Mutex::new(Some(operation)),
        project_token: capture.project_token,
        world_capture: world_capture.closure,
    });
    request
        .extensions_mut()
        .insert(OfficialAxumOperationContext {
            operation: operation.clone(),
        });
    let operation: Arc<dyn ActiveAxumOperation> = operation;
    capture_request(
        request,
        next,
        capture.classifier,
        capture.operation_name,
        context,
        operation,
    )
    .await
}

async fn capture_request(
    mut request: Request,
    next: Next,
    classifier: Arc<dyn AxumFailureClassifier>,
    operation_name: String,
    context: OperationContext,
    operation: Arc<dyn ActiveAxumOperation>,
) -> Response {
    let guard = OperationGuard::new(operation.clone());
    let input = InputCapture::new(operation, request_content_type(request.headers()));
    let original = std::mem::replace(request.body_mut(), Body::empty());
    *request.body_mut() = Body::new(CaptureBody {
        capture: input.clone(),
        inner: original,
    });
    request.extensions_mut().insert(context.clone());

    let response = next.run(request).await;
    if !input.complete() {
        drop(guard);
        return response;
    }
    capture_response(response, classifier, operation_name, context, guard)
}

struct OperationGuard {
    active: bool,
    operation: Arc<dyn ActiveAxumOperation>,
}

impl OperationGuard {
    fn new(operation: Arc<dyn ActiveAxumOperation>) -> Self {
        Self {
            active: true,
            operation,
        }
    }

    fn abandon(&mut self) {
        if self.active {
            self.operation.abandon();
            self.active = false;
        }
    }

    const fn complete(&mut self) {
        self.active = false;
    }
}

trait ActiveAxumOperation: Send + Sync {
    fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error>;
    fn succeed(&self) -> Result<(), Error>;
    fn fail(&self, failure: &FailurePayload) -> Result<(), Error>;
    fn abandon(&self);
}

struct SdkAxumOperation {
    finished: AtomicBool,
    operation_id: OperationId,
    sdk: Sdk,
}

impl SdkAxumOperation {
    fn finish_once(&self) -> bool {
        !self.finished.swap(true, Ordering::AcqRel)
    }
}

impl ActiveAxumOperation for SdkAxumOperation {
    fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error> {
        if self.finished.load(Ordering::Acquire) {
            return Err(incomplete_operation());
        }
        self.sdk.record_input(self.operation_id, input)
    }

    fn succeed(&self) -> Result<(), Error> {
        if self.finish_once() {
            self.sdk.succeed(self.operation_id);
        }
        Ok(())
    }

    fn fail(&self, failure: &FailurePayload) -> Result<(), Error> {
        if !self.finish_once() {
            return Err(incomplete_operation());
        }
        let result = self.sdk.fail(self.operation_id, failure);
        if result.is_err() {
            self.sdk.abandon_incomplete(self.operation_id);
        }
        result
    }

    fn abandon(&self) {
        if self.finish_once() {
            self.sdk.abandon_incomplete(self.operation_id);
        }
    }
}

struct OfficialAxumOperation {
    operation: Mutex<Option<OfficialManagedRustOperation>>,
    project_token: ProjectTokenProvider,
    world_capture: Arc<dyn ManagedRustCaptureClosureProvider>,
}

impl OfficialAxumOperation {
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
}

impl ActiveAxumOperation for OfficialAxumOperation {
    fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error> {
        self.operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .ok_or_else(incomplete_operation)?
            .record_input(input)
    }

    fn succeed(&self) -> Result<(), Error> {
        self.take()?.succeed();
        Ok(())
    }

    fn fail(&self, failure: &FailurePayload) -> Result<(), Error> {
        let project_token = self.project_token.clone();
        let operation_id = self.operation_id()?;
        let closure =
            ManagedRustOperationClosure::capture(operation_id, self.world_capture.as_ref())?;
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

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.abandon();
    }
}

#[derive(Clone)]
struct InputCapture(Arc<Mutex<InputCaptureState>>);

struct InputCaptureState {
    bytes: Vec<u8>,
    complete: bool,
    content_type: Option<String>,
    failed: bool,
    operation: Arc<dyn ActiveAxumOperation>,
}

impl InputCapture {
    fn new(operation: Arc<dyn ActiveAxumOperation>, content_type: Option<String>) -> Self {
        Self(Arc::new(Mutex::new(InputCaptureState {
            bytes: Vec::new(),
            complete: false,
            content_type,
            failed: false,
            operation,
        })))
    }

    fn record(&self, bytes: &Bytes) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.failed {
            return;
        }
        let Some(next_size) = state.bytes.len().checked_add(bytes.len()) else {
            reject_input(&mut state);
            return;
        };
        if next_size > MAX_CAPTURED_INPUT_BYTES {
            reject_input(&mut state);
            return;
        }
        state.bytes.extend_from_slice(bytes);
    }

    fn finish(&self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if state.failed || state.complete {
            return;
        }
        let Some(content_type) = state.content_type.take() else {
            reject_input(&mut state);
            return;
        };
        let payload = OperationInputPayload {
            channel: InputChannel::Input,
            content_type,
            format: OperationInputFormat::V1,
            input_index: 0,
            value: encode_base64url(&state.bytes),
            value_digest: Digest::of(&state.bytes),
        };
        if state.operation.record_input(&payload).is_err() {
            reject_input(&mut state);
            return;
        }
        state.complete = true;
    }

    fn fail(&self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        reject_input(&mut state);
    }

    fn complete(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .complete
    }

    fn terminal(&self) -> bool {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.complete || state.failed
    }
}

fn reject_input(state: &mut InputCaptureState) {
    if !state.failed {
        state.failed = true;
        state.bytes.clear();
        state.operation.abandon();
    }
}

struct CaptureBody {
    capture: InputCapture,
    inner: Body,
}

impl HttpBody for CaptureBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    this.capture.record(bytes);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.capture.fail();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.capture.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.capture.terminal() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

fn capture_response(
    response: Response,
    classifier: Arc<dyn AxumFailureClassifier>,
    operation_name: String,
    context: OperationContext,
    mut guard: OperationGuard,
) -> Response {
    let (parts, body) = response.into_parts();
    if !response_headers_within_bound(&parts.headers) {
        guard.abandon();
        return Response::from_parts(parts, body);
    }
    let mut completion = ResponseCompletion {
        body: Vec::new(),
        classifier,
        context,
        guard,
        headers: parts.headers.clone(),
        operation_name,
        status: parts.status,
        terminal: false,
    };
    if body.is_end_stream() {
        completion.finish();
        return Response::from_parts(parts, body);
    }
    Response::from_parts(
        parts,
        Body::new(CaptureResponseBody {
            completion,
            inner: body,
        }),
    )
}

fn response_headers_within_bound(headers: &HeaderMap) -> bool {
    if headers.len() > MAX_CAPTURED_RESPONSE_HEADERS {
        return false;
    }
    headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
                .filter(|total| *total <= MAX_CAPTURED_RESPONSE_HEADER_BYTES)
        })
        .is_some()
}

struct ResponseCompletion {
    body: Vec<u8>,
    classifier: Arc<dyn AxumFailureClassifier>,
    context: OperationContext,
    guard: OperationGuard,
    headers: HeaderMap,
    operation_name: String,
    status: StatusCode,
    terminal: bool,
}

impl ResponseCompletion {
    fn record(&mut self, bytes: &Bytes) {
        if self.terminal {
            return;
        }
        let Some(next_size) = self.body.len().checked_add(bytes.len()) else {
            self.abandon();
            return;
        };
        if next_size > MAX_CAPTURED_OUTPUT_BYTES {
            self.abandon();
            return;
        }
        self.body.extend_from_slice(bytes);
    }

    fn finish(&mut self) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        let observation = AxumResponseObservation {
            body: &self.body,
            headers: &self.headers,
            status: self.status,
        };
        let identity = self.classifier.classify(&self.context, &observation);
        self.body.fill(0);
        self.body.clear();
        let Some(identity) = identity else {
            if self.guard.operation.succeed().is_ok() {
                self.guard.complete();
            } else {
                self.guard.abandon();
            }
            return;
        };
        let result = failure_payload(identity, &self.operation_name)
            .and_then(|payload| self.guard.operation.fail(&payload));
        if result.is_ok() {
            self.guard.complete();
        } else {
            self.guard.abandon();
        }
    }

    fn abandon(&mut self) {
        if !self.terminal {
            self.terminal = true;
            self.body.clear();
            self.guard.abandon();
        }
    }
}

struct CaptureResponseBody {
    completion: ResponseCompletion,
    inner: Body,
}

impl HttpBody for CaptureResponseBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    this.completion.record(bytes);
                }
                if this.inner.is_end_stream() {
                    this.completion.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.completion.abandon();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.completion.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.completion.terminal && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CaptureResponseBody {
    fn drop(&mut self) {
        self.completion.abandon();
    }
}

fn request_content_type(headers: &HeaderMap) -> Option<String> {
    match headers.get(header::CONTENT_TYPE) {
        Some(value) => {
            let value = value.to_str().ok()?;
            if value.is_empty() || value.len() > 256 {
                return None;
            }
            Some(value.to_owned())
        }
        None => Some(DEFAULT_CONTENT_TYPE.to_owned()),
    }
}

fn valid_operation_name(operation_name: String) -> Result<String, Error> {
    if operation_name.is_empty() || operation_name.len() > 128 {
        return Err(Error::schema_invalid());
    }
    Ok(operation_name)
}

fn operation_begin(
    operation_name: &str,
    causal_parent_id: Option<OperationId>,
) -> OperationBeginPayload {
    OperationBeginPayload {
        adapter_id: ADAPTER_ID.to_owned(),
        adapter_version: ADAPTER_VERSION.to_owned(),
        causal_parent_ids: causal_parent_id.into_iter().collect(),
        format: OperationBeginFormat::V1,
        operation_kind: OperationKind::RequestResponse,
        operation_name: operation_name.to_owned(),
    }
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

fn failure_payload(
    identity: FailureIdentity,
    operation_name: &str,
) -> Result<FailurePayload, Error> {
    identity.validate()?;
    let (operation_kind, identity_operation_name) = identity.operation();
    if operation_kind != OperationKind::RequestResponse || identity_operation_name != operation_name
    {
        return Err(Error::schema_invalid());
    }
    let grouping = identity.grouping()?;
    Ok(FailurePayload {
        failure: FailureReference {
            category: grouping.category,
            identity: grouping.identity_digest,
            matcher: grouping.matcher,
            object_id: new_object_id().ok_or_else(Error::schema_invalid)?,
            schema: "reproit.failure.v1".to_owned(),
        },
        format: FailurePayloadFormat::V1,
        identity,
    })
}

fn new_capture_id() -> Option<CaptureId> {
    CaptureId::from_str(&format!("cap_{}", Uuid::now_v7())).ok()
}

fn new_operation_id() -> Option<OperationId> {
    OperationId::from_str(&format!("op_{}", Uuid::now_v7())).ok()
}

fn new_object_id() -> Option<ObjectId> {
    ObjectId::from_str(&format!("obj_{}", Uuid::now_v7())).ok()
}
