#![forbid(unsafe_code)]

use std::{
    pin::Pin,
    str::FromStr as _,
    sync::{Arc, Mutex, PoisonError},
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
    Error,
    crypto::encode_base64url,
    identity::{CaptureId, Digest, ObjectId, OperationId},
    model::{
        Deployment, FailureIdentity, FailurePayload, FailurePayloadFormat, FailureReference,
        InputChannel, OperationBeginFormat, OperationBeginPayload, OperationInputFormat,
        OperationInputPayload, OperationKind, Validate as _,
    },
};
use reproit_sdk_rust::{CandidateStart, Sdk};
use uuid::Uuid;

const ADAPTER_ID: &str = "axum";
const ADAPTER_VERSION: &str = "0.8.9";
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";
const MAX_CAPTURED_INPUT_BYTES: usize = 32 * 1_024;
const MAX_CAPTURED_OUTPUT_BYTES: usize = 32 * 1_024;
const MAX_CAPTURED_RESPONSE_HEADER_BYTES: usize = 16 * 1_024;
const MAX_CAPTURED_RESPONSE_HEADERS: usize = 128;

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
        let operation_name = operation_name.into();
        if operation_name.is_empty() || operation_name.len() > 128 {
            return Err(Error::schema_invalid());
        }
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

pub async fn capture_axum_request(
    State(capture): State<AxumRequestCapture>,
    mut request: Request,
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
    let begin = OperationBeginPayload {
        adapter_id: ADAPTER_ID.to_owned(),
        adapter_version: ADAPTER_VERSION.to_owned(),
        causal_parent_ids: context.causal_parent_id.into_iter().collect(),
        format: OperationBeginFormat::V1,
        operation_kind: OperationKind::RequestResponse,
        operation_name: capture.operation_name.clone(),
    };
    if capture.sdk.begin(start, &begin).is_err() {
        return next.run(request).await;
    }
    let guard = OperationGuard {
        active: true,
        operation_id,
        sdk: capture.sdk.clone(),
    };
    let input = InputCapture::new(
        capture.sdk.clone(),
        operation_id,
        request_content_type(request.headers()),
    );
    let original = std::mem::replace(request.body_mut(), Body::empty());
    *request.body_mut() = Body::new(CaptureBody {
        capture: input.clone(),
        inner: original,
    });
    request.extensions_mut().insert(context.clone());

    let response = next.run(request).await;
    if !input.complete() {
        capture.sdk.abandon_incomplete(operation_id);
        drop(guard);
        return response;
    }
    capture_response(response, capture, context, guard)
}

struct OperationGuard {
    active: bool,
    operation_id: OperationId,
    sdk: Sdk,
}

impl OperationGuard {
    fn abandon(&mut self) {
        if self.active {
            self.sdk.abandon_incomplete(self.operation_id);
            self.active = false;
        }
    }

    const fn complete(&mut self) {
        self.active = false;
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
    operation_id: OperationId,
    sdk: Sdk,
}

impl InputCapture {
    fn new(sdk: Sdk, operation_id: OperationId, content_type: Option<String>) -> Self {
        Self(Arc::new(Mutex::new(InputCaptureState {
            bytes: Vec::new(),
            complete: false,
            content_type,
            failed: false,
            operation_id,
            sdk,
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
        if state
            .sdk
            .record_input(state.operation_id, &payload)
            .is_err()
        {
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
        state.sdk.abandon_incomplete(state.operation_id);
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
    capture: AxumRequestCapture,
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
        classifier: capture.classifier,
        context,
        guard,
        headers: parts.headers.clone(),
        operation_name: capture.operation_name,
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
            self.guard.sdk.succeed(self.guard.operation_id);
            self.guard.complete();
            return;
        };
        let result = failure_payload(identity, &self.operation_name)
            .and_then(|payload| self.guard.sdk.fail(self.guard.operation_id, &payload));
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
