#![forbid(unsafe_code)]

use std::{
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, header},
    middleware::Next,
    response::Response,
};
use http_body::{Body as HttpBody, Frame};
use reproit_core::{
    Error,
    identity::OperationId,
    model::{OperationBeginFormat, OperationBeginPayload, OperationKind},
};
use reproit_sdk_rust::{
    AutomaticOperationContext, RequestResponseFailureClassifier, RequestResponseHeader,
    RequestResponseOperation, RustOperationFactory,
};

const ADAPTER_ID: &str = "axum";
const ADAPTER_VERSION: &str = "0.8.9";
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationContext {
    pub causal_parent_id: Option<OperationId>,
    pub operation_id: OperationId,
}

#[derive(Clone)]
pub struct AxumRequestCapture {
    classifier: Arc<dyn RequestResponseFailureClassifier>,
    factory: Arc<dyn RustOperationFactory>,
    operation_name: String,
}

impl AxumRequestCapture {
    pub fn new(
        factory: Arc<dyn RustOperationFactory>,
        operation_name: impl Into<String>,
        classifier: Arc<dyn RequestResponseFailureClassifier>,
    ) -> Result<Self, Error> {
        let operation_name = operation_name.into();
        if operation_name.is_empty() || operation_name.len() > 128 {
            return Err(Error::schema_invalid());
        }
        Ok(Self {
            classifier,
            factory,
            operation_name,
        })
    }
}

pub async fn capture_axum_request(
    State(configuration): State<AxumRequestCapture>,
    mut request: Request,
    next: Next,
) -> Response {
    let causal_parent_id = request
        .extensions()
        .get::<OperationContext>()
        .map(|context| context.operation_id);
    let begin = OperationBeginPayload {
        adapter_id: ADAPTER_ID.to_owned(),
        adapter_version: ADAPTER_VERSION.to_owned(),
        causal_parent_ids: causal_parent_id.into_iter().collect(),
        format: OperationBeginFormat::V1,
        operation_kind: OperationKind::RequestResponse,
        operation_name: configuration.operation_name.clone(),
    };
    let Some(content_type) = request_content_type(request.headers()) else {
        return next.run(request).await;
    };
    let Ok(operation) = RequestResponseOperation::start(
        configuration.factory.as_ref(),
        &begin,
        &content_type,
        configuration.classifier,
    ) else {
        return next.run(request).await;
    };
    let Some(operation_id) = operation.operation_id() else {
        return next.run(request).await;
    };
    let automatic_context = operation.automatic_context();
    let context = OperationContext {
        causal_parent_id,
        operation_id,
    };
    let capture = Arc::new(Mutex::new(operation));
    let original = std::mem::replace(request.body_mut(), Body::empty());
    *request.body_mut() = Body::new(RequestCaptureBody {
        capture: capture.clone(),
        inner: original,
        terminal: false,
    });
    request.extensions_mut().insert(context);

    let response = match automatic_context.as_ref() {
        Some(context) => context.scope(next.run(request)).await,
        None => next.run(request).await,
    };
    if !lock_capture(&capture).input_complete() {
        lock_capture(&capture).abandon();
        return response;
    }
    capture_response(response, capture, automatic_context)
}

struct RequestCaptureBody {
    capture: Arc<Mutex<RequestResponseOperation>>,
    inner: Body,
    terminal: bool,
}

impl HttpBody for RequestCaptureBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref()
                    && lock_capture(&this.capture)
                        .record_input_chunk(bytes)
                        .is_err()
                {
                    this.terminal = true;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                lock_capture(&this.capture).abandon();
                this.terminal = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if !this.terminal {
                    let result = lock_capture(&this.capture).finish_input();
                    if result.is_err() {
                        lock_capture(&this.capture).abandon();
                    }
                    this.terminal = true;
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for RequestCaptureBody {
    fn drop(&mut self) {
        if !self.terminal {
            lock_capture(&self.capture).abandon();
        }
    }
}

fn capture_response(
    response: Response,
    capture: Arc<Mutex<RequestResponseOperation>>,
    automatic_context: Option<AutomaticOperationContext>,
) -> Response {
    let (parts, body) = response.into_parts();
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| RequestResponseHeader {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        });
    if lock_capture(&capture)
        .begin_response(parts.status.as_u16(), headers)
        .is_err()
    {
        return Response::from_parts(parts, body);
    }
    if body.is_end_stream() {
        let _ = lock_capture(&capture).finish_response();
        return Response::from_parts(parts, body);
    }
    Response::from_parts(
        parts,
        Body::new(ResponseCaptureBody {
            automatic_context,
            capture,
            inner: body,
            terminal: false,
        }),
    )
}

struct ResponseCaptureBody {
    automatic_context: Option<AutomaticOperationContext>,
    capture: Arc<Mutex<RequestResponseOperation>>,
    inner: Body,
    terminal: bool,
}

impl HttpBody for ResponseCaptureBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let frame = match this.automatic_context.as_ref() {
            Some(operation_context) => {
                operation_context.scope_poll(|| Pin::new(&mut this.inner).poll_frame(context))
            }
            None => Pin::new(&mut this.inner).poll_frame(context),
        };
        match frame {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref()
                    && lock_capture(&this.capture)
                        .record_response_chunk(bytes)
                        .is_err()
                {
                    this.terminal = true;
                }
                if !this.terminal && this.inner.is_end_stream() {
                    let _ = lock_capture(&this.capture).finish_response();
                    this.terminal = true;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                lock_capture(&this.capture).abandon();
                this.terminal = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if !this.terminal {
                    let _ = lock_capture(&this.capture).finish_response();
                    this.terminal = true;
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ResponseCaptureBody {
    fn drop(&mut self) {
        if !self.terminal {
            lock_capture(&self.capture).abandon();
        }
    }
}

fn request_content_type(headers: &HeaderMap) -> Option<String> {
    match headers.get(header::CONTENT_TYPE) {
        Some(value) => {
            let value = value.to_str().ok()?;
            if value.is_empty() || value.len() > 128 {
                return None;
            }
            Some(value.to_owned())
        }
        None => Some(DEFAULT_CONTENT_TYPE.to_owned()),
    }
}

fn lock_capture(
    capture: &Mutex<RequestResponseOperation>,
) -> std::sync::MutexGuard<'_, RequestResponseOperation> {
    capture.lock().unwrap_or_else(PoisonError::into_inner)
}
