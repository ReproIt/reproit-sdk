use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicU64, Ordering},
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::Extension,
    http::{Request, StatusCode},
    middleware,
    response::Response,
    routing::post,
};
use reproit_core::{
    Error,
    crypto::decode_base64url_bytes,
    identity::OperationId,
    model::{
        ExceptionCategory, ExceptionFailureIdentity, FailureFrame, FailureIdentity,
        OperationBeginPayload, OperationInputPayload, OperationKind, TriggerCompletion,
    },
};
use reproit_sdk_rust::{
    ExactResponseFailureClassifier, MAX_REQUEST_INPUT_CHUNK_BYTES, MAX_RESPONSE_HEADER_BYTES,
    RustOperation, RustOperationFactory,
};
use reproit_sdk_rust_axum::{AxumRequestCapture, OperationContext, capture_axum_request};
use tower::ServiceExt as _;

#[derive(Clone, Debug)]
enum OperationEvent {
    Abandoned,
    Begin(OperationBeginPayload),
    Failed(FailureIdentity),
    Input(OperationInputPayload),
    Succeeded,
}

#[derive(Default)]
struct RecordingFactory {
    events: Arc<Mutex<Vec<OperationEvent>>>,
    next_id: AtomicU64,
    reject_input_at: Option<u16>,
}

impl RecordingFactory {
    fn events(&self) -> Vec<OperationEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RustOperationFactory for RecordingFactory {
    fn start(&self, begin: &OperationBeginPayload) -> Result<Box<dyn RustOperation>, Error> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(OperationEvent::Begin(begin.clone()));
        let index = self.next_id.fetch_add(1, Ordering::SeqCst);
        let operation_id = format!("op_01890f3e-7b1c-7cc0-8a1b-{index:012x}").parse()?;
        Ok(Box::new(RecordingOperation {
            events: self.events.clone(),
            operation_id,
            reject_input_at: self.reject_input_at,
        }))
    }
}

struct RecordingOperation {
    events: Arc<Mutex<Vec<OperationEvent>>>,
    operation_id: OperationId,
    reject_input_at: Option<u16>,
}

impl RustOperation for RecordingOperation {
    fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    fn record_input(&self, input: &OperationInputPayload) -> Result<(), Error> {
        if self
            .reject_input_at
            .is_some_and(|index| input.input_index >= index)
        {
            return Err(Error::new(
                reproit_core::ErrorCode::RuntimeQuota,
                "The test operation input limit was reached.",
            ));
        }
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(OperationEvent::Input(input.clone()));
        Ok(())
    }

    fn succeed(self: Box<Self>) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(OperationEvent::Succeeded);
    }

    fn abandon_incomplete(self: Box<Self>) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(OperationEvent::Abandoned);
    }

    fn fail(
        self: Box<Self>,
        identity: FailureIdentity,
        completion: TriggerCompletion,
    ) -> Result<(), Error> {
        assert_eq!(completion, TriggerCompletion::Return);
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(OperationEvent::Failed(identity));
        Ok(())
    }
}

#[tokio::test]
async fn adapter_translates_failure_into_the_framework_neutral_operation() {
    let failure = failure_identity();
    let factory = Arc::new(RecordingFactory::default());
    let capture = AxumRequestCapture::new(
        factory.clone(),
        "orders.increment",
        Arc::new(ExactResponseFailureClassifier::new(
            500,
            br#"{"counter":25}"#.to_vec(),
            failure,
        )),
    )
    .unwrap();
    let parent = OperationContext {
        causal_parent_id: None,
        operation_id: "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1".parse().unwrap(),
    };
    let app = app(capture, failing_handler);
    let mut request = Request::post("/orders")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"amount":10}"#))
        .unwrap();
    request.extensions_mut().insert(parent.clone());

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 64 * 1_024).await.unwrap(),
        br#"{"counter":25}"#[..]
    );

    let events = factory.events();
    let OperationEvent::Begin(begin) = &events[0] else {
        panic!("the first event must start the operation");
    };
    assert_eq!(begin.causal_parent_ids, vec![parent.operation_id]);
    let OperationEvent::Input(input) = &events[1] else {
        panic!("the second event must contain the Trigger input");
    };
    assert_eq!(input.content_type, "application/json");
    let OperationEvent::Failed(identity) = &events[2] else {
        panic!("the third event must contain the Failure identity");
    };
    assert_eq!(identity, &failure_identity());
}

#[tokio::test]
async fn successful_response_deletes_the_framework_neutral_operation() {
    let factory = Arc::new(RecordingFactory::default());
    let capture = AxumRequestCapture::new(
        factory.clone(),
        "orders.increment",
        Arc::new(ExactResponseFailureClassifier::new(
            500,
            Vec::new(),
            failure_identity(),
        )),
    )
    .unwrap();
    let response = app(capture, success_handler)
        .oneshot(Request::post("/orders").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = to_bytes(response.into_body(), 1).await.unwrap();
    assert!(matches!(
        factory.events().last(),
        Some(OperationEvent::Succeeded)
    ));
}

#[tokio::test]
async fn large_input_streams_as_ordered_bounded_input_records() {
    let factory = Arc::new(RecordingFactory::default());
    let capture = capture_failure(factory.clone());
    let response = app(capture, size_handler)
        .oneshot(
            Request::post("/orders")
                .body(Body::from(vec![0x41; MAX_REQUEST_INPUT_CHUNK_BYTES + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["x-body-size"], "32769");
    let _ = to_bytes(response.into_body(), 1).await.unwrap();
    let inputs = factory
        .events()
        .into_iter()
        .filter_map(|event| match event {
            OperationEvent::Input(input) => Some(input),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0].input_index, 0);
    assert_eq!(inputs[1].input_index, 1);
    assert_eq!(
        decode_base64url_bytes(&inputs[0].value).unwrap().len(),
        MAX_REQUEST_INPUT_CHUNK_BYTES
    );
    assert_eq!(decode_base64url_bytes(&inputs[1].value).unwrap(), [0x41]);
}

#[tokio::test]
async fn operation_input_bound_exhaustion_preserves_the_response_and_stays_local() {
    let factory = Arc::new(RecordingFactory {
        reject_input_at: Some(1),
        ..RecordingFactory::default()
    });
    let capture = capture_failure(factory.clone());
    let response = app(capture, size_handler)
        .oneshot(
            Request::post("/orders")
                .body(Body::from(vec![0x41; MAX_REQUEST_INPUT_CHUNK_BYTES + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["x-body-size"], "32769");
    let _ = to_bytes(response.into_body(), 1).await.unwrap();
    assert!(matches!(
        factory.events().last(),
        Some(OperationEvent::Abandoned)
    ));
}

#[tokio::test]
async fn large_output_streams_through_the_failure_classifier() {
    let factory = Arc::new(RecordingFactory::default());
    let capture = AxumRequestCapture::new(
        factory.clone(),
        "orders.increment",
        Arc::new(ExactResponseFailureClassifier::new(
            500,
            vec![0x41; 32 * 1_024 + 1],
            failure_identity(),
        )),
    )
    .unwrap();
    let response = app(capture, large_output_handler)
        .oneshot(Request::post("/orders").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 32 * 1_024 + 1)
        .await
        .unwrap();
    assert_eq!(body.len(), 32 * 1_024 + 1);
    assert!(matches!(
        factory.events().last(),
        Some(OperationEvent::Failed(_))
    ));
}

#[tokio::test]
async fn oversized_headers_preserve_the_application_response_and_stay_local() {
    let factory = Arc::new(RecordingFactory::default());
    let capture = capture_failure(factory.clone());
    let response = app(capture, large_header_handler)
        .oneshot(Request::post("/orders").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        response.headers()["x-large"].as_bytes().len(),
        MAX_RESPONSE_HEADER_BYTES + 1
    );
    let _ = to_bytes(response.into_body(), 64 * 1_024).await.unwrap();
    assert!(matches!(
        factory.events().last(),
        Some(OperationEvent::Abandoned)
    ));
}

#[tokio::test]
async fn dropped_response_abandons_the_framework_neutral_operation() {
    let factory = Arc::new(RecordingFactory::default());
    let capture = capture_failure(factory.clone());
    let response = app(capture, failing_handler)
        .oneshot(
            Request::post("/orders")
                .body(Body::from(r#"{"amount":10}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    drop(response);
    assert!(matches!(
        factory.events().last(),
        Some(OperationEvent::Abandoned)
    ));
}

fn capture_failure(factory: Arc<RecordingFactory>) -> AxumRequestCapture {
    let failure = failure_identity();
    AxumRequestCapture::new(
        factory,
        "orders.increment",
        Arc::new(ExactResponseFailureClassifier::new(
            500,
            br#"{"counter":25}"#.to_vec(),
            failure,
        )),
    )
    .unwrap()
}

fn failure_identity() -> FailureIdentity {
    FailureIdentity::Exception(ExceptionFailureIdentity {
        category: ExceptionCategory::Exception,
        cause_types: Vec::new(),
        frames: vec![FailureFrame {
            function: "orders::increment".to_owned(),
            module: "orders".to_owned(),
            source: "src/orders.rs".to_owned(),
        }],
        operation_kind: OperationKind::RequestResponse,
        operation_name: "orders.increment".to_owned(),
        runtime_family: "rust".to_owned(),
        schema: "reproit.failure.v1".to_owned(),
        stable_code: None,
        type_name: "CounterInvariant".to_owned(),
    })
}

fn app<H, T>(capture: AxumRequestCapture, handler: H) -> Router
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    Router::new()
        .route("/orders", post(handler))
        .route_layer(middleware::from_fn_with_state(
            capture,
            capture_axum_request,
        ))
}

async fn failing_handler(
    Extension(context): Extension<OperationContext>,
    body: Bytes,
) -> (StatusCode, &'static str) {
    assert!(!context.operation_id.to_string().is_empty());
    assert_eq!(body, br#"{"amount":10}"#[..]);
    (StatusCode::INTERNAL_SERVER_ERROR, r#"{"counter":25}"#)
}

async fn success_handler(Extension(_context): Extension<OperationContext>, _body: Bytes) {}

async fn size_handler(Extension(_context): Extension<OperationContext>, body: Bytes) -> Response {
    Response::builder()
        .header("x-body-size", body.len().to_string())
        .body(Body::empty())
        .unwrap()
}

async fn large_output_handler(
    Extension(_context): Extension<OperationContext>,
    _body: Bytes,
) -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(vec![0x41; 32 * 1_024 + 1]))
        .unwrap()
}

async fn large_header_handler(
    Extension(_context): Extension<OperationContext>,
    _body: Bytes,
) -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("x-large", "A".repeat(MAX_RESPONSE_HEADER_BYTES + 1))
        .body(Body::from(r#"{"counter":25}"#))
        .unwrap()
}
