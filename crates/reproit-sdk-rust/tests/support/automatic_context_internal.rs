use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
};

use reproit_core::{
    canonical,
    crypto::encode_base64url,
    identity::{CaptureId, Digest, OperationId},
    model::{
        AutomaticObservationClass, Candidate, DependencyOutcome, Deployment, DeploymentFormat,
        OperationBeginFormat, OperationBeginPayload, OperationKind, ProcessingMode,
        SemanticDependencyOperation, SemanticDependencyRequest, SemanticDependencyRequestFormat,
        SemanticDependencyResponse, SemanticDependencyResponseFormat, SemanticObservationOutcome,
        Subject, SubjectFormat, TriggerCompletion,
    },
};

use super::*;
use crate::{
    AutomaticCandidateStart, CandidateSink, Sdk,
    automatic_world::{AutomaticObservationRegistration, AutomaticWorldCoordinator},
};

static PROCESS_TEST: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct Sink;

impl CandidateSink for Sink {
    fn queued_bytes(&self) -> usize {
        0
    }

    fn try_send(&self, _candidate: Candidate) -> bool {
        false
    }
}

#[test]
fn semantic_observation_routes_across_async_yields() {
    let _process = process_test();
    let (context, shared, sdk, operation_id) = started_context(1);
    let runtime = runtime();

    let application_result = runtime.block_on(async move {
        tokio::spawn(async move {
            context
                .scope(async {
                    tokio::task::yield_now().await;
                    let current = AutomaticOperationContext::current().unwrap();
                    assert_eq!(current.operation_id(), operation_id);
                    let mut session = current
                        .open_observation(AutomaticObservationClass::Database, None)
                        .unwrap();
                    let (request, response) = database_records();
                    session.write_request(&request).unwrap();
                    tokio::task::yield_now().await;
                    assert_eq!(session.dispatch().unwrap(), "capture");
                    session.write_response(&response).unwrap();
                    session.finish(DependencyOutcome::Response).unwrap();
                    73_u8
                })
                .await
        })
        .await
        .unwrap()
    });

    assert_eq!(application_result, 73);
    let coordinator = shared.take_for_close().unwrap();
    let capture = coordinator.close(TriggerCompletion::Return).unwrap();
    assert_eq!(capture.fence.observation_count, 3);
    drop(capture);
    sdk.abandon_incomplete(operation_id);
}

#[test]
fn lost_context_invalidates_active_operations_and_preserves_the_application_result() {
    let _process = process_test();
    let (context, shared, sdk, operation_id) = started_context(2);

    assert_eq!(
        error(AutomaticOperationContext::current()).code,
        ErrorCode::IncompleteCandidate
    );
    assert_eq!(
        error(context.open_observation(AutomaticObservationClass::Database, None)).code,
        ErrorCode::IncompleteCandidate
    );
    assert_eq!(
        error(shared.take_for_close()).code,
        ErrorCode::IncompleteCandidate
    );
    sdk.abandon_incomplete(operation_id);
}

#[test]
fn nested_scopes_restore_the_parent_context() {
    let _process = process_test();
    let (outer, outer_shared, outer_sdk, outer_id) = started_context(3);
    let (inner, inner_shared, inner_sdk, inner_id) = started_context(4);
    let runtime = runtime();

    runtime.block_on(outer.scope(async {
        assert_eq!(
            AutomaticOperationContext::current().unwrap().operation_id(),
            outer_id
        );
        inner
            .scope(async {
                assert_eq!(
                    AutomaticOperationContext::current().unwrap().operation_id(),
                    inner_id
                );
                tokio::task::yield_now().await;
            })
            .await;
        assert_eq!(
            AutomaticOperationContext::current().unwrap().operation_id(),
            outer_id
        );
    }));

    close_and_abandon(&outer_shared, &outer_sdk, outer_id);
    close_and_abandon(&inner_shared, &inner_sdk, inner_id);
}

#[test]
fn one_over_nesting_masks_context_and_preserves_the_application_result() {
    let _process = process_test();
    let (context, shared, sdk, operation_id) = started_context(5);
    let stack = (0..MAX_AUTOMATIC_OPERATION_NESTING)
        .map(|_| inert_context(operation_id))
        .collect::<Vec<_>>();
    let runtime = runtime();
    let _stack = TestAutomaticOperationStack::install(stack);

    let application_result = runtime.block_on(context.scope(async {
        assert_eq!(
            error(AutomaticOperationContext::current()).code,
            ErrorCode::IncompleteCandidate
        );
        91_u8
    }));

    assert_eq!(application_result, 91);
    assert_eq!(
        error(shared.take_for_close()).code,
        ErrorCode::IncompleteCandidate
    );
    sdk.abandon_incomplete(operation_id);
}

#[test]
fn scoped_future_installs_context_for_each_manual_poll() {
    let _process = process_test();
    let (context, shared, sdk, operation_id) = started_context(8);
    let mut future = Box::pin(context.scope(ManualContextFuture {
        operation_id,
        poll_count: 0,
    }));
    let mut task_context = Context::from_waker(Waker::noop());

    assert_eq!(future.as_mut().poll(&mut task_context), Poll::Pending);
    assert!(automatic_operation_stack_is_empty());
    assert_eq!(future.as_mut().poll(&mut task_context), Poll::Ready(41));
    assert!(automatic_operation_stack_is_empty());

    close_and_abandon(&shared, &sdk, operation_id);
}

#[test]
fn dropped_session_releases_state_and_keeps_world_incomplete() {
    let _process = process_test();
    let (context, shared, sdk, operation_id) = started_context(6);
    let runtime = runtime();

    let application_result = runtime.block_on(context.scope(async {
        let current = AutomaticOperationContext::current().unwrap();
        let mut session = current
            .open_observation(AutomaticObservationClass::Database, None)
            .unwrap();
        let (request, _) = database_records();
        session.write_request(&request).unwrap();
        drop(session);
        "application-result"
    }));

    assert_eq!(application_result, "application-result");
    assert_eq!(
        error(shared.take_for_close()).code,
        ErrorCode::IncompleteCandidate
    );
    sdk.abandon_incomplete(operation_id);
}

#[test]
fn ambient_session_allocation_is_bounded() {
    let _process = process_test();
    let (context, shared, sdk, operation_id) = started_context(7);
    shared.state.lock().unwrap().ambient_session_count = MAX_EVENTS;
    let runtime = runtime();

    let application_result = runtime.block_on(context.scope(async {
        let current = AutomaticOperationContext::current().unwrap();
        assert_eq!(
            error(current.open_observation(AutomaticObservationClass::Database, None)).code,
            ErrorCode::RuntimeQuota
        );
        19_u8
    }));

    assert_eq!(application_result, 19);
    assert_eq!(
        error(shared.take_for_close()).code,
        ErrorCode::IncompleteCandidate
    );
    sdk.abandon_incomplete(operation_id);
}

fn started_context(
    suffix: u64,
) -> (
    AutomaticOperationContext,
    Arc<AutomaticOperationShared>,
    Sdk,
    OperationId,
) {
    let operation_id = operation_id(suffix);
    let sdk = Sdk::new(Arc::new(Sink));
    sdk.begin_automatic(
        AutomaticCandidateStart {
            capture_id: capture_id(suffix),
            deployment: deployment(),
            operation_id,
        },
        &OperationBeginPayload {
            adapter_id: "test-adapter".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            causal_parent_ids: Vec::new(),
            format: OperationBeginFormat::V1,
            operation_kind: OperationKind::RequestResponse,
            operation_name: "orders.increment".to_owned(),
        },
    )
    .unwrap();
    let registrations = AutomaticObservationClass::ALL
        .into_iter()
        .map(|class| {
            let registration = AutomaticObservationRegistration::new(
                class,
                "test-semantic-adapter".to_owned(),
                "1.0.0".to_owned(),
                Digest::of(b"test-semantic-adapter"),
            )
            .unwrap();
            (class, registration)
        })
        .collect();
    let mut coordinator =
        AutomaticWorldCoordinator::new_with_registrations(sdk.clone(), operation_id, registrations)
            .unwrap();
    coordinator.capture_ambient().unwrap();
    coordinator
        .bind_native_sentinel_coverage(b"clean bounded kernel trace")
        .unwrap();
    let shared = AutomaticOperationShared::new(operation_id, coordinator).unwrap();
    let context = AutomaticOperationContext::new(operation_id, shared.clone());
    (context, shared, sdk, operation_id)
}

fn close_and_abandon(shared: &AutomaticOperationShared, sdk: &Sdk, operation_id: OperationId) {
    shared
        .take_for_close()
        .unwrap()
        .close(TriggerCompletion::Return)
        .unwrap();
    sdk.abandon_incomplete(operation_id);
}

fn inert_context(operation_id: OperationId) -> AutomaticOperationContext {
    AutomaticOperationContext {
        operation_id,
        shared: Arc::new(AutomaticOperationShared {
            operation_id,
            registered: AtomicBool::new(false),
            state: Mutex::new(AutomaticOperationState {
                ambient_session_count: 0,
                coordinator: None,
                invalid_context: false,
            }),
        }),
    }
}

struct ManualContextFuture {
    operation_id: OperationId,
    poll_count: u8,
}

impl Future for ManualContextFuture {
    type Output = u8;

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(
            AutomaticOperationContext::current().unwrap().operation_id(),
            self.operation_id
        );
        self.poll_count += 1;
        if self.poll_count == 1 {
            Poll::Pending
        } else {
            Poll::Ready(41)
        }
    }
}

struct TestAutomaticOperationStack {
    previous: Vec<AutomaticOperationContext>,
}

impl TestAutomaticOperationStack {
    fn install(stack: Vec<AutomaticOperationContext>) -> Self {
        let previous = AUTOMATIC_OPERATION_STACK
            .with(|current| mem::replace(&mut *current.borrow_mut(), stack));
        Self { previous }
    }
}

impl Drop for TestAutomaticOperationStack {
    fn drop(&mut self) {
        AUTOMATIC_OPERATION_STACK.with(|current| {
            *current.borrow_mut() = mem::take(&mut self.previous);
        });
    }
}

fn automatic_operation_stack_is_empty() -> bool {
    AUTOMATIC_OPERATION_STACK.with(|stack| stack.borrow().is_empty())
}

fn database_records() -> (Vec<u8>, Vec<u8>) {
    let request = SemanticDependencyRequest {
        encoding: "bytes".to_owned(),
        format: SemanticDependencyRequestFormat::V1,
        metadata: Vec::new(),
        method: None,
        observation_class: AutomaticObservationClass::Database,
        operation: SemanticDependencyOperation::DatabaseExecute,
        payload: encode_base64url(b"select balance"),
        protocol: "test-protocol".to_owned(),
        target: encode_base64url(b"test-database"),
    };
    let request_bytes = canonical::canonical_bytes(&request).unwrap();
    let response = SemanticDependencyResponse {
        error_code: None,
        error_number: None,
        format: SemanticDependencyResponseFormat::V1,
        metadata: Vec::new(),
        observation_class: AutomaticObservationClass::Database,
        operation: SemanticDependencyOperation::DatabaseExecute,
        outcome: SemanticObservationOutcome::Response,
        payload: Some(encode_base64url(b"balance=6")),
        request_digest: canonical::digest(&request).unwrap(),
        status: None,
        status_code: None,
    };
    (
        request_bytes,
        canonical::canonical_bytes(&response).unwrap(),
    )
}

fn operation_id(suffix: u64) -> OperationId {
    format!("op_01890f3e-7b1c-7cc0-8a1b-{suffix:012x}")
        .parse()
        .unwrap()
}

fn capture_id(suffix: u64) -> CaptureId {
    format!("cap_01890f3e-7b1c-7cc0-8a1b-{suffix:012x}")
        .parse()
        .unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

fn process_test() -> MutexGuard<'static, ()> {
    PROCESS_TEST.lock().unwrap_or_else(PoisonError::into_inner)
}

fn deployment() -> Deployment {
    Deployment {
        format: DeploymentFormat::V1,
        organization_id: parse("org_01890f3e-7b1c-7cc0-8a1b-123456789abd"),
        processing_mode: ProcessingMode::Private,
        project_id: parse("prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"),
        repository_id: "source.example/example/service".to_owned(),
        runtime_capabilities: vec![
            "architecture.native".to_owned(),
            "operating-system.linux".to_owned(),
            "runtime.rust-native".to_owned(),
        ],
        runtime_endpoint: "https://runtime.example.invalid".to_owned(),
        service_id: parse("svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"),
        service_path: "services/example".to_owned(),
        signature: encode_base64url(&[0_u8; 64]),
        signed_at: parse("2026-01-01T00:00:00.000Z"),
        signer_key_id: "test-deployment".to_owned(),
        source_revision: "0123456789abcdef".to_owned(),
        subject: Subject {
            architecture: "architecture.native".to_owned(),
            arguments: Vec::new(),
            artifact_digest: Digest::of(b"test-subject"),
            artifact_media_type: "application/vnd.reproit.native-executable.v1".to_owned(),
            artifact_uri: concat!(
                "oci://example.invalid/service@sha256:",
                "1111111111111111111111111111111111111111111111111111111111111111"
            )
            .to_owned(),
            environment_names: Vec::new(),
            executable: "/reproit/subject/service".to_owned(),
            format: SubjectFormat::V1,
            operating_system: "operating-system.linux".to_owned(),
            working_directory: "/reproit/subject".to_owned(),
        },
    }
}

fn parse<T: std::str::FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn error<T>(result: Result<T, Error>) -> Error {
    match result {
        Ok(_) => panic!("the operation must fail closed"),
        Err(error) => error,
    }
}
