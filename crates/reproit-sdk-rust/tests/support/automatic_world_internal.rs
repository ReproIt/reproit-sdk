use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use reproit_core::{
    crypto::encode_base64url,
    identity::{Digest, OperationId},
    model::{
        AutomaticObservationClass, Candidate, DependencyOutcome, DependencyTranscript, Deployment,
        DeploymentFormat, OperationBeginFormat, OperationBeginPayload, OperationKind,
        ProcessingMode, SemanticObservationOperation, SemanticObservationOutcome,
        SemanticObservationRequest, SemanticObservationRequestFormat, SemanticObservationResponse,
        SemanticObservationResponseFormat, Subject, SubjectFormat, TriggerCompletion,
        semantic_observation_value,
    },
};

use super::*;
use crate::{AutomaticCandidateStart, CandidateSink};

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
fn transcript_binds_objects_causal_parent_and_fence_observation() {
    let _process = process_test();
    let (sdk, operation_id, causal_parent_id) = started_sdk();
    let mut coordinator = coordinator_with_coverage(sdk.clone(), operation_id);
    capture(
        &mut coordinator,
        1,
        AutomaticObservationClass::Database,
        Some(causal_parent_id),
        b"select balance",
        b"balance=6",
        0,
    );

    let capture = coordinator.close(TriggerCompletion::Return).unwrap();
    let transcript_artifact = capture
        .closure
        .artifacts
        .iter()
        .find(|artifact| artifact.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE)
        .unwrap();
    let transcript: DependencyTranscript =
        canonical::parse_strict(&fs::read(&transcript_artifact.path).unwrap()).unwrap();
    assert_eq!(transcript.interactions.len(), 1);
    let interaction = &transcript.interactions[0];
    assert_eq!(interaction.causal_parent_id, Some(causal_parent_id));
    assert_eq!(interaction.operation_id, operation_id);
    assert_eq!(interaction.request_digest, Digest::of(b"select balance"));
    assert_eq!(interaction.response_digest, Digest::of(b"balance=6"));
    let object_ids = capture
        .closure
        .artifacts
        .iter()
        .map(|artifact| artifact.object_id)
        .collect::<BTreeSet<_>>();
    assert!(object_ids.contains(&interaction.request_object_id));
    assert!(object_ids.contains(&interaction.response_object_id));
    assert_eq!(capture.fence.observation_count, 1);
    assert_eq!(capture.fence.adapter_ownership.len(), 7);
}

#[test]
fn immutable_state_keeps_only_response_and_keys_it_by_request_digest() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = coordinator_with_coverage(sdk, operation_id);
    let (request, response) = capture(
        &mut coordinator,
        1,
        AutomaticObservationClass::Filesystem,
        None,
        b"config/settings.json",
        b"enabled=true",
        0,
    );

    let capture = coordinator.close(TriggerCompletion::Return).unwrap();
    assert_eq!(capture.closure.artifacts.len(), 1);
    let request_digest = Digest::of(&request);
    let artifact = &capture.closure.artifacts[0];
    assert!(artifact.uri.contains(&request_digest.to_string()));
    assert_eq!(capture.closure.world.points[0].artifacts.len(), 1);
    assert_eq!(
        capture.closure.world.points[0].artifacts[0].digest,
        Digest::of(&response)
    );
}

#[test]
fn registered_hooks_without_native_sentinel_evidence_fail_closed() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = AutomaticWorldCoordinator::new(sdk.clone(), operation_id).unwrap();
    for class in AutomaticObservationClass::ALL {
        coordinator
            .register_observation_adapter(
                class,
                ADAPTER_ID.to_owned(),
                ADAPTER_VERSION.to_owned(),
                Digest::of(b"semantic-hook-implementation"),
            )
            .unwrap();
    }
    coordinator.capture_ambient().unwrap();
    for (session_id, class) in [
        AutomaticObservationClass::Database,
        AutomaticObservationClass::Filesystem,
        AutomaticObservationClass::OutboundHttp,
        AutomaticObservationClass::Queue,
        AutomaticObservationClass::Randomness,
    ]
    .into_iter()
    .enumerate()
    {
        capture(
            &mut coordinator,
            u64::try_from(session_id).unwrap() + 1,
            class,
            None,
            b"request",
            b"response",
            0,
        );
    }

    let Err(error) = coordinator.close(TriggerCompletion::Return) else {
        panic!("missing sentinel evidence must fail closed");
    };
    assert_eq!(error.code, ErrorCode::WorldNotClosed);
    sdk.abandon_incomplete(operation_id);
}

#[test]
fn one_unowned_observation_stops_before_candidate_delivery() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = AutomaticWorldCoordinator::new(sdk.clone(), operation_id).unwrap();
    coordinator
        .mark_unowned(
            AutomaticObservationClass::Filesystem,
            None,
            b"unsupported effect",
        )
        .unwrap();

    let Err(error) = coordinator.close(TriggerCompletion::Return) else {
        panic!("unowned observation must fail closed");
    };
    assert_eq!(error.code, ErrorCode::WorldNotClosed);
    sdk.abandon_incomplete(operation_id);
    assert_eq!(sdk.recall_counters().candidate_incomplete, 1);
}

#[test]
fn open_abandoned_and_overflowed_sessions_reject_world_close() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut open = coordinator_with_coverage(sdk.clone(), operation_id);
    open.open_observation(1, AutomaticObservationClass::Database, None)
        .unwrap();
    assert_world_not_closed(open);

    let mut abandoned = coordinator_with_coverage(sdk.clone(), operation_id);
    abandoned
        .open_observation(2, AutomaticObservationClass::Database, None)
        .unwrap();
    abandoned.abandon_observation(2).unwrap();
    assert_world_not_closed(abandoned);

    let mut overflowed = coordinator_with_coverage(sdk, operation_id);
    overflowed
        .open_observation(3, AutomaticObservationClass::Database, None)
        .unwrap();
    let chunk = vec![0_u8; MAX_AUTOMATIC_OBSERVATION_CHUNK_BYTES + 1];
    assert_eq!(
        overflowed
            .write_observation_request(3, &chunk)
            .unwrap_err()
            .code,
        ErrorCode::RuntimeQuota
    );
    assert_world_not_closed(overflowed);
}

#[test]
fn abandon_removes_the_session_once_and_marks_the_operation_incomplete() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = coordinator_with_coverage(sdk, operation_id);
    coordinator
        .open_observation(1, AutomaticObservationClass::Database, None)
        .unwrap();

    coordinator.abandon_observation(1).unwrap();

    assert!(!coordinator.sessions.contains_key(&1));
    assert!(coordinator.incomplete_session);
    assert_eq!(
        coordinator.abandon_observation(1).unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn one_over_per_operation_session_bound_is_rejected() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = coordinator_with_coverage(sdk, operation_id);
    for session_id in 0..MAX_AUTOMATIC_OBSERVATION_SESSIONS_PER_OPERATION {
        coordinator
            .open_observation(
                u64::try_from(session_id).unwrap(),
                AutomaticObservationClass::Database,
                None,
            )
            .unwrap();
    }
    assert_eq!(
        coordinator
            .open_observation(
                u64::try_from(MAX_AUTOMATIC_OBSERVATION_SESSIONS_PER_OPERATION).unwrap(),
                AutomaticObservationClass::Database,
                None,
            )
            .unwrap_err()
            .code,
        ErrorCode::RuntimeQuota
    );
}

#[test]
fn caller_session_position_must_match_canonical_order() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = coordinator_with_coverage(sdk, operation_id);
    coordinator
        .open_observation(1, AutomaticObservationClass::Database, None)
        .unwrap();
    coordinator
        .write_observation_request(1, b"request")
        .unwrap();
    coordinator.dispatch_observation(1).unwrap();
    coordinator
        .write_observation_response(1, b"response")
        .unwrap();
    assert_eq!(
        coordinator
            .finish_observation(1, DependencyOutcome::Response, 1)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteCandidate
    );
}

#[test]
fn semantic_record_class_and_request_binding_fail_closed() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut wrong_class = coordinator_with_coverage(sdk.clone(), operation_id);
    let (random_request, _) = semantic_records(
        AutomaticObservationClass::Randomness,
        b"unused",
        b"12345678",
    );
    wrong_class
        .open_observation(1, AutomaticObservationClass::Filesystem, None)
        .unwrap();
    wrong_class
        .write_observation_request(1, &random_request)
        .unwrap();
    assert_eq!(
        wrong_class.dispatch_observation(1).unwrap_err().code,
        ErrorCode::IncompleteCandidate
    );

    let mut wrong_binding = coordinator_with_coverage(sdk.clone(), operation_id);
    let (request, response) = semantic_records(
        AutomaticObservationClass::Filesystem,
        b"/data/input",
        b"fixture",
    );
    let mut response: SemanticObservationResponse = canonical::parse_strict(&response).unwrap();
    response.request_digest = Digest::of(b"another request");
    let response = canonical::canonical_bytes(&response).unwrap();
    wrong_binding
        .open_observation(2, AutomaticObservationClass::Filesystem, None)
        .unwrap();
    wrong_binding
        .write_observation_request(2, &request)
        .unwrap();
    wrong_binding.dispatch_observation(2).unwrap();
    wrong_binding
        .write_observation_response(2, &response)
        .unwrap();
    assert_eq!(
        wrong_binding
            .finish_observation(2, DependencyOutcome::Response, 0)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteCandidate
    );

    let mut malformed_response = coordinator_with_coverage(sdk, operation_id);
    let (request, _) = semantic_records(
        AutomaticObservationClass::Filesystem,
        b"/data/input",
        b"fixture",
    );
    malformed_response
        .open_observation(3, AutomaticObservationClass::Filesystem, None)
        .unwrap();
    malformed_response
        .write_observation_request(3, &request)
        .unwrap();
    malformed_response.dispatch_observation(3).unwrap();
    malformed_response
        .write_observation_response(3, b"{}")
        .unwrap();
    assert_eq!(
        malformed_response
            .finish_observation(3, DependencyOutcome::Response, 0)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteCandidate
    );
    assert_world_not_closed(malformed_response);
}

#[test]
fn replay_reads_are_bounded_advance_offset_and_reject_capture_state() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let mut coordinator = coordinator_with_coverage(sdk, operation_id);
    coordinator
        .open_observation(1, AutomaticObservationClass::Database, None)
        .unwrap();
    let response = vec![7_u8; MAX_AUTOMATIC_OBSERVATION_RESPONSE_READ_BYTES + 1];
    let session = coordinator.sessions.get_mut(&1).unwrap();
    fs::write(&session.response_path, &response).unwrap();
    session.response_bytes = u64::try_from(response.len()).unwrap();
    session.state = AutomaticObservationSessionState::Replay { response_offset: 0 };

    let (first, first_eof) = coordinator.read_observation_response(1).unwrap();
    assert_eq!(first.len(), MAX_AUTOMATIC_OBSERVATION_RESPONSE_READ_BYTES);
    assert!(!first_eof);
    let (second, second_eof) = coordinator.read_observation_response(1).unwrap();
    assert_eq!(second, vec![7_u8]);
    assert!(second_eof);

    coordinator
        .open_observation(2, AutomaticObservationClass::Database, None)
        .unwrap();
    assert_eq!(
        coordinator.read_observation_response(2).unwrap_err().code,
        ErrorCode::IncompleteCandidate
    );
}

#[test]
fn successful_capture_drop_deletes_the_local_spool() {
    let _process = process_test();
    let (sdk, operation_id, _) = started_sdk();
    let coordinator = coordinator_with_coverage(sdk, operation_id);
    let spool = coordinator.spool.path().to_owned();
    let capture = coordinator.close(TriggerCompletion::Return).unwrap();
    assert!(spool.exists());
    drop(capture);
    assert!(!spool.exists());
}

fn capture(
    coordinator: &mut AutomaticWorldCoordinator,
    session_id: u64,
    class: AutomaticObservationClass,
    causal_parent_id: Option<OperationId>,
    request: &[u8],
    response: &[u8],
    session_position: u64,
) -> (Vec<u8>, Vec<u8>) {
    let (request, response) = semantic_records(class, request, response);
    coordinator
        .open_observation(session_id, class, causal_parent_id)
        .unwrap();
    coordinator
        .write_observation_request(session_id, &request)
        .unwrap();
    assert_eq!(
        coordinator
            .dispatch_observation(session_id)
            .unwrap()
            .as_str(),
        "capture"
    );
    coordinator
        .write_observation_response(session_id, &response)
        .unwrap();
    coordinator
        .finish_observation(session_id, DependencyOutcome::Response, session_position)
        .unwrap();
    (request, response)
}

fn semantic_records(
    class: AutomaticObservationClass,
    request: &[u8],
    response: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let operation = match class {
        AutomaticObservationClass::Clock => SemanticObservationOperation::ClockWallTime,
        AutomaticObservationClass::Environment => SemanticObservationOperation::EnvironmentRead,
        AutomaticObservationClass::Filesystem => SemanticObservationOperation::FilesystemRead,
        AutomaticObservationClass::Randomness => SemanticObservationOperation::RandomBytes,
        _ => return (request.to_vec(), response.to_vec()),
    };
    let target = matches!(
        operation,
        SemanticObservationOperation::EnvironmentRead
            | SemanticObservationOperation::FilesystemRead
    )
    .then(|| encode_base64url(request));
    let length = matches!(
        operation,
        SemanticObservationOperation::FilesystemRead | SemanticObservationOperation::RandomBytes
    )
    .then(|| u64::try_from(response.len()).unwrap());
    let offset = (operation == SemanticObservationOperation::FilesystemRead).then_some(0);
    let request = SemanticObservationRequest {
        format: SemanticObservationRequestFormat::V1,
        length,
        offset,
        operation,
        target,
    };
    let request_bytes = canonical::canonical_bytes(&request).unwrap();
    let response = SemanticObservationResponse {
        error_code: None,
        error_number: None,
        format: SemanticObservationResponseFormat::V1,
        operation,
        outcome: SemanticObservationOutcome::Response,
        request_digest: Digest::of(&request_bytes),
        value: Some(semantic_observation_value(response).unwrap()),
    };
    (
        request_bytes,
        canonical::canonical_bytes(&response).unwrap(),
    )
}

fn coordinator_with_coverage(sdk: Sdk, operation_id: OperationId) -> AutomaticWorldCoordinator {
    let mut coordinator = AutomaticWorldCoordinator::new(sdk, operation_id).unwrap();
    for class in AutomaticObservationClass::ALL {
        coordinator
            .register_observation_adapter(
                class,
                ADAPTER_ID.to_owned(),
                ADAPTER_VERSION.to_owned(),
                Digest::of(b"semantic-hook-implementation"),
            )
            .unwrap();
        coordinator
            .register_sentinel_coverage(class, Digest::of(class.boundary_id().as_bytes()))
            .unwrap();
    }
    coordinator
}

fn assert_world_not_closed(coordinator: AutomaticWorldCoordinator) {
    let Err(error) = coordinator.close(TriggerCompletion::Return) else {
        panic!("an incomplete session must fail closed");
    };
    assert_eq!(error.code, ErrorCode::WorldNotClosed);
}

fn started_sdk() -> (Sdk, OperationId, OperationId) {
    let operation_id = parse("op_01890f3e-7b1c-7cc0-8a1b-123456789ab1");
    let causal_parent_id = parse("op_01890f3e-7b1c-7cc0-8a1b-123456789ab2");
    let sdk = Sdk::new(Arc::new(Sink));
    sdk.begin_automatic(
        AutomaticCandidateStart {
            capture_id: parse("cap_01890f3e-7b1c-7cc0-8a1b-123456789abc"),
            deployment: deployment(),
            operation_id,
        },
        &OperationBeginPayload {
            adapter_id: "test-adapter".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            causal_parent_ids: vec![causal_parent_id],
            format: OperationBeginFormat::V1,
            operation_kind: OperationKind::RequestResponse,
            operation_name: "orders.increment".to_owned(),
        },
    )
    .unwrap();
    (sdk, operation_id, causal_parent_id)
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

fn process_test() -> MutexGuard<'static, ()> {
    PROCESS_TEST.lock().unwrap_or_else(PoisonError::into_inner)
}
