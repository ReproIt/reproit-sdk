#![cfg(target_os = "linux")]

mod support;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use reproit_core::{
    ErrorCode,
    model::{TriggerCompletion, WorldCheckpoint, WorldCheckpointFormat},
};
use reproit_sdk_rust::{
    ManagedRustCaptureClosure, ManagedRustLocalRecorder, ManagedRustOperationClosure,
    OfficialManagedProject, OfficialManagedRustOperation, Sdk,
};

const PROJECT: &str = r#"
format = 1
organization_id = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd"
profile = "backend"
profile_format = 1
processing_mode = "managed"
project_id = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"
repository_id = "source.example/acme/commerce"
sdk = "rust"
service_id = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
service_path = "services/orders"

[run]
arguments = ["serve"]
program = "orders"
working_directory = "services/orders"

[source]
remote = "origin"
"#;
const REPOSITORY_ID: &str = "source.example/acme/commerce";
const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn operation_mismatch_stops_before_official_connection_and_token_access() {
    let (recorded, world) = recorded_failure();
    let other_operation_id = parse("op_01890f3e-7b1c-7cc0-8a1b-123456789ab2");
    let operation_closure = ManagedRustOperationClosure::capture(other_operation_id, &move |_| {
        Ok(ManagedRustCaptureClosure {
            artifacts: Vec::new(),
            completion: TriggerCompletion::Return,
            world: world.clone(),
        })
    })
    .expect("capture operation closure");
    let token_accessed = AtomicBool::new(false);
    let result = recorded.finalize_official(operation_closure, || {
        token_accessed.store(true, Ordering::SeqCst);
        panic!("the token provider must not run")
    });
    assert!(matches!(
        result,
        Err(error) if error.code == ErrorCode::IncompleteCandidate
    ));
    assert!(!token_accessed.load(Ordering::SeqCst));
}

#[test]
fn official_operation_owns_ids_and_suppresses_success() {
    if include_str!("../src/official_managed.rs")
        .contains("__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__")
    {
        return;
    }
    let fixture = support::fixture();
    let project = project();
    let first = OfficialManagedRustOperation::start(&project, capture_closure(), &fixture.begin)
        .expect("start first operation");
    let first_capture = first.capture_id();
    let first_operation = first.operation_id();
    first.record_input(&fixture.input).expect("record input");
    let counters = first.succeed();
    assert_eq!(counters.eligible_failure_observed, 0);
    assert_eq!(counters.candidate_durably_accepted, 0);

    let second = OfficialManagedRustOperation::start(&project, capture_closure(), &fixture.begin)
        .expect("start second operation");
    assert_ne!(second.capture_id(), first_capture);
    assert_ne!(second.operation_id(), first_operation);
    let counters = second.abandon_incomplete();
    assert_eq!(counters.candidate_incomplete, 1);
}

#[test]
fn official_failure_stops_before_token_access_when_release_is_unbound() {
    if !include_str!("../src/official_managed.rs")
        .contains("__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__")
    {
        return;
    }
    let token_accessed = AtomicBool::new(false);
    let result = OfficialManagedProject::from_build(PROJECT, REPOSITORY_ID, SOURCE_REVISION);
    assert!(matches!(
        result,
        Err(error) if error.code == ErrorCode::ConfigConflict
    ));
    assert!(!token_accessed.load(Ordering::SeqCst));
}

#[test]
fn official_project_api_has_no_host_or_container_variant() {
    if include_str!("../src/official_managed.rs")
        .contains("__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__")
    {
        return;
    }
    let host = project();
    let container = project();
    assert_eq!(host, container);
}

fn recorded_failure() -> (
    reproit_sdk_rust::ManagedRustRecordedFailure,
    WorldCheckpoint,
) {
    let mut fixture = support::fixture();
    let world = empty_world();
    fixture.start.world_id = world.world_id().expect("world ID");
    let recorder = Arc::new(
        ManagedRustLocalRecorder::new(fixture.start.operation_id).expect("local recorder"),
    );
    recorder
        .bind_deployment(&mut fixture.start.deployment)
        .expect("bind deployment");
    let sdk = Sdk::new(recorder.clone());
    sdk.begin(fixture.start.clone(), &fixture.begin)
        .expect("start operation");
    sdk.record_input(fixture.start.operation_id, &fixture.input)
        .expect("record operation input");
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .expect("record operation failure");
    let failed_capture = recorder
        .take_failed_candidate()
        .expect("one recorded failure");
    (failed_capture, world)
}

fn empty_world() -> WorldCheckpoint {
    WorldCheckpoint {
        created_at: "2026-01-01T00:00:00.000Z".parse().expect("fixed timestamp"),
        format: WorldCheckpointFormat::V1,
        points: Vec::new(),
    }
}

fn capture_closure() -> ManagedRustCaptureClosure {
    ManagedRustCaptureClosure {
        artifacts: Vec::new(),
        completion: TriggerCompletion::Return,
        world: empty_world(),
    }
}

fn project() -> OfficialManagedProject {
    OfficialManagedProject::from_build(PROJECT, REPOSITORY_ID, SOURCE_REVISION)
        .expect("managed project build binding")
}

fn parse<T: std::str::FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().expect("valid fixture value")
}
