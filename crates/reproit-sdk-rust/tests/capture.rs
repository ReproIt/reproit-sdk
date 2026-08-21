use std::sync::{Arc, Mutex};

use reproit_core::model::{Candidate, Validate};
use reproit_sdk_rust::{CandidateSink, CandidateStart, MAX_ACTIVE_OPERATIONS, Sdk};

mod support;

#[derive(Default)]
struct Sink {
    candidates: Mutex<Vec<Candidate>>,
}

impl CandidateSink for Sink {
    fn queued_bytes(&self) -> usize {
        0
    }

    fn try_send(&self, candidate: Candidate) -> bool {
        self.candidates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(candidate);
        true
    }
}

#[test]
fn successful_operation_sends_nothing() {
    let fixture = support::fixture();
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    sdk.begin(fixture.start.clone(), &fixture.begin).unwrap();
    sdk.succeed(fixture.start.operation_id);
    assert_eq!(sdk.active_operations(), 0);
    assert!(sink.candidates.lock().unwrap().is_empty());
}

#[test]
fn failure_sends_one_complete_candidate() {
    let fixture = support::fixture();
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    sdk.begin(fixture.start.clone(), &fixture.begin).unwrap();
    sdk.record_input(fixture.start.operation_id, &fixture.input)
        .unwrap();
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .unwrap();

    let candidates = sink.candidates.lock().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].capture_id, fixture.start.capture_id);
    assert_eq!(candidates[0].operation_id, fixture.start.operation_id);
    assert_eq!(candidates[0].world_id, fixture.start.world_id);
    assert_eq!(candidates[0].deployment, fixture.start.deployment);
    assert_eq!(candidates[0].failure, fixture.failure.failure);
    candidates[0].validate().unwrap();
    assert_eq!(sdk.active_operations(), 0);
}

#[test]
fn repeated_failure_with_a_refreshed_world_is_suppressed() {
    let fixture = support::fixture();
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    sdk.begin(fixture.start.clone(), &fixture.begin).unwrap();
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .unwrap();

    let mut refreshed = fixture.start;
    refreshed.capture_id = "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3".parse().unwrap();
    refreshed.operation_id = "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4".parse().unwrap();
    refreshed.world_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        .parse()
        .unwrap();
    sdk.begin(refreshed.clone(), &fixture.begin).unwrap();
    sdk.fail(refreshed.operation_id, &fixture.failure).unwrap();

    assert_eq!(sink.candidates.lock().unwrap().len(), 1);
}

#[test]
fn one_thousand_exact_failures_use_one_candidate_token() {
    let fixture = support::fixture();
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    for index in 0..1_000_u64 {
        let start = CandidateStart {
            capture_id: format!("cap_01890f3e-7b1c-7cc0-8a1b-{index:012x}")
                .parse()
                .unwrap(),
            deployment: fixture.start.deployment.clone(),
            operation_id: format!("op_01890f3e-7b1c-7cc0-8a1b-{index:012x}")
                .parse()
                .unwrap(),
            world_id: fixture.start.world_id,
        };
        sdk.begin(start.clone(), &fixture.begin).unwrap();
        sdk.fail(start.operation_id, &fixture.failure).unwrap();
    }
    assert_eq!(sink.candidates.lock().unwrap().len(), 1);
}

#[test]
fn active_operation_count_is_bounded() {
    let fixture = support::fixture();
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    let mut operation_ids = Vec::with_capacity(MAX_ACTIVE_OPERATIONS);

    for index in 0..MAX_ACTIVE_OPERATIONS {
        let operation_id = format!("op_01890f3e-7b1c-7cc0-8a1b-{index:012x}")
            .parse()
            .unwrap();
        sdk.begin(
            CandidateStart {
                capture_id: fixture.start.capture_id,
                deployment: fixture.start.deployment.clone(),
                operation_id,
                world_id: fixture.start.world_id,
            },
            &fixture.begin,
        )
        .unwrap();
        operation_ids.push(operation_id);
    }

    let rejected_operation = "op_01890f3e-7b1c-7cc0-8a1b-000000000200".parse().unwrap();
    assert!(
        sdk.begin(
            CandidateStart {
                capture_id: fixture.start.capture_id,
                deployment: fixture.start.deployment,
                operation_id: rejected_operation,
                world_id: fixture.start.world_id,
            },
            &fixture.begin,
        )
        .is_err()
    );
    assert_eq!(sdk.active_operations(), MAX_ACTIVE_OPERATIONS);
    assert!(sink.candidates.lock().unwrap().is_empty());

    for operation_id in operation_ids {
        sdk.cancel(operation_id);
    }
    assert_eq!(sdk.active_operations(), 0);
}
