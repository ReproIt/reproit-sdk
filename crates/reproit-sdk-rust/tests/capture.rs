use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use reproit_core::model::{Candidate, Validate};
use reproit_sdk_rust::{
    AutomaticCandidateStart, CandidateSink, CandidateStart, MAX_ACTIVE_OPERATIONS, Sdk,
};

mod support;

static PROCESS_TEST: Mutex<()> = Mutex::new(());

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
    let _process = process_test();
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
    let _process = process_test();
    let fixture = fixture("orders.failure");
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
fn automatic_operation_requires_one_world_binding_before_failure() {
    let _process = process_test();
    let fixture = fixture("orders.automatic-world");
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    sdk.begin_automatic(
        AutomaticCandidateStart {
            capture_id: fixture.start.capture_id,
            deployment: fixture.start.deployment,
            operation_id: fixture.start.operation_id,
        },
        &fixture.begin,
    )
    .unwrap();

    assert!(
        sdk.fail(fixture.start.operation_id, &fixture.failure)
            .is_err()
    );
    sdk.bind_automatic_world(fixture.start.operation_id, fixture.start.world_id)
        .unwrap();
    assert!(
        sdk.bind_automatic_world(fixture.start.operation_id, fixture.start.world_id)
            .is_err()
    );
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .unwrap();

    let candidates = sink.candidates.lock().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].world_id, fixture.start.world_id);
}

#[test]
fn repeated_failure_with_a_refreshed_world_is_suppressed() {
    let _process = process_test();
    let fixture = fixture("orders.repeated");
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
    let _process = process_test();
    let fixture = fixture("orders.storm");
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
    let _process = process_test();
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

#[test]
fn active_operation_count_is_process_wide_across_sdk_instances() {
    let _process = process_test();
    let fixture = support::fixture();
    let sink = Arc::new(Sink::default());
    let sdks = (0..=MAX_ACTIVE_OPERATIONS)
        .map(|_| Sdk::new(sink.clone()))
        .collect::<Vec<_>>();
    let mut operation_ids = Vec::new();
    for (index, sdk) in sdks.iter().take(MAX_ACTIVE_OPERATIONS).enumerate() {
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
    let rejected = "op_01890f3e-7b1c-7cc0-8a1b-000000000200".parse().unwrap();
    assert!(
        sdks[MAX_ACTIVE_OPERATIONS]
            .begin(
                CandidateStart {
                    capture_id: fixture.start.capture_id,
                    deployment: fixture.start.deployment,
                    operation_id: rejected,
                    world_id: fixture.start.world_id,
                },
                &fixture.begin,
            )
            .is_err()
    );
    for (sdk, operation_id) in sdks.iter().zip(operation_ids) {
        sdk.cancel(operation_id);
    }
}

fn fixture(operation_name: &str) -> support::SdkFixture {
    let mut fixture = support::fixture();
    operation_name.clone_into(&mut fixture.begin.operation_name);
    let reproit_core::model::FailureIdentity::Exception(identity) = &mut fixture.failure.identity
    else {
        panic!("the fixture must contain an exception identity");
    };
    operation_name.clone_into(&mut identity.operation_name);
    let grouping = fixture.failure.identity.grouping().unwrap();
    fixture.failure.failure.category = grouping.category;
    fixture.failure.failure.identity = grouping.identity_digest;
    fixture.failure.failure.matcher = grouping.matcher;
    fixture
}

fn process_test() -> MutexGuard<'static, ()> {
    PROCESS_TEST.lock().unwrap_or_else(PoisonError::into_inner)
}
