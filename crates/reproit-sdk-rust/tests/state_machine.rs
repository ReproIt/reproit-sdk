use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use proptest::prelude::*;
use reproit_core::model::{Candidate, FailureIdentity};
use reproit_sdk_rust::{CandidateSink, CandidateStart, Sdk};

mod support;

#[derive(Clone, Copy, Debug)]
enum Action {
    Begin,
    Input,
    Succeed,
    Cancel,
    Fail,
}

#[derive(Default)]
struct Sink {
    candidates: Mutex<Vec<Candidate>>,
}

impl CandidateSink for Sink {
    fn queued_bytes(&self) -> usize {
        0
    }

    fn try_send(&self, candidate: Candidate) -> bool {
        self.candidates.lock().unwrap().push(candidate);
        true
    }
}

proptest! {
    #[test]
    fn sdk_transitions_match_the_bounded_operation_model(
        actions in prop::collection::vec(action(), 0..64)
    ) {
        let mut fixture = support::fixture();
        make_failure_unique(&mut fixture.failure);
        let sink = Arc::new(Sink::default());
        let sdk = Sdk::new(sink.clone());
        let start = CandidateStart {
            capture_id: fixture.start.capture_id,
            deployment: fixture.start.deployment,
            operation_id: fixture.start.operation_id,
            world_id: fixture.start.world_id,
        };
        let mut active = false;

        for action in actions {
            match action {
                Action::Begin => {
                    prop_assert_eq!(sdk.begin(start.clone(), &fixture.begin).is_ok(), !active);
                    active = true;
                }
                Action::Input => {
                    prop_assert_eq!(
                        sdk.record_input(start.operation_id, &fixture.input).is_ok(), active
                    );
                }
                Action::Succeed => {
                    sdk.succeed(start.operation_id);
                    active = false;
                }
                Action::Cancel => {
                    sdk.cancel(start.operation_id);
                    active = false;
                }
                Action::Fail => {
                    let candidates_before = sink.candidates.lock().unwrap().len();
                    prop_assert_eq!(sdk.fail(start.operation_id, &fixture.failure).is_ok(), active);
                    let candidates_after = sink.candidates.lock().unwrap().len();
                    prop_assert!(candidates_after == candidates_before
                        || (active && candidates_after == candidates_before + 1));
                    active = false;
                }
            }
            prop_assert_eq!(sdk.active_operations(), usize::from(active));
        }
    }
}

fn make_failure_unique(failure: &mut reproit_core::model::FailurePayload) {
    static CASE_ID: AtomicU64 = AtomicU64::new(0);

    let case_id = CASE_ID.fetch_add(1, Ordering::Relaxed);
    match &mut failure.identity {
        FailureIdentity::Exception(identity) => {
            identity.stable_code = Some(format!("state-machine-{case_id}"));
        }
        FailureIdentity::Contract(_) => panic!("the fixture uses an exception failure"),
    }
    let grouping = failure
        .identity
        .grouping()
        .expect("the generated failure identity is valid");
    failure.failure.category = grouping.category;
    failure.failure.identity = grouping.identity_digest;
    failure.failure.matcher = grouping.matcher;
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Begin),
        Just(Action::Input),
        Just(Action::Succeed),
        Just(Action::Cancel),
        Just(Action::Fail),
    ]
}
