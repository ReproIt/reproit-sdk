use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use reproit_core::model::Candidate;
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
        let fixture = support::fixture();
        let sink = Arc::new(Sink::default());
        let sdk = Sdk::new(sink.clone());
        let start = CandidateStart {
            capture_id: fixture.start.capture_id,
            deployment: fixture.start.deployment,
            operation_id: fixture.start.operation_id,
            world_id: fixture.start.world_id,
        };
        let mut active = false;
        let mut failure_admitted = false;
        let mut sent = 0_usize;

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
                    prop_assert_eq!(sdk.fail(start.operation_id, &fixture.failure).is_ok(), active);
                    if active && !failure_admitted {
                        sent += 1;
                        failure_admitted = true;
                    }
                    active = false;
                }
            }
            prop_assert_eq!(sdk.active_operations(), usize::from(active));
            prop_assert_eq!(sink.candidates.lock().unwrap().len(), sent);
        }
    }
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
