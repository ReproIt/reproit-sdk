use std::sync::{Arc, Mutex, PoisonError};

use reproit_core::{
    canonical,
    crypto::{decode_base64url_bytes, encode_base64url},
    identity::Digest,
    model::{
        Candidate, EventKind, FailureIdentity, InputChannel, OperationBeginPayload,
        OperationInputPayload, OperationKind,
    },
};
use reproit_sdk_rust::{CandidateSink, Sdk};

mod support;

#[derive(Default)]
struct Sink(Mutex<Vec<Candidate>>);

impl CandidateSink for Sink {
    fn queued_bytes(&self) -> usize {
        0
    }

    fn try_send(&self, candidate: Candidate) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(candidate);
        true
    }
}

#[test]
fn request_response_uses_the_canonical_candidate_bytes() {
    let fixture = support::fixture();
    let expected = capture_failure(&fixture, None);
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    sdk.begin(fixture.start.clone(), &fixture.begin).unwrap();
    sdk.record_input(fixture.start.operation_id, &fixture.input)
        .unwrap();
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .unwrap();

    let candidates = sink.0.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        canonical::canonical_bytes(&candidates[0]).unwrap(),
        canonical::canonical_bytes(&expected).unwrap()
    );
}

#[test]
fn stream_preserves_ordered_input_frames() {
    let mut fixture = support::fixture();
    set_operation_kind(
        &mut fixture.begin,
        &mut fixture.failure.identity,
        OperationKind::Stream,
    );
    refresh_failure_reference(&mut fixture.failure);
    let second_bytes = br#"{"amount":11}"#;
    let mut second = fixture.input.clone();
    second.input_index = 1;
    second.value = encode_base64url(second_bytes);
    second.value_digest = Digest::of(second_bytes);

    let candidate = capture_failure(&fixture, Some(&second));
    assert_eq!(candidate.records.len(), 5);
    assert_eq!(candidate.records[0].kind, EventKind::Begin);
    assert_eq!(candidate.records[1].kind, EventKind::Input);
    assert_eq!(candidate.records[2].kind, EventKind::Input);
    assert_eq!(candidate.records[3].kind, EventKind::Failure);
    assert_eq!(candidate.records[4].kind, EventKind::Terminal);
    let first: OperationInputPayload = decode(&candidate, 1);
    let second: OperationInputPayload = decode(&candidate, 2);
    assert_eq!(first.channel, InputChannel::Input);
    assert_eq!(first.input_index, 0);
    assert_eq!(second.input_index, 1);
    assert_eq!(
        decode_base64url_bytes(&second.value).unwrap(),
        br#"{"amount":11}"#
    );
}

#[test]
fn delivered_work_emits_only_one_failed_candidate() {
    let mut fixture = support::fixture();
    set_operation_kind(
        &mut fixture.begin,
        &mut fixture.failure.identity,
        OperationKind::DeliveredWork,
    );
    refresh_failure_reference(&mut fixture.failure);

    let candidate = capture_failure(&fixture, None);
    let begin: OperationBeginPayload = decode(&candidate, 0);
    assert_eq!(begin.operation_kind, OperationKind::DeliveredWork);
    assert_eq!(candidate.records.last().unwrap().kind, EventKind::Terminal);
}

fn capture_failure(
    fixture: &support::SdkFixture,
    second_input: Option<&OperationInputPayload>,
) -> Candidate {
    let sink = Arc::new(Sink::default());
    let sdk = Sdk::new(sink.clone());
    sdk.begin(fixture.start.clone(), &fixture.begin).unwrap();
    sdk.record_input(fixture.start.operation_id, &fixture.input)
        .unwrap();
    if let Some(input) = second_input {
        sdk.record_input(fixture.start.operation_id, input).unwrap();
    }
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .unwrap();
    assert_eq!(sdk.active_operations(), 0);
    drop(sdk);
    Arc::try_unwrap(sink)
        .ok()
        .expect("the SDK releases its sink")
        .0
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .pop()
        .expect("one failed candidate")
}

fn set_operation_kind(
    begin: &mut OperationBeginPayload,
    identity: &mut FailureIdentity,
    operation_kind: OperationKind,
) {
    begin.operation_kind = operation_kind;
    let FailureIdentity::Exception(identity) = identity else {
        panic!("the Rust SDK fixture must use an exception identity");
    };
    identity.operation_kind = operation_kind;
}

fn refresh_failure_reference(failure: &mut reproit_core::model::FailurePayload) {
    let grouping = failure.identity.grouping().unwrap();
    failure.failure.category = grouping.category;
    failure.failure.identity = grouping.identity_digest;
    failure.failure.matcher = grouping.matcher;
}

fn decode<T: serde::de::DeserializeOwned>(candidate: &Candidate, index: usize) -> T {
    let bytes = decode_base64url_bytes(&candidate.records[index].payload).unwrap();
    canonical::parse_strict(&bytes).unwrap()
}
