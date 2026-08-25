#![cfg(any())]

use std::{
    sync::{Arc, Condvar, Mutex, PoisonError},
    time::Duration,
};

use reproit_core::{
    canonical,
    crypto::{decode_base64url_bytes, encode_base64url},
    identity::Digest,
    model::{
        Candidate, EventKind, FailureIdentity, InputChannel, OperationBeginPayload,
        OperationInputPayload, OperationKind,
    },
};
use reproit_sdk_rust::{
    BoundedCandidateSink, CandidateDelivery, CandidateSink, DeliveryOutcome, Sdk,
};

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
    let delivery = Arc::new(RecordingDelivery::default());
    let sink = Arc::new(BoundedCandidateSink::new(delivery.clone()).unwrap());
    let sdk = Sdk::new(sink);
    sdk.begin(fixture.start.clone(), &fixture.begin).unwrap();
    sdk.record_input(fixture.start.operation_id, &fixture.input)
        .unwrap();
    sdk.fail(fixture.start.operation_id, &fixture.failure)
        .unwrap();

    assert_eq!(
        delivery.wait(),
        canonical::canonical_bytes(&expected).unwrap()
    );
}

#[derive(Default)]
struct RecordingDelivery {
    bytes: (Mutex<Option<Vec<u8>>>, Condvar),
}

impl RecordingDelivery {
    fn wait(&self) -> Vec<u8> {
        let (lock, ready) = &self.bytes;
        let bytes = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let (bytes, _) = ready
            .wait_timeout_while(bytes, Duration::from_secs(2), |bytes| bytes.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        bytes.clone().expect("the Runtime receives one candidate")
    }
}

impl CandidateDelivery for RecordingDelivery {
    fn deliver(
        &self,
        _capture_id: reproit_core::identity::CaptureId,
        bytes: &[u8],
        _timeout: Duration,
    ) -> DeliveryOutcome {
        let (lock, ready) = &self.bytes;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = Some(bytes.to_vec());
        ready.notify_all();
        DeliveryOutcome::Accepted
    }
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
