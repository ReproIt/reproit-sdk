use std::sync::Arc;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use reproit_core::model::Candidate;
use reproit_sdk_rust::{CandidateSink, Sdk};

#[path = "../tests/support/mod.rs"]
mod support;

#[derive(Default)]
struct AcceptingSink;

impl CandidateSink for AcceptingSink {
    fn queued_bytes(&self) -> usize {
        0
    }

    fn try_send(&self, _candidate: Candidate) -> bool {
        true
    }
}

fn capture_latency(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("sdk_capture");
    group.throughput(Throughput::Elements(1));
    group.bench_function("successful_operation", |bencher| {
        bencher.iter_batched(
            || (Sdk::new(Arc::new(AcceptingSink)), support::fixture()),
            |(sdk, fixture)| {
                sdk.begin(fixture.start.clone(), &fixture.begin)
                    .expect("begin operation");
                sdk.record_input(fixture.start.operation_id, &fixture.input)
                    .expect("record input");
                sdk.succeed(fixture.start.operation_id);
                assert_eq!(sdk.active_operations(), 0);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("failed_operation", |bencher| {
        bencher.iter_batched(
            || (Sdk::new(Arc::new(AcceptingSink)), support::fixture()),
            |(sdk, fixture)| {
                sdk.begin(fixture.start.clone(), &fixture.begin)
                    .expect("begin operation");
                sdk.record_input(fixture.start.operation_id, &fixture.input)
                    .expect("record input");
                sdk.fail(fixture.start.operation_id, &fixture.failure)
                    .expect("capture failure");
                assert_eq!(sdk.active_operations(), 0);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, capture_latency);
criterion_main!(benches);
