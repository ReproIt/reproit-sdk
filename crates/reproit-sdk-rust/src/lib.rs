#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use reproit_core::{
    ErrorCode, canonical,
    crypto::encode_base64url,
    identity::{CaptureId, Digest, OperationId},
    model::{
        Candidate, CandidateFormat, Deployment, EventKind, EventRecord, TerminalFormat,
        TerminalPayload, Validate,
    },
};

pub use reproit_core::{
    Error,
    model::{
        DependencyCursorFormat, DependencyCursorPayload, FailurePayload, FailurePayloadFormat,
        InputChannel, OperationBeginFormat, OperationBeginPayload, OperationInputFormat,
        OperationInputPayload, OperationKind, TriggerCompletion, WorldCheckpoint,
        WorldCheckpointFormat,
    },
};

mod managed;
mod managed_deployment;
mod managed_identity;
mod managed_sink;
mod managed_transport;
mod official_managed;
mod official_operation;
mod processor_capture;
mod subject;

pub use managed::{
    ManagedCandidateArtifact, ManagedCandidateGrantDelivery, ManagedCandidateIngressDelivery,
    ManagedRustCaptureClosure, ManagedRustCaptureClosureProvider, ManagedRustOperationClosure,
    PreparedManagedRustCandidate, SealedManagedRustCandidate,
};
pub use managed_deployment::OfficialManagedProject;
pub use managed_identity::{
    MAX_MANAGED_DEPLOYMENT_METADATA_BYTES, MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
    ManagedWorkloadIdentityState, ManagedWorkloadRegistrationReceipt,
    load_or_create_managed_workload_key,
};
pub use managed_sink::{
    ManagedRustCandidateSink, ManagedRustLocalRecorder, ManagedRustRecordedFailure,
    ManagedRustSinkConfiguration,
};
pub use managed_transport::{ManagedProjectToken, ManagedTlsClient, ManagedTlsEndpoint};
pub use official_operation::OfficialManagedRustOperation;
pub use processor_capture::capture_processor_capabilities;
pub use subject::{PackagedSubjectObject, RustSubjectPackage, package_running_rust_subject};

pub const MAX_GLOBAL_BYTES: usize = 1_048_576;
pub const MAX_OPERATION_BYTES: usize = 262_144;
pub const MAX_EVENT_BYTES: usize = 65_536;
pub const MAX_EVENTS: usize = 1_024;
pub const MAX_ACTIVE_OPERATIONS: usize = 512;
pub const MAX_QUEUED_CANDIDATES: usize = 16;
pub const MAX_FAILURE_STORM_IDENTITIES: usize = 256;
const FAILURE_SUPPRESSION_MS: u64 = 60_000;
const FAILURE_TOKENS_MILLI_CAPACITY: u64 = 4_000;

pub trait CandidateSink: Send + Sync {
    fn queued_bytes(&self) -> usize;
    fn recall_counters(&self) -> SdkRecallCounters {
        SdkRecallCounters::default()
    }
    fn try_send(&self, candidate: Candidate) -> bool;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SdkRecallCounters {
    pub candidate_delivery_expired: u64,
    pub candidate_durably_accepted: u64,
    pub candidate_incomplete: u64,
    pub candidate_queue_full: u64,
    pub candidate_rejected: u64,
    pub eligible_failure_observed: u64,
    pub suppressed_exact_storm: u64,
    pub suppressed_high_cardinality_storm: u64,
}

impl SdkRecallCounters {
    fn merge(&mut self, other: &Self) {
        self.candidate_delivery_expired = self
            .candidate_delivery_expired
            .saturating_add(other.candidate_delivery_expired);
        self.candidate_durably_accepted = self
            .candidate_durably_accepted
            .saturating_add(other.candidate_durably_accepted);
        self.candidate_incomplete = self
            .candidate_incomplete
            .saturating_add(other.candidate_incomplete);
        self.candidate_queue_full = self
            .candidate_queue_full
            .saturating_add(other.candidate_queue_full);
        self.candidate_rejected = self
            .candidate_rejected
            .saturating_add(other.candidate_rejected);
        self.eligible_failure_observed = self
            .eligible_failure_observed
            .saturating_add(other.eligible_failure_observed);
        self.suppressed_exact_storm = self
            .suppressed_exact_storm
            .saturating_add(other.suppressed_exact_storm);
        self.suppressed_high_cardinality_storm = self
            .suppressed_high_cardinality_storm
            .saturating_add(other.suppressed_high_cardinality_storm);
    }
}

#[derive(Debug, Clone)]
pub struct CandidateStart {
    pub capture_id: CaptureId,
    pub deployment: Deployment,
    pub operation_id: OperationId,
    pub world_id: Digest,
}

#[derive(Clone)]
pub struct Sdk {
    state: Arc<Mutex<State>>,
    sink: Arc<dyn CandidateSink>,
}

impl Sdk {
    pub fn new(sink: Arc<dyn CandidateSink>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::new())),
            sink,
        }
    }

    pub fn begin(
        &self,
        start: CandidateStart,
        payload: &OperationBeginPayload,
    ) -> Result<(), Error> {
        let record = event_record(EventKind::Begin, 0, payload)?;
        let record_bytes = record_size(&record);
        let mut state = self.lock_state();
        if state.operations.contains_key(&start.operation_id) {
            return Err(Error::schema_invalid());
        }
        if state.operations.len() >= MAX_ACTIVE_OPERATIONS
            || state
                .global_bytes
                .saturating_add(self.sink.queued_bytes())
                .saturating_add(record_bytes)
                > MAX_GLOBAL_BYTES
        {
            return Err(runtime_quota());
        }
        state.global_bytes += record_bytes;
        state.operations.insert(
            start.operation_id,
            ActiveOperation {
                bytes: record_bytes,
                records: vec![record],
                start,
            },
        );
        Ok(())
    }

    pub fn record_input(
        &self,
        operation_id: OperationId,
        payload: &OperationInputPayload,
    ) -> Result<(), Error> {
        self.append(operation_id, EventKind::Input, payload)
    }

    pub fn record_dependency(
        &self,
        operation_id: OperationId,
        payload: &DependencyCursorPayload,
    ) -> Result<(), Error> {
        self.append(operation_id, EventKind::Dependency, payload)
    }

    pub fn succeed(&self, operation_id: OperationId) {
        let mut state = self.lock_state();
        state.delete(operation_id);
    }

    pub fn cancel(&self, operation_id: OperationId) {
        let mut state = self.lock_state();
        state.delete(operation_id);
    }

    pub fn abandon_incomplete(&self, operation_id: OperationId) {
        let mut state = self.lock_state();
        if state.operations.contains_key(&operation_id) {
            state.delete(operation_id);
            state.recall.candidate_incomplete = state.recall.candidate_incomplete.saturating_add(1);
        }
    }

    pub fn fail(&self, operation_id: OperationId, payload: &FailurePayload) -> Result<(), Error> {
        {
            let mut state = self.lock_state();
            state.recall.eligible_failure_observed =
                state.recall.eligible_failure_observed.saturating_add(1);
        }
        let failure_record = {
            let state = self.lock_state();
            let operation = state
                .operations
                .get(&operation_id)
                .ok_or_else(incomplete_candidate)?;
            event_record(
                EventKind::Failure,
                u16::try_from(operation.records.len()).map_err(|_| runtime_quota())?,
                payload,
            )?
        };

        {
            let mut state = self.lock_state();
            let Some(mut operation) = state.operations.remove(&operation_id) else {
                return Err(incomplete_candidate());
            };
            state.global_bytes = state.global_bytes.saturating_sub(operation.bytes);
            let added_bytes = record_size(&failure_record);
            if !within_operation_bounds(&operation, added_bytes) {
                return Err(runtime_quota());
            }
            operation.records.push(failure_record);
            let terminal = TerminalPayload {
                complete: true,
                event_count: u16::try_from(operation.records.len()).map_err(|_| runtime_quota())?,
                format: TerminalFormat::V1,
            };
            let terminal_record =
                event_record(EventKind::Terminal, terminal.event_count, &terminal)?;
            if operation
                .bytes
                .saturating_add(added_bytes)
                .saturating_add(record_size(&terminal_record))
                > MAX_OPERATION_BYTES
            {
                return Err(runtime_quota());
            }
            operation.records.push(terminal_record);
            let processing_mode = operation.start.deployment.processing_mode;
            let candidate = Candidate {
                capture_id: operation.start.capture_id,
                deployment: operation.start.deployment,
                failure: payload.failure.clone(),
                format: CandidateFormat::V1,
                operation_id,
                processing_mode,
                records: operation.records,
                world_id: operation.start.world_id,
            };
            candidate.validate()?;
            match state
                .storm
                .admit(candidate.failure_storm_identity()?.key()?)
            {
                StormDecision::Admitted => {}
                StormDecision::SuppressedExact => {
                    state.recall.suppressed_exact_storm =
                        state.recall.suppressed_exact_storm.saturating_add(1);
                    return Ok(());
                }
                StormDecision::SuppressedHighCardinality => {
                    state.recall.suppressed_high_cardinality_storm = state
                        .recall
                        .suppressed_high_cardinality_storm
                        .saturating_add(1);
                    return Ok(());
                }
            }
            let candidate_bytes = canonical::canonical_bytes(&candidate)?;
            if candidate_bytes.len() > MAX_OPERATION_BYTES
                || state
                    .global_bytes
                    .saturating_add(self.sink.queued_bytes())
                    .saturating_add(candidate_bytes.len())
                    > MAX_GLOBAL_BYTES
            {
                state.recall.candidate_queue_full =
                    state.recall.candidate_queue_full.saturating_add(1);
                return Err(runtime_quota());
            }
            if !self.sink.try_send(candidate) {
                return Err(runtime_quota());
            }
        }
        Ok(())
    }

    pub fn active_operations(&self) -> usize {
        self.lock_state().operations.len()
    }

    pub fn recall_counters(&self) -> SdkRecallCounters {
        let mut counters = self.lock_state().recall.clone();
        counters.merge(&self.sink.recall_counters());
        counters
    }

    fn append<T: serde::Serialize>(
        &self,
        operation_id: OperationId,
        kind: EventKind,
        payload: &T,
    ) -> Result<(), Error> {
        let mut state = self.lock_state();
        let operation = state
            .operations
            .get(&operation_id)
            .ok_or_else(incomplete_candidate)?;
        let record = event_record(
            kind,
            u16::try_from(operation.records.len()).map_err(|_| runtime_quota())?,
            payload,
        )?;
        let added_bytes = record_size(&record);
        if !within_operation_bounds(operation, added_bytes)
            || state
                .global_bytes
                .saturating_add(self.sink.queued_bytes())
                .saturating_add(added_bytes)
                > MAX_GLOBAL_BYTES
        {
            state.delete(operation_id);
            return Err(runtime_quota());
        }
        let operation = state
            .operations
            .get_mut(&operation_id)
            .expect("the active operation must still exist");
        operation.bytes += added_bytes;
        operation.records.push(record);
        state.global_bytes += added_bytes;
        Ok(())
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct State {
    global_bytes: usize,
    operations: BTreeMap<OperationId, ActiveOperation>,
    recall: SdkRecallCounters,
    storm: FailureStormGate,
}

impl State {
    fn new() -> Self {
        Self {
            global_bytes: 0,
            operations: BTreeMap::new(),
            recall: SdkRecallCounters::default(),
            storm: FailureStormGate::new(),
        }
    }

    fn delete(&mut self, operation_id: OperationId) {
        if let Some(operation) = self.operations.remove(&operation_id) {
            self.global_bytes = self.global_bytes.saturating_sub(operation.bytes);
        }
    }
}

struct FailureStormGate {
    admitted: BTreeMap<Digest, FailureStormEntry>,
    last_refill_ms: u64,
    started: Instant,
    token_rejections: u64,
    tokens_milli: u64,
}

struct FailureStormEntry {
    admitted_at_ms: u64,
    observed_at_ms: u64,
    suppressed: u64,
}

impl FailureStormGate {
    fn new() -> Self {
        Self {
            admitted: BTreeMap::new(),
            last_refill_ms: 0,
            started: Instant::now(),
            token_rejections: 0,
            tokens_milli: FAILURE_TOKENS_MILLI_CAPACITY,
        }
    }

    fn admit(&mut self, identity: Digest) -> StormDecision {
        let now_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.refill(now_ms);
        self.admitted.retain(|_, entry| {
            now_ms.saturating_sub(entry.admitted_at_ms) < FAILURE_SUPPRESSION_MS
        });
        if let Some(entry) = self.admitted.get_mut(&identity) {
            entry.observed_at_ms = now_ms;
            entry.suppressed = entry.suppressed.saturating_add(1);
            return StormDecision::SuppressedExact;
        }
        if self.tokens_milli < 1_000 {
            self.token_rejections = self.token_rejections.saturating_add(1);
            return StormDecision::SuppressedHighCardinality;
        }
        if self.admitted.len() >= MAX_FAILURE_STORM_IDENTITIES {
            let oldest = self
                .admitted
                .iter()
                .min_by_key(|(digest, entry)| (entry.observed_at_ms, **digest))
                .map(|(digest, _)| *digest);
            if let Some(oldest) = oldest {
                self.admitted.remove(&oldest);
            }
        }
        self.tokens_milli -= 1_000;
        self.admitted.insert(
            identity,
            FailureStormEntry {
                admitted_at_ms: now_ms,
                observed_at_ms: now_ms,
                suppressed: 0,
            },
        );
        StormDecision::Admitted
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        self.tokens_milli = self
            .tokens_milli
            .saturating_add(elapsed_ms.saturating_mul(2))
            .min(FAILURE_TOKENS_MILLI_CAPACITY);
        self.last_refill_ms = now_ms;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StormDecision {
    Admitted,
    SuppressedExact,
    SuppressedHighCardinality,
}

struct ActiveOperation {
    bytes: usize,
    records: Vec<EventRecord>,
    start: CandidateStart,
}

fn event_record<T: serde::Serialize>(
    kind: EventKind,
    sequence: u16,
    payload: &T,
) -> Result<EventRecord, Error> {
    let bytes = canonical::canonical_bytes(payload)?;
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(runtime_quota());
    }
    Ok(EventRecord {
        kind,
        payload: encode_base64url(&bytes),
        sequence,
    })
}

fn record_size(record: &EventRecord) -> usize {
    record.payload.len().saturating_add(32)
}

fn within_operation_bounds(operation: &ActiveOperation, added_bytes: usize) -> bool {
    operation.records.len() < MAX_EVENTS
        && operation.bytes.saturating_add(added_bytes) <= MAX_OPERATION_BYTES
}

fn runtime_quota() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The SDK capture limit was reached.",
    )
}

fn incomplete_candidate() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The operation does not have complete capture state.",
    )
}

#[cfg(test)]
mod storm_tests {
    use super::*;

    #[test]
    fn high_cardinality_churn_cannot_bypass_candidate_tokens() {
        let mut gate = FailureStormGate::new();
        let admitted = (0_u64..257)
            .filter(|index| {
                gate.last_refill_ms = u64::MAX;
                gate.admit(Digest::of(&index.to_be_bytes())) == StormDecision::Admitted
            })
            .count();
        assert_eq!(admitted, 4);
        assert_eq!(gate.token_rejections, 253);
    }
}
