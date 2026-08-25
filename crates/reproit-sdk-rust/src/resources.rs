use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock, PoisonError},
    time::Instant,
};

use reproit_core::identity::{CaptureId, Digest, OperationId};

use crate::{
    FAILURE_SUPPRESSION_MS, FAILURE_TOKENS_MILLI_CAPACITY, MAX_ACTIVE_OPERATIONS,
    MAX_FAILURE_STORM_IDENTITIES, MAX_GLOBAL_BYTES, MAX_PROCESS_CAPTURE_BYTES,
    MAX_QUEUED_CANDIDATES,
};

static PROCESS_RESOURCES: OnceLock<Mutex<ProcessResources>> = OnceLock::new();

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StormDecision {
    Admitted,
    SuppressedExact,
    SuppressedHighCardinality,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CandidateState {
    Handoff,
    Retained,
}

struct CandidateEntry {
    bytes: usize,
    state: CandidateState,
}

struct ProcessResources {
    active: BTreeMap<OperationId, usize>,
    active_bytes: usize,
    candidates: BTreeMap<CaptureId, CandidateEntry>,
    candidate_bytes: usize,
    capture_bytes: u64,
    storm: FailureStormGate,
}

impl ProcessResources {
    fn new() -> Self {
        Self {
            active: BTreeMap::new(),
            active_bytes: 0,
            candidates: BTreeMap::new(),
            candidate_bytes: 0,
            capture_bytes: 0,
            storm: FailureStormGate::new(),
        }
    }

    fn bytes_with(&self, added_bytes: usize) -> Option<usize> {
        self.active_bytes
            .checked_add(self.candidate_bytes)?
            .checked_add(added_bytes)
    }

    fn reserve_capture_bytes(&mut self, reserved_bytes: &mut u64, bytes: u64) -> bool {
        let Some(next) = self.capture_bytes.checked_add(bytes) else {
            return false;
        };
        if next > MAX_PROCESS_CAPTURE_BYTES {
            return false;
        }
        self.capture_bytes = next;
        *reserved_bytes += bytes;
        true
    }

    fn reserve_candidate_handoff(&mut self, capture_id: CaptureId, bytes: usize) -> bool {
        if self.candidates.contains_key(&capture_id)
            || self.candidates.len() >= MAX_QUEUED_CANDIDATES
            || self
                .bytes_with(bytes)
                .is_none_or(|total| total > MAX_GLOBAL_BYTES)
        {
            return false;
        }
        self.candidate_bytes += bytes;
        self.candidates.insert(
            capture_id,
            CandidateEntry {
                bytes,
                state: CandidateState::Handoff,
            },
        );
        true
    }

    fn release_candidate(&mut self, capture_id: CaptureId) {
        if let Some(entry) = self.candidates.remove(&capture_id) {
            self.candidate_bytes = self.candidate_bytes.saturating_sub(entry.bytes);
        }
    }
}

pub(crate) struct LogicalByteReservation {
    bytes: u64,
}

impl LogicalByteReservation {
    pub(crate) const fn new() -> Self {
        Self { bytes: 0 }
    }

    pub(crate) fn reserve(&mut self, bytes: u64) -> bool {
        let mut resources = lock_resources();
        resources.reserve_capture_bytes(&mut self.bytes, bytes)
    }

    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn release(&mut self, bytes: u64) {
        let released = bytes.min(self.bytes);
        self.bytes -= released;
        let mut resources = lock_resources();
        resources.capture_bytes = resources.capture_bytes.saturating_sub(released);
    }
}

impl Drop for LogicalByteReservation {
    fn drop(&mut self) {
        let mut resources = lock_resources();
        resources.capture_bytes = resources.capture_bytes.saturating_sub(self.bytes);
    }
}

pub(crate) fn reserve_operation(operation_id: OperationId, bytes: usize) -> bool {
    let mut resources = lock_resources();
    if resources.active.contains_key(&operation_id)
        || resources.active.len() >= MAX_ACTIVE_OPERATIONS
        || resources
            .bytes_with(bytes)
            .is_none_or(|total| total > MAX_GLOBAL_BYTES)
    {
        return false;
    }
    resources.active_bytes += bytes;
    resources.active.insert(operation_id, bytes);
    true
}

pub(crate) fn grow_operation(operation_id: OperationId, added_bytes: usize) -> bool {
    let mut resources = lock_resources();
    if resources
        .bytes_with(added_bytes)
        .is_none_or(|total| total > MAX_GLOBAL_BYTES)
    {
        return false;
    }
    let Some(bytes) = resources.active.get_mut(&operation_id) else {
        return false;
    };
    *bytes = bytes.saturating_add(added_bytes);
    resources.active_bytes += added_bytes;
    true
}

pub(crate) fn release_operation(operation_id: OperationId) {
    let mut resources = lock_resources();
    if let Some(bytes) = resources.active.remove(&operation_id) {
        resources.active_bytes = resources.active_bytes.saturating_sub(bytes);
    }
}

pub(crate) fn reserve_candidate_handoff(capture_id: CaptureId, bytes: usize) -> bool {
    lock_resources().reserve_candidate_handoff(capture_id, bytes)
}

pub(crate) fn claim_candidate(capture_id: CaptureId, bytes: usize) -> bool {
    let mut resources = lock_resources();
    if let Some(entry) = resources.candidates.get_mut(&capture_id) {
        if entry.bytes != bytes || entry.state != CandidateState::Handoff {
            return false;
        }
        entry.state = CandidateState::Retained;
        return true;
    }
    if resources.candidates.len() >= MAX_QUEUED_CANDIDATES
        || resources
            .bytes_with(bytes)
            .is_none_or(|total| total > MAX_GLOBAL_BYTES)
    {
        return false;
    }
    resources.candidate_bytes += bytes;
    resources.candidates.insert(
        capture_id,
        CandidateEntry {
            bytes,
            state: CandidateState::Retained,
        },
    );
    true
}

pub(crate) fn candidate_is_retained(capture_id: CaptureId) -> bool {
    lock_resources()
        .candidates
        .get(&capture_id)
        .is_some_and(|entry| entry.state == CandidateState::Retained)
}

pub(crate) fn release_candidate(capture_id: CaptureId) {
    lock_resources().release_candidate(capture_id);
}

pub(crate) fn admit_storm(identity: Digest) -> StormDecision {
    lock_resources().storm.admit(identity)
}

fn lock_resources() -> std::sync::MutexGuard<'static, ProcessResources> {
    PROCESS_RESOURCES
        .get_or_init(|| Mutex::new(ProcessResources::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

struct FailureStormGate {
    admitted: BTreeMap<Digest, FailureStormEntry>,
    last_refill_ms: u64,
    started: Instant,
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

#[cfg(test)]
pub(super) fn high_cardinality_admission_count_for_test() -> usize {
    let mut gate = FailureStormGate::new();
    (0_u64..257)
        .filter(|index| {
            gate.last_refill_ms = u64::MAX;
            gate.admit(Digest::of(&index.to_be_bytes())) == StormDecision::Admitted
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_queue_and_logical_bytes_are_process_wide() {
        let mut resources = ProcessResources::new();
        let captures = (0..MAX_QUEUED_CANDIDATES)
            .map(|index| {
                format!("cap_01890f3e-7b1c-7cc0-8a1b-{index:012x}")
                    .parse()
                    .unwrap()
            })
            .collect::<Vec<CaptureId>>();
        for capture_id in &captures {
            assert!(resources.reserve_candidate_handoff(*capture_id, 1));
        }
        let extra = "cap_01890f3e-7b1c-7cc0-8a1b-000000000100".parse().unwrap();
        assert!(!resources.reserve_candidate_handoff(extra, 1));
        for capture_id in captures {
            resources.release_candidate(capture_id);
        }

        let mut reserved_bytes = 0;
        assert!(resources.reserve_capture_bytes(&mut reserved_bytes, MAX_PROCESS_CAPTURE_BYTES));
        let mut extra_bytes = 0;
        assert!(!resources.reserve_capture_bytes(&mut extra_bytes, 1));
        resources.capture_bytes -= reserved_bytes;
        assert!(resources.reserve_capture_bytes(&mut extra_bytes, 1));
    }
}
