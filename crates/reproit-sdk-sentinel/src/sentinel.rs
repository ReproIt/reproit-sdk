//! Bounded Linux coverage sentinel for automatic World capture.
//!
//! The sentinel detects unowned kernel-visible effects. It never reads syscall
//! arguments or copies application payload bytes. A clean trace is one part of
//! World coverage. The engine can bind it only when all seven semantic adapter
//! classes are registered. Official package validation must prove that the
//! registered hooks are installed. Registration alone does not prove this.

use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock, PoisonError},
};

use reproit_core::model::AutomaticObservationClass;

const MAX_ACTIVE_OPERATIONS: usize = 512;
const MAX_ACTIVE_OBSERVATIONS: usize = 1_024;

static SENTINEL: OnceLock<Mutex<Controller>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCoverage {
    Incomplete,
    CleanKernelTrace(KernelTraceEvidence),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelTraceEvidence {
    start_sequence: u64,
    end_sequence: u64,
    relevant_events: u64,
    owned_events: u64,
}

impl KernelTraceEvidence {
    #[must_use]
    pub fn encode(self) -> [u8; 40] {
        const FORMAT: u64 = 1;

        let mut encoded = [0_u8; 40];
        for (index, value) in [
            FORMAT,
            self.start_sequence,
            self.end_sequence,
            self.relevant_events,
            self.owned_events,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = index * size_of::<u64>();
            encoded[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_be_bytes());
        }
        encoded
    }
}

#[derive(Clone, Copy)]
struct ActiveOperation {
    start_sequence: u64,
    relevant_events: u64,
    owned_events: u64,
    incomplete: bool,
}

#[derive(Clone, Copy)]
struct ActiveObservation {
    operation_handle: u64,
    class: AutomaticObservationClass,
    thread_id: i32,
    dispatched: bool,
}

struct Controller {
    active_observations: BTreeMap<u64, ActiveObservation>,
    active_operations: BTreeMap<u64, ActiveOperation>,
    engine_count: usize,
    runtime: Option<platform::Runtime>,
}

impl Controller {
    fn new() -> Self {
        Self {
            active_observations: BTreeMap::new(),
            active_operations: BTreeMap::new(),
            engine_count: 0,
            runtime: None,
        }
    }

    fn drain(&mut self) {
        if self.runtime.is_none() {
            self.mark_all_incomplete();
            return;
        }
        let mut events = [platform::Event::default(); 64];
        loop {
            let count = self
                .runtime
                .as_mut()
                .map_or(0, |runtime| runtime.drain(&mut events));
            for event in &events[..count] {
                self.apply_event(*event);
            }
            if count < events.len() {
                break;
            }
        }
        if !self
            .runtime
            .as_mut()
            .is_some_and(platform::Runtime::is_healthy)
        {
            self.mark_all_incomplete();
        }
    }

    fn apply_event(&mut self, event: platform::Event) {
        if event.kind == platform::EventKind::Exit {
            return;
        }
        let exact_owner = self
            .active_observations
            .values()
            .filter(|observation| {
                observation.dispatched
                    && observation.thread_id == event.thread_id
                    && event.kind.is_exactly_owned_by(observation.class)
            })
            .map(|observation| observation.operation_handle)
            .collect::<Vec<_>>();
        let owner = if exact_owner.is_empty() {
            self.active_observations
                .values()
                .filter(|observation| {
                    observation.dispatched
                        && observation.thread_id == event.thread_id
                        && event.kind.is_owned_by(observation.class)
                })
                .map(|observation| observation.operation_handle)
                .collect::<Vec<_>>()
        } else {
            exact_owner
        };
        if owner.len() == 1 {
            if let Some(operation) = self.active_operations.get_mut(&owner[0]) {
                operation.relevant_events = operation.relevant_events.saturating_add(1);
                operation.owned_events = operation.owned_events.saturating_add(1);
            }
            return;
        }
        for operation in self.active_operations.values_mut() {
            operation.relevant_events = operation.relevant_events.saturating_add(1);
            operation.incomplete = true;
        }
    }

    fn mark_all_incomplete(&mut self) {
        for operation in self.active_operations.values_mut() {
            operation.incomplete = true;
        }
    }

    fn operation_started(&mut self, operation_handle: u64) {
        self.drain();
        if self.active_operations.len() >= MAX_ACTIVE_OPERATIONS {
            self.mark_all_incomplete();
            return;
        }
        let (start_sequence, incomplete) = self.runtime.as_mut().map_or((0, true), |runtime| {
            (runtime.sequence(), !runtime.is_healthy())
        });
        self.active_operations.insert(
            operation_handle,
            ActiveOperation {
                start_sequence,
                relevant_events: 0,
                owned_events: 0,
                incomplete,
            },
        );
    }

    fn operation_finished(&mut self, operation_handle: u64) -> OperationCoverage {
        self.drain();
        self.active_observations
            .retain(|_, observation| observation.operation_handle != operation_handle);
        let Some(operation) = self.active_operations.remove(&operation_handle) else {
            return OperationCoverage::Incomplete;
        };
        let healthy = self
            .runtime
            .as_mut()
            .is_some_and(platform::Runtime::is_healthy);
        let end_sequence = self.runtime.as_ref().map_or(0, platform::Runtime::sequence);
        coverage_result(operation, healthy, end_sequence)
    }

    fn remove_operation(&mut self, operation_handle: u64) {
        self.drain();
        self.active_observations
            .retain(|_, observation| observation.operation_handle != operation_handle);
        self.active_operations.remove(&operation_handle);
    }
}

pub struct EngineCallGuard {
    ignore: Option<platform::IgnoreGuard>,
}

pub fn engine_call_scope() -> EngineCallGuard {
    let ignore = controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .runtime
        .as_ref()
        .and_then(platform::Runtime::ignore_current_thread);
    EngineCallGuard { ignore }
}

impl Drop for EngineCallGuard {
    fn drop(&mut self) {
        self.ignore.take();
    }
}

pub fn engine_opened() {
    let mut controller = controller().lock().unwrap_or_else(PoisonError::into_inner);
    controller.engine_count = controller.engine_count.saturating_add(1);
    if controller.runtime.is_none() {
        controller.runtime = platform::Runtime::install().ok();
    }
}

pub fn engine_closed() {
    let _runtime = {
        let mut controller = controller().lock().unwrap_or_else(PoisonError::into_inner);
        controller.engine_count = controller.engine_count.saturating_sub(1);
        if controller.engine_count == 0 {
            controller.mark_all_incomplete();
            controller.active_observations.clear();
            controller.active_operations.clear();
            controller.runtime.take()
        } else {
            None
        }
    };
}

#[must_use]
pub fn platform_probe() -> bool {
    platform::Runtime::install().is_ok()
}

pub fn operation_started(operation_handle: u64) {
    controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .operation_started(operation_handle);
}

pub fn operation_finished(operation_handle: u64) -> OperationCoverage {
    controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .operation_finished(operation_handle)
}

pub fn operation_removed(operation_handle: u64) {
    controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove_operation(operation_handle);
}

pub fn observation_opened(
    observation_handle: u64,
    operation_handle: u64,
    class: AutomaticObservationClass,
) {
    let mut controller = controller().lock().unwrap_or_else(PoisonError::into_inner);
    controller.drain();
    if controller.active_observations.len() >= MAX_ACTIVE_OBSERVATIONS {
        controller.mark_all_incomplete();
        return;
    }
    controller.active_observations.insert(
        observation_handle,
        ActiveObservation {
            operation_handle,
            class,
            thread_id: 0,
            dispatched: false,
        },
    );
}

pub fn observation_dispatched(observation_handle: u64) {
    let mut controller = controller().lock().unwrap_or_else(PoisonError::into_inner);
    controller.drain();
    let thread_id = platform::current_thread_id();
    let Some(observation) = controller.active_observations.get_mut(&observation_handle) else {
        controller.mark_all_incomplete();
        return;
    };
    observation.thread_id = thread_id;
    observation.dispatched = true;
}

pub fn observation_finished(observation_handle: u64) {
    let mut controller = controller().lock().unwrap_or_else(PoisonError::into_inner);
    controller.drain();
    if controller
        .active_observations
        .remove(&observation_handle)
        .is_none()
    {
        controller.mark_all_incomplete();
    }
}

#[doc(hidden)]
pub fn observation_is_active(observation_handle: u64) -> bool {
    controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .active_observations
        .contains_key(&observation_handle)
}

fn controller() -> &'static Mutex<Controller> {
    SENTINEL.get_or_init(|| Mutex::new(Controller::new()))
}

const fn coverage_result(
    operation: ActiveOperation,
    runtime_healthy: bool,
    end_sequence: u64,
) -> OperationCoverage {
    if operation.incomplete
        || !runtime_healthy
        || operation.owned_events > operation.relevant_events
        || end_sequence < operation.start_sequence
    {
        OperationCoverage::Incomplete
    } else {
        OperationCoverage::CleanKernelTrace(KernelTraceEvidence {
            start_sequence: operation.start_sequence,
            end_sequence,
            relevant_events: operation.relevant_events,
            owned_events: operation.owned_events,
        })
    }
}

#[cfg(target_os = "linux")]
#[path = "sentinel_linux.rs"]
mod platform;

#[cfg(not(target_os = "linux"))]
mod platform {
    use reproit_core::model::AutomaticObservationClass;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(super) struct Event {
        pub(super) kind: EventKind,
        pub(super) thread_id: i32,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(super) enum EventKind {
        #[default]
        Exit,
    }

    #[allow(clippy::unused_self)]
    impl EventKind {
        pub(super) const fn is_owned_by(self, _: AutomaticObservationClass) -> bool {
            false
        }

        pub(super) const fn is_exactly_owned_by(self, _: AutomaticObservationClass) -> bool {
            false
        }
    }

    pub(super) struct IgnoreGuard;
    pub(super) struct Runtime;

    #[allow(clippy::unused_self)]
    impl Runtime {
        pub(super) fn install() -> Result<Self, ()> {
            Err(())
        }

        pub(super) const fn drain(&mut self, _: &mut [Event]) -> usize {
            0
        }

        pub(super) const fn is_healthy(&mut self) -> bool {
            false
        }

        pub(super) const fn sequence(&self) -> u64 {
            0
        }

        pub(super) const fn ignore_current_thread(&self) -> Option<IgnoreGuard> {
            None
        }
    }

    pub(super) const fn current_thread_id() -> i32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_kernel_trace_does_not_claim_full_world_coverage() {
        let operation = ActiveOperation {
            start_sequence: 7,
            relevant_events: 2,
            owned_events: 2,
            incomplete: false,
        };
        assert_eq!(
            coverage_result(operation, true, 9),
            OperationCoverage::CleanKernelTrace(KernelTraceEvidence {
                start_sequence: 7,
                end_sequence: 9,
                relevant_events: 2,
                owned_events: 2,
            })
        );
        assert_ne!(
            coverage_result(operation, true, 9),
            OperationCoverage::Incomplete
        );
    }

    #[test]
    fn loss_overflow_or_invalid_counters_make_coverage_incomplete() {
        let clean = ActiveOperation {
            start_sequence: 7,
            relevant_events: 2,
            owned_events: 2,
            incomplete: false,
        };
        assert_eq!(
            coverage_result(
                ActiveOperation {
                    incomplete: true,
                    ..clean
                },
                true,
                9
            ),
            OperationCoverage::Incomplete
        );
        assert_eq!(
            coverage_result(clean, false, 9),
            OperationCoverage::Incomplete
        );
        assert_eq!(
            coverage_result(
                ActiveOperation {
                    owned_events: 3,
                    ..clean
                },
                true,
                9
            ),
            OperationCoverage::Incomplete
        );
        assert_eq!(
            coverage_result(clean, true, 6),
            OperationCoverage::Incomplete
        );
    }

    #[test]
    fn clean_coverage_evidence_has_one_fixed_encoding() {
        let evidence = KernelTraceEvidence {
            start_sequence: 1,
            end_sequence: 2,
            relevant_events: 3,
            owned_events: 3,
        }
        .encode();

        assert_eq!(evidence.len(), 40);
        assert_eq!(&evidence[..8], &1_u64.to_be_bytes());
        assert_eq!(&evidence[8..16], &1_u64.to_be_bytes());
        assert_eq!(&evidence[16..24], &2_u64.to_be_bytes());
        assert_eq!(&evidence[24..32], &3_u64.to_be_bytes());
        assert_eq!(&evidence[32..], &3_u64.to_be_bytes());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn exact_observation_owns_an_event_inside_a_transitive_dependency() {
        let mut controller = Controller::new();
        controller.active_operations.insert(
            7,
            ActiveOperation {
                start_sequence: 1,
                relevant_events: 0,
                owned_events: 0,
                incomplete: false,
            },
        );
        controller.active_observations.insert(
            8,
            ActiveObservation {
                operation_handle: 7,
                class: AutomaticObservationClass::OutboundHttp,
                thread_id: 11,
                dispatched: true,
            },
        );
        controller.active_observations.insert(
            9,
            ActiveObservation {
                operation_handle: 7,
                class: AutomaticObservationClass::Randomness,
                thread_id: 11,
                dispatched: true,
            },
        );

        controller.apply_event(platform::Event {
            kind: platform::EventKind::Randomness,
            thread_id: 11,
            ..platform::Event::default()
        });

        let operation = controller.active_operations.get(&7).unwrap();
        assert_eq!(operation.relevant_events, 1);
        assert_eq!(operation.owned_events, 1);
        assert!(!operation.incomplete);
    }
}
