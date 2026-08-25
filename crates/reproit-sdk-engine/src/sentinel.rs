//! Bounded Linux coverage sentinel for automatic World capture.
//!
//! The sentinel detects unowned kernel-visible effects. It never reads syscall
//! arguments or copies application payload bytes. A clean syscall trace is not
//! sufficient proof for observations that can stay in process, such as vDSO
//! clock reads and environment access. The engine therefore keeps the result
//! local and does not bind it as complete World coverage.

use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock, PoisonError},
};

use reproit_core::model::AutomaticObservationClass;

const MAX_ACTIVE_OPERATIONS: usize = 512;
const MAX_ACTIVE_OBSERVATIONS: usize = 1_024;

static SENTINEL: OnceLock<Mutex<Controller>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationCoverage {
    Incomplete,
    KernelTraceCompleteButFullCoverageUnproved,
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
        let owner = self
            .active_observations
            .values()
            .filter(|observation| {
                observation.dispatched
                    && observation.thread_id == event.thread_id
                    && event.kind.is_owned_by(observation.class)
            })
            .map(|observation| observation.operation_handle)
            .collect::<Vec<_>>();
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
        let counters_valid = operation.owned_events <= operation.relevant_events
            && self
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.sequence() >= operation.start_sequence);
        coverage_result(operation.incomplete, healthy, counters_valid)
    }

    fn remove_operation(&mut self, operation_handle: u64) {
        self.drain();
        self.active_observations
            .retain(|_, observation| observation.operation_handle != operation_handle);
        self.active_operations.remove(&operation_handle);
    }
}

pub(crate) struct EngineCallGuard {
    ignore: Option<platform::IgnoreGuard>,
}

pub(crate) fn engine_call_scope() -> EngineCallGuard {
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

pub(crate) fn engine_opened() {
    let mut controller = controller().lock().unwrap_or_else(PoisonError::into_inner);
    controller.engine_count = controller.engine_count.saturating_add(1);
    if controller.runtime.is_none() {
        controller.runtime = platform::Runtime::install().ok();
    }
}

pub(crate) fn engine_closed() {
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

pub(crate) fn operation_started(operation_handle: u64) {
    controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .operation_started(operation_handle);
}

pub(crate) fn operation_finished(operation_handle: u64) -> OperationCoverage {
    controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .operation_finished(operation_handle)
}

pub(crate) fn operation_removed(operation_handle: u64) {
    controller()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove_operation(operation_handle);
}

pub(crate) fn observation_opened(
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

pub(crate) fn observation_dispatched(observation_handle: u64) {
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

pub(crate) fn observation_finished(observation_handle: u64) {
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

fn controller() -> &'static Mutex<Controller> {
    SENTINEL.get_or_init(|| Mutex::new(Controller::new()))
}

const fn coverage_result(
    incomplete: bool,
    runtime_healthy: bool,
    counters_valid: bool,
) -> OperationCoverage {
    if incomplete || !runtime_healthy || !counters_valid {
        OperationCoverage::Incomplete
    } else {
        // Syscalls cannot prove vDSO clock reads or in-process environment reads.
        OperationCoverage::KernelTraceCompleteButFullCoverageUnproved
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
        assert_eq!(
            coverage_result(false, true, true),
            OperationCoverage::KernelTraceCompleteButFullCoverageUnproved
        );
        assert_ne!(
            coverage_result(false, true, true),
            OperationCoverage::Incomplete
        );
    }

    #[test]
    fn loss_overflow_or_invalid_counters_make_coverage_incomplete() {
        assert_eq!(
            coverage_result(true, true, true),
            OperationCoverage::Incomplete
        );
        assert_eq!(
            coverage_result(false, false, true),
            OperationCoverage::Incomplete
        );
        assert_eq!(
            coverage_result(false, true, false),
            OperationCoverage::Incomplete
        );
    }
}
