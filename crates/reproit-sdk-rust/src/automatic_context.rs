use std::{
    cell::RefCell,
    collections::BTreeMap,
    future::Future,
    mem,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use reproit_core::{
    Error, ErrorCode,
    identity::OperationId,
    model::{AutomaticObservationClass, DependencyOutcome},
};

use crate::{
    MAX_ACTIVE_OPERATIONS, MAX_EVENTS,
    automatic_world::{AutomaticObservationStream, AutomaticWorldCoordinator},
};

const AMBIENT_SESSION_ID_START: u64 = 1_u64 << 63;
const MAX_AUTOMATIC_OPERATION_NESTING: usize = 16;

std::thread_local! {
    static AUTOMATIC_OPERATION_STACK: RefCell<Vec<AutomaticOperationContext>> =
        const { RefCell::new(Vec::new()) };
}

static ACTIVE_AMBIENT_OPERATIONS: OnceLock<
    Mutex<BTreeMap<OperationId, Weak<AutomaticOperationShared>>>,
> = OnceLock::new();

#[derive(Clone)]
pub struct AutomaticOperationContext {
    operation_id: OperationId,
    shared: Arc<AutomaticOperationShared>,
}

impl AutomaticOperationContext {
    pub(crate) fn new(operation_id: OperationId, shared: Arc<AutomaticOperationShared>) -> Self {
        Self {
            operation_id,
            shared,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub fn current() -> Result<Self, Error> {
        let Some(context) = AUTOMATIC_OPERATION_STACK
            .try_with(|stack| stack.borrow().last().cloned())
            .ok()
            .flatten()
        else {
            invalidate_all_active_operations();
            return Err(invalid_context());
        };
        context.require_current()?;
        Ok(context)
    }

    #[must_use = "A scoped future does nothing until it is polled."]
    pub fn scope<F>(&self, future: F) -> AutomaticOperationScope<F>
    where
        F: Future,
    {
        AutomaticOperationScope {
            context: self.clone(),
            future: Box::pin(future),
        }
    }

    #[doc(hidden)]
    pub fn scope_poll<T>(&self, poll: impl FnOnce() -> T) -> T {
        let _poll_context = AutomaticPollContext::install(self);
        poll()
    }

    pub fn open_observation(
        &self,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
    ) -> Result<AutomaticObservationSession, Error> {
        self.require_current()?;
        let (session_id, session_position) = self
            .shared
            .open_ambient_observation(class, causal_parent_id)?;
        Ok(AutomaticObservationSession {
            context: self.clone(),
            finished: false,
            session_id,
            session_position,
        })
    }

    fn require_current(&self) -> Result<(), Error> {
        let matches = AUTOMATIC_OPERATION_STACK
            .try_with(|stack| {
                stack.borrow().last().is_some_and(|current| {
                    current.operation_id == self.operation_id
                        && Arc::ptr_eq(&current.shared, &self.shared)
                })
            })
            .unwrap_or(false);
        if !matches || !self.shared.is_active() {
            self.shared.invalidate();
            if let Ok(Some(current)) =
                AUTOMATIC_OPERATION_STACK.try_with(|stack| stack.borrow().last().cloned())
            {
                current.shared.invalidate();
            }
            return Err(invalid_context());
        }
        Ok(())
    }
}

pub struct AutomaticOperationScope<F>
where
    F: Future,
{
    context: AutomaticOperationContext,
    future: Pin<Box<F>>,
}

impl<F> Future for AutomaticOperationScope<F>
where
    F: Future,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, task_context: &mut Context<'_>) -> Poll<Self::Output> {
        let scope = self.get_mut();
        let _poll_context = AutomaticPollContext::install(&scope.context);
        scope.future.as_mut().poll(task_context)
    }
}

enum AutomaticPollRestore {
    Pop(AutomaticOperationContext),
    Replace(Vec<AutomaticOperationContext>),
}

struct AutomaticPollContext {
    restore: Option<AutomaticPollRestore>,
}

impl AutomaticPollContext {
    fn install(context: &AutomaticOperationContext) -> Self {
        let restore = AUTOMATIC_OPERATION_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            let can_push = context.shared.is_active()
                && stack.len() < MAX_AUTOMATIC_OPERATION_NESTING
                && !stack
                    .iter()
                    .any(|entry| Arc::ptr_eq(&entry.shared, &context.shared));
            if can_push {
                stack.push(context.clone());
                AutomaticPollRestore::Pop(context.clone())
            } else {
                context.shared.invalidate();
                AutomaticPollRestore::Replace(mem::take(&mut *stack))
            }
        });
        Self {
            restore: Some(restore),
        }
    }
}

impl Drop for AutomaticPollContext {
    fn drop(&mut self) {
        let Some(restore) = self.restore.take() else {
            return;
        };
        AUTOMATIC_OPERATION_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            match restore {
                AutomaticPollRestore::Pop(expected) => {
                    let matches = stack.pop().is_some_and(|current| {
                        let matches = current.operation_id == expected.operation_id
                            && Arc::ptr_eq(&current.shared, &expected.shared);
                        if !matches {
                            current.shared.invalidate();
                        }
                        matches
                    });
                    if !matches {
                        expected.shared.invalidate();
                        for context in stack.drain(..) {
                            context.shared.invalidate();
                        }
                    }
                }
                AutomaticPollRestore::Replace(previous) => {
                    for context in stack.drain(..) {
                        context.shared.invalidate();
                    }
                    *stack = previous;
                }
            }
        });
    }
}

pub struct AutomaticObservationSession {
    context: AutomaticOperationContext,
    finished: bool,
    session_id: u64,
    session_position: u64,
}

impl AutomaticObservationSession {
    #[must_use]
    pub const fn session_position(&self) -> u64 {
        self.session_position
    }

    pub fn write_request(&mut self, chunk: &[u8]) -> Result<(), Error> {
        self.run(|coordinator, session_id| {
            coordinator.write_observation(session_id, AutomaticObservationStream::Request, chunk)
        })
    }

    pub fn dispatch(&mut self) -> Result<&'static str, Error> {
        self.run(|coordinator, session_id| {
            coordinator
                .dispatch_observation(session_id)
                .map(super::automatic_world::AutomaticObservationAction::as_str)
        })
    }

    pub fn write_response(&mut self, chunk: &[u8]) -> Result<(), Error> {
        self.run(|coordinator, session_id| {
            coordinator.write_observation(session_id, AutomaticObservationStream::Response, chunk)
        })
    }

    pub fn read_response(&mut self) -> Result<(Vec<u8>, bool), Error> {
        self.run(AutomaticWorldCoordinator::read_observation_response)
    }

    pub fn finish(mut self, outcome: DependencyOutcome) -> Result<(), Error> {
        let session_position = self.session_position;
        let result = self.run(|coordinator, session_id| {
            coordinator.finish_observation(session_id, outcome, session_position)
        });
        if result.is_ok() {
            self.finished = true;
        }
        result
    }

    pub fn abandon(mut self) -> Result<(), Error> {
        self.context.require_current()?;
        let result = self.context.shared.abandon_session(self.session_id);
        self.finished = true;
        result
    }

    fn run<T>(
        &mut self,
        action: impl FnOnce(&mut AutomaticWorldCoordinator, u64) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.finished {
            return Err(invalid_context());
        }
        if let Err(error) = self.context.require_current() {
            self.context.shared.fail_session(self.session_id);
            self.finished = true;
            return Err(error);
        }
        let result = self
            .context
            .shared
            .with_coordinator(|coordinator| action(coordinator, self.session_id));
        if result.is_err() {
            self.context.shared.fail_session(self.session_id);
            self.finished = true;
        }
        result
    }
}

impl Drop for AutomaticObservationSession {
    fn drop(&mut self) {
        if !self.finished {
            self.context.shared.fail_session(self.session_id);
            self.finished = true;
        }
    }
}

pub(crate) struct AutomaticOperationShared {
    operation_id: OperationId,
    registered: AtomicBool,
    state: Mutex<AutomaticOperationState>,
}

struct AutomaticOperationState {
    ambient_session_count: usize,
    coordinator: Option<AutomaticWorldCoordinator>,
    invalid_context: bool,
}

impl AutomaticOperationShared {
    pub(crate) fn new(
        operation_id: OperationId,
        coordinator: AutomaticWorldCoordinator,
    ) -> Result<Arc<Self>, Error> {
        let shared = Arc::new(Self {
            operation_id,
            registered: AtomicBool::new(false),
            state: Mutex::new(AutomaticOperationState {
                ambient_session_count: 0,
                coordinator: Some(coordinator),
                invalid_context: false,
            }),
        });
        register_active_operation(operation_id, &shared)?;
        shared.registered.store(true, Ordering::Release);
        Ok(shared)
    }

    pub(crate) fn with_coordinator<T>(
        &self,
        action: impl FnOnce(&mut AutomaticWorldCoordinator) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut state = self.lock_state()?;
        if state.invalid_context {
            return Err(invalid_context());
        }
        action(state.coordinator.as_mut().ok_or_else(invalid_context)?)
    }

    pub(crate) fn take_for_close(&self) -> Result<AutomaticWorldCoordinator, Error> {
        self.unregister();
        let mut state = self.lock_state()?;
        if state.invalid_context {
            state.coordinator.take();
            return Err(invalid_context());
        }
        state.invalid_context = true;
        state.coordinator.take().ok_or_else(invalid_context)
    }

    pub(crate) fn deactivate(&self) {
        self.unregister();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.invalid_context = true;
        state.coordinator.take();
    }

    fn open_ambient_observation(
        &self,
        class: AutomaticObservationClass,
        causal_parent_id: Option<OperationId>,
    ) -> Result<(u64, u64), Error> {
        let mut state = self.lock_state()?;
        if state.invalid_context {
            return Err(invalid_context());
        }
        if state.ambient_session_count >= MAX_EVENTS {
            state.invalidate();
            return Err(context_quota());
        }
        let session_offset =
            u64::try_from(state.ambient_session_count).map_err(|_| context_quota())?;
        let session_id = AMBIENT_SESSION_ID_START
            .checked_add(session_offset)
            .ok_or_else(context_quota)?;
        state.ambient_session_count += 1;
        let session_position = state
            .coordinator
            .as_mut()
            .ok_or_else(invalid_context)?
            .open_observation(session_id, class, causal_parent_id)?;
        Ok((session_id, session_position))
    }

    fn abandon_session(&self, session_id: u64) -> Result<(), Error> {
        let mut state = self.lock_state()?;
        let result = state
            .coordinator
            .as_mut()
            .ok_or_else(invalid_context)?
            .abandon_observation(session_id);
        state.invalid_context = true;
        result
    }

    fn fail_session(&self, session_id: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(coordinator) = state.coordinator.as_mut() {
            let _result = coordinator.abandon_observation(session_id);
        }
        state.invalid_context = true;
    }

    fn invalidate(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .invalidate();
    }

    fn is_active(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| !state.invalid_context && state.coordinator.is_some())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, AutomaticOperationState>, Error> {
        match self.state.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                poisoned.into_inner().invalidate();
                Err(invalid_context())
            }
        }
    }

    fn unregister(&self) {
        if self.registered.swap(false, Ordering::AcqRel) {
            unregister_active_operation(self.operation_id);
        }
    }
}

impl Drop for AutomaticOperationShared {
    fn drop(&mut self) {
        self.unregister();
    }
}

impl AutomaticOperationState {
    fn invalidate(&mut self) {
        self.invalid_context = true;
        if let Some(coordinator) = self.coordinator.as_mut() {
            coordinator.invalidate_ambient_context();
        }
    }
}

fn active_operations() -> &'static Mutex<BTreeMap<OperationId, Weak<AutomaticOperationShared>>> {
    ACTIVE_AMBIENT_OPERATIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn register_active_operation(
    operation_id: OperationId,
    shared: &Arc<AutomaticOperationShared>,
) -> Result<(), Error> {
    let mut operations = active_operations()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    operations.retain(|_, entry| entry.strong_count() != 0);
    if operations.len() >= MAX_ACTIVE_OPERATIONS || operations.contains_key(&operation_id) {
        return Err(context_quota());
    }
    operations.insert(operation_id, Arc::downgrade(shared));
    Ok(())
}

fn unregister_active_operation(operation_id: OperationId) {
    active_operations()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&operation_id);
}

fn invalidate_all_active_operations() {
    let operations = {
        let mut active = active_operations()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let operations = active
            .values()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        active.retain(|_, entry| entry.strong_count() != 0);
        operations
    };
    for operation in operations {
        operation.invalidate();
    }
}

fn invalid_context() -> Error {
    Error::new(
        ErrorCode::IncompleteCandidate,
        "The automatic operation context is unavailable.",
    )
}

fn context_quota() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The automatic operation context reached its limit.",
    )
}

#[cfg(test)]
#[path = "../tests/support/automatic_context_internal.rs"]
mod tests;
