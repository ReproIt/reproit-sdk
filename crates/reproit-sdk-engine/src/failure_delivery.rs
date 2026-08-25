use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

use reproit_core::{Error, ErrorCode, model::FailureIdentity};
use reproit_sdk_rust::{AutomaticManagedOperation, ManagedProjectToken, ManagedRustCandidateSink};

pub(crate) const MAX_FAILURE_TASKS: usize = 16;

pub(crate) struct FailureWork {
    task: Arc<FailureTask>,
}

enum FailureJob {
    Production(Box<ProductionFailureJob>),
    #[cfg(test)]
    DropProbe(DropProbe),
}

struct ProductionFailureJob {
    failure: FailureIdentity,
    operation: AutomaticManagedOperation,
    project_token: ManagedProjectToken,
}

#[cfg(test)]
struct DropProbe(Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

pub(crate) struct FailureWorker {
    sender: Option<SyncSender<FailureWork>>,
}

pub(crate) struct FailureTask {
    changed: Condvar,
    state: Mutex<FailureTaskState>,
}

enum FailureTaskState {
    Cancelled,
    Failed(Error),
    Pending(Option<FailureJob>),
    Ready(Arc<ReadySink>),
    Running,
}

pub(crate) struct ReadySink {
    wait_until_idle: Box<dyn Fn(Duration) -> bool + Send + Sync>,
}

impl ReadySink {
    pub(crate) fn new(wait_until_idle: impl Fn(Duration) -> bool + Send + Sync + 'static) -> Self {
        Self {
            wait_until_idle: Box::new(wait_until_idle),
        }
    }

    fn managed(sink: ManagedRustCandidateSink) -> Self {
        let sink = Arc::new(sink);
        Self::new(move |timeout| sink.wait_until_idle(timeout))
    }

    fn wait_until_idle(&self, timeout: Duration) -> bool {
        (self.wait_until_idle)(timeout)
    }
}

impl FailureTask {
    pub(crate) fn pending(
        operation: AutomaticManagedOperation,
        failure: FailureIdentity,
        project_token: ManagedProjectToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            changed: Condvar::new(),
            state: Mutex::new(FailureTaskState::Pending(Some(FailureJob::Production(
                Box::new(ProductionFailureJob {
                    failure,
                    operation,
                    project_token,
                }),
            )))),
        })
    }

    #[cfg(test)]
    pub(crate) fn pending_for_test() -> Arc<Self> {
        Arc::new(Self {
            changed: Condvar::new(),
            state: Mutex::new(FailureTaskState::Pending(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn pending_drop_probe(dropped: Arc<std::sync::atomic::AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            changed: Condvar::new(),
            state: Mutex::new(FailureTaskState::Pending(Some(FailureJob::DropProbe(
                DropProbe(dropped),
            )))),
        })
    }

    pub(crate) fn work(self: &Arc<Self>) -> FailureWork {
        FailureWork { task: self.clone() }
    }

    pub(crate) fn cancel(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state = FailureTaskState::Cancelled;
        self.changed.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn is_cancelled(&self) -> bool {
        matches!(
            *self.state.lock().unwrap_or_else(PoisonError::into_inner),
            FailureTaskState::Cancelled
        )
    }

    fn complete(&self, result: Result<ReadySink, Error>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*state, FailureTaskState::Cancelled) {
            return;
        }
        *state = match result {
            Ok(sink) => FailureTaskState::Ready(Arc::new(sink)),
            Err(error) => FailureTaskState::Failed(error),
        };
        self.changed.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn complete_for_test(&self, result: Result<ReadySink, Error>) {
        self.complete(result);
    }

    fn take_job(&self) -> Option<FailureJob> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let FailureTaskState::Pending(job) = &mut *state else {
            return None;
        };
        let job = job.take()?;
        *state = FailureTaskState::Running;
        Some(job)
    }

    pub(crate) fn wait_until_idle(&self, timeout: Duration) -> Result<bool, Error> {
        let started = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match &*state {
                FailureTaskState::Cancelled => return Err(not_found()),
                FailureTaskState::Failed(error) => return Err(error.clone()),
                FailureTaskState::Ready(sink) => {
                    let sink = sink.clone();
                    drop(state);
                    return Ok(sink.wait_until_idle(timeout.saturating_sub(started.elapsed())));
                }
                FailureTaskState::Pending(_) | FailureTaskState::Running => {}
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(false);
            }
            let waited = self.changed.wait_timeout(state, remaining);
            let (next, timed_out) = waited.unwrap_or_else(PoisonError::into_inner);
            state = next;
            if timed_out.timed_out()
                && matches!(
                    *state,
                    FailureTaskState::Pending(_) | FailureTaskState::Running
                )
            {
                return Ok(false);
            }
        }
    }
}

impl FailureWork {
    fn run(self) {
        let Some(job) = self.task.take_job() else {
            return;
        };
        let (failure, operation, project_token) = match job {
            FailureJob::Production(job) => {
                let ProductionFailureJob {
                    failure,
                    operation,
                    project_token,
                } = *job;
                (failure, operation, project_token)
            }
            #[cfg(test)]
            FailureJob::DropProbe(_probe) => {
                self.task.complete(Err(background_unavailable()));
                return;
            }
        };
        finish_failure_task(&self.task, move || {
            operation
                .fail(failure, project_token)
                .map(ReadySink::managed)
        });
    }
}

impl FailureWorker {
    pub(crate) fn start() -> Self {
        let (sender, receiver) = sync_channel::<FailureWork>(MAX_FAILURE_TASKS);
        let worker = thread::Builder::new()
            .name("reproit-sdk-engine-failure".to_owned())
            .spawn(move || {
                while let Ok(work) = receiver.recv() {
                    work.run();
                }
            });
        Self {
            sender: worker.ok().map(|_| sender),
        }
    }

    pub(crate) fn try_send(&self, work: FailureWork) -> Result<(), Error> {
        let Some(sender) = &self.sender else {
            return Err(background_unavailable());
        };
        send_bounded(sender, work)
    }
}

fn finish_failure_task(task: &FailureTask, finalize: impl FnOnce() -> Result<ReadySink, Error>) {
    let result =
        catch_unwind(AssertUnwindSafe(finalize)).unwrap_or_else(|_| Err(background_unavailable()));
    task.complete(result);
}

fn send_bounded<T>(sender: &SyncSender<T>, value: T) -> Result<(), Error> {
    sender.try_send(value).map_err(|error| match error {
        TrySendError::Full(_) => quota_error(),
        TrySendError::Disconnected(_) => background_unavailable(),
    })
}

fn quota_error() -> Error {
    Error::new(
        ErrorCode::RuntimeQuota,
        "The shared SDK failure task limit was reached.",
    )
}

fn not_found() -> Error {
    Error::new(
        ErrorCode::NotFound,
        "The shared SDK failure task does not exist.",
    )
}

fn background_unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The shared SDK failure task is unavailable.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn bounded_queue_rejects_one_entry_over_capacity() {
        let (sender, _receiver) = sync_channel(MAX_FAILURE_TASKS);
        for value in 0..MAX_FAILURE_TASKS {
            send_bounded(&sender, value).unwrap();
        }
        let error = send_bounded(&sender, MAX_FAILURE_TASKS).unwrap_err();
        assert_eq!(error.code, ErrorCode::RuntimeQuota);
    }

    #[test]
    fn task_reports_background_errors() {
        let task = FailureTask::pending_for_test();
        task.complete_for_test(Err(Error::new(
            ErrorCode::UploadExpired,
            "The test failure task expired.",
        )));
        let error = task.wait_until_idle(Duration::ZERO).unwrap_err();
        assert_eq!(error.code, ErrorCode::UploadExpired);
    }

    #[test]
    fn task_contains_panics() {
        let task = FailureTask::pending_for_test();
        finish_failure_task(&task, || -> Result<ReadySink, Error> {
            panic!("test failure task panic");
        });
        let error = task.wait_until_idle(Duration::ZERO).unwrap_err();
        assert_eq!(error.code, ErrorCode::ServiceUnavailable);
    }

    #[test]
    fn cancelling_a_pending_task_drops_its_boxed_job() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task = FailureTask::pending_drop_probe(dropped.clone());
        task.cancel();
        assert!(dropped.load(Ordering::SeqCst));
    }
}
