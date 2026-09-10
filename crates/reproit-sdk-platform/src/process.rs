//! Native process ownership and bounded output-reader completion.

use std::{
    io,
    process::{ChildStderr, ChildStdout, Command, ExitStatus},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use process_wrap::std::{ChildWrapper, CommandWrap};

const POLL_INTERVAL: Duration = Duration::from_millis(2);
pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

pub struct ProcessTree {
    child: Box<dyn ChildWrapper>,
    stopped: bool,
}

impl ProcessTree {
    pub fn spawn(command: Command) -> io::Result<Self> {
        let mut command = CommandWrap::from(command);
        #[cfg(unix)]
        command.wrap(process_wrap::std::ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(process_wrap::std::JobObject);
        #[cfg(not(any(unix, windows)))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Process trees are unsupported.",
        ));
        Ok(Self {
            child: command.spawn()?,
            stopped: false,
        })
    }

    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout().take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr().take()
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Stop descendants even when the direct child has already exited.
    pub fn terminate(&mut self) -> io::Result<ExitStatus> {
        if !self.stopped {
            if let Err(error) = self.child.start_kill() {
                // ESRCH means that the owned Unix process group is already absent.
                #[cfg(unix)]
                if error.raw_os_error() != Some(3) {
                    return Err(error);
                }
                #[cfg(not(unix))]
                return Err(error);
            }
            self.stopped = true;
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(cleanup_timeout());
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.terminate();
        }
    }
}

pub fn finish_reader<T>(reader: JoinHandle<T>, deadline: Instant) -> io::Result<T> {
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            return Err(cleanup_timeout());
        }
        thread::sleep(POLL_INTERVAL);
    }
    reader
        .join()
        .map_err(|_| io::Error::other("The output reader stopped unexpectedly."))
}

fn cleanup_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "Process cleanup reached its time limit.",
    )
}
