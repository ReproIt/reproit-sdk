use std::{
    fs,
    mem::{self, MaybeUninit},
    os::fd::RawFd,
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicI32, AtomicU8, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use reproit_core::model::AutomaticObservationClass;

const MAX_TRACED_THREADS: usize = 1_024;
const MAX_IGNORED_THREADS: usize = 64;
const MAX_QUEUED_EVENTS: u64 = 4_096;
const MAX_TOTAL_EVENTS: u64 = 1_u64 << 40;
const STARTUP_WAIT_MS: i32 = 1_000;
const SHUTDOWN_POLLS: usize = 500;
const WAIT_ALL: libc::c_int = 0x4000_0000;
const PTRACE_GETEVENTMSG: libc::c_uint = 0x4201;
const PTRACE_SEIZE: libc::c_uint = 0x4206;
const PTRACE_INTERRUPT: libc::c_uint = 0x4207;
const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
const PTRACE_EVENT_FORK: i32 = 1;
const PTRACE_EVENT_VFORK: i32 = 2;
const PTRACE_EVENT_CLONE: i32 = 3;
const PTRACE_EVENT_EXEC: i32 = 4;
const PTRACE_EVENT_EXIT: i32 = 6;
const PTRACE_EVENT_STOP: i32 = 128;
const PTRACE_SYSCALL_INFO_ENTRY: u8 = 1;
const TRACE_OPTIONS: libc::c_ulong = (libc::PTRACE_O_TRACESYSGOOD
    | libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_TRACEEXIT) as libc::c_ulong;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum EventKind {
    Filesystem = 1,
    Network = 2,
    Clock = 3,
    Randomness = 4,
    Process = 5,
    #[default]
    Exit = 6,
}

impl EventKind {
    pub(super) const fn is_owned_by(self, class: AutomaticObservationClass) -> bool {
        match self {
            // A semantic dependency owns its transitive kernel effects. For example,
            // SQLite reads files, and a TLS client can read trust roots, read the clock,
            // and request random bytes. The dependency transcript owns those effects as
            // one application-visible observation.
            Self::Filesystem => matches!(
                class,
                AutomaticObservationClass::Database
                    | AutomaticObservationClass::Filesystem
                    | AutomaticObservationClass::OutboundHttp
                    | AutomaticObservationClass::Queue
            ),
            Self::Network => matches!(
                class,
                AutomaticObservationClass::Database
                    | AutomaticObservationClass::OutboundHttp
                    | AutomaticObservationClass::Queue
            ),
            Self::Clock => matches!(
                class,
                AutomaticObservationClass::Clock
                    | AutomaticObservationClass::Database
                    | AutomaticObservationClass::OutboundHttp
                    | AutomaticObservationClass::Queue
            ),
            Self::Randomness => matches!(
                class,
                AutomaticObservationClass::Database
                    | AutomaticObservationClass::OutboundHttp
                    | AutomaticObservationClass::Queue
                    | AutomaticObservationClass::Randomness
            ),
            Self::Process | Self::Exit => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(super) struct Event {
    pub(super) thread_id: i32,
    pub(super) kind: EventKind,
    padding: [u8; 3],
    sequence: u64,
}

#[repr(C)]
struct SharedState {
    overflowed: AtomicU8,
    tracer_alive: AtomicU8,
    sequence: AtomicU64,
    queued_events: AtomicU64,
    ignored_tids: [AtomicI32; MAX_IGNORED_THREADS],
    ignored_depths: [AtomicU64; MAX_IGNORED_THREADS],
}

struct SharedControl {
    pointer: NonNull<SharedState>,
}

// The mapping contains only process-shared atomic values.
unsafe impl Send for SharedControl {}
// The mapping contains only process-shared atomic values.
unsafe impl Sync for SharedControl {}

impl SharedControl {
    fn allocate() -> Result<Arc<Self>, ()> {
        // Safety: The mapping is private to this process family and has the exact state size.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mem::size_of::<SharedState>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(());
        }
        let Some(pointer) = NonNull::new(pointer.cast::<SharedState>()) else {
            // Safety: `mmap` returned a valid mapping at address zero.
            unsafe { libc::munmap(pointer, mem::size_of::<SharedState>()) };
            return Err(());
        };
        let state = SharedState {
            overflowed: AtomicU8::new(0),
            tracer_alive: AtomicU8::new(0),
            sequence: AtomicU64::new(0),
            queued_events: AtomicU64::new(0),
            ignored_tids: [const { AtomicI32::new(0) }; MAX_IGNORED_THREADS],
            ignored_depths: [const { AtomicU64::new(0) }; MAX_IGNORED_THREADS],
        };
        // Safety: The mapping is writable, aligned, and uninitialized.
        unsafe { pointer.as_ptr().write(state) };
        Ok(Arc::new(Self { pointer }))
    }

    fn state(&self) -> &SharedState {
        // Safety: The mapping remains valid for the lifetime of this owner.
        unsafe { self.pointer.as_ref() }
    }
}

impl Drop for SharedControl {
    fn drop(&mut self) {
        // Safety: This owner created the mapping with this exact size.
        unsafe {
            libc::munmap(self.pointer.as_ptr().cast(), mem::size_of::<SharedState>());
        }
    }
}

pub(super) struct IgnoreGuard {
    control: Arc<SharedControl>,
    slot: usize,
}

impl Drop for IgnoreGuard {
    fn drop(&mut self) {
        let state = self.control.state();
        let previous = state.ignored_depths[self.slot].fetch_sub(1, Ordering::SeqCst);
        if previous == 1 {
            state.ignored_tids[self.slot].store(0, Ordering::SeqCst);
        } else if previous == 0 {
            state.overflowed.store(1, Ordering::SeqCst);
        }
    }
}

pub(super) struct Runtime {
    child_pid: libc::pid_t,
    control: Arc<SharedControl>,
    event_read_fd: RawFd,
    reaped: bool,
}

impl Runtime {
    pub(super) fn install() -> Result<Self, ()> {
        let initial_tids = enumerate_threads()?;
        let control = SharedControl::allocate()?;
        let event_pipe = create_pipe(libc::O_CLOEXEC | libc::O_NONBLOCK)?;
        let gate_pipe = match create_pipe(libc::O_CLOEXEC) {
            Ok(pipe) => pipe,
            Err(()) => {
                close_pipe(event_pipe);
                return Err(());
            }
        };
        let ready_pipe = match create_pipe(libc::O_CLOEXEC) {
            Ok(pipe) => pipe,
            Err(()) => {
                close_pipe(event_pipe);
                close_pipe(gate_pipe);
                return Err(());
            }
        };

        // Safety: No Rust work runs in the child after the fork. The child uses fixed storage
        // and async-signal-safe system interfaces before it exits with `_exit`.
        let child_pid = unsafe { libc::fork() };
        if child_pid < 0 {
            close_pipe(event_pipe);
            close_pipe(gate_pipe);
            close_pipe(ready_pipe);
            return Err(());
        }
        if child_pid == 0 {
            // Safety: This is the isolated tracer child. It does not return to Rust code.
            unsafe {
                libc::close(event_pipe[0]);
                libc::close(gate_pipe[1]);
                libc::close(ready_pipe[0]);
                tracer_child(
                    libc::getppid(),
                    initial_tids.as_ptr(),
                    initial_tids.len(),
                    control.pointer.as_ptr(),
                    event_pipe[1],
                    gate_pipe[0],
                    ready_pipe[1],
                );
            }
        }

        // Safety: These descriptors are owned by this branch.
        unsafe {
            libc::close(event_pipe[1]);
            libc::close(gate_pipe[0]);
            libc::close(ready_pipe[1]);
        }
        // Safety: Authorization is restricted to the exact tracer child.
        let authorized = unsafe { libc::prctl(libc::PR_SET_PTRACER, child_pid, 0, 0, 0) } == 0;
        let gate = u8::from(authorized);
        // Safety: The descriptor and one-byte source are valid.
        let gate_written = unsafe { libc::write(gate_pipe[1], (&raw const gate).cast(), 1) } == 1;
        // Safety: This branch owns the descriptor.
        unsafe { libc::close(gate_pipe[1]) };
        if !authorized || !gate_written || !wait_ready(ready_pipe[0]) {
            // Safety: This branch owns the descriptor.
            unsafe { libc::close(ready_pipe[0]) };
            abort_install(child_pid, event_pipe[0]);
            return Err(());
        }
        // Safety: This branch owns the descriptor.
        unsafe { libc::close(ready_pipe[0]) };
        let threads_changed = enumerate_threads()
            .map(|current| current.iter().any(|tid| !initial_tids.contains(tid)))
            .unwrap_or(true);
        if threads_changed {
            abort_install(child_pid, event_pipe[0]);
            return Err(());
        }
        if control.state().tracer_alive.load(Ordering::SeqCst) != 1 {
            abort_install(child_pid, event_pipe[0]);
            return Err(());
        }
        Ok(Self {
            child_pid,
            control,
            event_read_fd: event_pipe[0],
            reaped: false,
        })
    }

    pub(super) fn drain(&mut self, output: &mut [Event]) -> usize {
        self.poll_child();
        let mut count = 0;
        while count < output.len() {
            let mut event = MaybeUninit::<Event>::uninit();
            // Safety: The destination has space for one complete fixed-size event.
            let bytes = unsafe {
                libc::read(
                    self.event_read_fd,
                    event.as_mut_ptr().cast(),
                    mem::size_of::<Event>(),
                )
            };
            if bytes != isize::try_from(mem::size_of::<Event>()).unwrap_or(isize::MAX) {
                break;
            }
            // Safety: A complete event was read from the tracer pipe.
            output[count] = unsafe { event.assume_init() };
            self.control
                .state()
                .queued_events
                .fetch_sub(1, Ordering::SeqCst);
            count += 1;
        }
        count
    }

    pub(super) fn is_healthy(&mut self) -> bool {
        self.poll_child();
        !self.reaped
            && self.control.state().tracer_alive.load(Ordering::SeqCst) == 1
            && self.control.state().overflowed.load(Ordering::SeqCst) == 0
    }

    pub(super) fn sequence(&self) -> u64 {
        self.control.state().sequence.load(Ordering::SeqCst)
    }

    pub(super) fn ignore_current_thread(&self) -> Option<IgnoreGuard> {
        let tid = current_thread_id();
        let state = self.control.state();
        for slot in 0..MAX_IGNORED_THREADS {
            if state.ignored_tids[slot].load(Ordering::SeqCst) == tid {
                state.ignored_depths[slot].fetch_add(1, Ordering::SeqCst);
                return Some(IgnoreGuard {
                    control: self.control.clone(),
                    slot,
                });
            }
        }
        for slot in 0..MAX_IGNORED_THREADS {
            if state.ignored_tids[slot]
                .compare_exchange(0, tid, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                state.ignored_depths[slot].store(1, Ordering::SeqCst);
                return Some(IgnoreGuard {
                    control: self.control.clone(),
                    slot,
                });
            }
        }
        state.overflowed.store(1, Ordering::SeqCst);
        None
    }

    fn poll_child(&mut self) {
        if self.reaped {
            return;
        }
        let mut status = 0;
        // Safety: The PID identifies only the tracer child.
        let result = unsafe { libc::waitpid(self.child_pid, &raw mut status, libc::WNOHANG) };
        if result == self.child_pid || result < 0 {
            self.reaped = true;
            self.control.state().tracer_alive.store(0, Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    pub(super) fn terminate_tracer_for_test(&mut self) {
        if !self.reaped {
            // Safety: The PID identifies only the tracer child created by this runtime.
            unsafe { libc::kill(self.child_pid, libc::SIGKILL) };
            for _ in 0..SHUTDOWN_POLLS {
                self.poll_child();
                if self.reaped {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if !self.reaped {
            // Safety: Killing the tracer causes Linux to detach every tracee without changing
            // their pending syscall results.
            unsafe { libc::kill(self.child_pid, libc::SIGTERM) };
            for _ in 0..SHUTDOWN_POLLS {
                self.poll_child();
                if self.reaped {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            if !self.reaped {
                // Safety: The PID identifies only the bounded tracer child.
                unsafe {
                    libc::kill(self.child_pid, libc::SIGKILL);
                    libc::waitpid(self.child_pid, std::ptr::null_mut(), 0);
                }
                self.reaped = true;
            }
        }
        self.control.state().tracer_alive.store(0, Ordering::SeqCst);
        // Safety: This instance owns the descriptor and authorization scope.
        unsafe {
            libc::close(self.event_read_fd);
            libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0);
        }
    }
}

pub(super) fn current_thread_id() -> i32 {
    // Safety: `gettid` has no pointer arguments.
    let value = unsafe { libc::syscall(libc::SYS_gettid) };
    i32::try_from(value).unwrap_or(0)
}

fn enumerate_threads() -> Result<Vec<libc::pid_t>, ()> {
    let mut tids = Vec::new();
    for entry in fs::read_dir("/proc/self/task").map_err(|_| ())? {
        if tids.len() >= MAX_TRACED_THREADS {
            return Err(());
        }
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name();
        let tid = name
            .to_str()
            .ok_or(())?
            .parse::<libc::pid_t>()
            .map_err(|_| ())?;
        tids.push(tid);
    }
    if tids.is_empty() {
        return Err(());
    }
    tids.sort_unstable();
    Ok(tids)
}

fn create_pipe(flags: libc::c_int) -> Result<[RawFd; 2], ()> {
    let mut descriptors = [-1; 2];
    // Safety: The array has exactly two descriptor slots.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), flags) } != 0 {
        return Err(());
    }
    Ok(descriptors)
}

fn close_pipe(pipe: [RawFd; 2]) {
    // Safety: These descriptors are owned by the failed installation path.
    unsafe {
        libc::close(pipe[0]);
        libc::close(pipe[1]);
    }
}

fn abort_install(child_pid: libc::pid_t, event_read_fd: RawFd) {
    // Safety: The PID and descriptor belong to this failed installation.
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
        libc::waitpid(child_pid, std::ptr::null_mut(), 0);
        libc::close(event_read_fd);
        libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0);
    }
}

fn wait_ready(ready_fd: RawFd) -> bool {
    let mut descriptor = libc::pollfd {
        fd: ready_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // Safety: The poll descriptor remains valid for the bounded wait.
    if unsafe { libc::poll(&raw mut descriptor, 1, STARTUP_WAIT_MS) } != 1 {
        return false;
    }
    let mut ready = 0_u8;
    // Safety: The descriptor and one-byte destination are valid.
    (unsafe { libc::read(ready_fd, (&raw mut ready).cast(), 1) }) == 1 && ready == 1
}

#[repr(C)]
struct SyscallInfo {
    operation: u8,
    padding: [u8; 3],
    architecture: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u64; 8],
}

unsafe fn tracer_child(
    target_pid: libc::pid_t,
    initial_tids: *const libc::pid_t,
    initial_count: usize,
    shared: *mut SharedState,
    event_fd: RawFd,
    gate_fd: RawFd,
    ready_fd: RawFd,
) -> ! {
    let mut gate = 0_u8;
    // Safety: All pointers and descriptors come from mappings and pipes created before fork.
    if unsafe { libc::read(gate_fd, (&raw mut gate).cast(), 1) } != 1 || gate != 1 {
        unsafe { libc::_exit(2) };
    }
    unsafe { libc::close(gate_fd) };
    if initial_count == 0 || initial_count > MAX_TRACED_THREADS {
        unsafe { libc::_exit(3) };
    }
    let mut tids = [0_i32; MAX_TRACED_THREADS];
    let mut tid_count = initial_count;
    for (index, slot) in tids[..initial_count].iter_mut().enumerate() {
        *slot = unsafe { *initial_tids.add(index) };
        if unsafe {
            libc::ptrace(
                PTRACE_SEIZE,
                *slot,
                std::ptr::null_mut::<libc::c_void>(),
                TRACE_OPTIONS as usize as *mut libc::c_void,
            )
        } != 0
        {
            unsafe { libc::_exit(4) };
        }
    }
    for tid in &tids[..tid_count] {
        if unsafe {
            libc::ptrace(
                PTRACE_INTERRUPT,
                *tid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        } != 0
        {
            unsafe { libc::_exit(5) };
        }
    }
    let mut stopped = 0;
    while stopped < tid_count {
        let mut status = 0;
        if unsafe { libc::waitpid(-1, &raw mut status, WAIT_ALL) } <= 0 {
            unsafe { libc::_exit(6) };
        }
        if libc::WIFSTOPPED(status) {
            stopped += 1;
        }
    }
    unsafe { (*shared).tracer_alive.store(1, Ordering::SeqCst) };
    let ready = 1_u8;
    if unsafe { libc::write(ready_fd, (&raw const ready).cast(), 1) } != 1 {
        unsafe { libc::_exit(7) };
    }
    unsafe { libc::close(ready_fd) };
    for tid in &tids[..tid_count] {
        resume_syscall(*tid, 0);
    }

    loop {
        let mut status = 0;
        let tid = unsafe { libc::waitpid(-1, &raw mut status, WAIT_ALL) };
        if tid < 0 {
            unsafe { (*shared).tracer_alive.store(0, Ordering::SeqCst) };
            unsafe { libc::_exit(0) };
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            remove_tid(&mut tids, &mut tid_count, tid);
            if tid_count == 0 || tid == target_pid {
                unsafe { (*shared).tracer_alive.store(0, Ordering::SeqCst) };
                unsafe { libc::_exit(0) };
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        if signal == (libc::SIGTRAP | 0x80) {
            trace_syscall_entry(tid, shared, event_fd);
            resume_syscall(tid, 0);
            continue;
        }
        match event {
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE => {
                emit_event(tid, EventKind::Process, shared, event_fd);
                let mut new_tid = 0_u64;
                if unsafe {
                    libc::ptrace(
                        PTRACE_GETEVENTMSG,
                        tid,
                        std::ptr::null_mut::<libc::c_void>(),
                        (&raw mut new_tid).cast::<libc::c_void>(),
                    )
                } == 0
                {
                    let new_tid = i32::try_from(new_tid).unwrap_or(0);
                    if new_tid <= 0 || !add_tid(&mut tids, &mut tid_count, new_tid) {
                        unsafe { (*shared).overflowed.store(1, Ordering::SeqCst) };
                    }
                } else {
                    unsafe { (*shared).overflowed.store(1, Ordering::SeqCst) };
                }
                resume_syscall(tid, 0);
            }
            PTRACE_EVENT_EXEC => {
                emit_event(tid, EventKind::Process, shared, event_fd);
                resume_syscall(tid, 0);
            }
            PTRACE_EVENT_EXIT => {
                emit_event(tid, EventKind::Exit, shared, event_fd);
                resume_syscall(tid, 0);
            }
            PTRACE_EVENT_STOP if signal != libc::SIGTRAP => unsafe {
                libc::ptrace(
                    libc::PTRACE_LISTEN,
                    tid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
            },
            _ => resume_syscall(tid, signal),
        }
    }
}

fn resume_syscall(tid: libc::pid_t, signal: libc::c_int) {
    // Safety: The tracer owns this stopped tracee and preserves real signal delivery.
    unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            tid,
            std::ptr::null_mut::<libc::c_void>(),
            signal as usize as *mut libc::c_void,
        );
    }
}

fn trace_syscall_entry(tid: libc::pid_t, shared: *mut SharedState, event_fd: RawFd) {
    let mut info = MaybeUninit::<SyscallInfo>::zeroed();
    // Safety: The tracer owns the stopped tracee. The kernel writes only the fixed buffer size.
    let bytes = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            tid,
            mem::size_of::<SyscallInfo>(),
            info.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    if bytes < 0 {
        unsafe { (*shared).overflowed.store(1, Ordering::SeqCst) };
        return;
    }
    // Safety: A nonnegative result initializes the fixed header and entry number.
    let info = unsafe { info.assume_init() };
    if info.operation != PTRACE_SYSCALL_INFO_ENTRY || is_ignored(tid, shared) {
        return;
    }
    if let Some(kind) = classify_syscall(info.data[0] as libc::c_long) {
        emit_event(tid, kind, shared, event_fd);
    }
}

fn emit_event(tid: i32, kind: EventKind, shared: *mut SharedState, event_fd: RawFd) {
    // Safety: The mapping remains valid until the tracer exits.
    let state = unsafe { &*shared };
    if state.overflowed.load(Ordering::SeqCst) != 0 {
        return;
    }
    let queued = state.queued_events.fetch_add(1, Ordering::SeqCst);
    if queued >= MAX_QUEUED_EVENTS {
        state.queued_events.fetch_sub(1, Ordering::SeqCst);
        state.overflowed.store(1, Ordering::SeqCst);
        return;
    }
    let sequence = state.sequence.fetch_add(1, Ordering::SeqCst);
    if sequence >= MAX_TOTAL_EVENTS {
        state.queued_events.fetch_sub(1, Ordering::SeqCst);
        state.overflowed.store(1, Ordering::SeqCst);
        return;
    }
    let event = Event {
        thread_id: tid,
        kind,
        padding: [0; 3],
        sequence: sequence + 1,
    };
    // Safety: The event is fixed size, smaller than PIPE_BUF, and contains no pointers.
    let bytes =
        unsafe { libc::write(event_fd, (&raw const event).cast(), mem::size_of::<Event>()) };
    if bytes != isize::try_from(mem::size_of::<Event>()).unwrap_or(isize::MAX) {
        state.queued_events.fetch_sub(1, Ordering::SeqCst);
        state.overflowed.store(1, Ordering::SeqCst);
    }
}

fn is_ignored(tid: i32, shared: *mut SharedState) -> bool {
    // Safety: The mapping remains valid until the tracer exits.
    let state = unsafe { &*shared };
    (0..MAX_IGNORED_THREADS).any(|slot| {
        state.ignored_depths[slot].load(Ordering::SeqCst) > 0
            && state.ignored_tids[slot].load(Ordering::SeqCst) == tid
    })
}

fn add_tid(tids: &mut [i32; MAX_TRACED_THREADS], count: &mut usize, tid: i32) -> bool {
    if tids[..*count].contains(&tid) {
        return true;
    }
    if *count >= MAX_TRACED_THREADS {
        return false;
    }
    tids[*count] = tid;
    *count += 1;
    true
}

fn remove_tid(tids: &mut [i32; MAX_TRACED_THREADS], count: &mut usize, tid: i32) {
    let Some(index) = tids[..*count].iter().position(|entry| *entry == tid) else {
        return;
    };
    *count -= 1;
    tids[index] = tids[*count];
    tids[*count] = 0;
}

#[allow(clippy::too_many_lines)]
fn classify_syscall(number: libc::c_long) -> Option<EventKind> {
    if matches!(
        number,
        libc::SYS_read
            | libc::SYS_pread64
            | libc::SYS_readv
            | libc::SYS_preadv
            | libc::SYS_preadv2
            | libc::SYS_openat
            | libc::SYS_openat2
            | libc::SYS_fstat
            | libc::SYS_newfstatat
            | libc::SYS_statx
            | libc::SYS_faccessat
            | libc::SYS_faccessat2
            | libc::SYS_readlinkat
            | libc::SYS_getdents64
    ) || is_legacy_filesystem_syscall(number)
    {
        return Some(EventKind::Filesystem);
    }
    if matches!(
        number,
        libc::SYS_socket
            | libc::SYS_socketpair
            | libc::SYS_connect
            | libc::SYS_accept
            | libc::SYS_accept4
            | libc::SYS_sendto
            | libc::SYS_recvfrom
            | libc::SYS_sendmsg
            | libc::SYS_recvmsg
            | libc::SYS_sendmmsg
            | libc::SYS_recvmmsg
    ) {
        return Some(EventKind::Network);
    }
    if matches!(
        number,
        libc::SYS_clock_gettime
            | libc::SYS_clock_getres
            | libc::SYS_gettimeofday
            | libc::SYS_clock_nanosleep
            | libc::SYS_nanosleep
    ) || is_legacy_clock_syscall(number)
    {
        return Some(EventKind::Clock);
    }
    (number == libc::SYS_getrandom).then_some(EventKind::Randomness)
}

#[cfg(target_arch = "x86_64")]
const fn is_legacy_filesystem_syscall(number: libc::c_long) -> bool {
    matches!(
        number,
        libc::SYS_open
            | libc::SYS_creat
            | libc::SYS_stat
            | libc::SYS_lstat
            | libc::SYS_access
            | libc::SYS_readlink
            | libc::SYS_getdents
    )
}

#[cfg(not(target_arch = "x86_64"))]
const fn is_legacy_filesystem_syscall(_: libc::c_long) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
const fn is_legacy_clock_syscall(number: libc::c_long) -> bool {
    number == libc::SYS_time
}

#[cfg(not(target_arch = "x86_64"))]
const fn is_legacy_clock_syscall(_: libc::c_long) -> bool {
    false
}
