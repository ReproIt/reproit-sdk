#![allow(clippy::duplicate_mod, dead_code, unused_imports)]

#[cfg(target_os = "linux")]
#[path = "../src/sentinel_linux.rs"]
mod sentinel_linux;

#[cfg(target_os = "linux")]
#[path = "../src/sentinel.rs"]
mod sentinel_controller;

#[cfg(target_os = "linux")]
use std::{fs, thread, time::Duration};

#[cfg(target_os = "linux")]
use sentinel_linux::{Event, EventKind, Runtime};

#[cfg(target_os = "linux")]
fn main() {
    semantic_dependencies_own_their_transitive_kernel_effects();
    clean_syscall_trace_produces_bounded_evidence();
    finished_operation_releases_its_sentinel_state();
    detects_unowned_randomness_without_reading_arguments();
    tracks_clone_events();
    queue_overflow_makes_the_runtime_unhealthy();
    tracer_loss_preserves_application_results();
    clean_shutdown_preserves_application_results_and_reaps_the_child();
    println!("sentinel native checks passed");
}

#[cfg(target_os = "linux")]
fn semantic_dependencies_own_their_transitive_kernel_effects() {
    use reproit_core::model::AutomaticObservationClass;

    for class in [
        AutomaticObservationClass::Database,
        AutomaticObservationClass::OutboundHttp,
        AutomaticObservationClass::Queue,
    ] {
        assert!(EventKind::Filesystem.is_owned_by(class));
        assert!(EventKind::Network.is_owned_by(class));
        assert!(EventKind::Clock.is_owned_by(class));
        assert!(EventKind::Randomness.is_owned_by(class));
    }
    assert!(EventKind::Filesystem.is_owned_by(AutomaticObservationClass::Filesystem));
    assert!(EventKind::Clock.is_owned_by(AutomaticObservationClass::Clock));
    assert!(EventKind::Randomness.is_owned_by(AutomaticObservationClass::Randomness));
    assert!(!EventKind::Network.is_owned_by(AutomaticObservationClass::Filesystem));
    assert!(!EventKind::Process.is_owned_by(AutomaticObservationClass::Database));
}

#[cfg(target_os = "linux")]
fn finished_operation_releases_its_sentinel_state() {
    use sentinel_controller::OperationCoverage;

    sentinel_controller::engine_opened();
    let guard = sentinel_controller::engine_call_scope();
    sentinel_controller::operation_started(9_002);
    let _coverage = sentinel_controller::operation_finished(9_002);
    assert_eq!(
        sentinel_controller::operation_finished(9_002),
        OperationCoverage::Incomplete
    );
    drop(guard);
    sentinel_controller::engine_closed();
}

#[cfg(target_os = "linux")]
fn clean_syscall_trace_produces_bounded_evidence() {
    use sentinel_controller::OperationCoverage;

    sentinel_controller::engine_opened();
    let guard = sentinel_controller::engine_call_scope();
    sentinel_controller::operation_started(9_001);
    drop(guard);
    let guard = sentinel_controller::engine_call_scope();
    let coverage = sentinel_controller::operation_finished(9_001);
    drop(guard);
    let OperationCoverage::CleanKernelTrace(evidence) = coverage else {
        panic!("a clean native trace must produce coverage evidence");
    };
    assert_eq!(evidence.encode().len(), 40);
    sentinel_controller::engine_closed();
}

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn detects_unowned_randomness_without_reading_arguments() {
    let mut runtime = Runtime::install().expect("the native sentinel must install");
    drain(&mut runtime);
    let mut bytes = [0_u8; 16];
    assert_eq!(getrandom(&mut bytes), bytes.len());
    let events = wait_for_events(&mut runtime);
    assert!(
        events
            .iter()
            .any(|event| event.kind == EventKind::Randomness)
    );
}

#[cfg(target_os = "linux")]
fn tracks_clone_events() {
    let mut runtime = Runtime::install().expect("the native sentinel must install");
    drain(&mut runtime);
    thread::spawn(|| 7_u8)
        .join()
        .expect("the application thread must preserve its result");
    let events = wait_for_events(&mut runtime);
    assert!(events.iter().any(|event| event.kind == EventKind::Process));
}

#[cfg(target_os = "linux")]
fn queue_overflow_makes_the_runtime_unhealthy() {
    let mut runtime = Runtime::install().expect("the native sentinel must install");
    drain(&mut runtime);
    let mut byte = [0_u8; 1];
    for _ in 0..4_097 {
        assert_eq!(getrandom(&mut byte), 1);
    }
    let guard = runtime.ignore_current_thread();
    assert!(!runtime.is_healthy());
    drop(guard);
}

#[cfg(target_os = "linux")]
fn tracer_loss_preserves_application_results() {
    let path = "/proc/version";
    let expected = fs::read(path).expect("the control read must succeed");
    let mut runtime = Runtime::install().expect("the native sentinel must install");
    runtime.terminate_tracer_for_test();
    assert_eq!(
        fs::read(path).expect("the read after tracer loss must succeed"),
        expected
    );
    assert!(!runtime.is_healthy());
}

#[cfg(target_os = "linux")]
fn clean_shutdown_preserves_application_results_and_reaps_the_child() {
    let path = "/proc/version";
    let expected = fs::read(path).expect("the control read must succeed");
    let runtime = Runtime::install().expect("the native sentinel must install");
    drop(runtime);
    assert_eq!(
        fs::read(path).expect("the read after detach must succeed"),
        expected
    );
}

#[cfg(target_os = "linux")]
fn getrandom(output: &mut [u8]) -> usize {
    // Safety: The output pointer and byte length describe a valid writable buffer.
    let result =
        unsafe { libc::syscall(libc::SYS_getrandom, output.as_mut_ptr(), output.len(), 0) };
    usize::try_from(result).expect("getrandom must preserve its application result")
}

#[cfg(target_os = "linux")]
fn drain(runtime: &mut Runtime) -> Vec<Event> {
    let guard = runtime.ignore_current_thread();
    let mut all = Vec::new();
    let mut events = [Event::default(); 64];
    loop {
        let count = runtime.drain(&mut events);
        all.extend_from_slice(&events[..count]);
        if count < events.len() {
            break;
        }
    }
    drop(guard);
    all
}

#[cfg(target_os = "linux")]
fn wait_for_events(runtime: &mut Runtime) -> Vec<Event> {
    for _ in 0..500 {
        let events = drain(runtime);
        if !events.is_empty() {
            return events;
        }
        thread::sleep(Duration::from_millis(1));
    }
    Vec::new()
}
