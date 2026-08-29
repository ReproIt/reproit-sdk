#![deny(clippy::all, clippy::pedantic)]
#![allow(unsafe_code)]

mod sentinel;

#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static RUST_CAPTURE_PROBE_INITIALIZER: extern "C" fn() = rust_capture_probe;

#[cfg(target_os = "linux")]
extern "C" fn rust_capture_probe() {
    use std::io::Write as _;

    if std::env::var("REPROIT_INTERNAL_CAPTURE_PROBE_SDK").as_deref() != Ok("rust") {
        return;
    }
    let Ok(nonce) = std::env::var("REPROIT_INTERNAL_CAPTURE_PROBE") else {
        std::process::exit(2);
    };
    let nonce_is_valid = nonce.len() == 64
        && nonce
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value));
    if !nonce_is_valid || !sentinel::platform_probe() {
        std::process::exit(2);
    }
    let output = format!("reproit.capture-probe.v1:rust:{nonce}\n");
    if std::io::stdout().write_all(output.as_bytes()).is_err() || std::io::stdout().flush().is_err()
    {
        std::process::exit(2);
    }
    std::process::exit(0);
}

pub use sentinel::{
    EngineCallGuard, KernelTraceEvidence, OperationCoverage, engine_call_scope, engine_closed,
    engine_opened, observation_dispatched, observation_finished, observation_is_active,
    observation_opened, operation_finished, operation_removed, operation_started, platform_probe,
};
