//! SDK-side processor capture.
//!
//! One narrow effectful adapter over the pure capture rule in
//! `reproit_core::model::processor_capture`. The SDK cannot depend on the
//! backend crate, so this glue reads the two `/proc` views itself and the
//! replay host keeps its own equally thin reader. Both call the one pure
//! rule pinned by `specs/v1/processor-capture.json`.

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use reproit_core::model;

/// Capture the process-visible processor view of this host as sorted
/// `processor.*` capability strings. A non-Linux host captures nothing. A
/// read failure captures nothing, because capture may only add real
/// information and a failed SDK must never change application behavior.
pub fn capture_processor_capabilities() -> Vec<String> {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let architecture = if cfg!(target_arch = "aarch64") {
            model::ProcessorArchitecture::Arm64
        } else {
            model::ProcessorArchitecture::X86_64
        };
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let hwcap = std::fs::read("/proc/self/auxv")
            .ok()
            .as_deref()
            .and_then(model::parse_auxv_hwcap);
        model::capture_processor_capabilities(architecture, &cpuinfo, hwcap).capabilities
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_is_sorted_unique_prefixed_and_bounded() {
        let captured = capture_processor_capabilities();
        let mut sorted = captured.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(captured, sorted);
        assert!(captured.iter().all(|value| value.starts_with("processor.")));
        assert!(captured.len() <= 64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_linux_host_captures_at_least_one_processor_capability() {
        assert!(!capture_processor_capabilities().is_empty());
    }
}
