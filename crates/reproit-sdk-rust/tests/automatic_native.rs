#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod support;

#[cfg(target_os = "linux")]
mod linux {
    use super::support;

    use reproit_core::ErrorCode;
    use reproit_sdk_rust::{
        AutomaticManagedEngine, OfficialManagedProject, TriggerCompletion,
        package_running_rust_subject,
    };

    const PROJECT: &str = r#"
format = 1
organization_id = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd"
profile = "backend"
profile_format = 1
processing_mode = "managed"
project_id = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"
repository_id = "source.example/acme/commerce"
sdk = "rust"
service_id = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
service_path = "services/orders"

[run]
arguments = ["serve"]
program = "orders"
working_directory = "services/orders"

[source]
remote = "origin"
"#;
    const REPOSITORY_ID: &str = "source.example/acme/commerce";
    const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    pub(super) fn run() {
        if include_str!("../src/official_managed.rs")
            .contains("__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__")
        {
            return;
        }
        clean_operation_closes_with_all_native_guards();
        unowned_filesystem_effect_keeps_the_operation_incomplete();
        println!("automatic Rust native checks passed");
    }

    fn clean_operation_closes_with_all_native_guards() {
        let engine = engine();
        let fixture = support::fixture();
        let mut operation = engine.start(&fixture.begin).expect("start operation");
        operation
            .record_input(&fixture.input)
            .expect("record input");
        operation
            .close_world(TriggerCompletion::Return)
            .expect("close a clean World");
        operation.succeed();
    }

    fn unowned_filesystem_effect_keeps_the_operation_incomplete() {
        let engine = engine();
        let fixture = support::fixture();
        let mut operation = engine.start(&fixture.begin).expect("start operation");
        std::fs::read("/proc/version").expect("read one unowned file");
        let error = operation
            .close_world(TriggerCompletion::Return)
            .expect_err("reject an unowned filesystem effect");
        assert_eq!(error.code, ErrorCode::WorldNotClosed);
        operation.abandon_incomplete();
    }

    fn engine() -> AutomaticManagedEngine {
        let project = OfficialManagedProject::from_build(PROJECT, REPOSITORY_ID, SOURCE_REVISION)
            .expect("bind the managed project");
        let subject = package_running_rust_subject().expect("package the running test subject");
        AutomaticManagedEngine::new(project, subject)
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
