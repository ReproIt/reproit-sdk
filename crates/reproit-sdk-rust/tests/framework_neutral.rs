use std::{error::Error, fmt, sync::Arc};

use reproit_sdk_rust::ReproIt;

#[derive(Debug)]
struct ApplicationError;

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("customer failure")
    }
}

impl Error for ApplicationError {}

#[test]
fn operation_preserves_the_exact_application_error() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build the test runtime");
    let original = Arc::new(ApplicationError);
    let returned = original.clone();
    let observed = runtime
        .block_on(ReproIt::init().operation(
            "todos.create",
            br#"{"title":"trigger-bug"}"#,
            || async { Err::<(), _>(returned) },
        ))
        .expect_err("return the application error");
    assert!(Arc::ptr_eq(&observed, &original));
}
