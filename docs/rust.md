# Rust SDK

The Rust SDK captures Backend operations from a Rust application.

## Install

Add the base SDK:

```sh
cargo add reproit-sdk-rust@1.0.0
```

Add the Axum adapter for an Axum application:

```sh
cargo add reproit-sdk-rust-axum@1.0.0
```

`reproit init` writes `.reproit/project.toml`. Store `REPROIT_MANAGED_PROJECT_TOKEN` in the
deployment secret store. Do not commit the token.

## Add Axum middleware

Create one `OfficialManagedProject` when the process starts. Then add the Repro It middleware at
the application request boundary.

```rust
use axum::{Router, middleware, routing::post};
use reproit_sdk_rust::{Error, OfficialManagedProject};
use reproit_sdk_rust_axum::{
    OfficialAxumRequestCapture,
    capture_official_axum_request,
};

fn build_app(
    project_toml: &str,
    repository_id: &str,
    source_revision: &str,
) -> Result<Router, Error> {
    let project = OfficialManagedProject::from_build(
        project_toml,
        repository_id,
        source_revision,
    )?;
    let capture = OfficialAxumRequestCapture::new(
        project,
        "orders.request",
        || capture_initial_world(),
        |_context, response| classify_orders_failure(response),
    )?;

    Ok(Router::new()
        .route("/orders", post(create_order))
        .route_layer(middleware::from_fn_with_state(
            capture,
            capture_official_axum_request,
        )))
}
```

The build supplies the canonical repository identity and the deployed Git revision. The
`capture_initial_world` function returns an `OfficialAxumWorldCapture`. Its completion callback
receives the exact operation ID and returns the closed `ManagedRustCaptureClosure` after a Failure.
The `classify_orders_failure` function returns a `FailureIdentity` only for a known incorrect
outcome.

The World capture has two parts. Capture the initial checkpoint before the request runs. Complete
the same capture after a Failure, when all dependency results are available.

```rust
use reproit_sdk_rust::{Error, ManagedRustCaptureClosure};
use reproit_sdk_rust_axum::OfficialAxumWorldCapture;

fn capture_initial_world() -> Result<OfficialAxumWorldCapture, Error> {
    let world = application_world_capture()?;
    let world_id = world.world_id()?;

    Ok(OfficialAxumWorldCapture::new(
        world_id,
        move |operation_id| -> Result<ManagedRustCaptureClosure, Error> {
            world.complete(operation_id)
        },
    ))
}
```

Dependency adapters can read `OfficialAxumOperationContext` from the request extensions. They call
`record_dependency` for each observed dependency result. A capture error must not change the HTTP
response or application error.

The middleware reads `REPROIT_MANAGED_PROJECT_TOKEN` only after it observes a Failure. A successful
request does not create or upload a candidate.

## Capture another operation type

Use `OfficialManagedRustOperation` for ordered streams, delivered work, another framework, or a
direct operation boundary. Record the Trigger input and dependency results. Call `succeed` for a
successful operation. Call `fail_with_operation_closure` only after the World closure is complete.

## Verify SDK source

```sh
./tools/with-core.sh cargo test --workspace --all-targets --locked
./tools/with-core.sh cargo clippy --workspace --all-targets --locked -- -D warnings
```
