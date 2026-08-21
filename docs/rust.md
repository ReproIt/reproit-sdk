# Rust SDK

The Rust SDK captures Backend operations from any Rust framework or runtime.

## Install

```sh
cargo add reproit-sdk-rust@1.0.0
```

No framework package, Runtime, sidecar, or container socket is required.

## Start capture

Create one `ReproIt` value when the process starts. `reproit init` supplies the reviewed project
file. The build supplies the repository identity and deployed Git revision.

```rust
use reproit_sdk_rust::{Error, ReproIt};

let reproit = ReproIt::from_build(
    include_str!("../.reproit/project.toml"),
    BUILD_REPOSITORY_ID,
    SOURCE_REVISION,
    capture_world,
)?;
```

`capture_world` returns a `ManagedWorldCapture`. It captures the initial World before the operation.
Its completion callback closes the same World after a Failure.

## Wrap an operation

Call `run` inside the top-level framework handler. The same call works in Axum, Actix Web, Rocket,
Warp, a stream consumer, a queue worker, or application code.

```rust
let result = reproit
    .run(
        "orders.create",
        "application/json",
        &request_body,
        |capture| async move {
            dependencies.run_with(capture, || create_order(request_body)).await
        },
        classify_failure,
    )
    .await;
```

The SDK reads `REPROIT_MANAGED_PROJECT_TOKEN` only after a complete Failure. A successful or
incomplete operation makes no Cloud request. A capture error does not change `result`.

Use `run_stream` or `run_delivered_work` for those operation types. Use
`OperationCapture::record_dependency` from a dependency adapter. Application handlers do not
construct capture IDs, deployments, protocol records, endpoints, signers, or candidate sinks.

## Verify SDK source

```sh
./tools/with-core.sh cargo test --workspace --all-targets --locked
./tools/with-core.sh cargo clippy --workspace --all-targets --locked -- -D warnings
```
