# Rust SDK

Use the Rust SDK at one supported Backend operation boundary.

The SDK installs package-owned guards for all seven World observation classes.
The guards use the shared Linux coverage sentinel. A failed operation can leave
the process only when the native trace is healthy and every kernel-visible effect
belongs to a supported semantic observation. An unowned effect or a trace gap
keeps the failure local.

## Install

```sh
cargo add reproit-sdk-rust@1.0.0
```

The SDK core exposes `RustOperationFactory` for framework-neutral operation capture. It supports
request-response, ordered-stream, and delivered-work operations.

For Axum, add the optional adapter:

```sh
cargo add reproit-sdk-rust-axum@1.0.0
```

The Axum adapter streams bounded request inputs and response observations through the same Rust
operation API. It does not buffer a complete request or response body.

`reproit init` accepts a direct `cargo run` application command. The internal
startup probe verifies that the Rust SDK and the Linux native sentinel are linked
before it stores the command. The public CLI does not add a Rust-specific run
command.

The SDK sends only complete failed operations to managed Repro It Cloud. It keeps successful,
incomplete, unsupported, and resource-limited operations local.

## Verify SDK source

```sh
./tools/with-core.sh cargo test --workspace --all-targets --locked
./tools/with-core.sh cargo clippy --workspace --all-targets --locked -- -D warnings
```
