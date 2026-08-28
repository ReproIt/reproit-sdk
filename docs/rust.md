# Rust SDK

Use the Rust SDK at one supported Backend operation boundary.

The current SDK release does not provide package-owned automatic observation
adapters. The CLI does not declare this SDK ready for automatic World capture.
The operation and Axum APIs remain available for SDK development and conformance
work.

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

The SDK sends only complete failed operations to managed Repro It Cloud. It keeps successful,
incomplete, unsupported, and resource-limited operations local.

## Verify SDK source

```sh
./tools/with-core.sh cargo test --workspace --all-targets --locked
./tools/with-core.sh cargo clippy --workspace --all-targets --locked -- -D warnings
```
