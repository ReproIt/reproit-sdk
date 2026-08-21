# Repro It SDK for Rust

Capture failed Backend operations from a Rust application.

```sh
cargo add reproit-sdk-rust@1.0.0
```

Run `reproit init`, create one `OfficialManagedProject` during application setup, and wrap each
top-level operation. The base API supports request-response, ordered-stream, and delivered-work
operations.

Add `reproit-sdk-rust-axum` for Axum middleware:

```sh
cargo add reproit-sdk-rust-axum@1.0.0
```

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
