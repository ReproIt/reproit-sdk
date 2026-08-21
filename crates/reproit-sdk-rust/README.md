# Repro It SDK for Rust

Capture failed Backend operations from a Rust application.

Install this crate from the release directory that `reproit init` shows. Use
`OfficialManagedProject` during application setup. Use `OfficialManagedRustOperation` at each
top-level operation boundary.

The base crate supports request-response, ordered-stream, and delivered-work operations. Add
`reproit-sdk-rust-axum` for an Axum request adapter.

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
