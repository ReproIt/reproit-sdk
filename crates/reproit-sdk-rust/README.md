# Repro It SDK for Rust

Use this SDK at one supported Backend operation boundary. The SDK keeps bounded records. It sends
only complete failed operations to managed Repro It Cloud.

```sh
cargo add reproit-sdk-rust@1.0.0
```

The framework-neutral API supports request-response, ordered-stream, and delivered-work
operations. Use `reproit-sdk-rust-axum` for the optional Axum adapter.

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
