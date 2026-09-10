# Repro It SDK for Rust

Use this SDK at one supported Backend operation boundary. The SDK keeps bounded records. It sends
only complete failed operations to managed Repro It Cloud.

```sh
cargo add reproit-sdk-rust@1.0.0
```

The framework-neutral API supports request-response, ordered-stream, and delivered-work
operations. Use `reproit-sdk-rust-axum` for the optional Axum adapter.

The fuzzer sets `REPROIT_FUZZ_TARGET=1` when it starts the application. The SDK copies this
setting into failed captures as `fuzz-campaign` discovery provenance. A normal application run
does not set the variable, so its captures remain production captures.

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
