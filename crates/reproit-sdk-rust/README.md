# Repro It SDK for Rust

Use this SDK at one supported Backend operation boundary. The SDK keeps bounded records. It sends
only complete failed operations to managed Repro It Cloud.

```sh
cargo add reproit-sdk-rust@1.0.0
```

The framework-neutral API supports request-response, ordered-stream, and delivered-work
operations. Use `reproit-sdk-rust-axum` for the optional Axum adapter.

`AutomaticReplayOperation` reads a sealed automatic World through the shared Core
resolver. Run the application operation inside its context. Call `finish` before
reporting a reproduced Failure or a passing check. Completion requires every
recorded observation and a clean native coverage trace. A changed request, an
unfinished observation, or a live unowned effect rejects replay.

The fuzzer sets `REPROIT_FUZZ_TARGET=1` when it starts the application. The SDK copies this
setting into failed captures as `fuzz-campaign` discovery provenance. A normal application run
does not set the variable, so its captures remain production captures.

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
