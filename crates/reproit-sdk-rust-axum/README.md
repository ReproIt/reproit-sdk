# Repro It Axum adapter

Connect the Rust SDK to an Axum request-response boundary.

```sh
cargo add reproit-sdk-rust@1.0.0 reproit-sdk-rust-axum@1.0.0
```

Create one `OfficialManagedProject`. Then configure `OfficialAxumRequestCapture` and add
`capture_official_axum_request` with `axum::middleware::from_fn_with_state`.

The adapter records the request and response boundary. Dependency adapters use
`OfficialAxumOperationContext` from the request extensions. Use the base SDK for streams, delivered
work, other frameworks, and direct operation capture.

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
