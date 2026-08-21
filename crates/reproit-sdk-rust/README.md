# Repro It SDK for Rust

Install the official crate from your Repro It release bundle or internal Cargo source.

Use `OfficialManagedProject` for the reviewed project and source revision. Start one
`OfficialManagedRustOperation` for each accepted unit of work. Record its inputs and observed
dependencies. Mark successful operations as successful. Submit a failure only after its World
closure is complete.

The base crate is framework-neutral. Add `reproit-sdk-rust-axum` only when you need the Axum
request adapter. The SDK does not require a sidecar, container engine, orchestrator, or container
socket.

See the [Rust guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md) for source
verification and release behavior.
