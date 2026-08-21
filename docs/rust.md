# Rust SDK

## Install

Add the released `reproit-sdk-rust` package from the local release bundle or your internal Cargo
source. Add `reproit-sdk-rust-axum` only when you use its Axum request adapter.

The base package does not require Axum or another web framework.

## Integrate

Create one `OfficialManagedProject` from the reviewed project binding and exact source revision.
Start one `OfficialManagedRustOperation` for each accepted operation. Record its inputs and observed
dependency results. Call `succeed` for a successful operation. Call `fail` only after the World
closure is complete.

Source checkouts contain sentinel managed bindings. They reject official operation setup with
`CONFIG_CONFLICT`. Use an official release package for a real managed capture.

## Verify

```sh
./tools/with-core.sh cargo test --workspace --all-targets --locked
./tools/with-core.sh cargo clippy --workspace --all-targets --locked -- -D warnings
```
