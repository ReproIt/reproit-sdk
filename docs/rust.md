# Rust SDK

Add Repro It to a Rust application.

## Install

```sh
cargo add reproit-sdk-rust@1.0.0
```

Run `reproit init` in the application repository. Initialize the SDK once:

```rust
use reproit_sdk_rust::ReproIt;

let reproit = ReproIt::init();
```

Wrap one top-level application operation:

```rust
let todo = reproit
    .operation("todos.create", &input_bytes, || async { create_todo(input).await })
    .await?;
```

The SDK records a returned error as the Failure. It preserves the exact result. It does not import
a web framework.

## Verify SDK source

```sh
./tools/with-core.sh cargo test --workspace --all-targets --locked
./tools/with-core.sh cargo clippy --workspace --all-targets --locked -- -D warnings
```
