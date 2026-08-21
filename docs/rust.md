# Rust SDK

Use this SDK when a Rust application must capture a Backend operation.

## Install

Use the crate from the Repro It release directory that `reproit init` shows:

```sh
mkdir -p <sdk-directory>/reproit-sdk-rust
tar -xzf <release-directory>/reproit-sdk-rust-1.0.0.crate \
  -C <sdk-directory>/reproit-sdk-rust --strip-components=1
cargo add --path <sdk-directory>/reproit-sdk-rust
```

Add `reproit-sdk-rust-axum` from the same release when the application uses Axum.

## Configure

1. Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store.
2. Read `.reproit/project.toml` during application setup.
3. Get the repository identity and deployed Git revision from the build.
4. Call `OfficialManagedProject::from_build` once.

## Capture one operation

1. Capture the initial World with `ManagedRustCaptureClosure`.
2. Start `OfficialManagedRustOperation` with the operation begin payload.
3. Record each input and observed dependency result.
4. Call `succeed` when the operation succeeds.
5. Call `fail` with the Failure and a token callback when it fails.

The token callback must return `ManagedProjectToken::new(token)`. Keep the application result
independent from the capture result.

Use the Axum adapter only at an Axum request boundary. Use the base API for streams, delivered work,
other frameworks, and direct operation capture.

## Verify SDK source

```sh
./tools/with-core.sh cargo test --workspace --all-targets --locked
./tools/with-core.sh cargo clippy --workspace --all-targets --locked -- -D warnings
```
