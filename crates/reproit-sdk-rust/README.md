# Repro It SDK for Rust

Capture failed Backend operations from a Rust application.

```sh
cargo add reproit-sdk-rust@1.0.0
```

Run `reproit init` and create one `ReproIt` value during application setup. Call `ReproIt::run`
inside the top-level framework handler. The same call works with any Rust framework or runtime.

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
