# Repro It SDK for Rust

Capture failed Backend operations from a Rust application.

```sh
cargo add reproit-sdk-rust@1.0.0
```

Run `reproit init`. Then create `ReproIt::init()` once. Call `operation` at each top-level
application boundary. The API does not depend on a web framework.

Read the [Rust integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/rust.md).
