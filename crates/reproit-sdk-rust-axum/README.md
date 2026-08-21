# Repro It Axum adapter

This crate connects the Repro It Rust SDK to an Axum request-response boundary. It preserves the
application response when capture setup, recording, classification, or candidate handoff fails.

Install it with the official `reproit-sdk-rust` crate from the same release bundle. The base Rust
SDK remains framework-neutral.
