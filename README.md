# Repro It SDKs

This repository contains the five Backend SDK cores and the optional Rust Axum adapter.

| Language | Package | Setup |
| --- | --- | --- |
| Rust | `reproit-sdk-rust` | [Rust](docs/rust.md) |
| Rust Axum | `reproit-sdk-rust-axum` | [Rust](docs/rust.md) |
| Python | `reproit-sdk` | [Python](docs/python.md) |
| Go | `reproit.dev/sdk-go` | [Go](docs/go.md) |
| Node.js | `@reproit/sdk` | [Node.js](docs/node.md) |
| .NET | `ReproIt.Sdk` | [.NET](docs/dotnet.md) |

Each SDK core exposes the same framework-neutral operation model. An operation can use a
request-response, ordered-stream, or delivered-work Trigger. The Axum package translates Axum
request and response streams to the Rust operation model. It does not own capture policy.

The public packages support managed capture only. They send no successful or incomplete
operation to Repro It Cloud. A capture error or Cloud outage does not change the application
result.

All five SDKs implement the same distributed fuzz context boundary. Inbound HTTP
adapters validate `ReproIt-Fuzz-Context`. Delivered-work adapters validate
`reproit.fuzz.context`. Outbound adapters propagate the active signed context
and causal parent operation. An invalid fuzz context stays incomplete and never
becomes a production capture.

The SDK does not start or control a fuzz campaign. `reproit-fuzzer` owns search
and target control. The SDK only records bounded campaign provenance on eligible
captures.

Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store. Do not put the token in
tracked configuration. The SDK works in a host process or an OCI container. It does not require a
container engine, sidecar, orchestrator, or container control socket.

Read the [platform architecture](docs/platforms.md) for the native target matrix,
provider boundary, and replay compatibility rules.

## Maintain the SDKs

This repository pins the shared contract revision in `core-pin.json`. Run the local checks with:

```sh
./tools/test.sh
```

Run the native Linux package matrix with:

```sh
./tools/with-core.sh ./conformance/sdk/run.sh
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you change behavior shared by the five SDKs.
