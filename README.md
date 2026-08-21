# Repro It SDK

Use a Repro It SDK to capture failed backend operations in a running application. The SDK records
the operation that your application already handles. It sends only complete failures to managed
Repro It.

Choose the SDK for your application:

- [Rust](docs/rust.md), with an optional Axum adapter
- [Python](docs/python.md), with an optional ASGI adapter
- [Go](docs/go.md), with `net/http` support
- [Node.js](docs/node.md), with HTTP support
- [.NET](docs/dotnet.md), with an optional ASP.NET Core adapter

Each SDK supports request-response, ordered-stream, and delivered-work operations. The core API is
framework-neutral and container-neutral. You can run the SDK in a normal process or in an OCI
container. It does not require a sidecar, container engine, orchestrator, or container socket.

## How capture works

1. Start one SDK operation at the boundary where your application accepts work.
2. Record each input and dependency result that can affect the outcome.
3. Mark successful operations as successful. The SDK deletes their records.
4. On failure, close the observed World and submit the complete failed operation.

The SDK has fixed limits for records, bytes, operations, and queued failures. A capture failure or
managed-service outage does not change application behavior.

## Managed releases

Official release packages contain the managed HTTPS origin and capture signer identity. Source
packages fail closed until release construction installs valid production bindings. Applications do
not select a Cloud endpoint or signer key.

Release packages install from local files or an internal package source. A named public package
registry is not required.

## Shared contracts

[Repro It Core](https://github.com/ReproIt/reproit-core) is the source of truth for shared protocol
types, schemas, and conformance vectors. This repository pins one exact Core commit in
`core-pin.json`. It does not copy or redefine those contracts.

## Verify the repository

The complete local check fetches the pinned Core commit into the ignored `.core` directory. It then
runs the Rust, Python, Go, Node.js, and .NET checks that are available on the host.

Install Git, Rust, Python 3.14 with `uv`, Go 1.26, and Node.js 24. Install .NET 10 or run Docker for
the .NET check.

```sh
./tools/test.sh
```

Use the native container matrix on Linux ARM64 and Linux x86_64:

```sh
./tools/with-core.sh ./conformance/sdk/run.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before you change a shared SDK behavior.
