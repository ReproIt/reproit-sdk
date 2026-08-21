# Repro It SDKs

Repro It SDKs capture failed production operations and the World that affected them. Managed Repro
It verifies each capture before it shows a Repro to your team.

## Add capture to an application

1. Install the [Repro It CLI](https://github.com/ReproIt/reproit-cli).
2. Run `reproit init` in the application repository.
3. Select the service and SDK.
4. Run the SDK package command shown by `reproit init`.
5. Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store.
6. Wrap each top-level operation with the SDK operation API.
7. Deploy the application and trigger the bug.

Choose the guide for your language:

| Language | Base package | Optional adapter | Guide |
| --- | --- | --- | --- |
| Rust | `reproit-sdk-rust` | Axum | [Rust](docs/rust.md) |
| Python | `reproit_sdk` | ASGI | [Python](docs/python.md) |
| Go | `reproit.dev/sdk-go/reproit` | `net/http` | [Go](docs/go.md) |
| Node.js | `@reproit/sdk` | Node.js HTTP | [Node.js](docs/node.md) |
| .NET | `ReproIt.Sdk` | ASP.NET Core | [.NET](docs/dotnet.md) |

The base APIs support request-response, ordered-stream, and delivered-work operations. They work in
a host process or an OCI container. Framework adapters call the same base APIs.

## Record an operation

The World contains everything that the operation observed that can change its result.

Record the input and each observed dependency result that can change the outcome. Mark a successful
operation as successful. Submit a failed operation only after the World closure is complete.

The SDK bounds records, bytes, active operations, and queued failures. A capture error keeps the
original application result or exception.

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
