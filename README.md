# Repro It SDKs

Add Repro It to a backend application in two steps. Run `reproit init`, then wrap each top-level
application operation.

The SDK loads the project file and the current Git revision. Your application supplies an operation
name, its input bytes, and the function to run. It does not create schemas, IDs, endpoints, or
Failure records.

| Language | Package | Setup |
| --- | --- | --- |
| Rust | `reproit-sdk-rust` | [Rust](docs/rust.md) |
| Python | `reproit-sdk` | [Python](docs/python.md) |
| Go | `reproit.dev/sdk-go` | [Go](docs/go.md) |
| Node.js | `@reproit/sdk` | [Node.js](docs/node.md) |
| .NET | `ReproIt.Sdk` | [.NET](docs/dotnet.md) |

Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store. Deploy the application through
its normal release process. Capture failure never changes an application result or error.

The five SDK cores have no framework dependency. A framework adapter can translate its boundary to
the same operation API. An adapter cannot own capture rules or protocol data.

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
