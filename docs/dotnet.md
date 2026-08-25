# .NET SDK

Use the .NET SDK at one supported Backend operation boundary.

## Install

```sh
dotnet add package ReproIt.Sdk --version 1.0.0
```

Use `Operations.Run`, `Operations.RunStream`, or `Operations.RunDeliveredWork` with the
framework-neutral SDK core. Backend v1.0 does not publish a .NET framework adapter.

The SDK sends only complete failed operations to managed Repro It Cloud. It keeps successful,
incomplete, unsupported, and resource-limited operations local.

## Verify SDK source

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
