# Repro It SDK for .NET

Capture failed Backend operations from a .NET application.

```sh
dotnet add package ReproIt.Sdk --version 1.0.0
```

Run `reproit init`. Then create `ReproItCapture.Init()` once. Call `Operation` or `OperationAsync`
at each top-level application boundary. The API does not depend on a web framework.

Read the [.NET integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/dotnet.md).
