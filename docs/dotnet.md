# .NET SDK

Add Repro It to a .NET application.

## Install

```sh
dotnet add package ReproIt.Sdk --version 1.0.0
```

```csharp
using ReproIt.Sdk;

ReproItCapture capture = ReproItCapture.Init();
Todo todo = await capture.OperationAsync(
    "todos.create", inputBytes, () => CreateTodo(input));
```

Run `reproit init` before you deploy. Initialize the SDK once. Call `Operation` or `OperationAsync`
at a top-level application boundary. The SDK records an exception as the Failure. It preserves the
exact result. It does not reference a web framework.

## Verify SDK source

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
