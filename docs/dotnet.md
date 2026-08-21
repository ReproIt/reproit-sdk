# .NET SDK

The .NET SDK captures Backend operations from ASP.NET Core or application code.

## Install

```sh
dotnet add package ReproIt.Sdk --version 1.0.0
```

No second ASP.NET Core package is required.

## Start capture

```csharp
ReproItCapture capture = new(project, repositoryId, sourceRevision, captureWorld);
```

`reproit init` supplies `project`. The build supplies the repository identity and deployed Git
revision. `captureWorld` returns one `ManagedWorldCapture` for each operation.

## Add ASP.NET Core middleware

```csharp
app.Use(async (context, next) => await capture.RunAsync(
    "orders.create",
    context.Request.ContentType ?? "application/octet-stream",
    CaptureInput(context),
    async _ => { await next(context); return true; },
    ClassifyFailure));
```

Use `RunStream` or `RunStreamAsync` for an ordered stream. Use `RunDeliveredWork` or
`RunDeliveredWorkAsync` for delivered work. Every framework uses the same managed capture path.

The SDK reads `REPROIT_MANAGED_PROJECT_TOKEN` only after a complete Failure. Capture errors do not
change the application return value or exception.

## Verify SDK source

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
