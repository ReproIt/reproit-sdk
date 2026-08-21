# .NET SDK

The .NET SDK captures Backend operations from a .NET application.

## Install

Install the package from the Repro It release directory that `reproit init` shows:

```sh
dotnet add package ReproIt.Sdk --version 1.0.0 --source <release-directory>
```

Add `ReproIt.Sdk.AspNetCore` from the same source for an ASP.NET Core request boundary. The packages
target .NET 10.

## Configure

1. Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store.
2. Load `.reproit/project.toml` into a `JsonObject` during application setup.
3. Get the repository identity and deployed Git revision from the build.
4. Create `OfficialManagedProject` once.

## Capture one operation

1. Start the project operation with the World digest.
2. Create its candidate sink from the complete World closure.
3. Create `Sdk` with that sink.
4. Create `CandidateStart` from the operation IDs, deployment, and World digest.
5. Call `Operations.Run` around the application operation.

The token provider must return `new ManagedProjectToken(token)`. `Operations.Run` returns the
application result or throws the original application exception.

The ASP.NET Core adapter covers an HTTP request boundary. The base API covers streams, delivered
work, other frameworks, and direct operation capture.

## Verify SDK source

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
