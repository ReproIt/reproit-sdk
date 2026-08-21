# .NET SDK

## Install

Add `ReproIt.Sdk.1.0.0.nupkg` from the local release bundle or your internal NuGet source. Add
`ReproIt.Sdk.AspNetCore.1.0.0.nupkg` only when you use the ASP.NET Core middleware.

The packages target .NET 10. The base package does not require ASP.NET Core.

## Integrate

Create `OfficialManagedProject` from the reviewed project binding and exact source revision. Start
one operation for each accepted unit of work. Record inputs and dependency results. Discard
successful operations. Submit a failed operation only after its World closure is complete.

Source checkouts contain sentinel managed bindings. They reject official operation setup with
`CONFIG_CONFLICT`. Use an official release package for a real managed capture.

## Verify

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
