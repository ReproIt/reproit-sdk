# Repro It SDK for .NET

Capture failed Backend operations from a .NET application.

Install `ReproIt.Sdk` from the release directory that `reproit init` shows. Use
`OfficialManagedProject` during application setup. Use `Operations.Run` at each top-level operation
boundary.

Add `ReproIt.Sdk.AspNetCore` for an ASP.NET Core request adapter. Use the base package for streams,
delivered work, other frameworks, and direct operation capture.

Read the [.NET integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/dotnet.md).
