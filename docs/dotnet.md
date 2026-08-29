# .NET SDK

Use the .NET SDK at one supported Backend operation boundary.

The SDK installs guards for all seven automatic observation classes. The HTTP
adapter captures its supported `HttpClient` boundary. Six native guards cover
clock, database, environment, filesystem, queue, and randomness classes. The
shared Linux sentinel keeps a failure local when a kernel-visible effect is
unowned or the native trace is incomplete.

The packaged engine loads on macOS and Windows. Automatic capture stays local on
those hosts until a matching native coverage provider is available.

## Install

```sh
dotnet add package ReproIt.Sdk --version 1.0.0
```

## Integrate

Open one project with `AutomaticProject.Open`. Start an operation with
`StartOperation`.

The generic operation boundary supports request-response, stream, and
delivered-work operations. A framework adapter can translate framework events
into this boundary.

Record Trigger chunks with `RecordInput`. Finish the operation with `Succeed`,
`Cancel`, or `Fail`. `Fail` closes the World before delivery starts.

The operation is active in its asynchronous context until a terminal method runs.
The SDK automatically captures supported bodyless `HttpClient` calls in that context.
It keeps the operation local for bodies, credentials, sensitive headers, ambiguous errors,
changed runtime events, or resource limit failures.

`reproit init` accepts a direct `dotnet run` application command. The internal
startup probe verifies the managed SDK, the packaged engine, and the Linux native
sentinel. The public CLI does not add a .NET-specific run command.

The .NET layer owns subject discovery, operation context, and Failure
translation. The packaged shared engine owns candidate policy, closure,
encryption, delivery, and cleanup.

Dispose each unfinished operation and the project.

## Verify SDK source

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
