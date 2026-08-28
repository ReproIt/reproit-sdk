# .NET SDK

Use the .NET SDK at one supported Backend operation boundary.

The current SDK release does not provide the complete automatic adapter set that
`reproit init` requires. The CLI does not declare this SDK ready for automatic
World capture. The operation API and HTTP adapter remain available for SDK
development and conformance work.

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

The .NET layer owns subject discovery, operation context, and Failure
translation. The packaged shared engine owns candidate policy, closure,
encryption, delivery, and cleanup.

Dispose each unfinished operation and the project.

## Verify SDK source

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
