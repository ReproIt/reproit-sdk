# .NET SDK

Use the .NET SDK at one supported Backend operation boundary.

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

The .NET layer owns subject discovery, operation context, and Failure
translation. The packaged shared engine owns candidate policy, closure,
encryption, delivery, and cleanup.

Dispose each unfinished operation and the project.

## Verify SDK source

```sh
./tools/with-core.sh dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
```
