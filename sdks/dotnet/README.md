# Repro It SDK for .NET

Use this SDK at one supported Backend operation boundary.

```sh
dotnet add package ReproIt.Sdk --version 1.0.0
```

The generic operation boundary supports request-response, stream, and
delivered-work operations. Framework adapters can translate framework events
into this boundary.

Use `AutomaticProject.Open`, then start operations with `StartOperation`. Use
`RecordInput`, `Succeed`, `Cancel`, `Fail`, and `Dispose` to control the
operation lifecycle.

The .NET layer owns subject discovery, operation context, and Failure
translation. The packaged shared engine owns candidate policy, closure,
encryption, delivery, and cleanup.

Read the [.NET integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/dotnet.md).
