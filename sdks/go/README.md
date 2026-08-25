# Repro It SDK for Go

Use this SDK at one supported Backend operation boundary.

```sh
go get reproit.dev/sdk-go@v1.0.0
```

The generic operation boundary supports request-response, stream, and
delivered-work operations. Framework adapters can translate framework events
into this boundary.

Use `OpenAutomaticProject`, then start operations with `StartOperation` or
`StartOperationContext`. Use `RecordInput`, `Succeed`, `Cancel`, `Fail`, and
`Close` to control the operation lifecycle.

The Go layer owns subject discovery, operation context, and Failure translation.
The packaged shared engine owns candidate policy, closure, encryption, delivery,
and cleanup.

Read the [Go integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/go.md).
