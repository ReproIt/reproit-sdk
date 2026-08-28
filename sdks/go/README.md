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

An open project automatically observes supported requests through
`http.DefaultClient`. The adapter captures complete response streams up to 16 KiB.
It keeps unsupported, sensitive, partial, and oversized observations local.

The project also observes `crypto/rand.Reader` for the operation bound to the
current goroutine. It captures full reads up to 32 KiB and replays them without
live entropy. The instrumented build also captures `time.Now` and detects
process-environment mutations.

Ambiguous, partial, failed, and oversized reads keep the affected operations
local. The native sentinel rejects unowned database, filesystem, and queue
effects.

Read the [Go integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/go.md).
