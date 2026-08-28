# Go SDK

Use the Go SDK at one supported Backend operation boundary.

## Install

```sh
go get reproit.dev/sdk-go@v1.0.0
```

## Integrate

Open one project with `OpenAutomaticProject`. Start an operation with
`StartOperation` or `StartOperationContext`.

The generic operation boundary supports request-response, stream, and
delivered-work operations. A framework adapter can translate framework events
into this boundary.

Record Trigger chunks with `RecordInput`. Finish the operation with `Succeed`,
`Cancel`, or `Fail`. `Fail` closes the World before delivery starts.

The Go layer owns subject discovery, operation context, and Failure translation.
The packaged shared engine owns candidate policy, closure, encryption, delivery,
and cleanup.

An open project wraps `http.DefaultClient.Transport`. The adapter observes requests
that use an operation child context from `StartOperationContext`.

The adapter captures replayable request bodies and complete response bodies up to
16 KiB. It records a response stream only after the stream reaches EOF.

The adapter rejects credentials, sensitive headers, partial streams, read errors,
and values outside its bounds. These cases keep a failed operation local.

Custom clients and custom transports are outside this automatic adapter boundary.
Their effects remain unowned unless another package-owned adapter captures them.

An open project also wraps `crypto/rand.Reader`. The adapter captures full reads of
at most 32 KiB when the current goroutine owns an operation. Replay returns the
recorded bytes without a live entropy call.

`reproit init` accepts a direct `go run` application command. It stores the
internal Go build instrumentation flags in the project configuration. The public
workflow remains `reproit init`, `reproit debug`, and `reproit check`.

The instrumented build captures `time.Now` and detects process-environment
mutations. The SDK uses the same operation ownership for clock and random reads.
Nested operations bind to the innermost operation on the current goroutine.

Calls from a goroutine without a bound operation are ambiguous while any
operation is active. Partial, failed, oversized, and ambiguous reads keep every
affected operation local. A persistent application replacement of an installed
hook also prevents World closure.

The native sentinel guards database, filesystem, and queue effects that do not
have a package-owned semantic adapter. An unowned kernel-visible effect keeps the
operation local.

Close each unfinished operation and the project.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/go && go test ./... && go vet ./...'
```
