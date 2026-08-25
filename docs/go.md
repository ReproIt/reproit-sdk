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

Close each unfinished operation and the project.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/go && go test ./... && go vet ./...'
```
