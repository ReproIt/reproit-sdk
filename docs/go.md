# Go SDK

Use the Go SDK at one supported Backend operation boundary.

## Install

```sh
go get reproit.dev/sdk-go@v1.0.0
```

Use `RunOperation`, `RunStreamOperation`, or `RunDeliveredWork` with the framework-neutral SDK
core. Backend v1.0 does not publish a Go framework adapter.

The SDK sends only complete failed operations to managed Repro It Cloud. It keeps successful,
incomplete, unsupported, and resource-limited operations local.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/go && go test ./... && go vet ./...'
```
