# Repro It SDK for Go

Use this SDK at one supported Backend operation boundary. The SDK keeps bounded records. It sends
only complete failed operations to managed Repro It Cloud.

```sh
go get reproit.dev/sdk-go@v1.0.0
```

The framework-neutral API supports request-response, ordered-stream, and delivered-work
operations. Backend v1.0 does not publish a Go framework adapter.

Read the [Go integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/go.md).
