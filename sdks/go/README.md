# Repro It SDK for Go

Capture failed Backend operations from a Go application.

```sh
go get reproit.dev/sdk-go@v1.0.0
```

Run `reproit init`. Then call `capture := reproit.Init()` once. Call `reproit.Operation` at
each top-level application boundary. The API does not depend on a web framework.

Read the [Go integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/go.md).
