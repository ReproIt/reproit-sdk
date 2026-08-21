# Go SDK

The Go SDK captures Backend operations through `net/http` or application code.

## Install

```sh
go get reproit.dev/sdk-go@v1.0.0
```

## Start capture

```go
capture, err := reproit.Start(project, repositoryID, sourceRevision, captureWorld)
if err != nil {
	return err
}
```

`reproit init` supplies `project`. The build supplies the repository identity and deployed Git
revision. `captureWorld` returns one `ManagedWorldCapture` for each operation.

## Wrap an HTTP handler

```go
handler := capture.HTTP("orders.create", captureInput, classifyFailure, mux)
http.ListenAndServe(":8080", handler)
```

`net/http` is the standard Go boundary. Routers that implement `http.Handler` use the same wrapper.
Use `capture.Run` for another request-response boundary. Use `capture.RunStream` or
`capture.RunDeliveredWork` for those operation types.

Dependency adapters call `OperationFromRequest` and then `RecordDependency`. The SDK reads
`REPROIT_MANAGED_PROJECT_TOKEN` only after a complete Failure.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/go && go test ./... && go vet ./...'
```
