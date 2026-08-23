# Go SDK

Add Repro It to a Go application.

## Install

```sh
go get reproit.dev/sdk-go@v1.0.0
```

```go
import "reproit.dev/sdk-go/reproit"

capture := reproit.Init()
todo, err := reproit.Operation(capture, "todos.create", inputBytes, func() (Todo, error) {
	return createTodo(input)
})
```

Run `reproit init` before you deploy. Initialize the SDK once. Call `Operation` at a top-level
application boundary. Use `capture.Operation` when the operation returns only an error. The SDK
preserves the exact result and error. It does not import a web framework.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/go && go test ./... && go vet ./...'
```
