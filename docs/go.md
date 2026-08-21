# Go SDK

Use this SDK when a Go application must capture a Backend operation.

## Install

Use the module from the Repro It release directory that `reproit init` shows:

```sh
unzip <release-directory>/reproit.dev-sdk-go-v1.0.0.zip -d <sdk-directory>
go mod edit -require=reproit.dev/sdk-go@v1.0.0
go mod edit -replace=reproit.dev/sdk-go=<sdk-directory>/reproit.dev/sdk-go@v1.0.0
```

Import the SDK as `reproit.dev/sdk-go/reproit`. The HTTP adapter uses standard `net/http` types.

## Configure

1. Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store.
2. Load `.reproit/project.toml` into the project map during application setup.
3. Get the repository identity and deployed Git revision from the build.
4. Call `NewOfficialManagedProject` once.

## Capture one operation

1. Start the project operation with the World digest.
2. Create its candidate sink from the complete World closure.
3. Create `SDK` with that sink.
4. Build `CandidateStart` from the operation IDs, deployment, and World digest.
5. Call `RunOperation` around the application operation.

Create the token with `NewManagedProjectToken`. `RunOperation` returns the original application
error.

Use the HTTP adapter only at an HTTP request boundary. Use the base API for streams, delivered work,
other frameworks, and direct operation capture.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/go && go test ./...'
```
