# Node.js SDK

Use this SDK when a Node.js application must capture a Backend operation.

## Install

Use the package from the Repro It release directory that `reproit init` shows:

```sh
npm install <release-directory>/reproit-sdk-1.0.0.tgz
```

Import `@reproit/sdk/http` only for a Node.js HTTP request boundary.

## Configure

1. Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store.
2. Load `.reproit/project.toml` into the project object during application setup.
3. Get the repository identity and deployed Git revision from the build.
4. Create `OfficialManagedProject` once.

## Capture one operation

1. Start the project operation with the World digest.
2. Create its candidate sink from the complete World closure.
3. Create `Sdk` with that sink.
4. Build the start object from the operation IDs, deployment, and World digest.
5. Call `runOperation` around the application operation.

The token provider must return `new ManagedProjectToken(process.env.REPROIT_MANAGED_PROJECT_TOKEN)`.
The wrapper returns the application result or throws the original application error.

Use the HTTP adapter only at an HTTP request boundary. Use the base API for streams, delivered work,
other frameworks, and direct operation capture.

## Verify SDK source

```sh
./tools/with-core.sh sh -c 'cd sdks/node && npm test'
```
