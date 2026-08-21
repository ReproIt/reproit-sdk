# Python SDK

The Python SDK captures Backend operations from a Python application.

## Install

Install the wheel from the Repro It release directory that `reproit init` shows:

```sh
python -m pip install <release-directory>/reproit_sdk-1.0.0-py3-none-any.whl
```

The package supports Python 3.14. Import `reproit_sdk.asgi` only for an ASGI request boundary.

## Configure

1. Store `REPROIT_MANAGED_PROJECT_TOKEN` in the deployment secret store.
2. Load `.reproit/project.toml` into a mapping during application setup.
3. Get the repository identity and deployed Git revision from the build.
4. Call `OfficialManagedProject.from_build` once.

## Capture one operation

1. Start the project operation with the World digest.
2. Create its candidate sink from the complete World closure.
3. Create `Sdk` with that sink.
4. Build `CandidateStart` from the operation IDs, deployment, and World digest.
5. Call `run_operation` around the application operation.

The token provider must return `ManagedProjectToken(os.environ["REPROIT_MANAGED_PROJECT_TOKEN"])`.
The wrapper returns the application result or raises the original application exception.

The ASGI adapter covers an ASGI request boundary. The base API covers streams, delivered work,
other frameworks, and direct operation capture.

## Verify SDK source

```sh
./tools/with-core.sh python -m pytest sdks/python/tests
```
