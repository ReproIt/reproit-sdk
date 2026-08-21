# Python SDK

The Python SDK captures Backend operations from ASGI, WSGI, or application code.

## Install

```sh
python -m pip install reproit-sdk==1.0.0
```

## Start capture

```python
from reproit_sdk import ReproIt

reproit = ReproIt(project, BUILD_REPOSITORY_ID, SOURCE_REVISION, capture_world)
```

`reproit init` supplies `project`. The build supplies the repository identity and deployed Git
revision. `capture_world` returns a `ManagedWorldCapture` for each operation.

## Wrap an ASGI or WSGI application

```python
app = reproit.asgi(app, "orders.create", capture_input, classify_failure)
```

For a WSGI application, use the same setup:

```python
app = reproit.wsgi(app, "orders.create", capture_input, classify_failure)
```

Use `reproit.run` or `reproit.run_async` for another operation boundary. Set `operation_kind` to
`"stream"` or `"delivered-work"` for those operation types. Dependency adapters get
`OperationCapture` from the request environment and call `record_dependency`.

The SDK reads `REPROIT_MANAGED_PROJECT_TOKEN` only after a complete Failure. Capture errors do not
change the application return value or exception.

## Verify SDK source

```sh
./tools/with-core.sh python -m pytest sdks/python/tests
```
