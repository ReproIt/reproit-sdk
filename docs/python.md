# Python SDK

Add Repro It to a Python application.

## Install

```sh
python -m pip install reproit-sdk==1.0.0
```

```python
from reproit_sdk import ReproIt

reproit = ReproIt.init()
todo = await reproit.operation_async(
    "todos.create", input_bytes, lambda: create_todo(input)
)
```

Run `reproit init` before you deploy. Initialize the SDK once. Call `operation` or
`operation_async` at a top-level application boundary. The SDK records an exception as the Failure.
It preserves the exact result. It does not import a web framework.

## Verify SDK source

```sh
./tools/with-core.sh python -m pytest sdks/python/tests
```
