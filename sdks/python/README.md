# Repro It SDK for Python

Capture failed Backend operations from a Python application.

```sh
python -m pip install reproit-sdk==1.0.0
```

Run `reproit init`. Then create `ReproIt.init()` once. Call `operation` or `operation_async` at each
top-level application boundary. The API does not depend on a web framework.

Read the [Python integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/python.md).
