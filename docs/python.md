# Python SDK

Use the Python SDK at one supported Backend operation boundary.

## Install

```sh
python -m pip install reproit-sdk==1.0.0
```

Use `run_operation` with the framework-neutral SDK core. Backend v1.0 does not publish a Python
framework adapter.

The SDK sends only complete failed operations to managed Repro It Cloud. It keeps successful,
incomplete, unsupported, and resource-limited operations local.

## Verify SDK source

```sh
./tools/with-core.sh python -m pytest sdks/python/tests
```
