# Python SDK

## Install

Install the released wheel from a local release bundle or an internal package source:

```sh
python -m pip install ./reproit_sdk-1.0.0-py3-none-any.whl
```

The package supports Python 3.14. Import `reproit_sdk.asgi` only when you need the ASGI adapter.

## Integrate

Create `OfficialManagedProject.from_build(...)` from the reviewed project binding and source
revision. Start one operation for each accepted unit of work. Record inputs and dependency results.
Discard successful operations. Submit a failed operation only after its World closure is complete.

Source checkouts contain sentinel managed bindings. They reject official operation setup with
`CONFIG_CONFLICT`. Use an official release package for a real managed capture.

## Verify

```sh
./tools/with-core.sh python -m pytest sdks/python/tests
```
