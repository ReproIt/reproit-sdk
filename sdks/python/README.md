# Repro It SDK for Python

Install the official wheel from your Repro It release bundle:

```sh
python -m pip install ./reproit_sdk-1.0.0-py3-none-any.whl
```

Use `OfficialManagedProject` for the reviewed project and source revision. Start one operation for
each accepted unit of work. Record its inputs and observed dependencies. Mark successful operations
as successful. Submit a failure only after its World closure is complete.

The base package is framework-neutral. `reproit_sdk.asgi` supplies the optional ASGI adapter. The
SDK does not require a sidecar, container engine, orchestrator, or container socket.

See the [Python guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/python.md) for source
verification and release behavior.
