# Repro It SDK for Python

Capture failed Backend operations from a Python application.

Install the wheel from the release directory that `reproit init` shows. Use
`OfficialManagedProject` during application setup. Use `run_operation` at each top-level operation
boundary.

Import `reproit_sdk.asgi` for an ASGI request adapter. Use the base package for streams, delivered
work, other frameworks, and direct operation capture.

Read the [Python integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/python.md).
