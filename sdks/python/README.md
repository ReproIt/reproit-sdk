# Repro It SDK for Python

Use `ManagedEngineProject`, `OperationPreparation`, and `run_operation` at a
framework-neutral Backend operation boundary. The same boundary supports
request-response, stream, and delivered-work operations. A framework adapter can
delegate to it.

```sh
python -m pip install reproit-sdk==1.0.0
```

The Python layer owns subject discovery, operation context, and Failure translation.
The packaged shared engine owns candidate policy, World closure, encryption,
delivery, and cleanup. It deletes successful operations locally.

Read the
[Python integration guide](https://github.com/ReproIt/reproit-sdk/blob/main/docs/python.md).
