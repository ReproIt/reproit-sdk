# Python SDK

Use the framework-neutral operation boundary for request-response, stream, and
delivered-work operations. A framework adapter can delegate to the same boundary.

## Install

```sh
python -m pip install reproit-sdk==1.0.0
```

Open one project, prepare the operation, and run the application callback:

```python
from reproit_sdk import ManagedEngineProject, OperationPreparation, run_operation

project = ManagedEngineProject.open(
    project_toml=project_toml,
    build_repository_id=build_repository_id,
    source_revision=source_revision,
    project_token_provider=load_project_token,
)
preparation = OperationPreparation(
    begin=begin_payload,
    inputs=input_payloads,
    completion="return",
)
result = run_operation(
    project,
    preparation,
    lambda operation: application_call(),
    classify_failure,
)
```

Use `return` for request-response, `stream-end` for stream, and `acknowledgment`
or `task-end` for delivered work.

The Python layer owns subject discovery, operation context, and Failure translation.
The packaged shared engine owns candidate policy, World closure, encryption,
delivery, and cleanup. A successful operation is deleted locally.

## Verify SDK source

```sh
./tools/with-core.sh python -m pytest sdks/python/tests
```
