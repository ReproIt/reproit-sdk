import json
from pathlib import Path

import pytest

from reproit_sdk.distributed_fuzz import (
    FUZZ_CONTEXT_HTTP_HEADER,
    FUZZ_CONTEXT_QUEUE_METADATA,
    FUZZ_PARENT_HTTP_HEADER,
    FUZZ_PARENT_QUEUE_METADATA,
    FuzzContextError,
    FuzzContextValidator,
    _activate_fuzz_context,
    _reset_fuzz_context,
    extract_http_fuzz_context,
    extract_queue_fuzz_context,
    propagate_queue_fuzz_context,
)


def test_shared_context_vector_propagates_over_http_and_queue() -> None:
    vector = _vector()
    validator = FuzzContextValidator(
        project_id=vector["expected"]["project_id"],
        verification_key=vector["verification_key"],
    )
    context = extract_http_fuzz_context(
        {
            FUZZ_CONTEXT_HTTP_HEADER: vector["encoded_context"],
            FUZZ_PARENT_HTTP_HEADER: vector["parent_operation_id"],
        },
        validator,
        vector["now"],
    )
    assert context is not None
    assert context.campaign_id == vector["expected"]["campaign_id"]
    assert context.case_id == vector["expected"]["case_id"]
    assert context.context_digest == vector["expected"]["context_digest"]

    token = _activate_fuzz_context(context)
    try:
        metadata: dict[str, str] = {}
        propagate_queue_fuzz_context(metadata)
    finally:
        _reset_fuzz_context(token)
    assert metadata == {
        FUZZ_CONTEXT_QUEUE_METADATA: vector["encoded_context"],
        FUZZ_PARENT_QUEUE_METADATA: vector["parent_operation_id"],
    }
    assert extract_queue_fuzz_context(metadata, validator, vector["now"]) == context


def test_context_rejects_wrong_scope_and_expiry() -> None:
    vector = _vector()
    wrong_scope = FuzzContextValidator(
        project_id="prj_01890f3e-7b21-7cc0-8a1b-123456789abc",
        verification_key=vector["verification_key"],
    )
    with pytest.raises(FuzzContextError):
        wrong_scope.validate(vector["encoded_context"], vector["now"])

    validator = FuzzContextValidator(
        project_id=vector["expected"]["project_id"],
        verification_key=vector["verification_key"],
    )
    with pytest.raises(FuzzContextError):
        validator.validate(
            vector["encoded_context"],
            "2026-08-30T00:00:00.000Z",
        )


def _vector() -> dict[str, object]:
    path = (
        Path(__file__).resolve().parents[3]
        / "conformance"
        / "distributed-fuzz-context-vectors.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))
