"""Candidate bindings that the Python SDK must prove before handoff."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from typing import Any


def candidate_uses_mode(
    candidate_bytes: bytes,
    modes: frozenset[str],
    canonical_bytes: Callable[[Any], bytes],
) -> bool:
    try:
        candidate = json.loads(candidate_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    deployment = candidate.get("deployment") if isinstance(candidate, dict) else None
    return (
        isinstance(candidate, dict)
        and isinstance(deployment, Mapping)
        and canonical_bytes(candidate) == candidate_bytes
        and candidate.get("processing_mode") in modes
        and candidate.get("processing_mode") == deployment.get("processing_mode")
    )


def validate_candidate(
    candidate: Mapping[str, Any],
    failure: Mapping[str, Any],
    decode_payload: Callable[[Any], dict[str, Any]],
    digest_value: Callable[[Any], str],
) -> None:
    records = candidate.get("records")
    deployment = candidate.get("deployment")
    if (
        not isinstance(records, list)
        or len(records) < 3
        or not isinstance(deployment, Mapping)
        or not isinstance(candidate.get("failure"), Mapping)
        or candidate.get("failure") != failure.get("failure")
        or not _valid_record_sequence(records)
        or candidate.get("processing_mode") != deployment.get("processing_mode")
    ):
        raise ValueError("The candidate record sequence is incomplete.")
    payloads = [decode_payload(record) for record in records]
    failure_payload = next(
        payload
        for record, payload in zip(records, payloads, strict=True)
        if record["kind"] == "failure"
    )
    begin = payloads[0]
    terminal = payloads[-1]
    identity = failure_payload.get("identity")
    if (
        set(terminal) != {"complete", "event_count", "format"}
        or terminal.get("complete") is not True
        or terminal.get("event_count") != len(records) - 1
        or terminal.get("format") != "reproit.terminal.v1"
        or begin.get("format") != "reproit.operation-begin.v1"
        or not isinstance(identity, Mapping)
        or begin.get("operation_kind") != identity.get("operation_kind")
        or begin.get("operation_name") != identity.get("operation_name")
        or failure_payload != failure
        or digest_value(identity) != candidate["failure"].get("identity")
    ):
        raise ValueError("The candidate payload bindings are incomplete.")
    _validate_ordered_payloads(records, payloads)


def _valid_record_sequence(records: list[Any]) -> bool:
    try:
        return (
            records[0]["kind"] == "begin"
            and records[-1]["kind"] == "terminal"
            and all(record["sequence"] == index for index, record in enumerate(records))
            and sum(record["kind"] == "failure" for record in records) == 1
        )
    except (KeyError, TypeError):
        return False


def _validate_ordered_payloads(
    records: list[dict[str, Any]], payloads: list[dict[str, Any]]
) -> None:
    input_index = 0
    for record, payload in zip(records, payloads, strict=True):
        if record["kind"] == "input":
            if (
                payload.get("format") != "reproit.operation-input.v1"
                or type(payload.get("input_index")) is not int
                or payload["input_index"] != input_index
                or _digest_decoded_value(payload.get("value"))
                != payload.get("value_digest")
            ):
                raise ValueError("The candidate input binding is invalid.")
            input_index += 1
        elif record["kind"] == "dependency":
            if not _valid_dependency_cursor(payload):
                raise ValueError("The candidate dependency cursor is invalid.")
        elif record["kind"] not in {"begin", "failure", "terminal"}:
            raise ValueError("The candidate contains an unknown record kind.")


def _digest_decoded_value(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        return None
    return f"sha256:{hashlib.sha256(decoded).hexdigest()}"


def _valid_dependency_cursor(value: Mapping[str, Any]) -> bool:
    keys = {
        "adapter_id",
        "adapter_version",
        "causal_parent_id",
        "cursor",
        "cursor_digest",
        "format",
    }
    adapter_id = value.get("adapter_id")
    adapter_version = value.get("adapter_version")
    cursor = value.get("cursor")
    causal_parent_id = value.get("causal_parent_id")
    cursor_digest = value.get("cursor_digest")
    return (
        set(value) == keys
        and isinstance(adapter_id, str)
        and 1 <= len(adapter_id) <= 128
        and adapter_id.isascii()
        and adapter_id[0].islower()
        and all(
            character.islower() or character.isdigit() or character in ".-"
            for character in adapter_id
        )
        and isinstance(adapter_version, str)
        and 1 <= len(adapter_version) <= 64
        and isinstance(cursor, str)
        and 1 <= len(cursor) <= 16_384
        and all(
            character.isascii() and (character.isalnum() or character in "-_")
            for character in cursor
        )
        and (causal_parent_id is None or _valid_operation_id(causal_parent_id))
        and isinstance(cursor_digest, str)
        and cursor_digest.startswith("sha256:")
        and len(cursor_digest) == 71
        and all(character in "0123456789abcdef" for character in cursor_digest[7:])
        and value.get("format") == "reproit.dependency-cursor.v1"
    )


def _valid_operation_id(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("op_"):
        return False
    try:
        identifier = uuid.UUID(value[3:])
    except ValueError:
        return False
    return identifier.version == 7 and str(identifier) == value[3:]
