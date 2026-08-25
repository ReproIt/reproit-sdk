"""Private semantic dependency bridge to the shared SDK engine."""

from __future__ import annotations

import base64
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .native_engine import (
    MAX_OBSERVATION_RESPONSE_READ_BYTES,
    MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES,
)

_ObservationClass = Literal["database", "outbound-http", "queue"]
_Operation = Literal[
    "database-execute",
    "outbound-http-request",
    "queue-acknowledge",
    "queue-publish",
    "queue-receive",
    "queue-reject",
]
_Outcome = Literal["error", "response"]
_ErrorCode = Literal[
    "interrupted",
    "invalid-input",
    "not-found",
    "other",
    "permission-denied",
    "resource-limit",
    "unsupported",
]


class _SemanticDependencyError(RuntimeError):
    pass


@dataclass(frozen=True)
class _DependencyRequest:
    observation_class: _ObservationClass
    operation: _Operation
    protocol: str
    encoding: str
    target: str
    method: str | None
    payload: bytes
    metadata: tuple[tuple[str, bytes], ...] = ()


@dataclass(frozen=True)
class _DependencyResponse:
    outcome: _Outcome
    payload: bytes | None = None
    metadata: tuple[tuple[str, bytes], ...] = ()
    status: str | None = None
    status_code: int | None = None
    error_code: _ErrorCode | None = None
    error_number: int | None = None


def _run_dependency(
    request: _DependencyRequest,
    capture: Callable[[], _DependencyResponse | Awaitable[_DependencyResponse]],
) -> _DependencyResponse | Awaitable[_DependencyResponse]:
    """Drive one private dependency interaction through the shared engine."""
    context = _active_context()
    if context is None:
        return capture()
    try:
        request_input = _request_input(request)
        session = context._open_dependency(request_input)
    except Exception:  # noqa: BLE001 - capture infrastructure must fail open.
        context._abandon()
        return capture()
    if session is None:
        return capture()
    if session.action == "capture":
        return _capture_dependency(session, capture)
    if session.action == "replay":
        return _replay_dependency(session)
    session._abandon()
    return capture()


def _capture_dependency(
    session: object,
    capture: Callable[[], _DependencyResponse | Awaitable[_DependencyResponse]],
) -> _DependencyResponse | Awaitable[_DependencyResponse]:
    try:
        captured = capture()
    except BaseException:
        session._abandon()
        raise
    if inspect.isawaitable(captured):
        return _finish_capture_awaitable(session, captured)
    return _finish_capture(session, captured)


async def _finish_capture_awaitable(
    session: object,
    captured: Awaitable[_DependencyResponse],
) -> _DependencyResponse:
    try:
        response = await captured
    except BaseException:
        session._abandon()
        raise
    return _finish_capture(session, response)


def _finish_capture(
    session: object,
    response: _DependencyResponse,
) -> _DependencyResponse:
    try:
        session._finish(_response_input(response))
    except Exception:  # noqa: BLE001 - capture infrastructure must fail open.
        session._abandon()
    return response


def _replay_dependency(session: object) -> _DependencyResponse:
    try:
        response_record = _read_response(session)
        outcome = session._finish(None)
        if outcome is None:
            raise _invalid_replay()
        response = _response_from_record(response_record)
        if response.outcome != outcome:
            raise _invalid_replay()
        return response
    except Exception as error:
        session._abandon()
        if isinstance(error, _SemanticDependencyError):
            raise
        raise _invalid_replay() from error


def _request_input(request: _DependencyRequest) -> dict[str, object]:
    return {
        "encoding": _bounded_text(request.encoding),
        "metadata": _encode_metadata(request.metadata),
        "method": None if request.method is None else _bounded_text(request.method),
        "observation_class": _bounded_text(request.observation_class),
        "operation": _bounded_text(request.operation),
        "payload": _base64url(_bounded_bytes(request.payload)),
        "protocol": _bounded_text(request.protocol),
        "target": _base64url(_text_bytes(request.target)),
    }


def _response_input(response: _DependencyResponse) -> dict[str, object]:
    payload = response.payload
    return {
        "error_code": response.error_code,
        "error_number": response.error_number,
        "metadata": _encode_metadata(response.metadata),
        "outcome": _bounded_text(response.outcome),
        "payload": None if payload is None else _base64url(_bounded_bytes(payload)),
        "status": None if response.status is None else _bounded_text(response.status),
        "status_code": response.status_code,
    }


def _response_from_record(record: bytes) -> _DependencyResponse:
    try:
        value = json.loads(record)
        if not isinstance(value, dict):
            raise TypeError
        payload = value["payload"]
        return _DependencyResponse(
            outcome=value["outcome"],
            payload=None if payload is None else _decode_base64url(payload),
            metadata=_decode_metadata(value["metadata"]),
            status=value["status"],
            status_code=value["status_code"],
            error_code=value["error_code"],
            error_number=value["error_number"],
        )
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as error:
        raise _invalid_replay() from error


def _encode_metadata(
    metadata: Sequence[tuple[str, bytes]],
) -> list[dict[str, str]]:
    if not isinstance(metadata, tuple) or len(metadata) > (
        MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
    ):
        raise _invalid_value()
    encoded = []
    total_bytes = 0
    for field in metadata:
        if not isinstance(field, tuple) or len(field) != 2:
            raise _invalid_value()
        name, value = field
        name_bytes = _text_bytes(name)
        value_bytes = _bounded_bytes(value)
        total_bytes += len(name_bytes) + len(value_bytes)
        if total_bytes > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES:
            raise _invalid_value()
        encoded.append(
            {"name": _base64url(name_bytes), "value": _base64url(value_bytes)}
        )
    return encoded


def _decode_metadata(value: object) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(value, list) or len(value) > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES:
        raise _invalid_replay()
    fields = []
    total_bytes = 0
    for field in value:
        if not isinstance(field, Mapping):
            raise _invalid_replay()
        name = _decode_base64url(field.get("name")).decode("utf-8", "strict")
        field_value = _decode_base64url(field.get("value"))
        total_bytes += len(name.encode("utf-8")) + len(field_value)
        if total_bytes > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES:
            raise _invalid_replay()
        fields.append((name, field_value))
    return tuple(fields)


def _read_response(session: object) -> bytes:
    chunks = []
    total_bytes = 0
    maximum_reads = MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
    for _ in range(maximum_reads):
        result = session._read_response()
        if result is None:
            break
        chunk, eof = result
        if (
            not isinstance(chunk, bytes)
            or len(chunk) > MAX_OBSERVATION_RESPONSE_READ_BYTES
            or (not chunk and not eof)
        ):
            break
        total_bytes += len(chunk)
        if total_bytes > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES:
            break
        chunks.append(chunk)
        if eof:
            record = b"".join(chunks)
            if record:
                return record
            break
    raise _invalid_replay()


def _text_bytes(value: object) -> bytes:
    if not isinstance(value, str):
        raise _invalid_value()
    encoded = value.encode("utf-8", "strict")
    if len(encoded) > MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES:
        raise _invalid_value()
    return encoded


def _bounded_text(value: object) -> str:
    _text_bytes(value)
    return value


def _bounded_bytes(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) > (
        MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
    ):
        raise _invalid_value()
    return value


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > (
        MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES * 2
    ):
        raise _invalid_replay()
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    if _base64url(decoded) != value:
        raise _invalid_replay()
    return decoded


def _active_context() -> object | None:
    from .engine_operation import _current_operation_context

    return _current_operation_context()


def _invalid_value() -> _SemanticDependencyError:
    return _SemanticDependencyError("The semantic dependency value is invalid.")


def _invalid_replay() -> _SemanticDependencyError:
    return _SemanticDependencyError("The semantic dependency replay is invalid.")
