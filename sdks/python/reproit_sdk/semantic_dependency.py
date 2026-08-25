"""Private semantic dependency records over the shared observation session."""

from __future__ import annotations

import base64
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal, TypeVar

from .encoding import canonical_bytes
from .native_engine import (
    MAX_OBSERVATION_CHUNK_BYTES,
    MAX_OBSERVATION_RESPONSE_READ_BYTES,
)
from .subject_protocol import digest_bytes

_Result = TypeVar("_Result")
_REQUEST_FORMAT = "reproit.semantic-dependency-request.v1"
_RESPONSE_FORMAT = "reproit.semantic-dependency-response.v1"
_MAX_RECORD_BYTES = 65_536
_MAX_TARGET_BYTES = 8 * 1_024
_MAX_PAYLOAD_BYTES = 24 * 1_024
_MAX_METADATA_ENTRIES = 64
_MAX_METADATA_BYTES = 8 * 1_024
_MAX_METADATA_NAME_BYTES = 256
_MAX_METADATA_VALUE_BYTES = 4 * 1_024
_MAX_ERROR_NUMBER = (1 << 32) - 1
_COMPONENT = re.compile(r"[a-z][a-z0-9.-]*\Z")
_METHOD = re.compile(r"[A-Z][A-Z0-9-]{0,31}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

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
_ERROR_CODES = {
    "interrupted",
    "invalid-input",
    "not-found",
    "other",
    "permission-denied",
    "resource-limit",
    "unsupported",
}
_CLASS_OPERATIONS = {
    "database": {"database-execute"},
    "outbound-http": {"outbound-http-request"},
    "queue": {
        "queue-acknowledge",
        "queue-publish",
        "queue-receive",
        "queue-reject",
    },
}


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


def _encode_dependency_request(request: _DependencyRequest) -> bytes:
    _validate_request(request)
    value = {
        "encoding": request.encoding,
        "format": _REQUEST_FORMAT,
        "metadata": _encode_metadata(request.metadata),
        "method": request.method,
        "observation_class": request.observation_class,
        "operation": request.operation,
        "payload": _base64url(request.payload),
        "protocol": request.protocol,
        "target": _base64url(request.target.encode("utf-8", "strict")),
    }
    return _bounded_record(value)


def _decode_dependency_request(record: bytes) -> _DependencyRequest:
    value = _parse_record(record, _REQUEST_KEYS)
    if value["format"] != _REQUEST_FORMAT:
        raise _SemanticDependencyError("The semantic dependency record is invalid.")
    try:
        request = _DependencyRequest(
            observation_class=value["observation_class"],
            operation=value["operation"],
            protocol=value["protocol"],
            encoding=value["encoding"],
            target=_decode_base64url(value["target"]).decode("utf-8", "strict"),
            method=value["method"],
            payload=_decode_base64url(value["payload"]),
            metadata=_decode_metadata(value["metadata"]),
        )
        _validate_request(request)
    except (TypeError, ValueError, UnicodeError) as error:
        raise _SemanticDependencyError(
            "The semantic dependency record is invalid."
        ) from error
    return request


def _encode_dependency_response(
    request_record: bytes,
    response: _DependencyResponse,
) -> bytes:
    request = _decode_dependency_request(request_record)
    _validate_response(request, response)
    value = {
        "error_code": response.error_code,
        "error_number": response.error_number,
        "format": _RESPONSE_FORMAT,
        "metadata": _encode_metadata(response.metadata),
        "observation_class": request.observation_class,
        "operation": request.operation,
        "outcome": response.outcome,
        "payload": None if response.payload is None else _base64url(response.payload),
        "request_digest": digest_bytes(request_record),
        "status": response.status,
        "status_code": response.status_code,
    }
    return _bounded_record(value)


def _decode_dependency_response(
    request_record: bytes,
    response_record: bytes,
) -> _DependencyResponse:
    request = _decode_dependency_request(request_record)
    value = _parse_record(response_record, _RESPONSE_KEYS)
    if (
        value["format"] != _RESPONSE_FORMAT
        or value["observation_class"] != request.observation_class
        or value["operation"] != request.operation
        or not isinstance(value["request_digest"], str)
        or not _DIGEST.fullmatch(value["request_digest"])
        or value["request_digest"] != digest_bytes(request_record)
    ):
        raise _SemanticDependencyError("The semantic dependency record is invalid.")
    try:
        response = _DependencyResponse(
            outcome=value["outcome"],
            payload=(
                None
                if value["payload"] is None
                else _decode_base64url(value["payload"])
            ),
            metadata=_decode_metadata(value["metadata"]),
            status=value["status"],
            status_code=value["status_code"],
            error_code=value["error_code"],
            error_number=value["error_number"],
        )
        _validate_response(request, response)
    except (TypeError, ValueError, UnicodeError) as error:
        raise _SemanticDependencyError(
            "The semantic dependency record is invalid."
        ) from error
    return response


def _run_dependency(
    request: _DependencyRequest,
    capture: Callable[[], _DependencyResponse | Awaitable[_DependencyResponse]],
) -> _DependencyResponse | Awaitable[_DependencyResponse]:
    """Drive one private dependency interaction through the shared engine."""
    context = _active_context()
    if context is None:
        return capture()
    try:
        request_record = _encode_dependency_request(request)
    except Exception:
        _mark_invalid_request(context, request)
        return capture()
    try:
        session = context._open_observation(request.observation_class)
    except Exception:
        context._abandon()
        return capture()
    if session is None:
        return capture()
    try:
        written = _write(session._write_request, request_record)
    except Exception:
        session._abandon()
        return capture()
    if not written:
        return capture()
    try:
        action = session._dispatch()
    except Exception:
        session._abandon()
        return capture()
    if action == "capture":
        try:
            captured = capture()
        except BaseException:
            session._abandon()
            raise
        if inspect.isawaitable(captured):
            return _finish_capture_awaitable(session, request_record, captured)
        return _finish_capture(session, request_record, captured)
    if action == "replay":
        try:
            response_record = _read_response(session)
            response = _decode_dependency_response(request_record, response_record)
            if not session._finish(response.outcome):
                raise _SemanticDependencyError(
                    "The semantic dependency replay is invalid."
                )
            return response
        except Exception as error:
            session._abandon()
            if isinstance(error, _SemanticDependencyError):
                raise
            raise _SemanticDependencyError(
                "The semantic dependency replay is invalid."
            ) from error
    session._abandon()
    return capture()


def _mark_invalid_request(context: object, request: object) -> None:
    observation_class = getattr(request, "observation_class", None)
    if observation_class in _CLASS_OPERATIONS:
        context._mark_unowned(
            observation_class,
            b"semantic-dependency-request-invalid",
        )
    else:
        context._abandon()


async def _finish_capture_awaitable(
    session: object,
    request_record: bytes,
    captured: Awaitable[_DependencyResponse],
) -> _DependencyResponse:
    try:
        response = await captured
    except BaseException:
        session._abandon()
        raise
    return _finish_capture(session, request_record, response)


def _finish_capture(
    session: object,
    request_record: bytes,
    response: _DependencyResponse,
) -> _DependencyResponse:
    try:
        response_record = _encode_dependency_response(request_record, response)
    except Exception:
        session._abandon()
        return response
    if _write(session._write_response, response_record):
        session._finish(response.outcome)
    return response


def _validate_request(request: _DependencyRequest) -> None:
    if (
        request.observation_class not in _CLASS_OPERATIONS
        or request.operation not in _CLASS_OPERATIONS[request.observation_class]
        or not _valid_component(request.protocol, 64)
        or not _valid_component(request.encoding, 64)
        or not isinstance(request.payload, bytes)
        or len(request.payload) > _MAX_PAYLOAD_BYTES
    ):
        raise _SemanticDependencyError("The semantic dependency request is invalid.")
    _validate_target(request.target)
    _validate_metadata(request.metadata)
    if request.observation_class == "outbound-http":
        if not isinstance(request.method, str) or not _METHOD.fullmatch(request.method):
            raise _SemanticDependencyError("The semantic dependency request is invalid.")
    elif request.method is not None:
        raise _SemanticDependencyError("The semantic dependency request is invalid.")


def _validate_response(
    request: _DependencyRequest,
    response: _DependencyResponse,
) -> None:
    if response.outcome == "error":
        if (
            response.error_code not in _ERROR_CODES
            or not _valid_error_number(response.error_number)
            or response.payload is not None
            or not isinstance(response.metadata, tuple)
            or len(response.metadata) != 0
            or response.status is not None
            or response.status_code is not None
        ):
            raise _SemanticDependencyError("The semantic dependency response is invalid.")
        return
    if (
        response.outcome != "response"
        or response.error_code is not None
        or response.error_number is not None
        or not isinstance(response.payload, bytes)
        or len(response.payload) > _MAX_PAYLOAD_BYTES
    ):
        raise _SemanticDependencyError("The semantic dependency response is invalid.")
    _validate_metadata(response.metadata)
    if request.observation_class == "outbound-http":
        if (
            response.status is not None
            or isinstance(response.status_code, bool)
            or not isinstance(response.status_code, int)
            or not 100 <= response.status_code <= 599
        ):
            raise _SemanticDependencyError("The semantic dependency response is invalid.")
    elif response.status_code is not None or (
        response.status is not None and not _valid_component(response.status, 64)
    ):
        raise _SemanticDependencyError("The semantic dependency response is invalid.")


def _validate_target(target: str) -> None:
    if not isinstance(target, str):
        raise _SemanticDependencyError("The semantic dependency target is invalid.")
    try:
        encoded = target.encode("utf-8", "strict")
    except UnicodeError as error:
        raise _SemanticDependencyError(
            "The semantic dependency target is invalid."
        ) from error
    if not encoded or len(encoded) > _MAX_TARGET_BYTES:
        raise _SemanticDependencyError("The semantic dependency target is invalid.")


def _validate_metadata(metadata: Sequence[tuple[str, bytes]]) -> None:
    if not isinstance(metadata, tuple) or len(metadata) > _MAX_METADATA_ENTRIES:
        raise _SemanticDependencyError("The semantic dependency metadata is invalid.")
    total = 0
    for field in metadata:
        if not isinstance(field, tuple) or len(field) != 2:
            raise _SemanticDependencyError("The semantic dependency metadata is invalid.")
        name, value = field
        if not isinstance(name, str) or not isinstance(value, bytes):
            raise _SemanticDependencyError("The semantic dependency metadata is invalid.")
        try:
            name_bytes = name.encode("utf-8", "strict")
        except UnicodeError as error:
            raise _SemanticDependencyError(
                "The semantic dependency metadata is invalid."
            ) from error
        if (
            not name_bytes
            or len(name_bytes) > _MAX_METADATA_NAME_BYTES
            or len(value) > _MAX_METADATA_VALUE_BYTES
        ):
            raise _SemanticDependencyError("The semantic dependency metadata is invalid.")
        total += len(name_bytes) + len(value)
        if total > _MAX_METADATA_BYTES:
            raise _SemanticDependencyError("The semantic dependency metadata is invalid.")


def _encode_metadata(
    metadata: Sequence[tuple[str, bytes]],
) -> list[dict[str, str]]:
    return [
        {
            "name": _base64url(name.encode("utf-8", "strict")),
            "value": _base64url(value),
        }
        for name, value in metadata
    ]


def _decode_metadata(value: object) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(value, list):
        raise _SemanticDependencyError("The semantic dependency metadata is invalid.")
    fields = []
    for field in value:
        if not isinstance(field, dict) or set(field) != {"name", "value"}:
            raise _SemanticDependencyError("The semantic dependency metadata is invalid.")
        name = _decode_base64url(field["name"]).decode("utf-8", "strict")
        fields.append((name, _decode_base64url(field["value"])))
    metadata = tuple(fields)
    _validate_metadata(metadata)
    return metadata


def _parse_record(record: bytes, keys: set[str]) -> dict[str, object]:
    if not isinstance(record, bytes) or len(record) > _MAX_RECORD_BYTES:
        raise _SemanticDependencyError("The semantic dependency record is invalid.")
    try:
        value = json.loads(record)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise _SemanticDependencyError(
            "The semantic dependency record is invalid."
        ) from error
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or canonical_bytes(value) != record
    ):
        raise _SemanticDependencyError("The semantic dependency record is invalid.")
    return value


def _bounded_record(value: dict[str, object]) -> bytes:
    try:
        record = canonical_bytes(value)
    except (TypeError, ValueError, UnicodeError) as error:
        raise _SemanticDependencyError(
            "The semantic dependency record is invalid."
        ) from error
    if len(record) > _MAX_RECORD_BYTES:
        raise _SemanticDependencyError("The semantic dependency record is invalid.")
    return record


def _valid_component(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= maximum
        and _COMPONENT.fullmatch(value) is not None
    )


def _valid_error_number(value: object) -> bool:
    return value is None or (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= _MAX_ERROR_NUMBER
    )


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: object) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise _SemanticDependencyError("The semantic dependency bytes are invalid.")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeError) as error:
        raise _SemanticDependencyError(
            "The semantic dependency bytes are invalid."
        ) from error
    if _base64url(decoded) != value:
        raise _SemanticDependencyError("The semantic dependency bytes are invalid.")
    return decoded


def _write(writer: Callable[[bytes], bool], record: bytes) -> bool:
    for start in range(0, len(record), MAX_OBSERVATION_CHUNK_BYTES):
        if not writer(record[start : start + MAX_OBSERVATION_CHUNK_BYTES]):
            return False
    return True


def _read_response(session: object) -> bytes:
    chunks = []
    total = 0
    for _ in range(9):
        result = session._read_response()
        if result is None:
            break
        chunk, eof = result
        if not isinstance(chunk, bytes) or len(chunk) > MAX_OBSERVATION_RESPONSE_READ_BYTES:
            break
        total += len(chunk)
        if total > _MAX_RECORD_BYTES:
            break
        chunks.append(chunk)
        if eof:
            return b"".join(chunks)
    raise _SemanticDependencyError("The semantic dependency replay is invalid.")


def _active_context() -> object | None:
    from .engine_operation import _current_operation_context

    return _current_operation_context()


_REQUEST_KEYS = {
    "encoding",
    "format",
    "metadata",
    "method",
    "observation_class",
    "operation",
    "payload",
    "protocol",
    "target",
}
_RESPONSE_KEYS = {
    "error_code",
    "error_number",
    "format",
    "metadata",
    "observation_class",
    "operation",
    "outcome",
    "payload",
    "request_digest",
    "status",
    "status_code",
}
