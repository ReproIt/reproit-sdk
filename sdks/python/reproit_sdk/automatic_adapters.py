"""Automatic standard-library semantic observation adapters."""

from __future__ import annotations

import base64
import builtins
import contextvars
import errno
import hashlib
import io
import json
import os
import random
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from .encoding import canonical_bytes
from .native_engine import (
    MAX_OBSERVATION_CHUNK_BYTES,
    MAX_OBSERVATION_RESPONSE_READ_BYTES,
    NativeObservationClass,
)
from .observation_adapters import (
    _ObservationAdapterRegistration,
    _activate_observation_adapters,
    _deactivate_observation_adapters,
)
from .sqlite_adapter import (
    _hooks_are_original as _sqlite_hooks_are_original,
    _install_sqlite_adapter,
    _restore_sqlite_adapter,
)
from .subject_protocol import digest_bytes

_Result = TypeVar("_Result")
_REQUEST_FORMAT = "reproit.semantic-observation-request.v1"
_RESPONSE_FORMAT = "reproit.semantic-observation-response.v1"
_MAX_TARGET_BYTES = 16 * 1_024
_MAX_VALUE_BYTES = 32 * 1_024
_MAX_RESPONSE_BYTES = 48 * 1_024
_MAX_RESPONSE_READS = 6
_MAX_JSON_INTEGER = (1 << 53) - 1
_MAX_ERROR_NUMBER = (1 << 32) - 1
_ADAPTER_VERSION = "1.0.0"
_LOCK = threading.Lock()
_REENTRANT = contextvars.ContextVar("reproit_adapter_reentrant", default=False)
_OPEN_PROJECTS = 0

_ORIGINAL_TIME_NS = time.time_ns
_ORIGINAL_TIME = time.time
_UNSUPPORTED_CLOCK_NAMES = (
    "monotonic",
    "monotonic_ns",
    "perf_counter",
    "perf_counter_ns",
    "process_time",
    "process_time_ns",
    "thread_time",
    "thread_time_ns",
    "clock_gettime",
    "clock_gettime_ns",
)
_CLOCK_ORIGINALS = {
    name: getattr(time, name)
    for name in _UNSUPPORTED_CLOCK_NAMES
    if hasattr(time, name)
}
_ORIGINAL_URANDOM = os.urandom
_ORIGINAL_GETRANDOM = getattr(os, "getrandom", None)
_ORIGINAL_RANDOM_URANDOM = random._urandom
_ORIGINAL_PREAD = getattr(os, "pread", None)
_ORIGINAL_OS_READ = os.read
_ORIGINAL_OS_OPEN = os.open
_ORIGINAL_OPEN = builtins.open
_ORIGINAL_IO_OPEN = io.open
_ENVIRONMENT_TYPE = type(os.environ)
_ORIGINAL_ENVIRONMENT_GET = _ENVIRONMENT_TYPE.__getitem__
_ORIGINAL_ENVIRONMENT_ITER = _ENVIRONMENT_TYPE.__iter__
_ORIGINAL_ENVIRONMENT_LEN = _ENVIRONMENT_TYPE.__len__


def _make_clock_hook(name: str) -> Callable[..., Any]:
    def hook(*arguments: Any, **keywords: Any) -> Any:
        _mark_unowned("clock", b"unsupported-clock-call")
        return _CLOCK_ORIGINALS[name](*arguments, **keywords)

    return hook


_CLOCK_HOOKS = {name: _make_clock_hook(name) for name in _CLOCK_ORIGINALS}


class _ReplayInvalid(RuntimeError):
    pass


class _RecordedError(Exception):
    def __init__(self, code: str, number: int | None):
        self.code = code
        self.number = number


def _implementation_digest() -> str:
    try:
        files = tuple(
            Path(__file__).with_name(name)
            for name in (
                "automatic_adapters.py",
                "engine_operation.py",
                "semantic_dependency.py",
                "sqlite_adapter.py",
            )
        )
        hasher = hashlib.sha256()
        for file in files:
            hasher.update(file.name.encode("utf-8"))
            hasher.update(b"\0")
            hasher.update(file.read_bytes())
    except OSError:
        return f"sha256:{hashlib.sha256(b'reproit-python-adapters-v1').hexdigest()}"
    return f"sha256:{hasher.hexdigest()}"


_IMPLEMENTATION_DIGEST = _implementation_digest()
_REGISTRATIONS = tuple(
    _ObservationAdapterRegistration(
        adapter_id=f"reproit.python.{observation_class}",
        adapter_version=_ADAPTER_VERSION,
        observation_class=observation_class,
        implementation_digest=_IMPLEMENTATION_DIGEST,
    )
    for observation_class in (
        "clock",
        "database",
        "environment",
        "filesystem",
        "randomness",
    )
)


def _acquire_automatic_adapters() -> bool:
    """Install the package-owned hooks for the first open project."""
    global _OPEN_PROJECTS
    with _LOCK:
        if _OPEN_PROJECTS > 0:
            _OPEN_PROJECTS += 1
            return True
        if not _hooks_are_original():
            return False
        try:
            _install_hooks()
            _activate_observation_adapters(_REGISTRATIONS)
        except Exception:
            _restore_hooks()
            return False
        _OPEN_PROJECTS = 1
        return True


def _release_automatic_adapters() -> None:
    """Restore the standard library after the last project closes."""
    global _OPEN_PROJECTS
    with _LOCK:
        if _OPEN_PROJECTS == 0:
            return
        _OPEN_PROJECTS -= 1
        if _OPEN_PROJECTS != 0:
            return
        _deactivate_observation_adapters(_REGISTRATIONS)
        _restore_hooks()


def _hooks_are_original() -> bool:
    return (
        time.time_ns is _ORIGINAL_TIME_NS
        and time.time is _ORIGINAL_TIME
        and all(
            getattr(time, name, None) is original
            for name, original in _CLOCK_ORIGINALS.items()
        )
        and os.urandom is _ORIGINAL_URANDOM
        and getattr(os, "getrandom", None) is _ORIGINAL_GETRANDOM
        and random._urandom is _ORIGINAL_RANDOM_URANDOM
        and getattr(os, "pread", None) is _ORIGINAL_PREAD
        and os.read is _ORIGINAL_OS_READ
        and os.open is _ORIGINAL_OS_OPEN
        and builtins.open is _ORIGINAL_OPEN
        and io.open is _ORIGINAL_IO_OPEN
        and _ENVIRONMENT_TYPE.__getitem__ is _ORIGINAL_ENVIRONMENT_GET
        and _ENVIRONMENT_TYPE.__iter__ is _ORIGINAL_ENVIRONMENT_ITER
        and _ENVIRONMENT_TYPE.__len__ is _ORIGINAL_ENVIRONMENT_LEN
        and _sqlite_hooks_are_original()
    )


def _install_hooks() -> None:
    time.time_ns = _time_ns
    time.time = _unsupported_time
    for name, hook in _CLOCK_HOOKS.items():
        setattr(time, name, hook)
    os.urandom = _urandom
    if _ORIGINAL_GETRANDOM is not None:
        os.getrandom = _unsupported_getrandom
    random._urandom = _urandom
    if _ORIGINAL_PREAD is not None:
        os.pread = _pread
    os.read = _unsupported_os_read
    os.open = _unsupported_os_open
    builtins.open = _unsupported_open
    io.open = _unsupported_io_open
    _ENVIRONMENT_TYPE.__getitem__ = _environment_get
    _ENVIRONMENT_TYPE.__iter__ = _unsupported_environment_iter
    _ENVIRONMENT_TYPE.__len__ = _unsupported_environment_len
    _install_sqlite_adapter()


def _restore_hooks() -> None:
    _restore_sqlite_adapter()
    if time.time_ns is _time_ns:
        time.time_ns = _ORIGINAL_TIME_NS
    if time.time is _unsupported_time:
        time.time = _ORIGINAL_TIME
    for name, original in _CLOCK_ORIGINALS.items():
        if getattr(time, name, None) is _CLOCK_HOOKS[name]:
            setattr(time, name, original)
    if os.urandom is _urandom:
        os.urandom = _ORIGINAL_URANDOM
    if _ORIGINAL_GETRANDOM is not None and os.getrandom is _unsupported_getrandom:
        os.getrandom = _ORIGINAL_GETRANDOM
    if random._urandom is _urandom:
        random._urandom = _ORIGINAL_RANDOM_URANDOM
    if _ORIGINAL_PREAD is not None and getattr(os, "pread", None) is _pread:
        os.pread = _ORIGINAL_PREAD
    if os.read is _unsupported_os_read:
        os.read = _ORIGINAL_OS_READ
    if os.open is _unsupported_os_open:
        os.open = _ORIGINAL_OS_OPEN
    if builtins.open is _unsupported_open:
        builtins.open = _ORIGINAL_OPEN
    if io.open is _unsupported_io_open:
        io.open = _ORIGINAL_IO_OPEN
    if _ENVIRONMENT_TYPE.__getitem__ is _environment_get:
        _ENVIRONMENT_TYPE.__getitem__ = _ORIGINAL_ENVIRONMENT_GET
    if _ENVIRONMENT_TYPE.__iter__ is _unsupported_environment_iter:
        _ENVIRONMENT_TYPE.__iter__ = _ORIGINAL_ENVIRONMENT_ITER
    if _ENVIRONMENT_TYPE.__len__ is _unsupported_environment_len:
        _ENVIRONMENT_TYPE.__len__ = _ORIGINAL_ENVIRONMENT_LEN


def _unsupported_time() -> float:
    _mark_unowned("clock", b"unsupported-time-call")
    return _ORIGINAL_TIME()


def _unsupported_getrandom(*arguments: Any, **keywords: Any) -> bytes:
    _mark_unowned("randomness", b"unsupported-getrandom-call")
    return _ORIGINAL_GETRANDOM(*arguments, **keywords)


def _unsupported_os_read(*arguments: Any, **keywords: Any) -> bytes:
    _mark_unowned("filesystem", b"unsupported-os-read")
    return _ORIGINAL_OS_READ(*arguments, **keywords)


def _unsupported_os_open(*arguments: Any, **keywords: Any) -> int:
    _mark_unowned("filesystem", b"unsupported-os-open")
    return _ORIGINAL_OS_OPEN(*arguments, **keywords)


def _unsupported_open(*arguments: Any, **keywords: Any) -> Any:
    _mark_unowned("filesystem", b"unsupported-open")
    return _ORIGINAL_OPEN(*arguments, **keywords)


def _unsupported_io_open(*arguments: Any, **keywords: Any) -> Any:
    _mark_unowned("filesystem", b"unsupported-io-open")
    return _ORIGINAL_IO_OPEN(*arguments, **keywords)


def _unsupported_environment_iter(environment: Any) -> Any:
    _mark_unowned("environment", b"unsupported-environment-iteration")
    return _ORIGINAL_ENVIRONMENT_ITER(environment)


def _unsupported_environment_len(environment: Any) -> int:
    _mark_unowned("environment", b"unsupported-environment-length")
    return _ORIGINAL_ENVIRONMENT_LEN(environment)


def _time_ns() -> int:
    request = _request("clock-wall-time", None, None, None)
    return _observe(
        "clock",
        request,
        _ORIGINAL_TIME_NS,
        lambda value: int(value).to_bytes(8, "big", signed=True),
        lambda value: int.from_bytes(_exact_bytes(value, 8), "big", signed=True),
    )


def _urandom(length: int) -> bytes:
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        _mark_unowned("randomness", b"invalid-random-length")
        return _ORIGINAL_URANDOM(length)
    if length > _MAX_VALUE_BYTES:
        _mark_unowned("randomness", b"random-length-limit")
        return _ORIGINAL_URANDOM(length)
    if length == 0:
        return _ORIGINAL_URANDOM(length)
    request = _request("random-bytes", None, None, length)
    return _observe(
        "randomness",
        request,
        lambda: _ORIGINAL_URANDOM(length),
        _bounded_bytes,
        _bounded_bytes,
    )


def _environment_get(environment: Any, key: str) -> str:
    if not isinstance(key, str):
        _mark_unowned("environment", b"unsupported-environment-key")
        return _ORIGINAL_ENVIRONMENT_GET(environment, key)
    try:
        target = _target(key)
    except (UnicodeError, ValueError):
        _mark_unowned("environment", b"environment-key-limit")
        return _ORIGINAL_ENVIRONMENT_GET(environment, key)
    request = _request("environment-read", target, None, None)
    return _observe(
        "environment",
        request,
        lambda: _ORIGINAL_ENVIRONMENT_GET(environment, key),
        lambda value: value.encode("utf-8", "strict"),
        lambda value: _bounded_bytes(value).decode("utf-8", "strict"),
        missing_key=key,
    )


def _pread(file_descriptor: int, length: int, offset: int) -> bytes:
    if not _valid_read_arguments(file_descriptor, length, offset):
        _mark_unowned("filesystem", b"unsupported-filesystem-read")
        return _ORIGINAL_PREAD(file_descriptor, length, offset)
    if length > _MAX_VALUE_BYTES:
        _mark_unowned("filesystem", b"filesystem-read-limit")
        return _ORIGINAL_PREAD(file_descriptor, length, offset)
    if length == 0:
        return _ORIGINAL_PREAD(file_descriptor, length, offset)
    try:
        target = _target(_file_descriptor_path(file_descriptor))
    except (OSError, UnicodeError, ValueError):
        _mark_unowned("filesystem", b"filesystem-path-unavailable")
        return _ORIGINAL_PREAD(file_descriptor, length, offset)
    request = _request("filesystem-read", target, offset, length)
    return _observe(
        "filesystem",
        request,
        lambda: _ORIGINAL_PREAD(file_descriptor, length, offset),
        _bounded_bytes,
        _bounded_bytes,
    )


def _observe(
    observation_class: NativeObservationClass,
    request: dict[str, object],
    invoke: Callable[[], _Result],
    encode: Callable[[_Result], bytes],
    decode: Callable[[bytes], _Result],
    *,
    missing_key: str | None = None,
) -> _Result:
    context = _active_context()
    if context is None or _REENTRANT.get():
        return invoke()
    token = _REENTRANT.set(True)
    try:
        return _observe_active(
            context, observation_class, request, invoke, encode, decode, missing_key
        )
    finally:
        _REENTRANT.reset(token)


def _observe_active(
    context: Any,
    observation_class: NativeObservationClass,
    request: dict[str, object],
    invoke: Callable[[], _Result],
    encode: Callable[[_Result], bytes],
    decode: Callable[[bytes], _Result],
    missing_key: str | None,
) -> _Result:
    request_bytes = canonical_bytes(request)
    session = context._open_observation(observation_class)
    if session is None or not session._write_request(request_bytes):
        return invoke()
    action = session._dispatch()
    if action == "capture":
        return _capture(session, request_bytes, invoke, encode, missing_key)
    if action == "replay":
        return _replay(session, request_bytes, decode, missing_key)
    session._abandon()
    return invoke()


def _capture(
    session: Any,
    request_bytes: bytes,
    invoke: Callable[[], _Result],
    encode: Callable[[_Result], bytes],
    missing_key: str | None,
) -> _Result:
    try:
        result = invoke()
    except BaseException as original:
        if isinstance(original, KeyError) and missing_key is not None:
            response = _response(request_bytes, "response", None, None, None)
            _record_response(session, response, "response")
        elif isinstance(original, Exception):
            code, number = _error_identity(original)
            response = _response(request_bytes, "error", None, code, number)
            _record_response(session, response, "error")
        else:
            session._abandon()
        raise
    try:
        value = encode(result)
        response = _response(request_bytes, "response", value, None, None)
    except Exception:
        session._abandon()
        return result
    _record_response(session, response, "response")
    return result


def _replay(
    session: Any,
    request_bytes: bytes,
    decode: Callable[[bytes], _Result],
    missing_key: str | None,
) -> _Result:
    try:
        response_bytes = _read_response(session)
        response = _parse_response(response_bytes, request_bytes)
        if response["outcome"] == "error":
            if not session._finish("error"):
                raise _ReplayInvalid()
            raise _recorded_exception(response["error_code"], response["error_number"])
        value = response["value"]
        if value is None and missing_key is not None:
            if not session._finish("response"):
                raise _ReplayInvalid()
            raise KeyError(missing_key)
        decoded = decode(_decode_value(value))
        if not session._finish("response"):
            raise _ReplayInvalid()
        return decoded
    except (KeyError, OSError):
        raise
    except Exception as error:
        session._abandon()
        raise RuntimeError("The recorded observation is invalid.") from error


def _record_response(session: Any, response: dict[str, object], outcome: str) -> None:
    response_bytes = canonical_bytes(response)
    for start in range(0, len(response_bytes), MAX_OBSERVATION_CHUNK_BYTES):
        if not session._write_response(
            response_bytes[start : start + MAX_OBSERVATION_CHUNK_BYTES]
        ):
            return
    session._finish(outcome)


def _read_response(session: Any) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for _ in range(_MAX_RESPONSE_READS):
        value = session._read_response()
        if value is None:
            raise _ReplayInvalid()
        chunk, eof = value
        if len(chunk) > MAX_OBSERVATION_RESPONSE_READ_BYTES:
            raise _ReplayInvalid()
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            raise _ReplayInvalid()
        chunks.append(chunk)
        if eof:
            return b"".join(chunks)
    raise _ReplayInvalid()


def _request(
    operation: str,
    target: str | None,
    offset: int | None,
    length: int | None,
) -> dict[str, object]:
    return {
        "format": _REQUEST_FORMAT,
        "operation": operation,
        "target": target,
        "offset": offset,
        "length": length,
    }


def _response(
    request_bytes: bytes,
    outcome: str,
    value: bytes | None,
    error_code: str | None,
    error_number: int | None,
) -> dict[str, object]:
    request = json.loads(request_bytes)
    return {
        "format": _RESPONSE_FORMAT,
        "operation": request["operation"],
        "request_digest": digest_bytes(request_bytes),
        "outcome": outcome,
        "value": None if value is None else _base64url(value),
        "error_code": error_code,
        "error_number": error_number,
    }


def _parse_response(value: bytes, request_bytes: bytes) -> dict[str, Any]:
    try:
        response = json.loads(value)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise _ReplayInvalid() from error
    if not isinstance(response, dict) or canonical_bytes(response) != value:
        raise _ReplayInvalid()
    if set(response) != {
        "error_code",
        "error_number",
        "format",
        "operation",
        "outcome",
        "request_digest",
        "value",
    }:
        raise _ReplayInvalid()
    if response["format"] != _RESPONSE_FORMAT:
        raise _ReplayInvalid()
    if response["request_digest"] != digest_bytes(request_bytes):
        raise _ReplayInvalid()
    request = json.loads(request_bytes)
    if response["operation"] != request["operation"]:
        raise _ReplayInvalid()
    _validate_response_fields(response)
    _validate_response_pair(request, response)
    return response


def _validate_response_fields(response: dict[str, Any]) -> None:
    outcome = response["outcome"]
    value = response["value"]
    code = response["error_code"]
    number = response["error_number"]
    if outcome == "response":
        if code is not None or number is not None:
            raise _ReplayInvalid()
        if value is not None:
            _decode_value(value)
        return
    if outcome != "error" or value is not None:
        raise _ReplayInvalid()
    if code not in _ERROR_CODES:
        raise _ReplayInvalid()
    if number is not None and (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number < 0
        or number > _MAX_ERROR_NUMBER
    ):
        raise _ReplayInvalid()


def _validate_response_pair(
    request: dict[str, Any], response: dict[str, Any]
) -> None:
    if response["outcome"] != "response":
        return
    value = response["value"]
    operation = request["operation"]
    if value is None:
        if operation != "environment-read":
            raise _ReplayInvalid()
        return
    decoded = _decode_value(value)
    if operation == "clock-wall-time" and len(decoded) != 8:
        raise _ReplayInvalid()
    if operation == "filesystem-read" and len(decoded) > request["length"]:
        raise _ReplayInvalid()
    if operation == "random-bytes" and len(decoded) != request["length"]:
        raise _ReplayInvalid()


_ERROR_CODES = {
    "interrupted",
    "invalid-input",
    "not-found",
    "other",
    "permission-denied",
    "resource-limit",
    "unsupported",
}


def _error_identity(error: Exception) -> tuple[str, int | None]:
    number = error.errno if isinstance(error, OSError) else None
    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number < 0
        or number > _MAX_ERROR_NUMBER
    ):
        number = None
    if isinstance(error, InterruptedError):
        return "interrupted", number
    if isinstance(error, (TypeError, ValueError)):
        return "invalid-input", number
    if isinstance(error, FileNotFoundError):
        return "not-found", number
    if isinstance(error, PermissionError):
        return "permission-denied", number
    if isinstance(error, MemoryError) or number in {errno.EMFILE, errno.ENFILE, errno.ENOMEM}:
        return "resource-limit", number
    if isinstance(error, NotImplementedError):
        return "unsupported", number
    return "other", number


def _recorded_exception(code: Any, number: Any) -> OSError:
    if code == "interrupted":
        return InterruptedError(_errno(number, errno.EINTR), "Recorded operation failed.")
    if code == "not-found":
        return FileNotFoundError(_errno(number, errno.ENOENT), "Recorded operation failed.")
    if code == "permission-denied":
        return PermissionError(_errno(number, errno.EACCES), "Recorded operation failed.")
    if code == "invalid-input":
        return OSError(_errno(number, errno.EINVAL), "Recorded operation failed.")
    if code == "resource-limit":
        return OSError(_errno(number, errno.ENOMEM), "Recorded operation failed.")
    if code == "unsupported":
        return OSError(_errno(number, errno.ENOSYS), "Recorded operation failed.")
    return OSError(_errno(number, errno.EIO), "Recorded operation failed.")


def _errno(number: int | None, fallback: int) -> int:
    return fallback if number is None else number


def _target(value: str) -> str:
    encoded = value.encode("utf-8", "strict")
    if not encoded or len(encoded) > _MAX_TARGET_BYTES:
        raise ValueError("The observation target is too large.")
    return _base64url(encoded)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_value(value: Any) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise _ReplayInvalid()
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeError) as error:
        raise _ReplayInvalid() from error
    if _base64url(decoded) != value or len(decoded) > _MAX_VALUE_BYTES:
        raise _ReplayInvalid()
    return decoded


def _bounded_bytes(value: Any) -> bytes:
    if not isinstance(value, bytes) or len(value) > _MAX_VALUE_BYTES:
        raise ValueError("The observation value is invalid.")
    return value


def _exact_bytes(value: bytes, length: int) -> bytes:
    if len(value) != length:
        raise _ReplayInvalid()
    return value


def _valid_read_arguments(file_descriptor: Any, length: Any, offset: Any) -> bool:
    valid = all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in (file_descriptor, length, offset)
    )
    return valid and offset <= _MAX_JSON_INTEGER


def _file_descriptor_path(file_descriptor: int) -> str:
    if os.name == "posix" and Path("/proc/self/fd").is_dir():
        return os.readlink(f"/proc/self/fd/{file_descriptor}")
    if os.name == "posix":
        import fcntl

        result = fcntl.fcntl(file_descriptor, 50, bytes(1_024))
        return bytes(result).split(b"\0", 1)[0].decode("utf-8", "strict")
    raise OSError(errno.ENOSYS, "File descriptor paths are not supported.")


def _active_context() -> Any:
    from .engine_operation import _current_operation_context

    return _current_operation_context()


def _mark_unowned(observation_class: NativeObservationClass, evidence: bytes) -> None:
    context = _active_context()
    if context is not None and not _REENTRANT.get():
        token = _REENTRANT.set(True)
        try:
            context._mark_unowned(observation_class, evidence)
        finally:
            _REENTRANT.reset(token)
