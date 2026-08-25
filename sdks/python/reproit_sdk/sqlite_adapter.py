"""Bounded automatic capture for the standard-library SQLite client."""

from __future__ import annotations

import _sqlite3 as sqlite_native
import base64
import json
import math
import sqlite3
import sqlite3.dbapi2 as sqlite_dbapi2
import threading
from dataclasses import dataclass
from typing import Any, TypeVar

from .semantic_dependency import (
    _DependencyRequest,
    _DependencyResponse,
    _run_dependency,
)

_Result = TypeVar("_Result")
_FORMAT = "reproit.python-sqlite.v1"
_ENCODING = "python-sqlite-json-v1"
_MAX_PAYLOAD_BYTES = 16 * 1_024
_MAX_BINDINGS = 256
_MAX_DATABASES = 65_536
_MAX_CURSORS_PER_DATABASE = 65_536
_MAX_ERROR_ARGS = 8
_MAX_ERROR_NAME_BYTES = 128
_MAX_FIELDS = 256
_MAX_ROWS = 256
_MIN_INTEGER = -(1 << 63)
_MAX_INTEGER = (1 << 63) - 1
_UNSUPPORTED_EVIDENCE = b"python-sqlite-unsupported-v1"
_UNSUPPORTED_CONNECTION_ATTRIBUTES = {
    "autocommit",
    "in_transaction",
    "isolation_level",
    "row_factory",
    "text_factory",
    "total_changes",
}
_UNSUPPORTED_CURSOR_ATTRIBUTES = {
    "arraysize",
    "description",
    "lastrowid",
    "row_factory",
    "rowcount",
}
_LOCK = threading.Lock()
_ORIGINAL_CONNECT = sqlite3.connect
_ORIGINAL_DBAPI2_CONNECT = sqlite_dbapi2.connect
_ORIGINAL_NATIVE_CONNECT = sqlite_native.connect
_ORIGINAL_CONNECTION = sqlite3.Connection
_ORIGINAL_DBAPI2_CONNECTION = sqlite_dbapi2.Connection
_ORIGINAL_NATIVE_CONNECTION = sqlite_native.Connection
_ORIGINAL_CURSOR = sqlite3.Cursor
_SQLITE_ERROR_CLASSES = {
    error_class.__name__: error_class
    for error_class in (
        sqlite3.Warning,
        sqlite3.Error,
        sqlite3.InterfaceError,
        sqlite3.DatabaseError,
        sqlite3.DataError,
        sqlite3.OperationalError,
        sqlite3.IntegrityError,
        sqlite3.InternalError,
        sqlite3.ProgrammingError,
        sqlite3.NotSupportedError,
    )
}
_INSTALLED = False
_NEXT_DATABASE_ID = 1
_UNSUPPORTED_PROCESS_BOUNDARY = False


@dataclass
class _ConnectionState:
    database_id: str | None
    next_cursor_id: int = 1
    replaying: bool = False
    unowned_operation_id: str | None = None
    unsupported: bool = False


@dataclass
class _CursorState:
    connection: _ManagedConnection
    cursor_id: int
    replaying: bool = False
    surrogate: bool = False
    unowned_operation_id: str | None = None


class _ManagedConnection(_ORIGINAL_CONNECTION):
    __slots__ = ("_reproit_state",)

    def __init__(self, *arguments: Any, **keywords: Any) -> None:
        _ORIGINAL_CONNECTION.__init__(self, *arguments, **keywords)
        if _connection_state(self) is None:
            _initialize_connection(self)
        _mark_unowned(_connection_state(self))

    def cursor(self, *arguments: Any, **keywords: Any) -> _ManagedCursor:
        state = _connection_state(self)
        if state is None or state.unsupported:
            return _unsupported_connection_call(self, "cursor", arguments, keywords)
        if arguments or (keywords and set(keywords) != {"factory"}):
            state.unsupported = True
            return _unsupported_connection_call(self, "cursor", arguments, keywords)
        factory = keywords.get("factory", _ManagedCursor)
        if factory is not _ManagedCursor:
            state.unsupported = True
            _poison_process_boundary()
            return _unsupported_connection_call(self, "cursor", arguments, keywords)
        try:
            cursor_id = _allocate_cursor_id(state)
            request = _request(state, "cursor", cursor_id, None, ())
        except Exception:
            return _unsupported_connection_call(self, "cursor", arguments, keywords)

        def live() -> _ManagedCursor:
            cursor = _ORIGINAL_CONNECTION.cursor(self, factory=_ManagedCursor)
            _initialize_cursor(cursor, self, cursor_id)
            return cursor

        return _execute_dependency(
            request,
            live,
            lambda _value: _encode_payload([_FORMAT, "cursor", cursor_id]),
            lambda payload: _decode_cursor(payload, "cursor", self, state, cursor_id),
        )

    def execute(self, *arguments: Any, **keywords: Any) -> _ManagedCursor:
        state = _connection_state(self)
        parsed = _parse_execute(arguments, keywords)
        if state is None or state.unsupported or parsed is None:
            return _unsupported_connection_call(self, "execute", arguments, keywords)
        sql, bindings = parsed
        try:
            cursor_id = _allocate_cursor_id(state)
            request = _request(state, "execute", cursor_id, sql, bindings)
        except Exception:
            return _unsupported_connection_call(self, "execute", arguments, keywords)

        def live() -> _ManagedCursor:
            cursor = _ORIGINAL_CONNECTION.cursor(self, factory=_ManagedCursor)
            _initialize_cursor(cursor, self, cursor_id)
            _ORIGINAL_CURSOR.execute(cursor, *arguments, **keywords)
            return cursor

        return _execute_dependency(
            request,
            live,
            lambda _value: _encode_payload([_FORMAT, "execute", cursor_id]),
            lambda payload: _decode_cursor(payload, "execute", self, state, cursor_id),
        )

    def __setattr__(self, name: str, value: object) -> None:
        if name in _UNSUPPORTED_CONNECTION_ATTRIBUTES:
            state = _connection_state(self)
            if state is not None:
                state.unsupported = True
                _poison_process_boundary()
                _mark_unowned(state)
        super().__setattr__(name, value)

    def __getattribute__(self, name: str) -> Any:
        if name in _UNSUPPORTED_CONNECTION_ATTRIBUTES:
            state = _connection_state(self)
            _mark_unowned(state)
            if state is not None and state.replaying:
                raise _unsupported_replay()
        return super().__getattribute__(name)

    def __enter__(self) -> _ManagedConnection:
        return _unsupported_connection_call(self, "__enter__", (), {})

    def __exit__(self, *arguments: Any) -> object:
        return _unsupported_connection_call(self, "__exit__", arguments, {})


class _ManagedCursor(_ORIGINAL_CURSOR):
    __slots__ = ("_reproit_state",)

    def execute(self, *arguments: Any, **keywords: Any) -> _ManagedCursor:
        state = _cursor_state(self)
        parsed = _parse_execute(arguments, keywords)
        if state is None or parsed is None:
            return _unsupported_cursor_call(self, "execute", arguments, keywords)
        connection_state = _connection_state(state.connection)
        if connection_state is None or connection_state.unsupported:
            return _unsupported_cursor_call(self, "execute", arguments, keywords)
        sql, bindings = parsed
        try:
            request = _request(
                connection_state,
                "execute",
                state.cursor_id,
                sql,
                bindings,
            )
        except Exception:
            return _unsupported_cursor_call(self, "execute", arguments, keywords)
        return _execute_dependency(
            request,
            lambda: _ORIGINAL_CURSOR.execute(self, *arguments, **keywords),
            lambda _value: _encode_payload([_FORMAT, "execute", state.cursor_id]),
            lambda payload: _decode_same_cursor(payload, "execute", self, state),
        )

    def fetchone(self) -> tuple[object, ...] | None:
        state, request = _cursor_request(self, "fetchone")
        if state is None or request is None:
            return _unsupported_cursor_call(self, "fetchone", (), {})
        return _execute_dependency(
            request,
            lambda: _ORIGINAL_CURSOR.fetchone(self),
            _encode_one_row,
            _decode_one_row,
        )

    def fetchall(self) -> list[tuple[object, ...]]:
        state, request = _cursor_request(self, "fetchall")
        if state is None or request is None:
            return _unsupported_cursor_call(self, "fetchall", (), {})
        return _execute_dependency(
            request,
            lambda: _ORIGINAL_CURSOR.fetchall(self),
            _encode_all_rows,
            _decode_all_rows,
        )

    @property
    def connection(self) -> _ManagedConnection:
        state = _cursor_state(self)
        if state is None:
            return _ORIGINAL_CURSOR.connection.__get__(self, type(self))
        return state.connection

    def __getattribute__(self, name: str) -> Any:
        if name in _UNSUPPORTED_CURSOR_ATTRIBUTES:
            state = _cursor_state(self)
            _mark_unowned(state)
            if state is not None and (state.replaying or state.surrogate):
                raise _unsupported_replay()
        return super().__getattribute__(name)

    def __setattr__(self, name: str, value: object) -> None:
        if name in _UNSUPPORTED_CURSOR_ATTRIBUTES:
            _mark_unowned(_cursor_state(self))
        super().__setattr__(name, value)

    def __iter__(self) -> _ManagedCursor:
        state = _cursor_state(self)
        _mark_unowned(state)
        if state is not None and (state.replaying or state.surrogate):
            raise _unsupported_replay()
        return self

    def __next__(self) -> tuple[object, ...]:
        return _unsupported_cursor_call(self, "__next__", (), {})


def _connect(*arguments: Any, **keywords: Any) -> _ManagedConnection:
    selected = _selected_factory(arguments, keywords)
    if selected not in (None, _ManagedConnection):
        _poison_process_boundary()
        _mark_unowned()
        return _ORIGINAL_CONNECT(*arguments, **keywords)
    adjusted_arguments = list(arguments)
    adjusted_keywords = dict(keywords)
    if len(adjusted_arguments) > 5:
        adjusted_arguments[5] = _ManagedConnection
    else:
        adjusted_keywords["factory"] = _ManagedConnection
    connection = _ORIGINAL_CONNECT(*adjusted_arguments, **adjusted_keywords)
    if _connection_state(connection) is None:
        _initialize_connection(connection)
    return connection


def _selected_factory(arguments: tuple[Any, ...], keywords: dict[str, Any]) -> object:
    if len(arguments) > 5 and "factory" in keywords:
        return object()
    if len(arguments) > 5:
        return arguments[5]
    return keywords.get("factory")


def _initialize_connection(connection: _ManagedConnection) -> None:
    global _NEXT_DATABASE_ID
    with _LOCK:
        if _NEXT_DATABASE_ID > _MAX_DATABASES:
            database_id = None
        else:
            database_id = f"database-{_NEXT_DATABASE_ID}"
            _NEXT_DATABASE_ID += 1
    connection._reproit_state = _ConnectionState(database_id)


def _initialize_cursor(
    cursor: _ManagedCursor,
    connection: _ManagedConnection,
    cursor_id: int,
) -> None:
    cursor._reproit_state = _CursorState(connection, cursor_id)


def _allocate_cursor_id(state: _ConnectionState) -> int:
    with _LOCK:
        if state.next_cursor_id > _MAX_CURSORS_PER_DATABASE:
            raise _adapter_limit()
        cursor_id = state.next_cursor_id
        state.next_cursor_id += 1
        return cursor_id


def _request(
    state: _ConnectionState,
    action: str,
    cursor_id: int,
    sql: str | None,
    bindings: object,
) -> _DependencyRequest:
    if state.database_id is None:
        raise _adapter_limit()
    budget = [_MAX_PAYLOAD_BYTES]
    sql_value = None if sql is None else _bounded_string(sql, budget)
    encoded_bindings = _encode_bindings(bindings, budget)
    return _DependencyRequest(
        observation_class="database",
        operation="database-execute",
        protocol="sqlite",
        encoding=_ENCODING,
        target=state.database_id,
        method=None,
        payload=_encode_payload(
            [_FORMAT, action, state.database_id, cursor_id, sql_value, encoded_bindings]
        ),
    )


def _execute_dependency(
    request: _DependencyRequest,
    live: Any,
    encode: Any,
    decode: Any,
) -> Any:
    live_called = False
    live_result: Any = None
    live_error: BaseException | None = None

    def capture() -> _DependencyResponse:
        nonlocal live_called, live_result, live_error
        live_called = True
        try:
            live_result = live()
        except BaseException as error:
            live_error = error
            try:
                return _encode_sqlite_error(error)
            except Exception:
                _mark_unowned()
                raise error
        return _DependencyResponse(
            outcome="response",
            payload=encode(live_result),
        )

    try:
        translated = _run_dependency(request, capture)
        if live_called:
            if live_error is not None:
                raise live_error
            return live_result
        if not isinstance(translated, _DependencyResponse):
            raise _invalid_replay()
        if translated.outcome == "error":
            raise _decode_sqlite_error(translated)
        if translated.outcome != "response" or translated.payload is None:
            raise _invalid_replay()
        return decode(_decode_payload(translated.payload))
    except BaseException:
        if live_error is not None:
            raise live_error
        if live_called:
            return live_result
        raise


def _encode_sqlite_error(error: BaseException) -> _DependencyResponse:
    error_class = type(error)
    if error_class not in _SQLITE_ERROR_CLASSES.values():
        raise _adapter_value()
    if (
        error.__cause__ is not None
        or error.__context__ is not None
        or error.__suppress_context__
    ):
        raise _adapter_value()
    if not isinstance(error.args, tuple) or len(error.args) > _MAX_ERROR_ARGS:
        raise _adapter_limit()
    budget = [_MAX_PAYLOAD_BYTES]
    encoded_args = [_encode_error_arg(value, budget) for value in error.args]
    state = vars(error)
    error_number = None
    encoded_state: list[object] = ["none"]
    if state:
        if set(state) != {"sqlite_errorcode", "sqlite_errorname"}:
            raise _adapter_value()
        error_number = state["sqlite_errorcode"]
        error_name = state["sqlite_errorname"]
        if not _valid_sqlite_error_state(error_number, error_name):
            raise _adapter_value()
        encoded_name = _bounded_string(error_name, budget)
        if not encoded_name or len(encoded_name.encode("utf-8")) > _MAX_ERROR_NAME_BYTES:
            raise _adapter_value()
        encoded_state = ["sqlite", error_number, encoded_name]
    payload = _encode_payload(
        [_FORMAT, "error", error_class.__name__, encoded_args, encoded_state]
    )
    return _DependencyResponse(
        outcome="error",
        payload=payload,
        error_code="other",
        error_number=error_number,
    )


def _decode_sqlite_error(response: _DependencyResponse) -> BaseException:
    if (
        response.payload is None
        or response.error_code != "other"
        or response.metadata
        or response.status is not None
        or response.status_code is not None
    ):
        raise _invalid_replay()
    payload = _decode_payload(response.payload)
    _require_payload(payload, "error", 5)
    class_name, encoded_args, encoded_state = payload[2:]
    error_class = _SQLITE_ERROR_CLASSES.get(class_name)
    if error_class is None:
        raise _invalid_replay()
    if not isinstance(encoded_args, list) or len(encoded_args) > _MAX_ERROR_ARGS:
        raise _invalid_replay()
    arguments = tuple(_decode_error_arg(value) for value in encoded_args)
    error_number, error_name = _decode_error_state(encoded_state)
    if response.error_number != error_number:
        raise _invalid_replay()
    error = error_class(*arguments)
    if error_number is not None:
        error.sqlite_errorcode = error_number
        error.sqlite_errorname = error_name
    expected_state = (
        {}
        if error_number is None
        else {
            "sqlite_errorcode": error_number,
            "sqlite_errorname": error_name,
        }
    )
    if error.args != arguments or vars(error) != expected_state:
        raise _invalid_replay()
    return error


def _encode_error_arg(value: object, budget: list[int]) -> list[object]:
    if type(value) not in (type(None), int, float, str, bytes):
        raise _adapter_value()
    return _encode_value(value, budget)


def _decode_error_arg(value: object) -> object:
    decoded = _decode_value(value)
    if type(decoded) not in (type(None), int, float, str, bytes):
        raise _invalid_replay()
    return decoded


def _decode_error_state(value: object) -> tuple[int | None, str | None]:
    if value == ["none"]:
        return None, None
    if not isinstance(value, list) or len(value) != 3 or value[0] != "sqlite":
        raise _invalid_replay()
    error_number, error_name = value[1:]
    if not _valid_sqlite_error_state(error_number, error_name):
        raise _invalid_replay()
    try:
        encoded_name = error_name.encode("utf-8", "strict")
    except UnicodeError as error:
        raise _invalid_replay() from error
    if not encoded_name or len(encoded_name) > _MAX_ERROR_NAME_BYTES:
        raise _invalid_replay()
    return error_number, error_name


def _valid_sqlite_error_state(error_number: object, error_name: object) -> bool:
    return (
        type(error_number) is int
        and 0 <= error_number <= (1 << 32) - 1
        and type(error_name) is str
        and error_name.startswith("SQLITE_")
        and getattr(sqlite3, error_name, None) == error_number
    )


def _decode_cursor(
    payload: object,
    action: str,
    connection: _ManagedConnection,
    connection_state: _ConnectionState,
    cursor_id: int,
) -> _ManagedCursor:
    _require_payload(payload, action, 3)
    if payload[2] != cursor_id:
        raise _invalid_replay()
    cursor = _ORIGINAL_CURSOR.__new__(_ManagedCursor)
    cursor._reproit_state = _CursorState(
        connection,
        cursor_id,
        replaying=True,
        surrogate=True,
    )
    connection_state.replaying = True
    return cursor


def _decode_same_cursor(
    payload: object,
    action: str,
    cursor: _ManagedCursor,
    state: _CursorState,
) -> _ManagedCursor:
    _require_payload(payload, action, 3)
    if payload[2] != state.cursor_id:
        raise _invalid_replay()
    state.replaying = True
    connection_state = _connection_state(state.connection)
    if connection_state is not None:
        connection_state.replaying = True
    return cursor


def _cursor_request(
    cursor: _ManagedCursor,
    action: str,
) -> tuple[_CursorState | None, _DependencyRequest | None]:
    state = _cursor_state(cursor)
    connection_state = None if state is None else _connection_state(state.connection)
    if state is None or connection_state is None or connection_state.unsupported:
        return state, None
    try:
        request = _request(
            connection_state,
            action,
            state.cursor_id,
            None,
            (),
        )
    except Exception:
        return state, None
    return state, request


def _encode_one_row(value: object) -> bytes:
    budget = [_MAX_PAYLOAD_BYTES]
    encoded = ["none"] if value is None else ["row", _encode_row(value, budget)]
    return _encode_payload([_FORMAT, "fetchone", encoded])


def _decode_one_row(payload: object) -> tuple[object, ...] | None:
    _require_payload(payload, "fetchone", 3)
    value = payload[2]
    if value == ["none"]:
        return None
    if isinstance(value, list) and len(value) == 2 and value[0] == "row":
        return _decode_row(value[1])
    raise _invalid_replay()


def _encode_all_rows(value: object) -> bytes:
    if not isinstance(value, list) or len(value) > _MAX_ROWS:
        raise _adapter_limit()
    budget = [_MAX_PAYLOAD_BYTES]
    rows = [_encode_row(row, budget) for row in value]
    return _encode_payload([_FORMAT, "fetchall", rows])


def _decode_all_rows(payload: object) -> list[tuple[object, ...]]:
    _require_payload(payload, "fetchall", 3)
    rows = payload[2]
    if not isinstance(rows, list) or len(rows) > _MAX_ROWS:
        raise _invalid_replay()
    return [_decode_row(row) for row in rows]


def _encode_row(value: object, budget: list[int]) -> list[object]:
    if not isinstance(value, tuple) or len(value) > _MAX_FIELDS:
        raise _adapter_value()
    return [_encode_value(field, budget) for field in value]


def _decode_row(value: object) -> tuple[object, ...]:
    if not isinstance(value, list) or len(value) > _MAX_FIELDS:
        raise _invalid_replay()
    return tuple(_decode_value(field) for field in value)


def _encode_bindings(value: object, budget: list[int]) -> list[object]:
    if isinstance(value, dict):
        if len(value) > _MAX_BINDINGS:
            raise _adapter_limit()
        fields = []
        for index, (key, field_value) in enumerate(value.items()):
            if index >= _MAX_BINDINGS:
                raise _adapter_limit()
            fields.append(
                [_bounded_string(key, budget), _encode_value(field_value, budget)]
            )
        return ["named", fields]
    if not isinstance(value, (tuple, list)) or len(value) > _MAX_BINDINGS:
        raise _adapter_value()
    return ["ordered", [_encode_value(field, budget) for field in value]]


def _encode_value(value: object, budget: list[int]) -> list[object]:
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["integer", int(value)]
    if isinstance(value, int):
        if value < _MIN_INTEGER or value > _MAX_INTEGER:
            raise _adapter_value()
        return ["integer", value]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _adapter_value()
        return ["float", "-0.0" if value == 0 and math.copysign(1, value) < 0 else repr(value)]
    if isinstance(value, str):
        return ["string", _bounded_string(value, budget)]
    if isinstance(value, bytes):
        _spend(budget, len(value))
        return ["bytes", _base64url(value)]
    raise _adapter_value()


def _decode_value(value: object) -> object:
    if not isinstance(value, list) or not value:
        raise _invalid_replay()
    if value == ["null"]:
        return None
    if len(value) != 2:
        raise _invalid_replay()
    tag, encoded = value
    if tag == "integer" and isinstance(encoded, int) and not isinstance(encoded, bool):
        if _MIN_INTEGER <= encoded <= _MAX_INTEGER:
            return encoded
    if tag == "float" and isinstance(encoded, str):
        try:
            result = float(encoded)
        except ValueError as error:
            raise _invalid_replay() from error
        canonical = "-0.0" if result == 0 and math.copysign(1, result) < 0 else repr(result)
        if math.isfinite(result) and canonical == encoded:
            return result
    if tag == "string" and isinstance(encoded, str):
        return encoded
    if tag == "bytes" and isinstance(encoded, str):
        return _decode_base64url(encoded)
    raise _invalid_replay()


def _parse_execute(
    arguments: tuple[Any, ...],
    keywords: dict[str, Any],
) -> tuple[str, object] | None:
    if keywords or len(arguments) not in (1, 2) or not isinstance(arguments[0], str):
        return None
    bindings = () if len(arguments) == 1 else arguments[1]
    return arguments[0], bindings


def _encode_payload(value: object) -> bytes:
    try:
        result = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, UnicodeError, ValueError) as error:
        raise _adapter_value() from error
    if not result or len(result) > _MAX_PAYLOAD_BYTES:
        raise _adapter_limit()
    return result


def _decode_payload(value: bytes) -> object:
    if not isinstance(value, bytes) or not value or len(value) > _MAX_PAYLOAD_BYTES:
        raise _invalid_replay()
    try:
        decoded = json.loads(value.decode("utf-8", "strict"))
        if _encode_payload(decoded) != value:
            raise _invalid_replay()
        return decoded
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise _invalid_replay() from error


def _require_payload(value: object, action: str, length: int) -> None:
    if (
        not isinstance(value, list)
        or len(value) != length
        or value[0] != _FORMAT
        or value[1] != action
    ):
        raise _invalid_replay()


def _bounded_string(value: object, budget: list[int]) -> str:
    if not isinstance(value, str):
        raise _adapter_value()
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise _adapter_value() from error
    _spend(budget, len(encoded))
    return value


def _spend(budget: list[int], size: int) -> None:
    if size < 0 or size > budget[0]:
        raise _adapter_limit()
    budget[0] -= size


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    try:
        result = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as error:
        raise _invalid_replay() from error
    if _base64url(result) != value:
        raise _invalid_replay()
    return result


def _connection_state(connection: _ManagedConnection) -> _ConnectionState | None:
    return getattr(connection, "_reproit_state", None)


def _cursor_state(cursor: _ManagedCursor) -> _CursorState | None:
    return getattr(cursor, "_reproit_state", None)


def _unsupported_connection_call(
    connection: _ManagedConnection,
    name: str,
    arguments: tuple[Any, ...],
    keywords: dict[str, Any],
) -> Any:
    if name in {"cursor", "execute", "executemany", "executescript"}:
        _poison_process_boundary()
    state = _connection_state(connection)
    _mark_unowned(state)
    if state is not None and state.replaying:
        raise _unsupported_replay()
    return getattr(_ORIGINAL_CONNECTION, name)(connection, *arguments, **keywords)


def _unsupported_cursor_call(
    cursor: _ManagedCursor,
    name: str,
    arguments: tuple[Any, ...],
    keywords: dict[str, Any],
) -> Any:
    state = _cursor_state(cursor)
    _mark_unowned(state)
    if state is not None and (state.replaying or state.surrogate):
        raise _unsupported_replay()
    return getattr(_ORIGINAL_CURSOR, name)(cursor, *arguments, **keywords)


def _mark_unowned(state: _ConnectionState | _CursorState | None = None) -> None:
    from .engine_operation import _current_operation_context

    context = _current_operation_context()
    if context is not None:
        operation_id = context.operation_id
        if state is not None and state.unowned_operation_id == operation_id:
            return
        if state is not None:
            state.unowned_operation_id = operation_id
        context._mark_unowned("database", _UNSUPPORTED_EVIDENCE)


def _poison_process_boundary() -> None:
    global _UNSUPPORTED_PROCESS_BOUNDARY
    with _LOCK:
        _UNSUPPORTED_PROCESS_BOUNDARY = True


def _mark_unsupported_operation(context: object) -> None:
    with _LOCK:
        unsupported = _UNSUPPORTED_PROCESS_BOUNDARY
    if unsupported:
        context._mark_unowned("database", _UNSUPPORTED_EVIDENCE)


def _unsupported_connection_method(name: str) -> Any:
    def method(self: _ManagedConnection, *args: Any, **kwargs: Any) -> Any:
        return _unsupported_connection_call(self, name, args, kwargs)

    return method


def _unsupported_cursor_method(name: str) -> Any:
    def method(self: _ManagedCursor, *args: Any, **kwargs: Any) -> Any:
        return _unsupported_cursor_call(self, name, args, kwargs)

    return method


for _name in (
    "backup",
    "blobopen",
    "close",
    "commit",
    "create_aggregate",
    "create_collation",
    "create_function",
    "create_window_function",
    "deserialize",
    "enable_load_extension",
    "executemany",
    "executescript",
    "getconfig",
    "getlimit",
    "interrupt",
    "iterdump",
    "load_extension",
    "rollback",
    "serialize",
    "set_authorizer",
    "set_progress_handler",
    "set_trace_callback",
    "setconfig",
    "setlimit",
):
    if hasattr(_ORIGINAL_CONNECTION, _name):
        setattr(_ManagedConnection, _name, _unsupported_connection_method(_name))

for _name in (
    "close",
    "executemany",
    "executescript",
    "fetchmany",
    "setinputsizes",
    "setoutputsize",
):
    if hasattr(_ORIGINAL_CURSOR, _name):
        setattr(_ManagedCursor, _name, _unsupported_cursor_method(_name))


def _hooks_are_original() -> bool:
    return (
        not _INSTALLED
        and sqlite3.connect is _ORIGINAL_CONNECT
        and sqlite_dbapi2.connect is _ORIGINAL_DBAPI2_CONNECT
        and sqlite_native.connect is _ORIGINAL_NATIVE_CONNECT
        and sqlite3.Connection is _ORIGINAL_CONNECTION
        and sqlite_dbapi2.Connection is _ORIGINAL_DBAPI2_CONNECTION
        and sqlite_native.Connection is _ORIGINAL_NATIVE_CONNECTION
    )


def _install_sqlite_adapter() -> None:
    global _INSTALLED, _NEXT_DATABASE_ID
    if not _hooks_are_original():
        raise RuntimeError("The Python SQLite hook is unavailable.")
    sqlite3.connect = _connect
    sqlite_dbapi2.connect = _connect
    sqlite_native.connect = _connect
    sqlite3.Connection = _ManagedConnection
    sqlite_dbapi2.Connection = _ManagedConnection
    sqlite_native.Connection = _ManagedConnection
    _NEXT_DATABASE_ID = 1
    _INSTALLED = True


def _restore_sqlite_adapter() -> None:
    global _INSTALLED
    if sqlite3.connect is _connect:
        sqlite3.connect = _ORIGINAL_CONNECT
    if sqlite_dbapi2.connect is _connect:
        sqlite_dbapi2.connect = _ORIGINAL_DBAPI2_CONNECT
    if sqlite_native.connect is _connect:
        sqlite_native.connect = _ORIGINAL_NATIVE_CONNECT
    if sqlite3.Connection is _ManagedConnection:
        sqlite3.Connection = _ORIGINAL_CONNECTION
    if sqlite_dbapi2.Connection is _ManagedConnection:
        sqlite_dbapi2.Connection = _ORIGINAL_DBAPI2_CONNECTION
    if sqlite_native.Connection is _ManagedConnection:
        sqlite_native.Connection = _ORIGINAL_NATIVE_CONNECTION
    _INSTALLED = False


def _adapter_value() -> ValueError:
    return ValueError("The SQLite adapter value is invalid.")


def _adapter_limit() -> ValueError:
    return ValueError("The SQLite adapter limit was reached.")


def _invalid_replay() -> RuntimeError:
    return RuntimeError("The recorded SQLite dependency is invalid.")


def _unsupported_replay() -> RuntimeError:
    return RuntimeError("The recorded SQLite operation is unsupported.")
