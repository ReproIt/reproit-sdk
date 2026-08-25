"""Bounded automatic capture for simple standard-library URL requests."""

from __future__ import annotations

import base64
import contextvars
import email.message
import http.client
import json
import math
import socket
import threading
import urllib.parse
import urllib.error
import urllib.request
import weakref
from dataclasses import dataclass
from typing import Any

from .semantic_dependency import (
    _DependencyRequest,
    _DependencyResponse,
    _run_dependency,
)

_FORMAT = "reproit.python-urllib.v1"
_ENCODING = "python-urllib-json-v1"
_MAX_BODY_BYTES = 32 * 1_024
_MAX_HEADER_BYTES = 16 * 1_024
_MAX_HEADERS = 128
_MAX_PAYLOAD_BYTES = 48 * 1_024
_MAX_RESPONSES = 65_536
_MAX_URL_BYTES = 8 * 1_024
_UNSUPPORTED_EVIDENCE = b"python-urllib-unsupported-v1"
_LOCK = threading.Lock()
_ORIGINAL_URLOPEN = urllib.request.urlopen
_ORIGINAL_OPENER_OPEN = urllib.request.OpenerDirector.open
_ORIGINAL_REDIRECT = urllib.request.HTTPRedirectHandler.redirect_request
_ORIGINAL_PROXY_OPEN = urllib.request.ProxyHandler.proxy_open
_ORIGINAL_RESPONSE_READ = http.client.HTTPResponse.read
_ORIGINAL_RESPONSE_CLOSE = http.client.HTTPResponse.close
_ORIGINAL_RESPONSE_ISCLOSED = http.client.HTTPResponse.isclosed
_ORIGINAL_RESPONSE_CLOSED = http.client.HTTPResponse.closed
_ORIGINAL_RESPONSE_METHODS = {
    name: getattr(http.client.HTTPResponse, name)
    for name in (
        "detach",
        "fileno",
        "flush",
        "peek",
        "read1",
        "readable",
        "readinto",
        "readinto1",
        "readline",
        "readlines",
        "seek",
        "seekable",
        "tell",
        "truncate",
        "writable",
        "write",
        "writelines",
    )
    if hasattr(http.client.HTTPResponse, name)
}
_INSTALLED = False
_OWNED_OPENER: urllib.request.OpenerDirector | None = None
_OWNED_HANDLERS: tuple[int, ...] | None = None
_UNSUPPORTED_PROCESS_BOUNDARY = False
_ACTIVE_CALL: contextvars.ContextVar[_CallState | None] = contextvars.ContextVar(
    "reproit_urllib_call",
    default=None,
)
_RESPONSE_STATES: weakref.WeakKeyDictionary[
    http.client.HTTPResponse,
    _ResponseState,
] = weakref.WeakKeyDictionary()


@dataclass
class _CallState:
    unsupported: bool = False


@dataclass
class _ResponseState:
    operation_id: str | None
    response_id: int
    target: str
    closed: bool
    replaying: bool = False


def _urlopen(*arguments: Any, **keywords: Any) -> http.client.HTTPResponse:
    parsed = _parse_urlopen(arguments, keywords)
    if parsed is None or not _opener_is_supported():
        return _unsupported_urlopen(arguments, keywords)
    url, timeout = parsed
    try:
        request = _request("open", url, 0, _encode_timeout(timeout))
    except Exception:
        return _unsupported_urlopen(arguments, keywords)

    def live() -> http.client.HTTPResponse:
        call_state = _CallState()
        token = _ACTIVE_CALL.set(call_state)
        try:
            response = _ORIGINAL_URLOPEN(*arguments, **keywords)
        finally:
            _ACTIVE_CALL.reset(token)
        if not isinstance(response, http.client.HTTPResponse):
            _mark_unowned()
            return response
        _adopt_default_opener(call_state)
        if response.geturl() != url:
            call_state.unsupported = True
        if call_state.unsupported:
            _mark_unowned()
        _initialize_response(response, url)
        return response

    return _execute_dependency(
        request,
        live,
        _encode_open_response,
        lambda payload: _decode_open_response(payload, url),
        _encode_url_error,
        _decode_url_error,
    )


def _response_read(
    response: http.client.HTTPResponse,
    *arguments: Any,
    **keywords: Any,
) -> bytes:
    state = _response_state(response)
    if state is None or not _full_read(arguments, keywords):
        return _unsupported_response_call(response, "read", arguments, keywords)
    if not _same_operation(state):
        return _unsupported_response_call(response, "read", arguments, keywords)
    try:
        request = _request("read", state.target, state.response_id, None)
    except Exception:
        return _unsupported_response_call(response, "read", arguments, keywords)

    def live() -> bytes:
        value = _ORIGINAL_RESPONSE_READ(response, *arguments, **keywords)
        state.closed = _ORIGINAL_RESPONSE_ISCLOSED(response)
        return value

    value = _execute_dependency(
        request,
        live,
        _encode_read_response,
        _decode_read_response,
    )
    if state.replaying:
        state.closed = True
        response.fp = None
        if getattr(response, "length", None) is not None:
            response.length = 0
    return value


def _response_isclosed(response: http.client.HTTPResponse) -> bool:
    state = _response_state(response)
    if state is None:
        return _ORIGINAL_RESPONSE_ISCLOSED(response)
    return state.closed


def _response_close(response: http.client.HTTPResponse) -> None:
    state = _response_state(response)
    if state is None:
        _ORIGINAL_RESPONSE_CLOSE(response)
        return
    if state.replaying:
        response.fp = None
        state.closed = True
        return
    _ORIGINAL_RESPONSE_CLOSE(response)
    state.closed = True


def _response_closed(response: http.client.HTTPResponse) -> bool:
    state = _response_state(response)
    if state is None:
        return _ORIGINAL_RESPONSE_CLOSED.__get__(response, type(response))
    return state.closed


def _opener_open(
    opener: urllib.request.OpenerDirector,
    *arguments: Any,
    **keywords: Any,
) -> Any:
    if _ACTIVE_CALL.get() is None:
        _poison_process_boundary()
        _mark_unowned()
    return _ORIGINAL_OPENER_OPEN(opener, *arguments, **keywords)


def _redirect_request(self: object, *arguments: Any, **keywords: Any) -> Any:
    _mark_active_call_unsupported()
    return _ORIGINAL_REDIRECT(self, *arguments, **keywords)


def _proxy_open(self: object, *arguments: Any, **keywords: Any) -> Any:
    _mark_active_call_unsupported()
    return _ORIGINAL_PROXY_OPEN(self, *arguments, **keywords)


def _parse_urlopen(
    arguments: tuple[Any, ...],
    keywords: dict[str, Any],
) -> tuple[str, object] | None:
    if not 1 <= len(arguments) <= 3:
        return None
    if set(keywords) - {"data", "timeout", "context"}:
        return None
    if len(arguments) > 1 and "data" in keywords:
        return None
    if len(arguments) > 2 and "timeout" in keywords:
        return None
    url = arguments[0]
    data = arguments[1] if len(arguments) > 1 else keywords.get("data")
    timeout = (
        arguments[2]
        if len(arguments) > 2
        else keywords.get("timeout", socket._GLOBAL_DEFAULT_TIMEOUT)
    )
    context = keywords.get("context")
    if not isinstance(url, str) or data is not None or context is not None:
        return None
    try:
        encoded = url.encode("utf-8", "strict")
        parsed = urllib.parse.urlsplit(url)
    except (UnicodeError, ValueError):
        return None
    if (
        not encoded
        or len(encoded) > _MAX_URL_BYTES
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        return None
    if not _valid_timeout(timeout):
        return None
    return url, timeout


def _valid_timeout(value: object) -> bool:
    if value is socket._GLOBAL_DEFAULT_TIMEOUT or value is None:
        return True
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _encode_timeout(value: object) -> list[object]:
    if value is socket._GLOBAL_DEFAULT_TIMEOUT:
        return ["default"]
    if value is None:
        return ["none"]
    selected = float(value)
    return ["seconds", repr(selected)]


def _request(
    action: str,
    target: str,
    response_id: int,
    detail: object,
) -> _DependencyRequest:
    target_bytes = target.encode("utf-8", "strict")
    if not target_bytes or len(target_bytes) > _MAX_URL_BYTES:
        raise _adapter_limit()
    return _DependencyRequest(
        observation_class="outbound-http",
        operation="outbound-http-request",
        protocol="http-1.1",
        encoding=_ENCODING,
        target=target,
        method="GET" if action == "open" else None,
        payload=_encode_payload([_FORMAT, action, response_id, detail]),
    )


def _execute_dependency(
    request: object,
    live: Any,
    encode: Any,
    decode: Any,
    encode_error: Any = None,
    decode_error: Any = None,
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
            if encode_error is None:
                _mark_unowned()
                raise
            try:
                payload = encode_error(error)
            except Exception:
                _mark_unowned()
                raise error
            return _DependencyResponse(
                outcome="error",
                payload=payload,
            )
        return _DependencyResponse(
            outcome="response",
            payload=encode(live_result),
        )

    try:
        translated = _run_dependency(request, capture)
        if live_error is not None:
            raise live_error
        if live_called:
            return live_result
        if not isinstance(translated, _DependencyResponse):
            raise _invalid_replay()
        if translated.payload is None:
            raise _invalid_replay()
        payload = _decode_payload(translated.payload)
        if translated.outcome == "response":
            return decode(payload)
        if translated.outcome == "error" and decode_error is not None:
            raise decode_error(payload)
        raise _invalid_replay()
    except BaseException:
        if live_error is not None:
            raise live_error
        if live_called:
            return live_result
        raise


def _encode_url_error(error: BaseException) -> bytes:
    if type(error) is not urllib.error.URLError:
        raise _adapter_value()
    reason = error.reason
    if (
        not isinstance(reason, str)
        or error.args != (reason,)
        or vars(error) != {"reason": reason}
    ):
        raise _adapter_value()
    selected = _bounded_text(reason, 1_024)
    return _encode_payload([_FORMAT, "error", "url-error", selected])


def _decode_url_error(payload: object) -> urllib.error.URLError:
    if (
        not isinstance(payload, list)
        or len(payload) != 4
        or payload[0:3] != [_FORMAT, "error", "url-error"]
        or not isinstance(payload[3], str)
    ):
        raise _invalid_replay()
    reason = _bounded_text(payload[3], 1_024)
    error = urllib.error.URLError(reason)
    if error.args != (reason,) or vars(error) != {"reason": reason}:
        raise _invalid_replay()
    return error


def _encode_open_response(response: http.client.HTTPResponse) -> bytes:
    state = _response_state(response)
    if state is None:
        raise _adapter_value()
    headers = _encode_headers(response.headers)
    final_url = _bounded_text(response.geturl(), _MAX_URL_BYTES)
    reason = _bounded_text(str(response.reason), 1_024)
    values = [
        _FORMAT,
        "open",
        state.response_id,
        response.status,
        reason,
        response.version,
        final_url,
        headers,
        bool(response.will_close),
        bool(response.chunked),
        response.length,
        state.closed,
    ]
    return _encode_payload(values)


def _decode_open_response(payload: object, target: str) -> http.client.HTTPResponse:
    if not isinstance(payload, list) or len(payload) != 12:
        raise _invalid_replay()
    if payload[0:2] != [_FORMAT, "open"]:
        raise _invalid_replay()
    response_id, status, reason, version, final_url = payload[2:7]
    if (
        not isinstance(response_id, int)
        or not 1 <= response_id <= _MAX_RESPONSES
        or not isinstance(status, int)
        or not 100 <= status <= 599
        or not isinstance(reason, str)
        or not isinstance(version, int)
        or version not in {9, 10, 11}
        or final_url != target
        or not isinstance(payload[8], bool)
        or not isinstance(payload[9], bool)
        or (payload[10] is not None and not isinstance(payload[10], int))
        or not isinstance(payload[11], bool)
    ):
        raise _invalid_replay()
    if response_id != _allocate_response_id():
        raise _invalid_replay()
    headers = _decode_headers(payload[7])
    response = http.client.HTTPResponse.__new__(http.client.HTTPResponse)
    response.fp = None
    response.debuglevel = 0
    response._method = "GET"
    response.headers = headers
    response.msg = headers
    response.version = version
    response.status = status
    response.reason = reason
    response.url = final_url
    response.code = status
    response.will_close = payload[8]
    response.chunked = payload[9]
    response.chunk_left = None
    response.length = payload[10]
    state = _ResponseState(
        _current_operation_id(),
        response_id,
        target,
        payload[11],
        replaying=True,
    )
    _set_response_state(response, state)
    return response


def _encode_read_response(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise _adapter_value()
    if len(value) > _MAX_BODY_BYTES:
        raise _adapter_limit()
    return _encode_payload([_FORMAT, "read", _base64url(value)])


def _decode_read_response(payload: object) -> bytes:
    if (
        not isinstance(payload, list)
        or len(payload) != 3
        or payload[0:2] != [_FORMAT, "read"]
        or not isinstance(payload[2], str)
    ):
        raise _invalid_replay()
    value = _decode_base64url(payload[2])
    if len(value) > _MAX_BODY_BYTES:
        raise _invalid_replay()
    return value


def _encode_headers(headers: email.message.Message) -> list[list[str]]:
    fields = headers.items()
    if len(fields) > _MAX_HEADERS:
        raise _adapter_limit()
    result = []
    total_bytes = 0
    for name, value in fields:
        selected_name = _bounded_text(name, 1_024)
        selected_value = _bounded_text(value, _MAX_HEADER_BYTES)
        total_bytes += len(selected_name.encode()) + len(selected_value.encode())
        if total_bytes > _MAX_HEADER_BYTES:
            raise _adapter_limit()
        result.append([selected_name, selected_value])
    return result


def _decode_headers(value: object) -> http.client.HTTPMessage:
    if not isinstance(value, list) or len(value) > _MAX_HEADERS:
        raise _invalid_replay()
    result = http.client.HTTPMessage()
    total_bytes = 0
    for field in value:
        if (
            not isinstance(field, list)
            or len(field) != 2
            or not all(isinstance(item, str) for item in field)
        ):
            raise _invalid_replay()
        name, field_value = field
        total_bytes += len(name.encode()) + len(field_value.encode())
        if total_bytes > _MAX_HEADER_BYTES:
            raise _invalid_replay()
        result.add_header(name, field_value)
    return result


def _initialize_response(response: http.client.HTTPResponse, target: str) -> None:
    response_id = _allocate_response_id()
    if response_id == 0:
        _mark_unowned()
    state = _ResponseState(
        _current_operation_id(),
        response_id,
        target,
        _ORIGINAL_RESPONSE_ISCLOSED(response),
    )
    _set_response_state(response, state)


def _allocate_response_id() -> int:
    from .engine_operation import _current_operation_context

    context = _current_operation_context()
    if context is None:
        return 0
    with _LOCK:
        response_id = getattr(context, "_reproit_http_next_response_id", 1)
        if response_id > _MAX_RESPONSES:
            return 0
        setattr(context, "_reproit_http_next_response_id", response_id + 1)
        return response_id


def _set_response_state(
    response: http.client.HTTPResponse,
    state: _ResponseState,
) -> None:
    with _LOCK:
        _RESPONSE_STATES[response] = state


def _response_state(response: http.client.HTTPResponse) -> _ResponseState | None:
    with _LOCK:
        return _RESPONSE_STATES.get(response)


def _same_operation(state: _ResponseState) -> bool:
    operation_id = _current_operation_id()
    return operation_id is not None and operation_id == state.operation_id


def _current_operation_id() -> str | None:
    from .engine_operation import _current_operation_context

    context = _current_operation_context()
    return None if context is None else context.operation_id


def _full_read(arguments: tuple[Any, ...], keywords: dict[str, Any]) -> bool:
    if len(arguments) > 1 or set(keywords) - {"amt"}:
        return False
    if arguments and "amt" in keywords:
        return False
    amount = arguments[0] if arguments else keywords.get("amt")
    return amount is None


def _unsupported_urlopen(
    arguments: tuple[Any, ...],
    keywords: dict[str, Any],
) -> Any:
    _mark_unowned()
    call_state = _CallState(unsupported=True)
    token = _ACTIVE_CALL.set(call_state)
    try:
        return _ORIGINAL_URLOPEN(*arguments, **keywords)
    finally:
        _ACTIVE_CALL.reset(token)


def _unsupported_response_call(
    response: http.client.HTTPResponse,
    name: str,
    arguments: tuple[Any, ...],
    keywords: dict[str, Any],
) -> Any:
    _mark_unowned()
    state = _response_state(response)
    if state is not None and state.replaying:
        raise _unsupported_replay()
    original = (
        _ORIGINAL_RESPONSE_READ
        if name == "read"
        else _ORIGINAL_RESPONSE_METHODS[name]
    )
    return original(response, *arguments, **keywords)


def _unsupported_response_method(name: str) -> Any:
    def method(
        response: http.client.HTTPResponse,
        *arguments: Any,
        **keywords: Any,
    ) -> Any:
        return _unsupported_response_call(response, name, arguments, keywords)

    return method


_UNSUPPORTED_RESPONSE_HOOKS = {
    name: _unsupported_response_method(name)
    for name in _ORIGINAL_RESPONSE_METHODS
}


def _mark_active_call_unsupported() -> None:
    call_state = _ACTIVE_CALL.get()
    if call_state is None:
        _poison_process_boundary()
    else:
        call_state.unsupported = True
    _mark_unowned()


def _mark_unowned() -> None:
    from .engine_operation import _current_operation_context

    context = _current_operation_context()
    if context is not None:
        context._mark_unowned("outbound-http", _UNSUPPORTED_EVIDENCE)


def _poison_process_boundary() -> None:
    global _UNSUPPORTED_PROCESS_BOUNDARY
    with _LOCK:
        _UNSUPPORTED_PROCESS_BOUNDARY = True


def _mark_unsupported_operation(context: object) -> None:
    with _LOCK:
        unsupported = _UNSUPPORTED_PROCESS_BOUNDARY
    if unsupported:
        context._mark_unowned("outbound-http", _UNSUPPORTED_EVIDENCE)


def _opener_is_supported() -> bool:
    opener = urllib.request._opener
    if _OWNED_OPENER is None:
        return opener is None
    return opener is _OWNED_OPENER and _handler_fingerprint(opener) == _OWNED_HANDLERS


def _adopt_default_opener(call_state: _CallState) -> None:
    global _OWNED_HANDLERS, _OWNED_OPENER
    opener = urllib.request._opener
    if opener is None:
        call_state.unsupported = True
        return
    if _OWNED_OPENER is None:
        _OWNED_OPENER = opener
        _OWNED_HANDLERS = _handler_fingerprint(opener)
    elif opener is not _OWNED_OPENER:
        call_state.unsupported = True


def _handler_fingerprint(opener: urllib.request.OpenerDirector) -> tuple[int, ...]:
    return tuple(id(handler) for handler in opener.handlers)


def _bounded_text(value: object, maximum_bytes: int) -> str:
    if not isinstance(value, str):
        raise _adapter_value()
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise _adapter_value() from error
    if not encoded or len(encoded) > maximum_bytes:
        raise _adapter_limit()
    return value


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


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    try:
        result = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as error:
        raise _invalid_replay() from error
    if _base64url(result) != value:
        raise _invalid_replay()
    return result


def _hooks_are_original() -> bool:
    return (
        not _INSTALLED
        and urllib.request.urlopen is _ORIGINAL_URLOPEN
        and urllib.request.OpenerDirector.open is _ORIGINAL_OPENER_OPEN
        and urllib.request.HTTPRedirectHandler.redirect_request is _ORIGINAL_REDIRECT
        and urllib.request.ProxyHandler.proxy_open is _ORIGINAL_PROXY_OPEN
        and http.client.HTTPResponse.read is _ORIGINAL_RESPONSE_READ
        and http.client.HTTPResponse.close is _ORIGINAL_RESPONSE_CLOSE
        and http.client.HTTPResponse.isclosed is _ORIGINAL_RESPONSE_ISCLOSED
        and http.client.HTTPResponse.closed is _ORIGINAL_RESPONSE_CLOSED
        and all(
            getattr(http.client.HTTPResponse, name) is original
            for name, original in _ORIGINAL_RESPONSE_METHODS.items()
        )
    )


def _install_http_adapter() -> None:
    global _INSTALLED, _OWNED_HANDLERS, _OWNED_OPENER
    if not _hooks_are_original() or urllib.request._opener is not None:
        raise RuntimeError("The Python URL request hook is unavailable.")
    urllib.request.urlopen = _urlopen
    urllib.request.OpenerDirector.open = _opener_open
    urllib.request.HTTPRedirectHandler.redirect_request = _redirect_request
    urllib.request.ProxyHandler.proxy_open = _proxy_open
    http.client.HTTPResponse.read = _response_read
    http.client.HTTPResponse.close = _response_close
    http.client.HTTPResponse.isclosed = _response_isclosed
    http.client.HTTPResponse.closed = property(_response_closed)
    for name in _ORIGINAL_RESPONSE_METHODS:
        setattr(
            http.client.HTTPResponse,
            name,
            _UNSUPPORTED_RESPONSE_HOOKS[name],
        )
    _OWNED_OPENER = None
    _OWNED_HANDLERS = None
    _INSTALLED = True


def _restore_http_adapter() -> None:
    global _INSTALLED, _OWNED_HANDLERS, _OWNED_OPENER
    if urllib.request.urlopen is _urlopen:
        urllib.request.urlopen = _ORIGINAL_URLOPEN
    if urllib.request.OpenerDirector.open is _opener_open:
        urllib.request.OpenerDirector.open = _ORIGINAL_OPENER_OPEN
    if urllib.request.HTTPRedirectHandler.redirect_request is _redirect_request:
        urllib.request.HTTPRedirectHandler.redirect_request = _ORIGINAL_REDIRECT
    if urllib.request.ProxyHandler.proxy_open is _proxy_open:
        urllib.request.ProxyHandler.proxy_open = _ORIGINAL_PROXY_OPEN
    if http.client.HTTPResponse.read is _response_read:
        http.client.HTTPResponse.read = _ORIGINAL_RESPONSE_READ
    if http.client.HTTPResponse.close is _response_close:
        http.client.HTTPResponse.close = _ORIGINAL_RESPONSE_CLOSE
    if http.client.HTTPResponse.isclosed is _response_isclosed:
        http.client.HTTPResponse.isclosed = _ORIGINAL_RESPONSE_ISCLOSED
    if isinstance(http.client.HTTPResponse.closed, property):
        http.client.HTTPResponse.closed = _ORIGINAL_RESPONSE_CLOSED
    for name, original in _ORIGINAL_RESPONSE_METHODS.items():
        if getattr(http.client.HTTPResponse, name) is _UNSUPPORTED_RESPONSE_HOOKS[name]:
            setattr(http.client.HTTPResponse, name, original)
    _OWNED_OPENER = None
    _OWNED_HANDLERS = None
    _INSTALLED = False


def _adapter_value() -> ValueError:
    return ValueError("The URL request adapter value is invalid.")


def _adapter_limit() -> ValueError:
    return ValueError("The URL request adapter limit was reached.")


def _invalid_replay() -> RuntimeError:
    return RuntimeError("The recorded URL request dependency is invalid.")


def _unsupported_replay() -> RuntimeError:
    return RuntimeError("The recorded URL request operation is unsupported.")
