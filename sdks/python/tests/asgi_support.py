"""Validation-only ASGI boundary for neutral lifecycle experiments."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from reproit_sdk import CandidateStart, Sdk

Prepare = Callable[
    [Mapping[str, Any]],
    tuple[CandidateStart, Mapping[str, Any], list[Mapping[str, Any]]],
]
Failure = Callable[[BaseException], Mapping[str, Any]]


class AsgiMiddleware:
    def __init__(
        self,
        application: Callable[..., Awaitable[None]],
        sdk: Sdk,
        prepare: Prepare,
        failure: Failure,
    ) -> None:
        self._application = application
        self._sdk = sdk
        self._prepare = prepare
        self._failure = failure

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._application(scope, receive, send)
            return
        start: CandidateStart | None = None
        try:
            start, begin, inputs = self._prepare(scope)
            self._sdk.begin(start, begin)
            for value in inputs:
                self._sdk.record_input(start.operation_id, value)
        except Exception:
            if start is not None:
                _safe_abandon(self._sdk, start.operation_id)
            await self._application(scope, receive, send)
            return
        input_index = len(inputs)
        request_complete = bool(inputs) or _has_empty_body(scope)
        capture_active = True

        async def capture_receive() -> Any:
            nonlocal capture_active, input_index, request_complete
            message = await receive()
            if message.get("type") != "http.request":
                return message
            body = message.get("body", b"")
            if capture_active and body:
                try:
                    for offset in range(0, len(body), 32 * 1024):
                        chunk = body[offset : offset + 32 * 1024]
                        self._sdk.record_input(
                            start.operation_id,
                            _body_input(chunk, input_index, _content_type(scope)),
                        )
                        input_index += 1
                except Exception:
                    capture_active = False
                    _safe_abandon(self._sdk, start.operation_id)
            if not message.get("more_body", False):
                request_complete = True
            return message

        try:
            await self._application(scope, capture_receive, send)
        except BaseException as original:
            if capture_active and request_complete:
                try:
                    self._sdk.fail(start.operation_id, self._failure(original))
                except Exception:
                    pass
            elif capture_active:
                _safe_abandon(self._sdk, start.operation_id)
            raise
        try:
            self._sdk.succeed(start.operation_id)
        except Exception:
            pass


def _body_input(body: bytes, input_index: int, content_type: str) -> dict[str, Any]:
    return {
        "channel": "input",
        "content_type": content_type,
        "format": "reproit.operation-input.v1",
        "input_index": input_index,
        "value": base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii"),
        "value_digest": f"sha256:{hashlib.sha256(body).hexdigest()}",
    }


def _content_type(scope: Mapping[str, Any]) -> str:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-type":
            decoded = value.decode("ascii", errors="ignore")
            if 0 < len(decoded) <= 128:
                return decoded
    return "application/octet-stream"


def _has_empty_body(scope: Mapping[str, Any]) -> bool:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            return value.strip() == b"0"
    return False


def _safe_abandon(sdk: Sdk, operation_id: str) -> None:
    try:
        sdk.abandon_incomplete(operation_id)
    except Exception:
        try:
            sdk.cancel(operation_id)
        except Exception:
            pass
