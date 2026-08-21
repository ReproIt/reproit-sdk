"""ASGI request-response boundary for the Repro It Python SDK."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from . import CandidateStart, Sdk

Prepare = Callable[
    [Mapping[str, Any]],
    tuple[CandidateStart, Mapping[str, Any], list[Mapping[str, Any]]],
]
Failure = Callable[[BaseException], Mapping[str, Any]]


class AsgiMiddleware:
    """Capture exceptions that cross one top-level ASGI HTTP boundary."""

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
                try:
                    self._sdk.cancel(start.operation_id)
                except Exception:
                    pass
            await self._application(scope, receive, send)
            return
        try:
            await self._application(scope, receive, send)
        except BaseException as original:
            try:
                self._sdk.fail(start.operation_id, self._failure(original))
            except Exception:
                pass
            raise
        try:
            self._sdk.succeed(start.operation_id)
        except Exception:
            pass
