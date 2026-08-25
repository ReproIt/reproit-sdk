from __future__ import annotations

import asyncio
import base64
import json
import unittest

from reproit_sdk.engine_operation import (
    _PROJECT_CONSTRUCTOR,
    ManagedEngineProject,
    OperationPreparation,
    run_operation,
)
from reproit_sdk.semantic_dependency import (
    _DependencyRequest,
    _DependencyResponse,
    _run_dependency,
    _SemanticDependencyError,
)


def _request(**changes: object) -> _DependencyRequest:
    values = {
        "observation_class": "outbound-http",
        "operation": "outbound-http-request",
        "protocol": "http-1.1",
        "encoding": "http-1.1-message",
        "target": "https://inventory.example/item",
        "method": "POST",
        "payload": b"request",
        "metadata": (("x-tag", b"first"), ("x-tag", b"second")),
    }
    values.update(changes)
    return _DependencyRequest(**values)


def _response(**changes: object) -> _DependencyResponse:
    values = {
        "outcome": "response",
        "payload": b"response",
        "metadata": (("x-tag", b"first"), ("x-tag", b"second")),
        "status_code": 200,
    }
    values.update(changes)
    return _DependencyResponse(**values)


def _response_record(response: _DependencyResponse) -> bytes:
    def encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    return json.dumps(
        {
            "error_code": response.error_code,
            "error_number": response.error_number,
            "metadata": [
                {
                    "name": encode(name.encode()),
                    "value": encode(value),
                }
                for name, value in response.metadata
            ],
            "outcome": response.outcome,
            "payload": None if response.payload is None else encode(response.payload),
            "status": response.status,
            "status_code": response.status_code,
        },
        separators=(",", ":"),
    ).encode()


class DependencyBridge:
    def __init__(
        self,
        action: str,
        response: bytes = b"",
        *,
        read_bytes: int = 17,
    ) -> None:
        self.action = action
        self.calls: list[tuple[object, ...]] = []
        self.fail_finish = False
        self.fail_open = False
        self.fail_read = False
        self.offset = 0
        self.read_bytes = read_bytes
        self.response = response

    def operation_begin(self, _engine: int, _begin: object) -> object:
        return type("Native", (), {"handle": 2, "operation_id": "op_dependency"})()

    def operation_input(self, *_arguments: object) -> None:
        pass

    def dependency_open(
        self,
        handle: int,
        request: dict[str, object],
        parent: str | None,
    ) -> object:
        if self.fail_open:
            raise RuntimeError("private bridge failure")
        self.calls.append(("dependency-open", handle, request, parent))
        return type(
            "Dependency",
            (),
            {"handle": 4, "action": self.action},
        )()

    def observation_read(self, handle: int) -> tuple[bytes, bool]:
        if self.fail_read:
            raise RuntimeError("private bridge failure")
        end = min(self.offset + self.read_bytes, len(self.response))
        chunk = self.response[self.offset : end]
        self.offset = end
        self.calls.append(("observation-read", handle, len(chunk)))
        return chunk, self.offset == len(self.response)

    def dependency_finish(
        self,
        handle: int,
        response: dict[str, object] | None,
    ) -> str:
        if self.fail_finish:
            raise RuntimeError("private bridge failure")
        self.calls.append(("dependency-finish", handle, response))
        if response is None:
            return "response"
        return str(response["outcome"])

    def operation_succeed(self, *_arguments: object) -> None:
        pass

    def operation_abandon(self, handle: int) -> None:
        self.calls.append(("operation-abandon", handle))

    def engine_close(self, _handle: int) -> None:
        pass


class SemanticDependencyTests(unittest.TestCase):
    def test_capture_uses_exact_native_call_shape_for_response_and_error(self) -> None:
        for response in (
            _response(),
            _response(
                outcome="error",
                payload=None,
                metadata=(),
                status_code=None,
                error_code="not-found",
                error_number=2,
            ),
        ):
            with self.subTest(outcome=response.outcome):
                bridge = DependencyBridge("capture")
                self.assertIs(
                    self._run(bridge, lambda response=response: response),
                    response,
                )
                opened = bridge.calls[0]
                self.assertEqual(opened[:2], ("dependency-open", 2))
                request = opened[2]
                self.assertEqual(request["payload"], "cmVxdWVzdA")
                self.assertEqual(
                    request["metadata"],
                    [
                        {"name": "eC10YWc", "value": "Zmlyc3Q"},
                        {"name": "eC10YWc", "value": "c2Vjb25k"},
                    ],
                )
                finished = bridge.calls[1]
                self.assertEqual(finished[:2], ("dependency-finish", 4))
                self.assertEqual(finished[2]["outcome"], response.outcome)

    def test_replay_reads_chunks_finishes_validation_then_reconstructs(self) -> None:
        expected = _response()
        bridge = DependencyBridge("replay", _response_record(expected), read_bytes=7)
        live_calls = 0

        def live() -> _DependencyResponse:
            nonlocal live_calls
            live_calls += 1
            return expected

        actual = self._run(bridge, live)
        self.assertEqual(actual, expected)
        self.assertEqual(live_calls, 0)
        self.assertEqual(bridge.calls[-1], ("dependency-finish", 4, None))

    def test_capture_failures_preserve_one_exact_result_or_exception(self) -> None:
        for mode in ("conversion", "open", "finish"):
            with self.subTest(mode=mode, result=True):
                bridge = DependencyBridge("capture")
                bridge.fail_open = mode == "open"
                bridge.fail_finish = mode == "finish"
                request = (
                    _request(payload=b"x" * 65_537)
                    if mode == "conversion"
                    else _request()
                )
                result = _response()
                calls = 0

                def live(result=result) -> _DependencyResponse:
                    nonlocal calls
                    calls += 1
                    return result

                self.assertIs(self._run(bridge, live, request), result)
                self.assertEqual(calls, 1)
            with self.subTest(mode=mode, exception=True):
                bridge = DependencyBridge("capture")
                bridge.fail_open = mode == "open"
                bridge.fail_finish = mode == "finish"
                request = (
                    _request(payload=b"x" * 65_537)
                    if mode == "conversion"
                    else _request()
                )
                sentinel = RuntimeError("application sentinel")
                calls = 0

                def failing(sentinel=sentinel) -> _DependencyResponse:
                    nonlocal calls
                    calls += 1
                    raise sentinel

                with self.assertRaises(RuntimeError) as raised:
                    self._run(bridge, failing, request)
                self.assertIs(raised.exception, sentinel)
                self.assertEqual(calls, 1)

    def test_async_capture_preserves_the_exact_result(self) -> None:
        bridge = DependencyBridge("capture")
        expected = _response()

        async def live() -> _DependencyResponse:
            return expected

        result = self._run(bridge, lambda: _run_dependency(_request(), live))
        self.assertIs(asyncio.run(result), expected)

    def test_metadata_conversion_is_bounded_before_engine_open(self) -> None:
        bridge = DependencyBridge("capture")
        expected = _response()
        request = _request(metadata=(("name", b"x" * 65_537),))
        self.assertIs(self._run(bridge, lambda: expected, request), expected)
        self.assertFalse(any(call[0] == "dependency-open" for call in bridge.calls))

    def test_replay_failure_never_calls_the_live_dependency(self) -> None:
        for mode in ("read", "finish", "record"):
            bridge = DependencyBridge("replay", b"not-json")
            bridge.fail_read = mode == "read"
            bridge.fail_finish = mode == "finish"
            calls = 0

            def live() -> _DependencyResponse:
                nonlocal calls
                calls += 1
                return _response()

            with self.subTest(mode=mode), self.assertRaises(_SemanticDependencyError):
                self._run(bridge, live)
            self.assertEqual(calls, 0)

    @staticmethod
    def _run(
        bridge: DependencyBridge,
        live,
        request: _DependencyRequest | None = None,
    ):
        project = ManagedEngineProject(
            _PROJECT_CONSTRUCTOR,
            bridge,
            1,
            lambda: "unused",
            False,
        )
        preparation = OperationPreparation({}, (), "return")
        operation = live if request is None else lambda: _run_dependency(request, live)
        if request is None:
            operation = lambda: _run_dependency(_request(), live)
        return run_operation(
            project, preparation, lambda _context: operation(), lambda _: None
        )


if __name__ == "__main__":
    unittest.main()
