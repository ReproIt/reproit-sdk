from __future__ import annotations

import base64
import email.message
import http.client
import io
import json
import socket
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from itertools import count
from unittest import mock

from reproit_sdk import automatic_adapters, http_adapter
from reproit_sdk.engine_operation import (
    _PROJECT_CONSTRUCTOR,
    ManagedEngineProject,
    OperationPreparation,
    run_operation,
)

_BRIDGE_IDS = count(1)


class HttpBridge:
    def __init__(
        self,
        action: str,
        replay_responses: list[dict[str, object]] | None = None,
    ) -> None:
        self.abandoned = 0
        self.action = action
        self.bridge_id = next(_BRIDGE_IDS)
        self.current_response: dict[str, object] | None = None
        self.next_handle = 4
        self.offset = 0
        self.operation_count = 0
        self.replay_responses = list(replay_responses or [])
        self.requests: list[dict[str, object]] = []
        self.responses: list[dict[str, object]] = []
        self.unowned: list[tuple[str, bytes]] = []

    def operation_begin(self, _engine: int, _begin: object) -> object:
        self.operation_count += 1
        operation_id = f"op_http_{self.bridge_id}_{self.operation_count}"
        return type("Native", (), {"handle": 2, "operation_id": operation_id})()

    def operation_input(self, *_arguments: object) -> None:
        pass

    def dependency_open(
        self,
        _handle: int,
        request: dict[str, object],
        _parent: str | None,
    ) -> object:
        self.requests.append(request)
        handle = self.next_handle
        self.next_handle += 1
        if self.action == "replay":
            self.current_response = (
                self.replay_responses.pop(0) if self.replay_responses else None
            )
            self.offset = 0
        return type("Dependency", (), {"handle": handle, "action": self.action})()

    def observation_read(self, _handle: int) -> tuple[bytes, bool]:
        data = _response_record(self.current_response)
        end = min(self.offset + 97, len(data))
        chunk = data[self.offset : end]
        self.offset = end
        return chunk, end == len(data)

    def dependency_finish(
        self,
        _handle: int,
        response: dict[str, object] | None,
    ) -> str | None:
        if response is not None:
            self.responses.append(response)
            return str(response["outcome"])
        if self.current_response is None:
            return None
        return str(self.current_response["outcome"])

    def operation_unowned(
        self,
        _handle: int,
        observation_class: str,
        evidence: bytes,
        _parent: str | None,
    ) -> None:
        self.unowned.append((observation_class, bytes(evidence)))

    def operation_succeed(self, *_arguments: object) -> None:
        pass

    def operation_abandon(self, _handle: int) -> None:
        self.abandoned += 1

    def engine_close(self, _handle: int) -> None:
        pass


class HttpAdapterTests(unittest.TestCase):
    def tearDown(self) -> None:
        urllib.request._opener = None
        while automatic_adapters._OPEN_PROJECTS:
            automatic_adapters._release_automatic_adapters()
        with http_adapter._LOCK:
            http_adapter._UNSUPPORTED_PROCESS_BOUNDARY = False

    def test_install_is_shared_and_last_release_restores_every_hook(self) -> None:
        original_urlopen = urllib.request.urlopen
        original_read = http.client.HTTPResponse.read
        self.assertTrue(automatic_adapters._acquire_automatic_adapters())
        installed_urlopen = urllib.request.urlopen
        installed_read = http.client.HTTPResponse.read
        self.assertIsNot(installed_urlopen, original_urlopen)
        self.assertIsNot(installed_read, original_read)
        self.assertTrue(automatic_adapters._acquire_automatic_adapters())
        automatic_adapters._release_automatic_adapters()
        self.assertIs(urllib.request.urlopen, installed_urlopen)
        automatic_adapters._release_automatic_adapters()
        self.assertIs(urllib.request.urlopen, original_urlopen)
        self.assertIs(http.client.HTTPResponse.read, original_read)

    def test_capture_preserves_exact_response_and_replay_has_no_network(self) -> None:
        url = "http://service.test/items"
        live_response = _response(url, b"payload")
        with _adapters():
            _adopt_test_opener()
            bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                return_value=live_response,
            ):
                result = _run(
                    bridge,
                    lambda: self._open_and_read(url, live_response),
                )
        self.assertEqual(result, (200, "OK", "first, second", b"payload"))
        self.assertEqual(len(bridge.requests), 2)
        self.assertEqual(
            [_request_payload(request)[1] for request in bridge.requests],
            ["open", "read"],
        )
        self.assertEqual(
            _request_payload(bridge.requests[0]),
            [http_adapter._FORMAT, "open", 0, ["default"]],
        )
        self.assertEqual(
            _request_payload(bridge.requests[1]),
            [http_adapter._FORMAT, "read", 1, None],
        )

        with _adapters():
            replay = HttpBridge("replay", bridge.responses)
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=AssertionError("Replay called the network."),
            ), mock.patch.object(
                http_adapter,
                "_ORIGINAL_RESPONSE_READ",
                side_effect=AssertionError("Replay read a live socket."),
            ):
                replay_result = _run(
                    replay,
                    lambda: self._open_and_read(url),
                )
        self.assertEqual(replay_result, result)
        self.assertEqual(
            [_request_payload(request) for request in replay.requests],
            [_request_payload(request) for request in bridge.requests],
        )

    def test_url_error_capture_preserves_identity_and_replay_avoids_network(self) -> None:
        sentinel = urllib.error.URLError("bounded network failure")
        with _adapters():
            _adopt_test_opener()
            bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=sentinel,
            ):
                with self.assertRaises(urllib.error.URLError) as raised:
                    _run(
                        bridge,
                        lambda: urllib.request.urlopen("http://service.test/error"),
                    )
        self.assertIs(raised.exception, sentinel)
        self.assertEqual(bridge.responses[0]["outcome"], "error")

        with _adapters():
            replay = HttpBridge("replay", bridge.responses)
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=AssertionError("Replay called the network."),
            ):
                with self.assertRaises(urllib.error.URLError) as replayed:
                    _run(
                        replay,
                        lambda: urllib.request.urlopen(
                            "http://service.test/error"
                        ),
                    )
        self.assertIsNot(replayed.exception, sentinel)
        self.assertEqual(replayed.exception.reason, "bounded network failure")
        self.assertEqual(replayed.exception.args, ("bounded network failure",))
        self.assertEqual(
            vars(replayed.exception),
            {"reason": "bounded network failure"},
        )

    def test_streaming_http_error_is_exact_but_unowned_and_not_recorded(self) -> None:
        headers = email.message.Message()
        headers.add_header("Content-Length", "4")
        sentinel = urllib.error.HTTPError(
            "http://service.test/error",
            404,
            "Not Found",
            headers,
            io.BytesIO(b"body"),
        )
        with _adapters():
            _adopt_test_opener()
            bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=sentinel,
            ):
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    _run(
                        bridge,
                        lambda: urllib.request.urlopen(
                            "http://service.test/error"
                        ),
                    )
        self.assertIs(raised.exception, sentinel)
        self.assertEqual(bridge.responses, [])
        self.assertTrue(bridge.unowned)

    def test_corrupt_url_error_record_stops_without_network(self) -> None:
        reason = "recorded failure"
        payload = base64.urlsafe_b64encode(
            json.dumps(
                [http_adapter._FORMAT, "error", "url-error", reason],
                separators=(",", ":"),
            ).encode()
        ).rstrip(b"=").decode()
        noncanonical = base64.urlsafe_b64encode(
            json.dumps(
                [http_adapter._FORMAT, "error", "url-error", reason]
            ).encode()
        ).rstrip(b"=").decode()
        for corrupt_payload in (payload[:-1] + "!", noncanonical):
            corrupt = {
                "error_code": None,
                "error_number": None,
                "metadata": [],
                "outcome": "error",
                "payload": corrupt_payload,
                "status": None,
                "status_code": None,
            }
            with self.subTest(payload=corrupt_payload), _adapters():
                replay = HttpBridge("replay", [corrupt])
                with mock.patch.object(
                    http_adapter,
                    "_ORIGINAL_URLOPEN",
                    side_effect=AssertionError("Replay called the network."),
                ):
                    with self.assertRaises(RuntimeError):
                        _run(
                            replay,
                            lambda: urllib.request.urlopen(
                                "http://service.test/error"
                            ),
                        )

    def test_over_limit_url_error_reason_is_exact_and_unowned(self) -> None:
        sentinel = urllib.error.URLError("x" * 1_025)
        with _adapters():
            _adopt_test_opener()
            bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=sentinel,
            ):
                with self.assertRaises(urllib.error.URLError) as raised:
                    _run(
                        bridge,
                        lambda: urllib.request.urlopen(
                            "http://service.test/error"
                        ),
                    )
        self.assertIs(raised.exception, sentinel)
        self.assertEqual(bridge.responses, [])
        self.assertTrue(bridge.unowned)

    def test_redirect_body_context_request_and_partial_read_are_unowned(self) -> None:
        url = "http://service.test/items"
        with _adapters():
            _adopt_test_opener()

            redirect_response = _response(url, b"redirected")

            def redirected(*_args: object, **_kwargs: object) -> object:
                http_adapter._mark_active_call_unsupported()
                return redirect_response

            redirect_bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=redirected,
            ):
                response = _run(
                    redirect_bridge,
                    lambda: urllib.request.urlopen(url),
                )
            response.close()
            self.assertTrue(redirect_bridge.unowned)

            unsupported_cases = (
                lambda: urllib.request.urlopen(url, data=b"body"),
                lambda: urllib.request.urlopen(url, context=object()),
                lambda: urllib.request.urlopen(
                    urllib.request.Request(
                        url,
                        headers={"Authorization": "fixed-test-value"},
                    )
                ),
            )
            for call in unsupported_cases:
                bridge = HttpBridge("capture")
                expected = _response(url, b"value")
                with mock.patch.object(
                    http_adapter,
                    "_ORIGINAL_URLOPEN",
                    return_value=expected,
                ):
                    self.assertIs(_run(bridge, call), expected)
                expected.close()
                self.assertEqual(bridge.requests, [])
                self.assertTrue(bridge.unowned)

            partial_response = _response(url, b"partial")
            partial_bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                return_value=partial_response,
            ):
                value = _run(
                    partial_bridge,
                    lambda: urllib.request.urlopen(url).read(3),
                )
            self.assertEqual(value, b"par")
            self.assertTrue(partial_bridge.unowned)

    def test_over_limit_body_returns_exact_bytes_and_abandons_capture(self) -> None:
        url = "http://service.test/large"
        body = b"x" * (http_adapter._MAX_BODY_BYTES + 1)
        live_response = _response(url, body)
        with _adapters():
            _adopt_test_opener()
            bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                return_value=live_response,
            ):
                value = _run(
                    bridge,
                    lambda: urllib.request.urlopen(url).read(),
                )
        self.assertIs(value, body)
        self.assertEqual(bridge.abandoned, 1)

    def test_response_identity_limit_is_per_operation_and_releasable(self) -> None:
        url = "http://service.test/bounded"
        first = _response(url, b"first")
        second = _response(url, b"second")
        with _adapters(), mock.patch.object(http_adapter, "_MAX_RESPONSES", 1):
            _adopt_test_opener()
            bridge = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=[first, second],
            ):
                self.assertIs(_run(bridge, lambda: urllib.request.urlopen(url)), first)
                self.assertIs(_run(bridge, lambda: urllib.request.urlopen(url)), second)
            first.close()
            second.close()
        response_ids = [
            _native_response_payload(response)[2]
            for response in bridge.responses
        ]
        self.assertEqual(response_ids, [1, 1])

        one = _response(url, b"one")
        two = _response(url, b"two")
        with _adapters(), mock.patch.object(http_adapter, "_MAX_RESPONSES", 1):
            _adopt_test_opener()
            limited = HttpBridge("capture")
            with mock.patch.object(
                http_adapter,
                "_ORIGINAL_URLOPEN",
                side_effect=[one, two],
            ):
                returned = _run(
                    limited,
                    lambda: (
                        urllib.request.urlopen(url),
                        urllib.request.urlopen(url),
                    ),
                )
            returned[0].close()
            returned[1].close()
        self.assertTrue(limited.unowned)

    @staticmethod
    def _open_and_read(
        url: str,
        expected: http.client.HTTPResponse | None = None,
    ) -> tuple[int, str, str | None, bytes]:
        response = urllib.request.urlopen(url)
        if expected is not None and response is not expected:
            raise AssertionError("Capture changed the response identity.")
        if not isinstance(response, http.client.HTTPResponse):
            raise AssertionError("The response type changed.")
        return (
            response.status,
            response.reason,
            response.getheader("X-Order"),
            response.read(),
        )


def _response(url: str, body: bytes) -> http.client.HTTPResponse:
    response = http.client.HTTPResponse.__new__(http.client.HTTPResponse)
    headers = email.message.Message()
    headers.add_header("X-Order", "first")
    headers.add_header("X-Order", "second")
    headers.add_header("Content-Length", str(len(body)))
    response.fp = io.BytesIO(body)
    response.debuglevel = 0
    response._method = "GET"
    response.headers = headers
    response.msg = headers
    response.version = 11
    response.status = 200
    response.reason = "OK"
    response.url = url
    response.code = 200
    response.will_close = True
    response.chunked = False
    response.chunk_left = None
    response.length = len(body)
    return response


def _adopt_test_opener() -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    urllib.request._opener = opener
    http_adapter._OWNED_OPENER = opener
    http_adapter._OWNED_HANDLERS = http_adapter._handler_fingerprint(opener)


def _response_record(response: dict[str, object] | None) -> bytes:
    if response is None:
        return b"null"
    return json.dumps(response, separators=(",", ":")).encode("utf-8")


def _request_payload(request: dict[str, object]) -> object:
    value = request["payload"]
    assert isinstance(value, str)
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    return json.loads(decoded)


def _native_response_payload(response: dict[str, object]) -> object:
    value = response["payload"]
    assert isinstance(value, str)
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    return json.loads(decoded)


def _run(bridge: HttpBridge, operation: object) -> object:
    project = ManagedEngineProject(
        _PROJECT_CONSTRUCTOR,
        bridge,
        1,
        lambda: "unused",
        False,
    )
    return run_operation(
        project,
        OperationPreparation({}, (), "return"),
        lambda _context: operation(),
        lambda _error: None,
    )


@contextmanager
def _adapters() -> object:
    urllib.request._opener = None
    if not automatic_adapters._acquire_automatic_adapters():
        raise RuntimeError("The automatic adapters did not install.")
    try:
        yield
    finally:
        urllib.request._opener = None
        automatic_adapters._release_automatic_adapters()


if __name__ == "__main__":
    unittest.main()
