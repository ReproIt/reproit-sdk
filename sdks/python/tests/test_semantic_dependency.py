from __future__ import annotations

import asyncio
import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from reproit_sdk.encoding import canonical_bytes
from reproit_sdk.semantic_dependency import (
    _DependencyRequest,
    _DependencyResponse,
    _SemanticDependencyError,
    _decode_dependency_request,
    _decode_dependency_response,
    _encode_dependency_request,
    _encode_dependency_response,
    _run_dependency,
)


class FakeSession:
    def __init__(self, action: str, replay: bytes = b"") -> None:
        self.action = action
        self.replay = replay
        self.request_chunks: list[bytes] = []
        self.response_chunks: list[bytes] = []
        self.finished: str | None = None
        self.abandoned = False
        self.fail_request_write = False
        self.fail_response_write = False
        self.fail_finish = False
        self.fail_dispatch = False

    def _write_request(self, chunk: bytes) -> bool:
        self.request_chunks.append(chunk)
        return not self.fail_request_write

    def _write_response(self, chunk: bytes) -> bool:
        self.response_chunks.append(chunk)
        return not self.fail_response_write

    def _dispatch(self) -> str:
        if self.fail_dispatch:
            raise RuntimeError("private bridge failure")
        return self.action

    def _read_response(self) -> tuple[bytes, bool]:
        value = self.replay
        self.replay = b""
        return value, True

    def _finish(self, outcome: str) -> bool:
        self.finished = outcome
        return not self.fail_finish

    def _abandon(self) -> None:
        self.abandoned = True


class FakeContext:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.opened: list[str] = []
        self.unowned: list[tuple[str, bytes]] = []
        self.abandoned = False
        self.fail_open = False

    def _open_observation(self, observation_class: str) -> FakeSession:
        if self.fail_open:
            raise RuntimeError("private bridge failure")
        self.opened.append(observation_class)
        return self.session

    def _mark_unowned(self, observation_class: str, evidence: bytes) -> None:
        self.unowned.append((observation_class, evidence))

    def _abandon(self) -> None:
        self.abandoned = True


class SemanticDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        vector_path = (
            Path(__file__).parents[3]
            / ".core"
            / "specs/v1/protocol-vectors.json"
        )
        cls.vectors = json.loads(vector_path.read_bytes())
        cls.positive = cls.vectors["positive"]

    def test_positive_core_vectors_round_trip_exactly(self) -> None:
        for suffix in ("database", "outbound_http", "queue"):
            request_value = self.positive[
                f"semantic_dependency_request_{suffix}"
            ]["value"]
            response_value = self.positive[
                f"semantic_dependency_response_{suffix}"
            ]["value"]
            request_record = canonical_bytes(request_value)
            response_record = canonical_bytes(response_value)
            with self.subTest(suffix=suffix):
                request = _decode_dependency_request(request_record)
                response = _decode_dependency_response(
                    request_record, response_record
                )
                self.assertEqual(
                    _encode_dependency_request(request), request_record
                )
                self.assertEqual(
                    _encode_dependency_response(request_record, response),
                    response_record,
                )
        http = _decode_dependency_request(
            canonical_bytes(
                self.positive[
                    "semantic_dependency_request_outbound_http"
                ]["value"]
            )
        )
        self.assertEqual(
            http.metadata,
            (("x-tag", b"capture"), ("x-tag", b"second")),
        )

    def test_all_core_negative_vectors_are_rejected(self) -> None:
        negatives = [
            value
            for value in self.vectors["negative"]
            if value["name"].startswith("semantic-dependency-")
        ]
        self.assertEqual(len(negatives), 9)
        for vector in negatives:
            mutated = copy.deepcopy(self.positive[vector["base"]]["value"])
            self._apply_vector_change(mutated, vector)
            record = canonical_bytes(mutated)
            with (
                self.subTest(name=vector["name"]),
                self.assertRaises(_SemanticDependencyError),
            ):
                if vector["schema"] == "semantic_dependency_request":
                    _decode_dependency_request(record)
                else:
                    suffix = vector["base"].removeprefix(
                        "semantic_dependency_response_"
                    )
                    request = canonical_bytes(
                        self.positive[
                            f"semantic_dependency_request_{suffix}"
                        ]["value"]
                    )
                    _decode_dependency_response(request, record)

    def test_capture_uses_one_generic_session_and_exact_records(self) -> None:
        request_record, request, response_record, response = self._http_pair()
        session = FakeSession("capture")
        context = FakeContext(session)
        with mock.patch(
            "reproit_sdk.semantic_dependency._active_context",
            return_value=context,
        ):
            result = _run_dependency(request, lambda: response)
        self.assertEqual(result, response)
        self.assertEqual(context.opened, ["outbound-http"])
        self.assertEqual(b"".join(session.request_chunks), request_record)
        self.assertEqual(b"".join(session.response_chunks), response_record)
        self.assertEqual(session.finished, "response")

    def test_replay_returns_only_the_recorded_response(self) -> None:
        _, request, response_record, response = self._http_pair()
        session = FakeSession("replay", response_record)
        context = FakeContext(session)

        def live_call() -> _DependencyResponse:
            raise AssertionError("Replay called the live dependency.")

        with mock.patch(
            "reproit_sdk.semantic_dependency._active_context",
            return_value=context,
        ):
            result = _run_dependency(request, live_call)
        self.assertEqual(result, response)
        self.assertEqual(session.finished, "response")

    def test_async_capture_keeps_the_same_generic_session(self) -> None:
        _, request, _, response = self._http_pair()
        session = FakeSession("capture")

        async def capture() -> _DependencyResponse:
            return response

        with mock.patch(
            "reproit_sdk.semantic_dependency._active_context",
            return_value=FakeContext(session),
        ):
            result = asyncio.run(_run_dependency(request, capture))
        self.assertEqual(result, response)
        self.assertEqual(session.finished, "response")

    def test_bounds_apply_before_a_session_and_large_records_are_chunked(self) -> None:
        invalid = _DependencyRequest(
            "database",
            "database-execute",
            "postgresql",
            "postgresql-wire-v3",
            "primary",
            None,
            bytes(24 * 1_024 + 1),
        )
        context = FakeContext(FakeSession("capture"))
        sentinel = _DependencyResponse("response", b"")
        with mock.patch(
            "reproit_sdk.semantic_dependency._active_context",
            return_value=context,
        ):
            self.assertIs(_run_dependency(invalid, lambda: sentinel), sentinel)
        self.assertEqual(context.opened, [])
        self.assertEqual(len(context.unowned), 1)

        request = _DependencyRequest(
            "database",
            "database-execute",
            "postgresql",
            "postgresql-wire-v3",
            "primary",
            None,
            bytes(24 * 1_024),
        )
        response = _DependencyResponse("response", b"", status="complete")
        session = FakeSession("capture")
        with mock.patch(
            "reproit_sdk.semantic_dependency._active_context",
            return_value=FakeContext(session),
        ):
            _run_dependency(request, lambda: response)
        self.assertEqual(len(session.request_chunks), 2)
        self.assertTrue(all(len(value) <= 32_768 for value in session.request_chunks))

    def test_corrupt_replay_is_incomplete_without_a_live_fallback(self) -> None:
        _, request, _, _ = self._http_pair()
        session = FakeSession("replay", b"{}")
        with (
            mock.patch(
                "reproit_sdk.semantic_dependency._active_context",
                return_value=FakeContext(session),
            ),
            self.assertRaises(_SemanticDependencyError),
        ):
            _run_dependency(
                request,
                lambda: (_ for _ in ()).throw(
                    AssertionError("Replay called the live dependency.")
                ),
            )
        self.assertTrue(session.abandoned)

    def test_request_infrastructure_failures_preserve_live_result_and_error(self) -> None:
        _, request, _, response = self._http_pair()
        invalid = _DependencyRequest(
            "outbound-http",
            "outbound-http-request",
            "http-1.1",
            "http-1.1-message",
            "https://inventory.example/item",
            "POST",
            bytes(24 * 1_024 + 1),
        )
        for mode in ("invalid", "open", "write", "dispatch", "action", "live"):
            with self.subTest(mode=mode, outcome="result"):
                selected = invalid if mode == "invalid" else request
                session, context = self._failed_request_context(mode)
                calls = 0

                def live() -> _DependencyResponse:
                    nonlocal calls
                    calls += 1
                    return response

                with mock.patch(
                    "reproit_sdk.semantic_dependency._active_context",
                    return_value=context,
                ):
                    self.assertIs(_run_dependency(selected, live), response)
                self.assertEqual(calls, 1)
                if mode == "invalid":
                    self.assertEqual(len(context.unowned), 1)
            with self.subTest(mode=mode, outcome="error"):
                selected = invalid if mode == "invalid" else request
                session, context = self._failed_request_context(mode)
                sentinel = RuntimeError("application sentinel")
                calls = 0

                def failing() -> _DependencyResponse:
                    nonlocal calls
                    calls += 1
                    raise sentinel

                with (
                    mock.patch(
                        "reproit_sdk.semantic_dependency._active_context",
                        return_value=context,
                    ),
                    self.assertRaises(RuntimeError) as raised,
                ):
                    _run_dependency(selected, failing)
                self.assertIs(raised.exception, sentinel)
                self.assertEqual(calls, 1)

    def test_response_infrastructure_failures_preserve_live_result(self) -> None:
        _, request, _, response = self._http_pair()
        invalid_response = object()
        for mode in ("encode", "write", "finish"):
            with self.subTest(mode=mode):
                session = FakeSession("capture")
                if mode == "write":
                    session.fail_response_write = True
                if mode == "finish":
                    session.fail_finish = True
                sentinel = invalid_response if mode == "encode" else response
                calls = 0

                def live() -> object:
                    nonlocal calls
                    calls += 1
                    return sentinel

                with mock.patch(
                    "reproit_sdk.semantic_dependency._active_context",
                    return_value=FakeContext(session),
                ):
                    self.assertIs(_run_dependency(request, live), sentinel)
                self.assertEqual(calls, 1)

    @staticmethod
    def _failed_request_context(mode: str) -> tuple[FakeSession, FakeContext]:
        session = FakeSession("unknown" if mode == "action" else "capture")
        context = FakeContext(session)
        context.fail_open = mode == "open"
        session.fail_request_write = mode == "write"
        session.fail_dispatch = mode == "dispatch"
        return session, context

    def _http_pair(
        self,
    ) -> tuple[bytes, _DependencyRequest, bytes, _DependencyResponse]:
        request_record = canonical_bytes(
            self.positive["semantic_dependency_request_outbound_http"]["value"]
        )
        response_record = canonical_bytes(
            self.positive["semantic_dependency_response_outbound_http"]["value"]
        )
        return (
            request_record,
            _decode_dependency_request(request_record),
            response_record,
            _decode_dependency_response(request_record, response_record),
        )

    @staticmethod
    def _apply_vector_change(value: object, vector: dict[str, object]) -> None:
        parts = str(vector["path"]).removeprefix("/").split("/")
        parent = value
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        key = parts[-1]
        if isinstance(parent, list):
            parent[int(key)] = vector["value"]
        else:
            parent[key] = vector["value"]


if __name__ == "__main__":
    unittest.main()
