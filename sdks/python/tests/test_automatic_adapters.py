from __future__ import annotations

import base64
import json
import os
import time
import unittest
from pathlib import Path
from unittest import mock

from reproit_sdk import automatic_adapters
from reproit_sdk.encoding import canonical_bytes
from reproit_sdk.observation_adapters import _installed_observation_adapters
from reproit_sdk.subject_protocol import digest_bytes


class FakeSession:
    def __init__(self, action: str, replay: bytes = b"") -> None:
        self.action = action
        self.replay = replay
        self.request = bytearray()
        self.response = bytearray()
        self.finished: str | None = None
        self.abandoned = False

    def _write_request(self, chunk: bytes) -> bool:
        self.request.extend(chunk)
        return True

    def _write_response(self, chunk: bytes) -> bool:
        self.response.extend(chunk)
        return True

    def _dispatch(self) -> str:
        return self.action

    def _read_response(self) -> tuple[bytes, bool]:
        value = self.replay
        self.replay = b""
        return value, True

    def _finish(self, outcome: str) -> bool:
        self.finished = outcome
        return True

    def _abandon(self) -> None:
        self.abandoned = True


class FakeContext:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.opened: list[str] = []
        self.unowned: list[tuple[str, bytes]] = []

    def _open_observation(self, observation_class: str) -> FakeSession:
        self.opened.append(observation_class)
        return self.session

    def _mark_unowned(
        self,
        observation_class: str,
        evidence: bytes,
        causal_parent_id: str | None = None,
    ) -> None:
        self.unowned.append((observation_class, evidence))


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def replay_response(request: bytes, outcome: str, value: bytes | None) -> bytes:
    operation = json.loads(request)["operation"]
    return canonical_bytes(
        {
            "format": "reproit.semantic-observation-response.v1",
            "operation": operation,
            "request_digest": digest_bytes(request),
            "outcome": outcome,
            "value": None if value is None else encoded(value),
            "error_code": None,
            "error_number": None,
        }
    )


class AutomaticAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        core_root = Path(os.environ["REPROIT_CORE_ROOT"])
        vector_path = core_root / "specs/v1/semantic-observation-vector.json"
        cls.vectors = json.loads(vector_path.read_bytes())

    def tearDown(self) -> None:
        while automatic_adapters._OPEN_PROJECTS:
            automatic_adapters._release_automatic_adapters()

    def test_clock_capture_uses_the_exact_canonical_contract(self) -> None:
        session = FakeSession("capture")
        context = FakeContext(session)
        with (
            mock.patch.object(automatic_adapters, "_active_context", return_value=context),
            mock.patch.object(automatic_adapters, "_ORIGINAL_TIME_NS", return_value=42),
        ):
            self.assertEqual(automatic_adapters._time_ns(), 42)

        request = self.vectors["positive"][0]["request"]
        self.assertEqual(bytes(session.request), canonical_bytes(request))
        self.assertEqual(session.finished, "response")
        response = json.loads(session.response)
        self.assertEqual(response["request_digest"], digest_bytes(session.request))
        self.assertEqual(response["operation"], "clock-wall-time")
        self.assertEqual(base64.urlsafe_b64decode(response["value"] + "="), bytes(7) + b"*")

    def test_random_replay_never_calls_the_operating_system(self) -> None:
        request = canonical_bytes(
            {
                "format": "reproit.semantic-observation-request.v1",
                "operation": "random-bytes",
                "target": None,
                "offset": None,
                "length": 4,
            }
        )
        session = FakeSession("replay", replay_response(request, "response", b"seed"))
        context = FakeContext(session)
        with (
            mock.patch.object(automatic_adapters, "_active_context", return_value=context),
            mock.patch.object(
                automatic_adapters,
                "_ORIGINAL_URANDOM",
                side_effect=AssertionError("The replay called the operating system."),
            ),
        ):
            self.assertEqual(automatic_adapters._urandom(4), b"seed")
        self.assertEqual(bytes(session.request), request)
        self.assertEqual(session.finished, "response")

    def test_missing_environment_value_is_a_null_response(self) -> None:
        session = FakeSession("capture")
        context = FakeContext(session)

        def missing(environment: object, key: str) -> str:
            raise KeyError(key)

        with (
            mock.patch.object(automatic_adapters, "_active_context", return_value=context),
            mock.patch.object(automatic_adapters, "_ORIGINAL_ENVIRONMENT_GET", missing),
        ):
            with self.assertRaisesRegex(KeyError, "APP_MODE"):
                automatic_adapters._environment_get(os.environ, "APP_MODE")
        response = json.loads(session.response)
        self.assertEqual(response["outcome"], "response")
        self.assertIsNone(response["value"])
        self.assertEqual(session.finished, "response")

    @unittest.skipIf(not hasattr(os, "pread"), "os.pread is unavailable")
    def test_filesystem_capture_records_path_offset_and_length(self) -> None:
        session = FakeSession("capture")
        context = FakeContext(session)
        with (
            mock.patch.object(automatic_adapters, "_active_context", return_value=context),
            mock.patch.object(
                automatic_adapters,
                "_file_descriptor_path",
                return_value="/workspace/data.bin",
            ),
            mock.patch.object(automatic_adapters, "_ORIGINAL_PREAD", return_value=b"abc"),
        ):
            self.assertEqual(automatic_adapters._pread(3, 3, 7), b"abc")
        request = json.loads(session.request)
        self.assertEqual(request["target"], encoded(b"/workspace/data.bin"))
        self.assertEqual(request["offset"], 7)
        self.assertEqual(request["length"], 3)

    def test_invalid_replay_is_incomplete_and_does_not_call_original(self) -> None:
        session = FakeSession("replay", b"{}")
        context = FakeContext(session)
        with (
            mock.patch.object(automatic_adapters, "_active_context", return_value=context),
            mock.patch.object(
                automatic_adapters,
                "_ORIGINAL_URANDOM",
                side_effect=AssertionError("The replay called the operating system."),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "recorded observation"):
                automatic_adapters._urandom(4)
        self.assertTrue(session.abandoned)

    def test_core_semantic_vectors_are_accepted_or_rejected_exactly(self) -> None:
        for vector in self.vectors["positive"]:
            request = canonical_bytes(vector["request"])
            response = canonical_bytes(vector["response"])
            automatic_adapters._parse_response(response, request)
        for vector in self.vectors["negative"]:
            if vector["response"] is None:
                continue
            request = canonical_bytes(vector["request"])
            response = canonical_bytes(vector["response"])
            with self.assertRaises(RuntimeError, msg=vector["name"]):
                automatic_adapters._parse_response(response, request)

    def test_one_over_core_value_bound_is_unowned_before_session_open(self) -> None:
        session = FakeSession("capture")
        context = FakeContext(session)
        with (
            mock.patch.object(automatic_adapters, "_active_context", return_value=context),
            mock.patch.object(automatic_adapters, "_ORIGINAL_URANDOM", return_value=b"value"),
        ):
            self.assertEqual(automatic_adapters._urandom(32_769), b"value")
        self.assertEqual(context.opened, [])
        self.assertEqual(context.unowned, [("randomness", b"random-length-limit")])

    def test_unsupported_wall_clock_call_is_unowned_and_preserves_value(self) -> None:
        session = FakeSession("capture")
        context = FakeContext(session)
        with (
            mock.patch.object(automatic_adapters, "_active_context", return_value=context),
            mock.patch.object(automatic_adapters, "_ORIGINAL_TIME", return_value=4.5),
        ):
            self.assertEqual(automatic_adapters._unsupported_time(), 4.5)
        self.assertEqual(context.opened, [])
        self.assertEqual(context.unowned, [("clock", b"unsupported-time-call")])

    def test_nested_project_lifecycle_installs_and_restores_hooks(self) -> None:
        original_time_ns = time.time_ns
        original_time = time.time
        original_clocks = dict(automatic_adapters._CLOCK_ORIGINALS)
        self.assertTrue(automatic_adapters._acquire_automatic_adapters())
        self.assertTrue(automatic_adapters._acquire_automatic_adapters())
        self.assertIs(time.time_ns, automatic_adapters._time_ns)
        self.assertIs(time.time, automatic_adapters._unsupported_time)
        self.assertTrue(
            all(
                getattr(time, name) is automatic_adapters._CLOCK_HOOKS[name]
                for name in original_clocks
            )
        )
        self.assertEqual(
            [value["class"] for value in _installed_observation_adapters()],
            ["clock", "environment", "filesystem", "randomness"],
        )
        automatic_adapters._release_automatic_adapters()
        self.assertIs(time.time_ns, automatic_adapters._time_ns)
        automatic_adapters._release_automatic_adapters()
        self.assertIs(time.time_ns, original_time_ns)
        self.assertIs(time.time, original_time)
        self.assertTrue(
            all(getattr(time, name) is value for name, value in original_clocks.items())
        )
        self.assertEqual(_installed_observation_adapters(), [])

    def test_install_conflict_does_not_replace_an_existing_hook(self) -> None:
        original = time.time_ns

        def conflicting_hook() -> int:
            return 7

        time.time_ns = conflicting_hook
        try:
            self.assertFalse(automatic_adapters._acquire_automatic_adapters())
            self.assertIs(time.time_ns, conflicting_hook)
        finally:
            time.time_ns = original


if __name__ == "__main__":
    unittest.main()
