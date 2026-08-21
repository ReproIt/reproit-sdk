import json
import hashlib
import base64
import os
import asyncio
import copy
import socket
import tempfile
import threading
import time
import unittest

import reproit_sdk

from reproit_sdk import (
    MAX_ACTIVE_OPERATIONS,
    CandidateStart,
    CaptureError,
    Sdk,
    canonical_bytes,
    run_operation,
)
from reproit_sdk import _StagedCandidateSink as StagedCandidateSink
from reproit_sdk import _UnixRuntimeSink as UnixRuntimeSink
from reproit_sdk.asgi import AsgiMiddleware

from memory_sink import MemorySink


class Conformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.environ["REPROIT_PROTOCOL_VECTORS"], "rb") as source:
            cls.positive = json.load(source)["positive"]

    def setUp(self):
        self.expected = self.positive["candidate"]["value"]
        self.start = CandidateStart(
            self.expected["capture_id"],
            self.expected["deployment"],
            self.expected["operation_id"],
            self.expected["world_id"],
        )
        self.sink = MemorySink()
        self.sdk = Sdk(self.sink)

    def test_production_package_excludes_memory_sink(self):
        self.assertFalse(hasattr(reproit_sdk, "MemorySink"))

    def test_staged_delivery_encrypts_once_and_rejects_incomplete_capture(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        class RecordingTransport:
            def __init__(self):
                self.received = []

            def _deliver(self, capture_id, candidate, timeout):
                del capture_id, timeout
                self.received.append(candidate)
                return "cloud_protected"

        runtime = RecordingTransport()
        deferred = RecordingTransport()
        key = bytes([0x63]) * 32
        sink = StagedCandidateSink(runtime, deferred, key)
        candidate = canonical_bytes(self.expected)
        self.assertTrue(sink.try_send(self.expected["capture_id"], candidate))
        deadline = time.monotonic() + 2.0
        while (
            not runtime.received
            or not deferred.received
            or sink.recall_counters["candidate_durably_accepted"] == 0
        ) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(runtime.received, deferred.received)
        envelope = json.loads(runtime.received[0])
        stored = base64.urlsafe_b64decode(
            envelope["ciphertext"] + "=" * ((4 - len(envelope["ciphertext"]) % 4) % 4)
        )
        opened = AESGCM(key).decrypt(
            stored[:12],
            stored[12:],
            canonical_bytes(envelope["identity"]),
        )
        self.assertEqual(opened, candidate)

        incomplete = copy.deepcopy(self.expected)
        incomplete["records"].pop()
        self.assertFalse(
            sink.try_send(incomplete["capture_id"], canonical_bytes(incomplete))
        )
        self.assertEqual(len(runtime.received), 1)
        self.assertEqual(len(deferred.received), 1)
        self.assertEqual(sink.recall_counters["candidate_incomplete"], 1)
        self.assertEqual(sink.recall_counters["candidate_durably_accepted"], 1)
        self.assertEqual(sink.queued_bytes, 0)

    def test_incomplete_candidate_makes_no_staged_request(self):
        class RecordingTransport:
            def __init__(self):
                self.received = []

            def _deliver(self, capture_id, candidate, timeout):
                del capture_id, candidate, timeout
                self.received.append(True)
                return "cloud_protected"

        runtime = RecordingTransport()
        deferred = RecordingTransport()
        sink = StagedCandidateSink(runtime, deferred, bytes([0x63]) * 32)
        incomplete = copy.deepcopy(self.expected)
        incomplete["records"].pop()
        self.assertFalse(
            sink.try_send(incomplete["capture_id"], canonical_bytes(incomplete))
        )
        self.assertEqual(runtime.received, [])
        self.assertEqual(deferred.received, [])
        self.assertEqual(sink.recall_counters["candidate_incomplete"], 1)
        self.assertEqual(sink.queued_bytes, 0)

    def test_failure_matches_canonical_candidate(self):
        self.sdk.begin(self.start, self.positive["operation_begin_payload"]["value"])
        self.sdk.record_input(
            self.start.operation_id, self.positive["operation_input_payload"]["value"]
        )
        self.sdk.fail(
            self.start.operation_id, self.positive["failure_payload"]["value"]
        )
        self.assertEqual(self.sink.candidates, [canonical_bytes(self.expected)])
        self.assertEqual(self.sdk.active_operations, 0)

    def test_refreshed_world_does_not_bypass_failure_suppression(self):
        self.sdk.begin(self.start, self.positive["operation_begin_payload"]["value"])
        self.sdk.fail(
            self.start.operation_id, self.positive["failure_payload"]["value"]
        )
        refreshed = CandidateStart(
            "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
            self.start.deployment,
            "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4",
            "sha256:" + "a" * 64,
        )
        self.sdk.begin(refreshed, self.positive["operation_begin_payload"]["value"])
        self.sdk.fail(refreshed.operation_id, self.positive["failure_payload"]["value"])
        self.assertEqual(len(self.sink.candidates), 1)
        self.assertEqual(self.sdk.recall_counters["eligible_failure_observed"], 2)
        self.assertEqual(self.sdk.recall_counters["suppressed_exact_storm"], 1)

    def test_one_thousand_exact_failures_use_one_candidate_token(self):
        for index in range(1_000):
            start = CandidateStart(
                f"cap_01890f3e-7b1c-7cc0-8a1b-{index:012x}",
                self.start.deployment,
                f"op_01890f3e-7b1c-7cc0-8a1b-{index:012x}",
                self.start.world_id,
            )
            self.sdk.begin(start, self.positive["operation_begin_payload"]["value"])
            self.sdk.fail(start.operation_id, self.positive["failure_payload"]["value"])
        self.assertEqual(len(self.sink.candidates), 1)
        self.assertEqual(self.sdk.recall_counters["eligible_failure_observed"], 1_000)
        self.assertEqual(self.sdk.recall_counters["suppressed_exact_storm"], 999)

    def test_high_cardinality_storm_stops_at_candidate_tokens(self):
        for index in range(257):
            failure = copy.deepcopy(self.positive["failure_payload"]["value"])
            failure["identity"]["stable_code"] = f"storm-{index}"
            identity = hashlib.sha256(canonical_bytes(failure["identity"])).hexdigest()
            failure["failure"]["identity"] = f"sha256:{identity}"
            start = CandidateStart(
                f"cap_01890f3e-7b1c-7cc0-8a1b-{index:012x}",
                self.start.deployment,
                f"op_01890f3e-7b1c-7cc0-8a1b-{index:012x}",
                self.start.world_id,
            )
            self.sdk.begin(start, self.positive["operation_begin_payload"]["value"])
            self.sdk.fail(start.operation_id, failure)
        self.assertLessEqual(len(self.sink.candidates), 4)
        self.assertGreater(
            self.sdk.recall_counters["suppressed_high_cardinality_storm"], 0
        )

    def test_success_and_cancel_send_nothing(self):
        begin = self.positive["operation_begin_payload"]["value"]
        self.sdk.begin(self.start, begin)
        self.sdk.succeed(self.start.operation_id)
        self.assertEqual(self.sink.candidates, [])
        self.sdk.begin(self.start, begin)
        self.sdk.cancel(self.start.operation_id)
        self.assertEqual(self.sink.candidates, [])

    def test_application_exception_is_unchanged(self):
        original = RuntimeError("customer failure")

        def operation():
            raise original

        with self.assertRaises(RuntimeError) as raised:
            run_operation(
                self.sdk,
                self.start,
                self.positive["operation_begin_payload"]["value"],
                [self.positive["operation_input_payload"]["value"]],
                operation,
                lambda error: self.positive["failure_payload"]["value"],
            )
        self.assertIs(raised.exception, original)
        self.assertEqual(self.sink.candidates, [canonical_bytes(self.expected)])

    def test_authenticated_unix_delivery_uses_exact_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "runtime.sock")
            received = []
            complete = threading.Event()

            def serve():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(path)
                    listener.listen(1)
                    complete.set()
                    connection, _ = listener.accept()
                    with connection:
                        request = b""
                        while b"\r\n\r\n" not in request:
                            request += connection.recv(4_096)
                        header, body = request.split(b"\r\n\r\n", 1)
                        length = next(
                            int(line.split(b":", 1)[1])
                            for line in header.split(b"\r\n")
                            if line.lower().startswith(b"content-length:")
                        )
                        while len(body) < length:
                            body += connection.recv(4_096)
                        received.append((header, body))
                        connection.sendall(
                            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"
                        )

            server = threading.Thread(target=serve)
            server.start()
            self.assertTrue(complete.wait(1.0))
            sink = UnixRuntimeSink(path, lambda: "ReproIt workload-token")
            sdk = Sdk(sink)
            sdk.begin(self.start, self.positive["operation_begin_payload"]["value"])
            sdk.record_input(
                self.start.operation_id,
                self.positive["operation_input_payload"]["value"],
            )
            sdk.fail(self.start.operation_id, self.positive["failure_payload"]["value"])
            server.join(1.0)
            self.assertFalse(server.is_alive())
            deadline = time.monotonic() + 1.0
            while sink.queued_bytes and time.monotonic() < deadline:
                time.sleep(0.001)
            header, body = received[0]
            self.assertIn(b"Reproit-Protocol: 1", header)
            self.assertIn(b"Authorization: ReproIt workload-token", header)
            self.assertIn(self.expected["capture_id"].encode(), header)
            self.assertEqual(body, canonical_bytes(self.expected))
            self.assertEqual(sink.queued_bytes, 0)

    def test_unix_delivery_bounds_active_and_waiting_candidates(self):
        started = threading.Event()
        release = threading.Event()

        def authorization():
            started.set()
            release.wait(1.0)
            return None

        sink = UnixRuntimeSink("/tmp/reproit-missing-runtime.sock", authorization)
        candidate = canonical_bytes(self.expected)
        self.assertTrue(sink.try_send("capture-0", candidate))
        self.assertTrue(started.wait(1.0))
        for index in range(1, 16):
            self.assertTrue(sink.try_send(f"capture-{index}", candidate))
        self.assertFalse(sink.try_send("capture-16", candidate))
        release.set()
        deadline = time.monotonic() + 1.0
        while sink.queued_bytes and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertEqual(sink.queued_bytes, 0)

    def test_asgi_boundary_preserves_exception(self):
        original = RuntimeError("customer failure")

        async def application(scope, receive, send):
            del scope, receive, send
            raise original

        middleware = AsgiMiddleware(
            application,
            self.sdk,
            lambda scope: (
                self.start,
                self.positive["operation_begin_payload"]["value"],
                [self.positive["operation_input_payload"]["value"]],
            ),
            lambda error: self.positive["failure_payload"]["value"],
        )
        with self.assertRaises(RuntimeError) as raised:
            asyncio.run(middleware({"type": "http"}, None, None))
        self.assertIs(raised.exception, original)
        self.assertEqual(self.sink.candidates, [canonical_bytes(self.expected)])

    def test_asgi_prepare_failure_does_not_change_application(self):
        calls = []

        async def application(scope, receive, send):
            del scope, receive, send
            calls.append("application")

        def unavailable(scope):
            del scope
            raise CaptureError("The World token is unavailable.")

        middleware = AsgiMiddleware(
            application,
            self.sdk,
            unavailable,
            lambda error: self.positive["failure_payload"]["value"],
        )
        asyncio.run(middleware({"type": "http"}, None, None))
        self.assertEqual(calls, ["application"])
        self.assertEqual(self.sdk.active_operations, 0)
        self.assertEqual(self.sink.candidates, [])

    def test_asgi_success_cleanup_failure_does_not_change_application(self):
        class CleanupFailureSdk:
            def begin(self, start, begin):
                del start, begin

            def record_input(self, operation_id, value):
                del operation_id, value

            def succeed(self, operation_id):
                del operation_id
                raise CaptureError("The SDK cleanup failed.")

        calls = []

        async def application(scope, receive, send):
            del scope, receive, send
            calls.append("application")

        middleware = AsgiMiddleware(
            application,
            CleanupFailureSdk(),
            lambda scope: (
                self.start,
                self.positive["operation_begin_payload"]["value"],
                [self.positive["operation_input_payload"]["value"]],
            ),
            lambda error: self.positive["failure_payload"]["value"],
        )
        asyncio.run(middleware({"type": "http"}, None, None))
        self.assertEqual(calls, ["application"])

    def test_dependency_cursor_is_ordered_before_failure(self):
        cursor_bytes = b"python-http-transcript"
        cursor = base64.urlsafe_b64encode(cursor_bytes).rstrip(b"=").decode("ascii")
        dependency = {
            "adapter_id": "http-transcript",
            "adapter_version": "1.0.0",
            "causal_parent_id": None,
            "cursor": cursor,
            "cursor_digest": "sha256:" + hashlib.sha256(cursor_bytes).hexdigest(),
            "format": "reproit.dependency-cursor.v1",
        }
        self.sdk.begin(self.start, self.positive["operation_begin_payload"]["value"])
        self.sdk.record_input(
            self.start.operation_id,
            self.positive["operation_input_payload"]["value"],
        )
        self.sdk.record_dependency(self.start.operation_id, dependency)
        self.sdk.fail(
            self.start.operation_id, self.positive["failure_payload"]["value"]
        )
        records = json.loads(self.sink.candidates[0])["records"]
        self.assertEqual(
            [record["kind"] for record in records],
            ["begin", "input", "dependency", "failure", "terminal"],
        )
        terminal = json.loads(base64.urlsafe_b64decode(records[-1]["payload"] + "=="))
        self.assertEqual(terminal["event_count"], 4)

    def test_managed_candidate_does_not_use_private_plaintext_transport(self):
        class PrivateSink:
            processing_modes = frozenset(("private",))
            queued_bytes = 0

            def __init__(self):
                self.calls = 0

            def try_send(self, capture_id, candidate):
                del capture_id, candidate
                self.calls += 1
                return True

        sink = PrivateSink()
        sdk = Sdk(sink)
        deployment = copy.deepcopy(self.start.deployment)
        deployment["processing_mode"] = "managed"
        start = CandidateStart(
            self.start.capture_id,
            deployment,
            self.start.operation_id,
            self.start.world_id,
        )
        sdk.begin(start, self.positive["operation_begin_payload"]["value"])
        with self.assertRaisesRegex(CaptureError, "processing mode"):
            sdk.fail(start.operation_id, self.positive["failure_payload"]["value"])
        self.assertEqual(sink.calls, 0)
        self.assertEqual(sdk.active_operations, 0)
        self.assertEqual(sdk.recall_counters["candidate_incomplete"], 1)

    def test_private_transport_rejects_direct_managed_candidate(self):
        sink = UnixRuntimeSink(
            "/tmp/reproit-missing-runtime.sock", lambda: "Bearer service-one"
        )
        managed = copy.deepcopy(self.expected)
        managed["processing_mode"] = "managed"
        managed["deployment"]["processing_mode"] = "managed"
        self.assertFalse(sink.try_send(managed["capture_id"], canonical_bytes(managed)))
        self.assertEqual(sink.queued_bytes, 0)

    def test_oversized_failure_deletes_operation(self):
        self.sdk.begin(self.start, self.positive["operation_begin_payload"]["value"])
        failure = copy.deepcopy(self.positive["failure_payload"]["value"])
        failure["oversized"] = "x" * 65_536
        with self.assertRaises(CaptureError):
            self.sdk.fail(self.start.operation_id, failure)
        self.assertEqual(self.sdk.active_operations, 0)
        self.assertEqual(self.sink.candidates, [])

    def test_active_operation_count_is_bounded(self):
        operation_ids = []
        begin = self.positive["operation_begin_payload"]["value"]
        for index in range(MAX_ACTIVE_OPERATIONS):
            operation_id = f"op_01890f3e-7b1c-7cc0-8a1b-{index:012x}"
            self.sdk.begin(
                CandidateStart(
                    self.start.capture_id,
                    self.start.deployment,
                    operation_id,
                    self.start.world_id,
                ),
                begin,
            )
            operation_ids.append(operation_id)
        rejected = CandidateStart(
            self.start.capture_id,
            self.start.deployment,
            "op_01890f3e-7b1c-7cc0-8a1b-000000000200",
            self.start.world_id,
        )
        with self.assertRaises(CaptureError):
            self.sdk.begin(rejected, begin)
        self.assertEqual(self.sdk.active_operations, MAX_ACTIVE_OPERATIONS)
        self.assertEqual(self.sink.candidates, [])
        for operation_id in operation_ids:
            self.sdk.cancel(operation_id)
        self.assertEqual(self.sdk.active_operations, 0)


if __name__ == "__main__":
    unittest.main()
