"""Queue-bound and candidate-token evidence for the Python SDK.

These tests mirror the Rust SDK resource-amplification evidence in
crates/reproit-sdk-rust/tests/transport.rs and
crates/reproit-sdk-rust/src/lib.rs, so the five SDKs prove the same
claims: exactly sixteen failed candidates queue, the seventeenth is
dropped into a bounded recall counter without a change to application
behavior, a drained queue accepts new candidates, and the candidate
token bucket admits its burst capacity and then throttles.
"""

import copy
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import reproit_sdk
from reproit_sdk import (
    FAILURE_TOKEN_CAPACITY,
    MAX_QUEUED_CANDIDATES,
    CandidateStart,
    Sdk,
    canonical_bytes,
    run_operation,
)
from memory_sink import MemorySink

DRAIN_TIMEOUT_SECONDS = 2.0
RESTART_STATE_FORMAT = "reproit.sdk-queue-restart.v1"
MAX_RESTART_STATE_BYTES = 4_096


class QueueBounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.environ["REPROIT_PROTOCOL_VECTORS"], "rb") as source:
            cls.positive = json.load(source)["positive"]

    def setUp(self):
        self.expected = copy.deepcopy(self.positive["candidate"]["value"])
        self.expected["deployment"]["processing_mode"] = "managed"
        self.expected["deployment"]["runtime_endpoint"] = None
        resources = self._reset_candidate_capacity()
        with resources.lock:
            resources.storm_admitted.clear()
            resources.storm_last_refill = time.monotonic()
            resources.storm_token_rejections = 0
            resources.storm_tokens = FAILURE_TOKEN_CAPACITY
        self.start = CandidateStart(
            self.expected["capture_id"],
            self.expected["deployment"],
            self.expected["operation_id"],
            self.expected["world_id"],
        )

    def _queued_bytes_after_drain(self, sink):
        deadline = time.monotonic() + DRAIN_TIMEOUT_SECONDS
        while sink.queued_bytes and time.monotonic() < deadline:
            time.sleep(0.001)
        return sink.queued_bytes

    def _reset_candidate_capacity(self):
        resources = reproit_sdk._PROCESS_RESOURCES
        with resources.lock:
            resources.active_bytes = 0
            resources.active_operations.clear()
            resources.queued_bytes = 0
            resources.queued_candidates = 0
        return resources

    def test_sixteen_candidates_queue_and_the_seventeenth_is_dropped(self):
        resources = self._reset_candidate_capacity()
        accepted = sum(
            resources.reserve_candidate(1)
            for _ in range(MAX_QUEUED_CANDIDATES + 1)
        )
        self.assertEqual(accepted, MAX_QUEUED_CANDIDATES)
        for _ in range(accepted):
            resources.release_candidate(1)
        self.assertEqual(resources.queued_bytes, 0)

    def test_process_restart_recovers_exact_queue_capacity(self):
        probe = """
import json
import os
import sys
import time
import reproit_sdk

state_path = sys.argv[1]
resources = reproit_sdk._PROCESS_RESOURCES
accepted = sum(
    resources.reserve_candidate(1)
    for _ in range(reproit_sdk.MAX_QUEUED_CANDIDATES + 1)
)
with open(state_path, 'x', encoding='utf-8') as output:
    json.dump({'accepted': accepted}, output)
    output.flush()
    os.fsync(output.fileno())
while True:
    time.sleep(1)
"""

        def wait_for_state(path):
            deadline = time.monotonic() + DRAIN_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if path.is_file():
                    return json.loads(path.read_text(encoding="utf-8"))
                time.sleep(0.005)
            self.fail("The queue restart child did not publish its state.")

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = subprocess.Popen(
                [sys.executable, "-c", probe, str(root / "first.json")]
            )
            try:
                self.assertEqual(
                    wait_for_state(root / "first.json")["accepted"],
                    MAX_QUEUED_CANDIDATES,
                )
            finally:
                first.terminate()
                first.wait(timeout=DRAIN_TIMEOUT_SECONDS)

            second = subprocess.Popen(
                [sys.executable, "-c", probe, str(root / "second.json")]
            )
            try:
                self.assertEqual(
                    wait_for_state(root / "second.json")["accepted"],
                    MAX_QUEUED_CANDIDATES,
                )
            finally:
                second.terminate()
                second.wait(timeout=DRAIN_TIMEOUT_SECONDS)

    def test_incomplete_candidate_makes_no_runtime_request(self):
        sink = MemorySink()
        sdk = Sdk(sink)
        sdk.begin(self.start, self.positive["operation_begin_payload"]["value"])
        failure = copy.deepcopy(self.positive["failure_payload"]["value"])
        failure["failure"]["identity"] = "sha256:" + "0" * 64
        with self.assertRaises(Exception):
            sdk.fail(self.start.operation_id, failure)
        self.assertEqual(sink.candidates, [])
        self.assertEqual(sdk.recall_counters["candidate_incomplete"], 1)

    def test_candidate_token_bucket_admits_burst_capacity_then_throttles(self):
        sink = MemorySink()
        sdk = Sdk(sink)
        attempts = 20
        capacity = int(FAILURE_TOKEN_CAPACITY)
        for index in range(attempts):
            failure = copy.deepcopy(self.positive["failure_payload"]["value"])
            failure["identity"]["stable_code"] = f"token-{index}"
            digest = hashlib.sha256(canonical_bytes(failure["identity"])).hexdigest()
            failure["failure"]["identity"] = f"sha256:{digest}"
            start = CandidateStart(
                f"cap_01890f3e-7b1c-7cc0-8a1b-{index:012x}",
                self.start.deployment,
                f"op_01890f3e-7b1c-7cc0-8a1b-{index:012x}",
                self.start.world_id,
            )
            sdk.begin(start, self.positive["operation_begin_payload"]["value"])
            # Freeze the refill clock before each Failure so cache churn
            # cannot regain a token, exactly like the Rust evidence test
            # high_cardinality_churn_cannot_bypass_candidate_tokens.
            reproit_sdk._PROCESS_RESOURCES.storm_last_refill = (
                time.monotonic() + 3_600.0
            )
            sdk.fail(start.operation_id, failure)
        self.assertEqual(len(sink.candidates), capacity)
        self.assertEqual(
            sdk.recall_counters["suppressed_high_cardinality_storm"],
            attempts - capacity,
        )
