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

from reproit_sdk import (
    FAILURE_TOKEN_CAPACITY,
    MAX_QUEUED_CANDIDATES,
    CandidateStart,
    Sdk,
    canonical_bytes,
    run_operation,
)
from reproit_sdk import _UnixRuntimeSink as UnixRuntimeSink

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
        self.expected = self.positive["candidate"]["value"]
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

    def test_sixteen_candidates_queue_and_the_seventeenth_is_dropped(self):
        started = threading.Event()
        release = threading.Event()

        def authorization():
            started.set()
            release.wait(DRAIN_TIMEOUT_SECONDS)
            return None

        sink = UnixRuntimeSink("/tmp/reproit-missing-runtime.sock", authorization)
        candidate = canonical_bytes(self.expected)
        full_bytes = MAX_QUEUED_CANDIDATES * len(candidate)
        self.assertTrue(sink.try_send(self.start.capture_id, candidate))
        self.assertTrue(started.wait(DRAIN_TIMEOUT_SECONDS))
        for index in range(1, MAX_QUEUED_CANDIDATES):
            self.assertTrue(sink.try_send(f"capture-{index}", candidate))
        self.assertEqual(sink.queued_bytes, full_bytes)

        # One candidate over the bound is dropped without queue growth.
        self.assertFalse(sink.try_send("capture-over", candidate))
        self.assertEqual(sink.queued_bytes, full_bytes)

        # A full queue must not change application behavior, and the
        # drop must appear in the bounded local recall counter.
        sdk = Sdk(sink)
        original = RuntimeError("customer failure")

        def operation():
            raise original

        with self.assertRaises(RuntimeError) as raised:
            run_operation(
                sdk,
                self.start,
                self.positive["operation_begin_payload"]["value"],
                [self.positive["operation_input_payload"]["value"]],
                operation,
                lambda error: self.positive["failure_payload"]["value"],
            )
        self.assertIs(raised.exception, original)
        self.assertEqual(sdk.recall_counters["candidate_queue_full"], 1)
        self.assertEqual(sdk.active_operations, 0)
        self.assertEqual(sink.queued_bytes, full_bytes)

        release.set()
        self.assertEqual(self._queued_bytes_after_drain(sink), 0)

        # A drained queue accepts new candidates.
        self.assertTrue(sink.try_send(self.start.capture_id, candidate))
        self.assertEqual(self._queued_bytes_after_drain(sink), 0)

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
            sdk._storm_last_refill = time.monotonic() + 3_600.0
            sdk.fail(start.operation_id, failure)
        self.assertEqual(len(sink.candidates), capacity)
        self.assertEqual(
            sdk.recall_counters["suppressed_high_cardinality_storm"],
            attempts - capacity,
        )

    def test_process_restart_recovers_exact_queue_capacity(self):
        with tempfile.TemporaryDirectory(
            prefix="reproit-python-queue-restart-"
        ) as root:
            state = pathlib.Path(root) / "state.json"
            child_environment = os.environ.copy()
            child_environment["REPROIT_QUEUE_RESTART_STATE"] = str(state)
            child_environment["REPROIT_QUEUE_RESTART_CHILD"] = "seed"
            first = subprocess.Popen(
                [sys.executable, __file__],
                env=child_environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertTrue(_wait_for_state(state))
            first.terminate()
            first.wait(timeout=DRAIN_TIMEOUT_SECONDS)
            self.assertIsNotNone(first.returncode)

            child_environment["REPROIT_QUEUE_RESTART_CHILD"] = "recover"
            recovered = subprocess.run(
                [sys.executable, __file__],
                env=child_environment,
                capture_output=True,
                check=False,
                timeout=DRAIN_TIMEOUT_SECONDS,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr.decode())

            state.write_bytes(b"{")
            corrupt = subprocess.run(
                [sys.executable, __file__],
                env=child_environment,
                capture_output=True,
                check=False,
                timeout=DRAIN_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(corrupt.returncode, 0)

            _write_restart_state(
                state,
                {
                    "format": RESTART_STATE_FORMAT,
                    "pid": first.pid,
                    "queued_bytes": MAX_QUEUED_CANDIDATES + 1,
                    "queued_candidates": MAX_QUEUED_CANDIDATES + 1,
                    "one_over_accepted": False,
                },
            )
            one_over = subprocess.run(
                [sys.executable, __file__],
                env=child_environment,
                capture_output=True,
                check=False,
                timeout=DRAIN_TIMEOUT_SECONDS,
            )
            self.assertNotEqual(one_over.returncode, 0)


def _wait_for_state(path):
    deadline = time.monotonic() + DRAIN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return True
        time.sleep(0.005)
    return False


def _write_restart_state(path, state):
    encoded = canonical_bytes(state)
    if not encoded or len(encoded) > MAX_RESTART_STATE_BYTES:
        raise ValueError("The queue restart state exceeds its bound.")
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_restart_state(path, candidate_size):
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_size > MAX_RESTART_STATE_BYTES
    ):
        raise ValueError("The queue restart state is invalid.")
    state = json.loads(path.read_bytes())
    if (
        set(state)
        != {"format", "one_over_accepted", "pid", "queued_bytes", "queued_candidates"}
        or state["format"] != RESTART_STATE_FORMAT
        or state["one_over_accepted"] is not False
        or state["queued_candidates"] != MAX_QUEUED_CANDIDATES
        or state["queued_bytes"] != MAX_QUEUED_CANDIDATES * candidate_size
        or not isinstance(state["pid"], int)
        or state["pid"] <= 0
        or state["pid"] == os.getpid()
    ):
        raise ValueError("The queue restart state is invalid.")
    return state


def _run_restart_child():
    mode = os.environ["REPROIT_QUEUE_RESTART_CHILD"]
    state_path = pathlib.Path(os.environ["REPROIT_QUEUE_RESTART_STATE"])
    with open(os.environ["REPROIT_PROTOCOL_VECTORS"], "rb") as source:
        candidate = canonical_bytes(json.load(source)["positive"]["candidate"]["value"])
    if mode == "recover":
        _read_restart_state(state_path, len(candidate))
    elif mode != "seed":
        raise ValueError("The queue restart child mode is invalid.")

    started = threading.Event()
    release = threading.Event()

    def authorization():
        started.set()
        release.wait(60.0)
        return None

    sink = UnixRuntimeSink("/tmp/reproit-missing-runtime-restart.sock", authorization)
    accepted = sink.try_send("capture-0", candidate)
    if not accepted or not started.wait(DRAIN_TIMEOUT_SECONDS):
        raise RuntimeError("The queue restart child did not start delivery.")
    for index in range(1, MAX_QUEUED_CANDIDATES):
        if not sink.try_send(f"capture-{index}", candidate):
            raise RuntimeError("The queue restart child stopped below the bound.")
    one_over_accepted = sink.try_send("capture-over", candidate)
    observed = {
        "format": RESTART_STATE_FORMAT,
        "pid": os.getpid(),
        "queued_bytes": sink.queued_bytes,
        "queued_candidates": MAX_QUEUED_CANDIDATES,
        "one_over_accepted": one_over_accepted,
    }
    state_path.unlink(missing_ok=True)
    _write_restart_state(state_path, observed)
    if mode == "recover":
        os._exit(0)
    while True:
        time.sleep(1.0)


if __name__ == "__main__":
    if os.environ.get("REPROIT_QUEUE_RESTART_CHILD"):
        _run_restart_child()
    else:
        unittest.main()
