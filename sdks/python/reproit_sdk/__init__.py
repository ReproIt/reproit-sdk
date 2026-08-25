"""Bounded Repro It Backend operation capture for Python 3.14."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .candidate_validation import validate_candidate

MAX_GLOBAL_BYTES = 1_048_576
MAX_OPERATION_BYTES = 262_144
MAX_EVENT_BYTES = 65_536
MAX_EVENTS = 1_024
MAX_ACTIVE_OPERATIONS = 512
MAX_QUEUED_CANDIDATES = 16
MAX_FAILURE_STORM_IDENTITIES = 256
MAX_PROCESS_LOGICAL_BYTES = 4 * 1024 * 1024 * 1024
FAILURE_SUPPRESSION_SECONDS = 60.0
FAILURE_TOKEN_CAPACITY = 4.0
FAILURE_TOKENS_PER_SECOND = 2.0
_COUNTER_MAXIMUM = (1 << 63) - 1
_RECALL_KEYS = (
    "candidate_delivery_expired",
    "candidate_durably_accepted",
    "candidate_incomplete",
    "candidate_queue_full",
    "candidate_rejected",
    "eligible_failure_observed",
    "suppressed_exact_storm",
    "suppressed_high_cardinality_storm",
)


class _ProcessResources:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active_bytes = 0
        self.active_operations: set[str] = set()
        self.queued_bytes = 0
        self.queued_candidates = 0
        self.logical_bytes = 0
        self.storm_admitted: dict[str, tuple[float, float, int]] = {}
        self.storm_last_refill = time.monotonic()
        self.storm_token_rejections = 0
        self.storm_tokens = FAILURE_TOKEN_CAPACITY

    def reserve_operation(self, operation_id: str, size: int) -> str | None:
        with self.lock:
            if operation_id in self.active_operations:
                return "duplicate"
            if (
                len(self.active_operations) >= MAX_ACTIVE_OPERATIONS
                or self.active_bytes + self.queued_bytes + size > MAX_GLOBAL_BYTES
            ):
                return "limit"
            self.active_operations.add(operation_id)
            self.active_bytes += size
            return None

    def grow_operation(self, operation_id: str, size: int) -> bool:
        with self.lock:
            if (
                operation_id not in self.active_operations
                or self.active_bytes + self.queued_bytes + size > MAX_GLOBAL_BYTES
            ):
                return False
            self.active_bytes += size
            return True

    def release_operation(self, operation_id: str, size: int) -> None:
        with self.lock:
            if operation_id not in self.active_operations:
                return
            self.active_operations.remove(operation_id)
            self.active_bytes = max(0, self.active_bytes - size)

    def reserve_candidate(self, size: int) -> bool:
        with self.lock:
            if (
                self.queued_candidates >= MAX_QUEUED_CANDIDATES
                or self.active_bytes + self.queued_bytes + size > MAX_GLOBAL_BYTES
            ):
                return False
            self.queued_candidates += 1
            self.queued_bytes += size
            return True

    def release_candidate(self, size: int) -> None:
        with self.lock:
            self.queued_candidates = max(0, self.queued_candidates - 1)
            self.queued_bytes = max(0, self.queued_bytes - size)

    def reserve_logical(self, size: int) -> bool:
        with self.lock:
            if size < 0 or self.logical_bytes > MAX_PROCESS_LOGICAL_BYTES - size:
                return False
            self.logical_bytes += size
            return True

    def release_logical(self, size: int) -> None:
        with self.lock:
            self.logical_bytes = max(0, self.logical_bytes - size)


_PROCESS_RESOURCES = _ProcessResources()


class CaptureError(Exception):
    """A local capture was incomplete or exceeded a fixed bound."""


class CandidateSink(Protocol):
    @property
    def processing_modes(self) -> frozenset[str]: ...

    @property
    def queued_bytes(self) -> int: ...

    def try_send(self, capture_id: str, candidate: bytes) -> bool: ...


@dataclass(frozen=True)
class CandidateStart:
    capture_id: str
    deployment: Mapping[str, Any]
    operation_id: str
    world_id: str


@dataclass
class _Operation:
    byte_count: int
    records: list[dict[str, Any]]
    start: CandidateStart


def canonical_bytes(value: Any) -> bytes:
    """Encode the protocol JSON subset in deterministic JCS property order."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _payload(value: Mapping[str, Any]) -> str:
    encoded = canonical_bytes(value)
    if len(encoded) > MAX_EVENT_BYTES:
        raise CaptureError("The SDK capture limit was reached.")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _record(kind: str, sequence: int, value: Mapping[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "payload": _payload(value), "sequence": sequence}


def _record_size(record: Mapping[str, Any]) -> int:
    return len(str(record["payload"])) + 32


class Sdk:
    """Own bounded active records and send complete failed candidates only."""

    def __init__(self, sink: CandidateSink):
        self._sink = sink
        self._allow_private_for_tests = False
        self._operations: dict[str, _Operation] = {}
        self._lock = threading.Lock()
        self._recall = {key: 0 for key in _RECALL_KEYS}

    @property
    def active_operations(self) -> int:
        with self._lock:
            return len(self._operations)

    @property
    def recall_counters(self) -> dict[str, int]:
        """Return bounded counters that contain no customer values."""
        with self._lock:
            counters = dict(self._recall)
        sink_counters = getattr(self._sink, "recall_counters", None)
        if sink_counters is not None:
            for key in _RECALL_KEYS:
                counters[key] = min(
                    _COUNTER_MAXIMUM,
                    counters[key] + int(sink_counters.get(key, 0)),
                )
        return counters

    def begin(self, start: CandidateStart, value: Mapping[str, Any]) -> None:
        mode = start.deployment.get("processing_mode")
        if mode != "managed" and not (
            self._allow_private_for_tests and mode == "private"
        ):
            raise CaptureError("The operation does not have complete capture state.")
        record = _record("begin", 0, value)
        size = _record_size(record)
        with self._lock:
            if start.operation_id in self._operations:
                raise CaptureError("The operation already has capture state.")
            reservation = _PROCESS_RESOURCES.reserve_operation(start.operation_id, size)
            if reservation == "duplicate":
                raise CaptureError("The operation already has capture state.")
            if reservation is not None:
                raise CaptureError("The SDK capture limit was reached.")
            self._operations[start.operation_id] = _Operation(size, [record], start)

    def record_input(self, operation_id: str, value: Mapping[str, Any]) -> None:
        self._append(operation_id, "input", value)

    def record_dependency(self, operation_id: str, value: Mapping[str, Any]) -> None:
        self._append(operation_id, "dependency", value)

    def succeed(self, operation_id: str) -> None:
        with self._lock:
            self._delete(operation_id)

    def cancel(self, operation_id: str) -> None:
        with self._lock:
            self._delete(operation_id)

    def fail(self, operation_id: str, value: Mapping[str, Any]) -> None:
        with self._lock:
            self._increment("eligible_failure_observed")
            operation = self._operations.get(operation_id)
            if operation is None:
                self._increment("candidate_incomplete")
                raise CaptureError(
                    "The operation does not have complete capture state."
                )
            try:
                failure = _record("failure", len(operation.records), value)
            finally:
                self._delete(operation_id)
            failure_size = _record_size(failure)
            if not self._within_operation(operation, failure_size):
                self._increment("candidate_incomplete")
                raise CaptureError("The SDK capture limit was reached.")
            operation.records.append(failure)
            terminal_value = {
                "complete": True,
                "event_count": len(operation.records),
                "format": "reproit.terminal.v1",
            }
            terminal = _record("terminal", len(operation.records), terminal_value)
            if (
                operation.byte_count + failure_size + _record_size(terminal)
                > MAX_OPERATION_BYTES
            ):
                self._increment("candidate_incomplete")
                raise CaptureError("The SDK capture limit was reached.")
            operation.records.append(terminal)
            candidate = {
                "capture_id": operation.start.capture_id,
                "deployment": copy.deepcopy(operation.start.deployment),
                "failure": copy.deepcopy(value.get("failure")),
                "format": "reproit.candidate.v1",
                "operation_id": operation_id,
                "processing_mode": operation.start.deployment.get("processing_mode"),
                "records": operation.records,
                "world_id": operation.start.world_id,
            }
            try:
                self._validate(candidate, value)
            except CaptureError:
                self._increment("candidate_incomplete")
                raise
            processing_mode = candidate["processing_mode"]
            if processing_mode not in self._sink.processing_modes:
                self._increment("candidate_incomplete")
                raise CaptureError(
                    "The candidate sink does not support this processing mode."
                )
            storm_outcome = self._admit_failure(candidate, value)
            if storm_outcome == "suppressed_exact":
                self._increment("suppressed_exact_storm")
                return
            if storm_outcome == "suppressed_high_cardinality":
                self._increment("suppressed_high_cardinality_storm")
                return
            encoded = canonical_bytes(candidate)
            if len(encoded) > MAX_OPERATION_BYTES or not self._sink.try_send(
                operation.start.capture_id, encoded
            ):
                self._increment("candidate_queue_full")
                raise CaptureError("The SDK capture limit was reached.")

    def _admit_failure(
        self, candidate: Mapping[str, Any], value: Mapping[str, Any]
    ) -> str:
        identity = value.get("identity")
        failure = value.get("failure")
        deployment = candidate.get("deployment")
        if not isinstance(identity, Mapping) or not isinstance(failure, Mapping):
            raise CaptureError("The operation does not have complete capture state.")
        if not isinstance(deployment, Mapping) or not isinstance(
            deployment.get("subject"), Mapping
        ):
            raise CaptureError("The operation does not have complete capture state.")
        stable = {
            "failure_identity_digest": failure.get("identity"),
            "format": "reproit.failure-storm-identity.v1",
            "operation_kind": identity.get("operation_kind"),
            "operation_name": identity.get("operation_name"),
            "service_id": deployment.get("service_id"),
            "source_revision": deployment.get("source_revision"),
            "subject_artifact_digest": deployment["subject"].get("artifact_digest"),
        }
        if any(value is None for value in stable.values()):
            raise CaptureError("The operation does not have complete capture state.")
        key = hashlib.sha256(canonical_bytes(stable)).hexdigest()
        with _PROCESS_RESOURCES.lock:
            now = time.monotonic()
            elapsed = max(0.0, now - _PROCESS_RESOURCES.storm_last_refill)
            _PROCESS_RESOURCES.storm_tokens = min(
                FAILURE_TOKEN_CAPACITY,
                _PROCESS_RESOURCES.storm_tokens
                + elapsed * FAILURE_TOKENS_PER_SECOND,
            )
            _PROCESS_RESOURCES.storm_last_refill = now
            _PROCESS_RESOURCES.storm_admitted = {
                known: entry
                for known, entry in _PROCESS_RESOURCES.storm_admitted.items()
                if now - entry[0] < FAILURE_SUPPRESSION_SECONDS
            }
            if key in _PROCESS_RESOURCES.storm_admitted:
                admitted, _, suppressed = _PROCESS_RESOURCES.storm_admitted[key]
                _PROCESS_RESOURCES.storm_admitted[key] = (
                    admitted,
                    now,
                    min((1 << 64) - 1, suppressed + 1),
                )
                return "suppressed_exact"
            if _PROCESS_RESOURCES.storm_tokens < 1.0:
                _PROCESS_RESOURCES.storm_token_rejections = min(
                    (1 << 64) - 1,
                    _PROCESS_RESOURCES.storm_token_rejections + 1,
                )
                return "suppressed_high_cardinality"
            if len(_PROCESS_RESOURCES.storm_admitted) >= MAX_FAILURE_STORM_IDENTITIES:
                oldest = min(
                    _PROCESS_RESOURCES.storm_admitted,
                    key=lambda item: (_PROCESS_RESOURCES.storm_admitted[item][1], item),
                )
                del _PROCESS_RESOURCES.storm_admitted[oldest]
            _PROCESS_RESOURCES.storm_tokens -= 1.0
            _PROCESS_RESOURCES.storm_admitted[key] = (now, now, 0)
            return "admitted"

    def _increment(self, key: str) -> None:
        self._recall[key] = min(_COUNTER_MAXIMUM, self._recall[key] + 1)

    def _append(self, operation_id: str, kind: str, value: Mapping[str, Any]) -> None:
        with self._lock:
            operation = self._operations.get(operation_id)
            if operation is None:
                raise CaptureError(
                    "The operation does not have complete capture state."
                )
            record = _record(kind, len(operation.records), value)
            size = _record_size(record)
            if (
                not self._within_operation(operation, size)
                or not _PROCESS_RESOURCES.grow_operation(operation_id, size)
            ):
                self._delete(operation_id)
                raise CaptureError("The SDK capture limit was reached.")
            operation.records.append(record)
            operation.byte_count += size

    def _delete(self, operation_id: str) -> None:
        operation = self._operations.pop(operation_id, None)
        if operation is not None:
            _PROCESS_RESOURCES.release_operation(operation_id, operation.byte_count)

    @staticmethod
    def _within_operation(operation: _Operation, size: int) -> bool:
        return (
            len(operation.records) < MAX_EVENTS
            and operation.byte_count + size <= MAX_OPERATION_BYTES
        )

    @staticmethod
    def _validate(candidate: Mapping[str, Any], failure: Mapping[str, Any]) -> None:
        try:
            validate_candidate(candidate, failure, _decode_record_payload, _digest)
        except (KeyError, StopIteration, TypeError, ValueError) as error:
            raise CaptureError(
                "The operation does not have complete capture state."
            ) from error


def _digest(value: Any) -> str:
    return _digest_bytes(canonical_bytes(value))


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _decode_record_payload(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or not isinstance(record.get("payload"), str):
        raise ValueError("The complete candidate Failure record is invalid.")
    encoded = record["payload"]
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("The complete candidate Failure record is invalid.") from error
    if not isinstance(value, dict):
        raise ValueError("The complete candidate Failure record is invalid.")
    return value


def run_operation(
    sdk: Sdk,
    start: CandidateStart,
    begin: Mapping[str, Any],
    inputs: list[Mapping[str, Any]],
    operation: Callable[[], Any],
    failure: Callable[[BaseException], Mapping[str, Any]],
) -> Any:
    """Capture a boundary while preserving the application's exact outcome."""
    capture_active = True
    try:
        sdk.begin(start, begin)
        for value in inputs:
            sdk.record_input(start.operation_id, value)
    except Exception:
        capture_active = False
        try:
            sdk.cancel(start.operation_id)
        except Exception:
            pass
    try:
        result = operation()
    except BaseException as original:
        if capture_active:
            try:
                sdk.fail(start.operation_id, failure(original))
            except Exception:
                pass
        raise
    if capture_active:
        try:
            sdk.succeed(start.operation_id)
        except Exception:
            pass
    return result


from .managed_transport import ManagedProjectToken as ManagedProjectToken  # noqa: E402
from .official_managed import (  # noqa: E402
    OfficialManagedOperation as OfficialManagedOperation,
)
from .official_managed import (  # noqa: E402
    OfficialManagedProject as OfficialManagedProject,
)
from .official_managed import (  # noqa: E402
    official_managed_candidate_sink as official_managed_candidate_sink,
)

__all__ = [
    "CandidateSink",
    "CandidateStart",
    "CaptureError",
    "MAX_ACTIVE_OPERATIONS",
    "MAX_EVENT_BYTES",
    "MAX_EVENTS",
    "MAX_FAILURE_STORM_IDENTITIES",
    "MAX_GLOBAL_BYTES",
    "MAX_OPERATION_BYTES",
    "MAX_QUEUED_CANDIDATES",
    "ManagedProjectToken",
    "OfficialManagedOperation",
    "OfficialManagedProject",
    "Sdk",
    "canonical_bytes",
    "official_managed_candidate_sink",
    "run_operation",
]
