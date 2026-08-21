"""Bounded Repro It Backend operation capture for Python 3.14."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import queue
import secrets
import socket
import ssl
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .candidate_validation import candidate_uses_mode, validate_candidate

MAX_GLOBAL_BYTES = 1_048_576
MAX_OPERATION_BYTES = 262_144
MAX_EVENT_BYTES = 65_536
MAX_EVENTS = 1_024
MAX_ACTIVE_OPERATIONS = 512
MAX_QUEUED_CANDIDATES = 16
MAX_FAILURE_STORM_IDENTITIES = 256
FAILURE_SUPPRESSION_SECONDS = 60.0
FAILURE_TOKEN_CAPACITY = 4.0
FAILURE_TOKENS_PER_SECOND = 2.0
WORLD_TOKEN_BYTES = 65_536
WORLD_TOKEN_SECONDS = 5.0
_WORLD_REFRESH_SEED = secrets.token_bytes(32)
_WORLD_REQUEST_LOCK = threading.Lock()
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


class _WorldTokenCache:
    """Refresh one Runtime World token without blocking an operation."""

    def __init__(self, transport: _UnixRuntimeSink, service_id: str):
        self._transport = transport
        self._service_id = service_id
        self._token: tuple[str, float] | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        seed = hashlib.sha256(_WORLD_REFRESH_SEED + service_id.encode("utf-8")).digest()
        self._refresh_fraction = (50 + int.from_bytes(seed[:2], "big") % 21) / 100
        self._worker = threading.Thread(
            target=self._refresh,
            name="reproit-sdk-world",
            daemon=True,
        )
        self._worker.start()

    def candidate_start(
        self,
        capture_id: str,
        deployment: Mapping[str, Any],
        operation_id: str,
    ) -> CandidateStart:
        if deployment.get("service_id") != self._service_id:
            raise CaptureError("The World token does not match the deployment service.")
        with self._lock:
            token = self._token
        if token is None or time.monotonic() >= token[1]:
            raise CaptureError(
                "The operation started without a current Runtime World token."
            )
        return CandidateStart(capture_id, deployment, operation_id, token[0])

    def close(self) -> None:
        self._stop.set()
        self._worker.join(1.1)
        if self._worker.is_alive():
            raise CaptureError("The World-token refresh worker did not stop.")

    def _refresh(self) -> None:
        backoff = (0.1, 0.2, 0.4, 0.8, 1.6, 3.2)
        attempt = 0
        while not self._stop.is_set():
            with _WORLD_REQUEST_LOCK:
                token = self._transport.fetch_world_token(self._service_id, 1.0)
            if token is not None:
                world_id, lifetime = token
                received = time.monotonic()
                with self._lock:
                    self._token = (world_id, received + lifetime)
                attempt = 0
                self._stop.wait(lifetime * self._refresh_fraction)
                continue
            delay = backoff[min(attempt, len(backoff) - 1)]
            attempt += 1
            with self._lock:
                remaining = (
                    max(0.0, self._token[1] - time.monotonic())
                    if self._token is not None
                    else delay
                )
            self._stop.wait(min(delay, remaining))


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
        self._operations: dict[str, _Operation] = {}
        self._global_bytes = 0
        self._lock = threading.Lock()
        self._storm_admitted: dict[str, tuple[float, float, int]] = {}
        self._storm_last_refill = time.monotonic()
        self._storm_token_rejections = 0
        self._storm_tokens = FAILURE_TOKEN_CAPACITY
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
        record = _record("begin", 0, value)
        size = _record_size(record)
        with self._lock:
            if start.operation_id in self._operations:
                raise CaptureError("The operation already has capture state.")
            if (
                len(self._operations) >= MAX_ACTIVE_OPERATIONS
                or self._global_bytes + self._sink.queued_bytes + size
                > MAX_GLOBAL_BYTES
            ):
                raise CaptureError("The SDK capture limit was reached.")
            self._operations[start.operation_id] = _Operation(size, [record], start)
            self._global_bytes += size

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
        now = time.monotonic()
        elapsed = max(0.0, now - self._storm_last_refill)
        self._storm_tokens = min(
            FAILURE_TOKEN_CAPACITY,
            self._storm_tokens + elapsed * FAILURE_TOKENS_PER_SECOND,
        )
        self._storm_last_refill = now
        self._storm_admitted = {
            key: entry
            for key, entry in self._storm_admitted.items()
            if now - entry[0] < FAILURE_SUPPRESSION_SECONDS
        }
        if key in self._storm_admitted:
            admitted, _, suppressed = self._storm_admitted[key]
            self._storm_admitted[key] = (
                admitted,
                now,
                min((1 << 64) - 1, suppressed + 1),
            )
            return "suppressed_exact"
        if self._storm_tokens < 1.0:
            self._storm_token_rejections = min(
                (1 << 64) - 1, self._storm_token_rejections + 1
            )
            return "suppressed_high_cardinality"
        if len(self._storm_admitted) >= MAX_FAILURE_STORM_IDENTITIES:
            oldest = min(
                self._storm_admitted,
                key=lambda item: (self._storm_admitted[item][1], item),
            )
            del self._storm_admitted[oldest]
        self._storm_tokens -= 1.0
        self._storm_admitted[key] = (now, now, 0)
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
                or self._global_bytes + self._sink.queued_bytes + size
                > MAX_GLOBAL_BYTES
            ):
                self._delete(operation_id)
                raise CaptureError("The SDK capture limit was reached.")
            operation.records.append(record)
            operation.byte_count += size
            self._global_bytes += size

    def _delete(self, operation_id: str) -> None:
        operation = self._operations.pop(operation_id, None)
        if operation is not None:
            self._global_bytes = max(0, self._global_bytes - operation.byte_count)

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


class _UnixRuntimeSink:
    """Deliver candidates in the background over an authenticated Unix stream."""

    def __init__(self, socket_path: str, authorization: Callable[[], str | None]):
        if not socket_path.startswith("/"):
            raise ValueError("The Runtime socket path must be absolute.")
        self._socket_path = socket_path
        self._authorization = authorization
        self._candidate_path = "/v1/candidates/{capture_id}"
        self._candidate_content_type = "application/reproit-candidate+json"
        self._queued_bytes = 0
        self._queued_candidates = 0
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[str, bytes, float]] = queue.Queue(
            MAX_QUEUED_CANDIDATES
        )
        threading.Thread(
            target=self._worker, name="reproit-sdk-delivery", daemon=True
        ).start()

    @property
    def processing_modes(self) -> frozenset[str]:
        return frozenset(("private",))

    @property
    def queued_bytes(self) -> int:
        with self._lock:
            return self._queued_bytes

    def try_send(self, capture_id: str, candidate: bytes) -> bool:
        if not candidate_uses_mode(candidate, self.processing_modes, canonical_bytes):
            return False
        with self._lock:
            if (
                self._queued_candidates >= MAX_QUEUED_CANDIDATES
                or self._queued_bytes + len(candidate) > MAX_GLOBAL_BYTES
            ):
                return False
            self._queued_bytes += len(candidate)
            self._queued_candidates += 1
        try:
            self._queue.put_nowait((capture_id, candidate, time.monotonic()))
            return True
        except queue.Full:
            with self._lock:
                self._queued_bytes -= len(candidate)
                self._queued_candidates -= 1
            return False

    def _worker(self) -> None:
        while True:
            capture_id, candidate, started = self._queue.get()
            try:
                for offset in (0.0, 0.1, 0.3):
                    wait = started + offset - time.monotonic()
                    if wait > 0:
                        time.sleep(wait)
                    remaining = started + 1.0 - time.monotonic()
                    if remaining <= 0:
                        break
                    outcome = self._deliver(
                        capture_id, candidate, max(0.001, remaining)
                    )
                    if outcome != "retry":
                        break
            finally:
                with self._lock:
                    self._queued_bytes -= len(candidate)
                    self._queued_candidates -= 1
                self._queue.task_done()

    def _deliver(self, capture_id: str, candidate: bytes, timeout: float) -> str:
        authorization = self._authorization()
        if (
            not authorization
            or len(authorization) > 4_096
            or any(
                ord(character) < 32 or ord(character) > 126
                for character in authorization
            )
        ):
            return "reject"
        request = (
            f"PUT {self._candidate_path.format(capture_id=capture_id)} HTTP/1.1\r\n"
            "Host: reproit-runtime\r\n"
            f"Content-Type: {self._candidate_content_type}\r\n"
            f"Idempotency-Key: {capture_id}\r\n"
            "Reproit-Protocol: 1\r\n"
            f"Authorization: {authorization}\r\n"
            f"Content-Length: {len(candidate)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        try:
            with self._connect(timeout) as connection:
                connection.sendall(request + candidate)
                status, _, body = _read_response(connection)
        except ssl.SSLError:
            return "reject"
        except OSError:
            return "retry"
        if status in (429, 503):
            return "retry"
        if status not in (200, 202):
            return "reject"
        if self._candidate_path == "/v1/candidates/{capture_id}":
            return "accept"
        try:
            envelope = json.loads(candidate)
            receipt = json.loads(body)
        except UnicodeDecodeError, json.JSONDecodeError:
            return "reject"
        if (
            not isinstance(envelope, dict)
            or not isinstance(receipt, dict)
            or set(receipt) != {"capture_id", "request_digest", "state"}
            or receipt["capture_id"] != capture_id
            or receipt["request_digest"]
            != envelope.get("identity", {}).get("request_digest")
        ):
            return "reject"
        if receipt["state"] == "CLOUD_PROTECTED":
            return "cloud_protected"
        if (
            self._candidate_path == "/v1/staged-candidates/{capture_id}"
            and receipt["state"] == "LOCAL_ONLY"
        ):
            return "local_only"
        return "reject"

    def fetch_world_token(
        self, service_id: str, timeout: float
    ) -> tuple[str, float] | None:
        authorization = self._authorization()
        if (
            not authorization
            or len(authorization) > 4_096
            or any(
                ord(character) < 32 or ord(character) > 126
                for character in authorization
            )
        ):
            return None
        request = (
            f"GET /v1/services/{service_id}/world HTTP/1.1\r\n"
            "Host: reproit-runtime\r\nReproit-Protocol: 1\r\n"
            f"Authorization: {authorization}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        try:
            with self._connect(timeout) as connection:
                connection.sendall(request)
                status, headers, body = _read_response(connection)
        except OSError, ssl.SSLError:
            return None
        if status != 200 or len(body) > WORLD_TOKEN_BYTES:
            return None
        try:
            value = json.loads(body)
        except UnicodeDecodeError, json.JSONDecodeError:
            return None
        if (
            headers.get("content-length") != str(len(body))
            or not isinstance(value, dict)
            or set(value) != {"expires_in_ms", "format", "world_id"}
            or value["expires_in_ms"] != 5_000
            or value["format"] != "reproit.world-token.v1"
            or not isinstance(value["world_id"], str)
        ):
            return None
        return value["world_id"], WORLD_TOKEN_SECONDS

    def _connect(self, timeout: float) -> socket.socket:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        try:
            connection.connect(self._socket_path)
            return connection
        except BaseException:
            connection.close()
            raise


class _TlsRuntimeSink(_UnixRuntimeSink):
    """Deliver candidates to a shared Runtime through authenticated TLS."""

    def __init__(
        self,
        host: str,
        port: int,
        server_name: str,
        ca_certificate: str,
        authorization: Callable[[], str | None],
    ):
        if (
            not host
            or len(host) > 253
            or not 1 <= port <= 65_535
            or not server_name
            or len(server_name) > 253
        ):
            raise ValueError("The shared Runtime TLS endpoint is invalid.")
        super().__init__("/reproit-tls-transport", authorization)
        self._host = host
        self._port = port
        self._server_name = server_name
        metadata = os.lstat(ca_certificate)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > 1_048_576
        ):
            raise ValueError("The shared Runtime CA certificate is invalid.")
        with open(ca_certificate, "rb") as source:
            certificate = source.read(1_048_577)
        if len(certificate) != metadata.st_size:
            raise ValueError(
                "The shared Runtime CA certificate changed during validation."
            )
        self._tls = ssl.create_default_context(cadata=certificate.decode("ascii"))
        self._tls.check_hostname = True
        self._tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self._tls.maximum_version = ssl.TLSVersion.TLSv1_3

    def _connect(self, timeout: float) -> socket.socket:
        connection = socket.create_connection((self._host, self._port), timeout=timeout)
        try:
            return self._tls.wrap_socket(connection, server_hostname=self._server_name)
        except BaseException:
            connection.close()
            raise


class _UnixStagedRuntimeSink(_UnixRuntimeSink):
    """Deliver encrypted candidates to a host-local Runtime."""

    def __init__(self, socket_path: str, authorization: Callable[[], str | None]):
        super().__init__(socket_path, authorization)
        self._candidate_path = "/v1/staged-candidates/{capture_id}"
        self._candidate_content_type = "application/reproit-candidate-staging+json"


class _TlsStagedRuntimeSink(_TlsRuntimeSink):
    """Deliver encrypted candidates to a shared Runtime."""

    def __init__(
        self,
        host: str,
        port: int,
        server_name: str,
        ca_certificate: str,
        authorization: Callable[[], str | None],
    ):
        super().__init__(host, port, server_name, ca_certificate, authorization)
        self._candidate_path = "/v1/staged-candidates/{capture_id}"
        self._candidate_content_type = "application/reproit-candidate-staging+json"


class _StagedCandidateSink:
    """Encrypt one complete candidate and deliver it through two Runtime routes."""

    def __init__(
        self,
        runtime: _UnixStagedRuntimeSink | _TlsStagedRuntimeSink,
        deferred: _UnixStagedRuntimeSink | _TlsStagedRuntimeSink,
        key: bytes,
    ):
        if len(key) != 32:
            raise ValueError("The candidate staging key must contain 32 bytes.")
        self._runtime = runtime
        self._deferred = deferred
        self._key = bytes(key)
        self._queued_bytes = 0
        self._queued_candidates = 0
        self._recall = {key: 0 for key in _RECALL_KEYS}
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[str, bytes, float]] = queue.Queue(
            MAX_QUEUED_CANDIDATES
        )
        threading.Thread(
            target=self._worker,
            name="reproit-sdk-staged-delivery",
            daemon=True,
        ).start()

    @property
    def processing_modes(self) -> frozenset[str]:
        return frozenset(("private",))

    @property
    def queued_bytes(self) -> int:
        with self._lock:
            return self._queued_bytes

    @property
    def recall_counters(self) -> dict[str, int]:
        """Return bounded delivery counters without candidate values."""
        with self._lock:
            return dict(self._recall)

    def try_send(self, capture_id: str, candidate: bytes) -> bool:
        try:
            envelope = _seal_staged_candidate(candidate, self._key)
            value = json.loads(candidate)
            if value.get("capture_id") != capture_id:
                return False
        except TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError:
            with self._lock:
                self._recall["candidate_incomplete"] = min(
                    _COUNTER_MAXIMUM, self._recall["candidate_incomplete"] + 1
                )
            return False
        with self._lock:
            if (
                self._queued_candidates >= MAX_QUEUED_CANDIDATES
                or self._queued_bytes + len(envelope) > MAX_GLOBAL_BYTES
            ):
                self._recall["candidate_queue_full"] = min(
                    _COUNTER_MAXIMUM, self._recall["candidate_queue_full"] + 1
                )
                return False
            self._queued_bytes += len(envelope)
            self._queued_candidates += 1
        try:
            self._queue.put_nowait((capture_id, envelope, time.monotonic()))
            return True
        except queue.Full:
            with self._lock:
                self._queued_bytes -= len(envelope)
                self._queued_candidates -= 1
                self._recall["candidate_queue_full"] = min(
                    _COUNTER_MAXIMUM, self._recall["candidate_queue_full"] + 1
                )
            return False

    def _worker(self) -> None:
        while True:
            capture_id, envelope, started = self._queue.get()
            try:
                outcome = self._deliver(capture_id, envelope, started)
                with self._lock:
                    key = {
                        "cloud_protected": "candidate_durably_accepted",
                        "local_only": "candidate_durably_accepted",
                        "reject": "candidate_rejected",
                        "expired": "candidate_delivery_expired",
                    }[outcome]
                    self._recall[key] = min(_COUNTER_MAXIMUM, self._recall[key] + 1)
            finally:
                with self._lock:
                    self._queued_bytes -= len(envelope)
                    self._queued_candidates -= 1
                self._queue.task_done()

    def _deliver(self, capture_id: str, envelope: bytes, started: float) -> str:
        local_only = False
        for offset in (0.0, 0.1, 0.3):
            wait = started + offset - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            remaining = started + 1.0 - time.monotonic()
            if remaining <= 0:
                break
            outcomes: list[str] = []
            threads = [
                threading.Thread(
                    target=lambda transport=transport: outcomes.append(
                        transport._deliver(capture_id, envelope, max(0.001, remaining))
                    )
                )
                for transport in (self._runtime, self._deferred)
            ]
            for worker in threads:
                worker.start()
            for worker in threads:
                worker.join(max(0.001, started + 1.0 - time.monotonic()))
            if "cloud_protected" in outcomes:
                return "cloud_protected"
            local_only = local_only or "local_only" in outcomes
            if len(outcomes) == 2 and (
                set(outcomes) == {"reject"}
                or set(outcomes) == {"local_only", "reject"}
                or set(outcomes) == {"local_only"}
            ):
                return "local_only" if local_only else "reject"
        return "local_only" if local_only else "expired"


def _seal_staged_candidate(candidate_bytes: bytes, key: bytes) -> bytes:
    if len(candidate_bytes) > MAX_GLOBAL_BYTES:
        raise ValueError("The complete candidate exceeds the staging limit.")
    candidate = json.loads(candidate_bytes)
    if not isinstance(candidate, dict) or canonical_bytes(candidate) != candidate_bytes:
        raise ValueError("The complete candidate is not canonical.")
    records = candidate.get("records")
    if not isinstance(records, list):
        raise ValueError("The complete candidate is incomplete.")
    deployment = candidate.get("deployment")
    failure = candidate.get("failure")
    if not isinstance(deployment, dict) or not isinstance(failure, dict):
        raise ValueError("The complete candidate is incomplete.")
    subject = deployment.get("subject")
    failure_record = next(
        (record for record in records if record.get("kind") == "failure"),
        None,
    )
    failure_payload = _decode_record_payload(failure_record)
    validate_candidate(candidate, failure_payload, _decode_record_payload, _digest)
    failure_identity = failure_payload.get("identity")
    if not isinstance(subject, dict) or not isinstance(failure_identity, dict):
        raise ValueError("The complete candidate is incomplete.")
    if failure_payload.get("failure") != failure:
        raise ValueError("The complete candidate Failure does not match its record.")
    storm = {
        "failure_identity_digest": failure.get("identity"),
        "format": "reproit.failure-storm-identity.v1",
        "operation_kind": failure_identity.get("operation_kind"),
        "operation_name": failure_identity.get("operation_name"),
        "service_id": deployment.get("service_id"),
        "source_revision": deployment.get("source_revision"),
        "subject_artifact_digest": subject.get("artifact_digest"),
    }
    if any(value is None for value in storm.values()):
        raise ValueError("The complete candidate is incomplete.")
    identity = {
        "capture_id": candidate.get("capture_id"),
        "deployment_digest": _digest(deployment),
        "expires_at": _staging_expiration(),
        "failure_storm_digest": _digest(storm),
        "format": "reproit.candidate-staging-identity.v1",
        "organization_id": deployment.get("organization_id"),
        "processing_mode": deployment.get("processing_mode"),
        "project_id": deployment.get("project_id"),
        "provider_lease_digest": _digest(
            {
                "format": "reproit.provider-lease-binding.v1",
                "organization_id": deployment.get("organization_id"),
                "service_id": deployment.get("service_id"),
                "world_id": candidate.get("world_id"),
            }
        ),
        "request_digest": _digest(candidate),
        "service_id": deployment.get("service_id"),
        "world_id": candidate.get("world_id"),
    }
    if any(value is None for value in identity.values()):
        raise ValueError("The complete candidate is incomplete.")
    if identity["processing_mode"] != "private":
        raise ValueError("The private Runtime cannot stage a managed candidate.")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aad = canonical_bytes(identity)
    nonce = secrets.token_bytes(12)
    stored = nonce + AESGCM(key).encrypt(nonce, candidate_bytes, aad)
    envelope = {
        "cipher_digest": _digest_bytes(stored),
        "cipher_size": len(stored),
        "ciphertext": base64.urlsafe_b64encode(stored).rstrip(b"=").decode("ascii"),
        "format": "reproit.candidate-staging-envelope.v1",
        "identity": identity,
    }
    return canonical_bytes(envelope)


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


def _staging_expiration() -> str:
    value = datetime.now(UTC) + timedelta(hours=1)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _read_response(connection: socket.socket) -> tuple[int, dict[str, str], bytes]:
    response = b""
    while b"\r\n\r\n" not in response and len(response) < 4_096:
        chunk = connection.recv(min(4_096, 4_096 - len(response)))
        if not chunk:
            break
        response += chunk
    if b"\r\n\r\n" not in response:
        raise OSError("The Runtime response header is incomplete.")
    header, body = response.split(b"\r\n\r\n", 1)
    lines = header.decode("ascii").split("\r\n")
    status_parts = lines[0].split(" ")
    if len(status_parts) < 2:
        raise OSError("The Runtime response status is invalid.")
    headers = {
        name.lower(): value.strip()
        for line in lines[1:]
        for name, value in [line.split(":", 1)]
    }
    length = int(headers.get("content-length", "-1"))
    if length < 0 or length > WORLD_TOKEN_BYTES:
        raise OSError("The Runtime response body exceeds the limit.")
    while len(body) < length:
        chunk = connection.recv(min(4_096, length - len(body)))
        if not chunk:
            raise OSError("The Runtime response body is incomplete.")
        body += chunk
    return int(status_parts[1]), headers, body


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
