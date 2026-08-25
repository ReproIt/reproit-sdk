"""Bounded managed candidate sink with fail-open delivery.

Mirrors crates/reproit-sdk-rust/src/managed_sink.rs: a bounded in-process
queue, one background delivery worker, recall counters without customer
values, and fail-open semantics. A managed SDK failure never changes the
application's behavior.
"""

from __future__ import annotations

import copy
import json
import os
import queue
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from reproit_sdk import (
    MAX_GLOBAL_BYTES,
    MAX_OPERATION_BYTES,
    MAX_QUEUED_CANDIDATES,
    canonical_bytes,
    _PROCESS_RESOURCES,
)

from .managed_candidate import (
    FrozenManagedCaptureClosure,
    ManagedCaptureClosure,
    PreparedManagedCandidate,
)
from .managed_identity import (
    ManagedWorkloadIdentityState,
    ManagedWorkloadRegistrationReceipt,
    managed_deployment_binding_digest,
    managed_workload_key_id,
)
from .managed_protocol import (
    ManagedError,
    canonical_digest,
    decode_base64url,
    encode_base64url,
    now_timestamp,
    require_typed_id,
    schema_invalid,
    sign_bytes,
    valid_timestamp,
    validate_capabilities,
    verification_key,
    verify_signed_value,
)
from .managed_subject import (
    PythonSubjectPackage,
    package_running_python_subject,
    subject_binding,
)
from .managed_transport import ManagedProjectToken
from .processor_capture import capture_processor_capabilities

REGISTRATION_TIMEOUT_SECONDS = 5.0
CANDIDATE_DELIVERY_LIFETIME_SECONDS = 1_800.0
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


@dataclass(frozen=True)
class ManagedSinkConfiguration:
    capture_signer_id: str
    capture_signer_public_key: bytes
    project_token: ManagedProjectToken | Callable[[], ManagedProjectToken] | None
    service_id: str
    workload_state_root: str


class _DeadlineManagedClient:
    def __init__(self, client: object, deadline: float):
        self._client = client
        self._deadline = deadline

    def _timeout(self, requested: float) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ManagedError(
                "SERVICE_UNAVAILABLE",
                "The candidate delivery lifetime expired.",
            )
        return min(requested, remaining)

    def _check(self) -> None:
        self._timeout(0.001)

    def register_workload_key(self, token, request, timeout):
        result = self._client.register_workload_key(
            token, request, self._timeout(timeout)
        )
        self._check()
        return result

    def request_encryption_grant(self, request, timeout):
        result = self._client.request_encryption_grant(
            request, self._timeout(timeout)
        )
        self._check()
        return result

    def start(self, request, timeout):
        result = self._client.start(request, self._timeout(timeout))
        self._check()
        return result

    def missing(self, upload_id, upload_token, cursor, timeout):
        result = self._client.missing(
            upload_id, upload_token, cursor, self._timeout(timeout)
        )
        self._check()
        return result

    def upload_object(self, upload_url, digest, value, timeout):
        self._client.upload_object(
            upload_url, digest, value, self._timeout(timeout)
        )
        self._check()

    def commit(self, upload_id, upload_token, timeout):
        result = self._client.commit(
            upload_id, upload_token, self._timeout(timeout)
        )
        self._check()
        return result

    def cancel(self, upload_id, upload_token, timeout):
        result = self._client.cancel(
            upload_id, upload_token, self._timeout(timeout)
        )
        self._check()
        return result


class ManagedCandidateSink:
    """Deliver complete managed candidates through the bounded upload session."""

    def __init__(
        self,
        client: object,
        closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
        configuration: ManagedSinkConfiguration,
        subject: PythonSubjectPackage | None = None,
        operation_id: str | None = None,
    ):
        _validate_configuration(configuration)
        if isinstance(closure, ManagedCaptureClosure):
            closure = FrozenManagedCaptureClosure(closure)
        if operation_id is not None:
            require_typed_id(operation_id, "operation_id")
        if subject is None:
            subject = package_running_python_subject()
        self._client = client
        self._closure = closure
        self._configuration = configuration
        self._operation_id = operation_id
        self._subject = subject
        self._world_id = closure.world_id()
        self._project_token = configuration.project_token
        self._workload_identity: ManagedWorkloadIdentityState | None = None
        self._workload_signing_key: bytes | None = None
        self._workload_public_key: bytes | None = None
        self._workload_key_id: str | None = None
        self._registration_request: dict[str, object] | None = None
        self._registration_receipt: ManagedWorkloadRegistrationReceipt | None = None
        self._registration_lock = threading.Lock()
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._queued_bytes = 0
        self._queued_candidates = 0
        self._active = False
        self._recall = {key: 0 for key in _RECALL_KEYS}
        self._queue: queue.Queue[tuple[dict[str, object], int, float]] = queue.Queue(
            MAX_QUEUED_CANDIDATES
        )
        ready = threading.Event()
        worker = threading.Thread(
            target=self._worker,
            args=(ready,),
            name="reproit-managed-python-capture",
            daemon=True,
        )
        worker.start()
        if not ready.wait(REGISTRATION_TIMEOUT_SECONDS):
            raise ManagedError(
                "SERVICE_UNAVAILABLE", "The managed capture worker could not start."
            )

    @property
    def processing_modes(self) -> frozenset[str]:
        return frozenset(("managed",))

    @property
    def queued_bytes(self) -> int:
        with _PROCESS_RESOURCES.lock:
            return _PROCESS_RESOURCES.queued_bytes

    @property
    def recall_counters(self) -> dict[str, int]:
        """Return bounded counters that contain no customer values."""
        with self._lock:
            return dict(self._recall)

    @property
    def subject_manifest(self) -> dict[str, object]:
        return self._subject.manifest

    @property
    def workload_key_id(self) -> str:
        if self._workload_key_id is None:
            raise ManagedError(
                "CONFIG_CONFLICT", "The managed deployment is not bound."
            )
        return self._workload_key_id

    @property
    def workload_public_key(self) -> bytes:
        if self._workload_public_key is None:
            raise ManagedError(
                "CONFIG_CONFLICT", "The managed deployment is not bound."
            )
        return self._workload_public_key

    @property
    def world_id(self) -> str:
        return self._world_id

    def bind_deployment(self, deployment: dict[str, object]) -> None:
        """Bind the deployment to this subject and sign it as this workload."""
        if deployment.get("service_id") != self._configuration.service_id:
            raise ManagedError(
                "AUTHORIZATION_DENIED",
                "The managed deployment belongs to a different service.",
            )
        manifest = self._subject.manifest
        deployment["processing_mode"] = "managed"
        deployment["subject"] = subject_binding(manifest)
        capabilities = list(deployment.get("runtime_capabilities", []))
        capabilities.extend((manifest["architecture"], manifest["operating_system"]))
        # The captured World's process-visible processor view travels with
        # the candidate so admission starts from the complete observation
        # (spec 7.8.1).
        capabilities.extend(capture_processor_capabilities())
        deployment["runtime_capabilities"] = sorted(set(capabilities))
        deployment["signer_key_id"] = ""
        deployment["signature"] = ""
        binding_digest = managed_deployment_binding_digest(deployment)
        identity = ManagedWorkloadIdentityState.from_state_root(
            self._configuration.workload_state_root, binding_digest
        )
        signing_key = identity.load_or_create_key()
        deployment["signed_at"] = identity.load_or_create_deployment_signed_at(
            binding_digest, deployment.get("signed_at")
        )
        public_key = verification_key(signing_key)
        key_id = managed_workload_key_id(public_key)
        deployment["signer_key_id"] = key_id
        deployment["signature"] = sign_bytes(canonical_bytes(deployment), signing_key)
        _validate_deployment(deployment)
        request = {
            "algorithm": "Ed25519",
            "deployment": copy.deepcopy(deployment),
            "public_key": encode_base64url(public_key),
            "service_id": self._configuration.service_id,
        }
        receipt = ManagedWorkloadRegistrationReceipt(
            deployment_digest=canonical_digest(deployment),
            service_id=self._configuration.service_id,
            workload_key_id=key_id,
        )
        if (
            self._registration_request is not None
            and self._registration_request != request
        ):
            raise ManagedError(
                "CONFIG_CONFLICT",
                "The managed sink is already bound to another deployment.",
            )
        self._workload_identity = identity
        self._workload_signing_key = signing_key
        self._workload_public_key = public_key
        self._workload_key_id = key_id
        self._registration_request = request
        self._registration_receipt = receipt

    def wait_until_idle(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._idle:
            while self._active or self._queued_candidates != 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._idle.wait(remaining)
            return True

    def try_send(self, capture_id: str, candidate: bytes) -> bool:
        """Queue one complete candidate. Never raise into the application."""
        try:
            value = self._authorized_candidate(capture_id, candidate)
        except Exception:
            self._increment("candidate_incomplete")
            return False
        if not _PROCESS_RESOURCES.reserve_candidate(len(candidate)):
            with self._lock:
                self._recall["candidate_queue_full"] = min(
                    _COUNTER_MAXIMUM, self._recall["candidate_queue_full"] + 1
                )
            return False
        with self._lock:
            self._queued_bytes += len(candidate)
            self._queued_candidates += 1
        try:
            self._queue.put_nowait((value, len(candidate), time.monotonic()))
            return True
        except queue.Full:
            with self._lock:
                self._queued_bytes -= len(candidate)
                self._queued_candidates -= 1
                self._recall["candidate_queue_full"] = min(
                    _COUNTER_MAXIMUM, self._recall["candidate_queue_full"] + 1
                )
            _PROCESS_RESOURCES.release_candidate(len(candidate))
            return False

    def _authorized_candidate(
        self, capture_id: str, candidate: bytes
    ) -> dict[str, object]:
        if len(candidate) > MAX_OPERATION_BYTES:
            raise schema_invalid()
        value = json.loads(candidate)
        if (
            not isinstance(value, Mapping)
            or canonical_bytes(value) != candidate
            or value.get("capture_id") != capture_id
            or value.get("processing_mode") != "managed"
        ):
            raise schema_invalid()
        deployment = value.get("deployment")
        if (
            not isinstance(deployment, Mapping)
            or deployment.get("processing_mode") != "managed"
            or deployment.get("service_id") != self._configuration.service_id
            or self._workload_key_id is None
            or self._workload_public_key is None
            or deployment.get("signer_key_id") != self._workload_key_id
            or (
                self._operation_id is not None
                and value.get("operation_id") != self._operation_id
            )
        ):
            raise ManagedError(
                "AUTHORIZATION_DENIED",
                "The managed deployment does not use the registered workload key.",
            )
        verify_signed_value(deployment, self._workload_public_key)
        return dict(value)

    def _worker(self, ready: threading.Event) -> None:
        ready.set()
        while True:
            value, size, queued_at = self._queue.get()
            try:
                if time.monotonic() - queued_at >= CANDIDATE_DELIVERY_LIFETIME_SECONDS:
                    self._increment("candidate_delivery_expired")
                    continue
                with self._lock:
                    self._active = True
                try:
                    self._deliver(
                        value,
                        queued_at + CANDIDATE_DELIVERY_LIFETIME_SECONDS,
                    )
                except ManagedError as error:
                    self._record_failure(error)
                except Exception:
                    self._increment("candidate_rejected")
                else:
                    self._increment("candidate_durably_accepted")
            finally:
                with self._idle:
                    self._active = False
                    self._queued_bytes = max(0, self._queued_bytes - size)
                    self._queued_candidates = max(0, self._queued_candidates - 1)
                    self._idle.notify_all()
                _PROCESS_RESOURCES.release_candidate(size)
                self._queue.task_done()

    def _deliver(self, candidate: Mapping[str, object], deadline: float) -> None:
        configuration = self._configuration
        client = _DeadlineManagedClient(self._client, deadline)
        prepared = PreparedManagedCandidate.prepare_complete(
            candidate, self._subject, self._closure
        )
        self._ensure_registered(client)
        if self._workload_key_id is None or self._workload_signing_key is None:
            raise ManagedError(
                "CONFIG_CONFLICT", "The managed deployment is not bound."
            )
        grant = prepared.request_encryption_grant(
            client, self._workload_key_id, self._workload_signing_key
        )
        sealed = prepared.seal(
            grant,
            now_timestamp(),
            configuration.capture_signer_id,
            configuration.capture_signer_public_key,
        )
        renewal = sealed.request_capture_grant_renewal(
            client, self._workload_key_id, self._workload_signing_key
        )
        sealed.apply_renewed_capture_grant(
            renewal,
            now_timestamp(),
            configuration.capture_signer_id,
            configuration.capture_signer_public_key,
        )
        sealed.upload(client)

    def _ensure_registered(self, client: object) -> None:
        with self._registration_lock:
            identity = self._workload_identity
            request = self._registration_request
            receipt = self._registration_receipt
            if identity is None or request is None or receipt is None:
                raise ManagedError(
                    "CONFIG_CONFLICT", "The managed deployment is not bound."
                )
            if identity.load_registration_receipt(receipt) is not None:
                return
            token_source = self._project_token
            if token_source is None:
                raise ManagedError(
                    "AUTHENTICATION_REQUIRED",
                    "A project token is required to register this managed workload.",
                )
            project_token = token_source() if callable(token_source) else token_source
            if not isinstance(project_token, ManagedProjectToken):
                raise ManagedError(
                    "AUTHENTICATION_REQUIRED",
                    "The project token provider did not return a valid project token.",
                )
            registration = client.register_workload_key(
                project_token, request, REGISTRATION_TIMEOUT_SECONDS
            )
            if (
                registration["deployment_digest"] != receipt.deployment_digest
                or registration["key_id"] != receipt.workload_key_id
                or registration["service_id"] != receipt.service_id
            ):
                raise ManagedError(
                    "ATTESTATION_SCOPE",
                    "The managed workload registration does not match this deployment.",
                )
            identity.persist_registration_receipt(receipt)
            self._project_token = None

    def _record_failure(self, error: ManagedError) -> None:
        if error.code == "INCOMPLETE_CANDIDATE":
            self._increment("candidate_incomplete")
        elif error.retryable:
            self._increment("candidate_delivery_expired")
        else:
            self._increment("candidate_rejected")

    def _increment(self, key: str) -> None:
        with self._lock:
            self._recall[key] = min(_COUNTER_MAXIMUM, self._recall[key] + 1)


def _validate_configuration(configuration: ManagedSinkConfiguration) -> None:
    if (
        not isinstance(configuration.capture_signer_id, str)
        or not configuration.capture_signer_id
        or len(configuration.capture_signer_id) > 256
        or not isinstance(configuration.capture_signer_public_key, bytes)
        or len(configuration.capture_signer_public_key) != 32
        or (
            configuration.project_token is not None
            and not isinstance(configuration.project_token, ManagedProjectToken)
            and not callable(configuration.project_token)
        )
        or not isinstance(configuration.workload_state_root, str)
        or not configuration.workload_state_root
        or not os.path.isabs(configuration.workload_state_root)
    ):
        raise schema_invalid()
    require_typed_id(configuration.service_id, "service_id")


def _validate_deployment(deployment: Mapping[str, object]) -> None:
    """Mirror the reproit-core Deployment::validate checks the SDK can prove."""
    repository_id = deployment.get("repository_id")
    runtime_endpoint = deployment.get("runtime_endpoint")
    service_path = deployment.get("service_path")
    signer_key_id = deployment.get("signer_key_id")
    source_revision = deployment.get("source_revision")
    if (
        deployment.get("format") != "reproit.deployment.v1"
        or not isinstance(repository_id, str)
        or not 1 <= len(repository_id) <= 256
        or not isinstance(runtime_endpoint, str)
        or not 1 <= len(runtime_endpoint) <= 2_048
        or not isinstance(service_path, str)
        or not service_path
        or service_path.startswith("/")
        or any(part == ".." for part in service_path.split("/"))
        or not isinstance(signer_key_id, str)
        or not 1 <= len(signer_key_id) <= 256
        or not isinstance(source_revision, str)
        or not 1 <= len(source_revision) <= 256
        or not valid_timestamp(deployment.get("signed_at"))
    ):
        raise schema_invalid()
    validate_capabilities(deployment.get("runtime_capabilities"))
    decode_base64url(deployment.get("signature"), 64)
