"""Managed candidate preparation, sealing, and bounded upload.

Mirrors crates/reproit-sdk-rust/src/managed.rs: the SDK proves local
completeness first, then requests one managed candidate encryption grant,
seals every object with AES-256-GCM keyed through HKDF-SHA-256, and drives
the start, missing, object-PUT, commit, and cancel upload session. An
incomplete candidate stops before any network request.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from reproit_sdk import canonical_bytes
from reproit_sdk.candidate_validation import validate_candidate

from .managed_closure import (
    FrozenManagedCaptureClosure,
    ManagedCandidateArtifact,
    ManagedCaptureClosure,
    expected_world_artifacts,
    hash_file,
    validate_transcript_bytes,
    validate_world_checkpoint,
)
from .managed_protocol import (
    CANDIDATE_IDENTITY_FORMAT,
    CANDIDATE_MANIFEST_FORMAT,
    CANDIDATE_MEDIA_TYPE,
    CIPHER_SUITE,
    CIPHERTEXT_IDENTITY_FORMAT,
    DEPENDENCY_TRANSCRIPT_MEDIA_TYPE,
    FAILURE_MEDIA_TYPE,
    MAX_CHUNK_BYTES,
    SUBJECT_MANIFEST_MEDIA_TYPE,
    TRIGGER_MEDIA_TYPE,
    WORLD_MANIFEST_MEDIA_TYPE,
    ManagedError,
    NonceRegistry,
    canonical_digest,
    chunk_key_context,
    decode_base64url,
    derive_chunk_key,
    derive_object_key,
    digest_bytes,
    encode_base64url,
    encrypt_chunk,
    incomplete_candidate,
    new_object_id,
    object_key_context,
    parse_strict_json,
    schema_invalid,
    sign_bytes,
    valid_digest,
    valid_typed_id,
    validate_ciphertext_identity,
    validate_managed_candidate_identity,
    validate_upload_request,
    verify_capture_grant,
)
from .managed_subject import PythonSubjectPackage, validate_subject_closure_manifest
from .managed_transport import EncryptionResponse

__all__ = [
    "FrozenManagedCaptureClosure",
    "ManagedCandidateArtifact",
    "ManagedCandidateGrantDelivery",
    "ManagedCandidateIngressDelivery",
    "ManagedCaptureClosure",
    "PreparedManagedCandidate",
    "SealedManagedCandidate",
    "validate_subject_binding",
    "validate_world_checkpoint",
]

GRANT_TIMEOUT_SECONDS = 5.0
# The ingress verifies the digest and size of every declared ciphertext byte
# before it commits, so the commit wait scales with the declared closure. The
# rule mirrors the Rust reference: a five-second floor, a conservative
# verification rate, and a hard cap for the maximum closure.
COMMIT_TIMEOUT_FLOOR_SECONDS = 5.0
COMMIT_VERIFICATION_BYTES_PER_SECOND = 4 * 1024 * 1024
COMMIT_TIMEOUT_CAP_SECONDS = 180.0


def _commit_timeout_seconds(total_ciphertext_bytes: int) -> float:
    verification_seconds = -(
        -total_ciphertext_bytes // COMMIT_VERIFICATION_BYTES_PER_SECOND
    )
    return min(
        COMMIT_TIMEOUT_CAP_SECONDS,
        COMMIT_TIMEOUT_FLOOR_SECONDS + float(verification_seconds),
    )


_COMPLETIONS_BY_KIND = {
    "request-response": frozenset(("return",)),
    "stream": frozenset(("stream-end",)),
    "delivered-work": frozenset(("acknowledgment", "task-end")),
}


class ManagedCandidateGrantDelivery(Protocol):
    def request_encryption_grant(
        self, request: Mapping[str, object], timeout: float
    ) -> EncryptionResponse: ...


class ManagedCandidateIngressDelivery(Protocol):
    def start(
        self, request: Mapping[str, object], timeout: float
    ) -> dict[str, object]: ...

    def missing(
        self, upload_id: str, upload_token: str, cursor: str | None, timeout: float
    ) -> dict[str, object]: ...

    def upload_object(
        self, upload_url: str, digest: str, value: bytes, timeout: float
    ) -> None: ...

    def commit(
        self, upload_id: str, upload_token: str, timeout: float
    ) -> dict[str, object]: ...

    def cancel(
        self, upload_id: str, upload_token: str, timeout: float
    ) -> dict[str, object]: ...


@dataclass
class _PreparedObject:
    descriptor: dict[str, object]
    content: bytes | None
    path: str | None

    def read(self) -> bytes:
        if self.descriptor["plain_size"] > MAX_CHUNK_BYTES:
            raise incomplete_candidate()
        if self.content is not None:
            return self.content
        assert self.path is not None
        try:
            with open(self.path, "rb") as source:
                return source.read(MAX_CHUNK_BYTES + 1)
        except OSError as error:
            raise incomplete_candidate() from error


class PreparedManagedCandidate:
    """One locally complete candidate whose closure is proved before upload."""

    def __init__(
        self,
        identity: dict[str, object],
        objects: list[_PreparedObject],
        subject: PythonSubjectPackage,
        closure: FrozenManagedCaptureClosure,
    ):
        self._identity = identity
        self._objects = objects
        self._subject = subject
        # The frozen closure owns the artifact spool the objects reference.
        self._closure = closure

    @classmethod
    def prepare_complete(
        cls,
        candidate: Mapping[str, object],
        subject: PythonSubjectPackage,
        closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
    ) -> PreparedManagedCandidate:
        if isinstance(closure, ManagedCaptureClosure):
            closure = FrozenManagedCaptureClosure(closure)
        frozen = closure.closure
        _validate_candidate(candidate)
        validate_subject_closure_manifest(subject.manifest)
        if candidate["processing_mode"] != "managed":
            raise schema_invalid("Managed capture requires a managed deployment.")
        validate_subject_binding(candidate, subject.manifest)
        if closure.world_id() != candidate["world_id"]:
            raise incomplete_candidate()

        objects: list[_PreparedObject] = []
        try:
            _push_bytes(
                objects,
                new_object_id(),
                "candidate",
                CANDIDATE_MEDIA_TYPE,
                canonical_bytes(candidate),
            )
            _push_subject(objects, subject)
            _push_trigger_and_inputs(objects, candidate, frozen.completion)
            _push_failure(objects, candidate)
            _push_bytes(
                objects,
                new_object_id(),
                "world-manifest",
                WORLD_MANIFEST_MEDIA_TYPE,
                canonical_bytes(frozen.world),
            )
            _push_capture_artifacts(objects, candidate, frozen.world, frozen.artifacts)
        except (KeyError, TypeError, AttributeError) as error:
            raise incomplete_candidate() from error
        objects.sort(key=lambda entry: entry.descriptor["object_id"])
        _verify_local_closure(objects)

        descriptors = [dict(entry.descriptor) for entry in objects]
        total_plaintext_bytes = sum(entry["plain_size"] for entry in descriptors)
        if total_plaintext_bytes > 4 * 1024 * 1024 * 1024:
            raise incomplete_candidate()
        deployment = candidate["deployment"]
        identity = {
            "candidate_digest": canonical_digest(candidate),
            "capture_id": candidate["capture_id"],
            "deployment_digest": canonical_digest(deployment),
            "format": CANDIDATE_IDENTITY_FORMAT,
            "objects": descriptors,
            "organization_id": deployment["organization_id"],
            "processing_mode": "managed",
            "project_id": deployment["project_id"],
            "required_capabilities": list(deployment["runtime_capabilities"]),
            "service_id": deployment["service_id"],
            "subject_digest": canonical_digest(subject.manifest),
            "total_plaintext_bytes": total_plaintext_bytes,
        }
        validate_managed_candidate_identity(identity)
        return cls(identity, objects, subject, closure)

    @property
    def identity(self) -> dict[str, object]:
        return self._identity

    def request_encryption_grant(
        self,
        delivery: ManagedCandidateGrantDelivery,
        signer_key_id: str,
        signing_key: bytes,
    ) -> EncryptionResponse:
        validate_managed_candidate_identity(self._identity)
        _verify_local_closure(self._objects)
        request = _signed_grant_request(
            self._identity,
            canonical_digest(self._identity),
            self._identity["deployment_digest"],
            signer_key_id,
            signing_key,
        )
        return delivery.request_encryption_grant(request, GRANT_TIMEOUT_SECONDS)

    def seal(
        self,
        response: EncryptionResponse,
        now: str,
        capture_signer_id: str,
        capture_signer_public_key: bytes,
    ) -> SealedManagedCandidate:
        identity_digest = canonical_digest(self._identity)
        key_reference = response.capture_grant["candidate_key_reference"]
        verify_capture_grant(
            response.capture_grant,
            {
                "candidate_identity_digest": identity_digest,
                "candidate_key_reference": key_reference,
                "capture_id": self._identity["capture_id"],
                "organization_id": self._identity["organization_id"],
                "project_id": self._identity["project_id"],
                "service_id": self._identity["service_id"],
                "signer_key_id": capture_signer_id,
            },
            now,
            capture_signer_public_key,
        )
        _verify_local_closure(self._objects)

        spool = tempfile.TemporaryDirectory(prefix="reproit-managed-candidate-")
        ciphertext: dict[str, str] = {}
        nonces = NonceRegistry()
        encrypted_objects = [
            _encrypt_object(
                response.candidate_key,
                self._identity,
                entry,
                spool.name,
                ciphertext,
                nonces,
            )
            for entry in self._objects
        ]
        manifest = {
            "candidate_identity": self._identity,
            "candidate_identity_digest": identity_digest,
            "candidate_key_reference": key_reference,
            "cipher_suite": CIPHER_SUITE,
            "format": CANDIDATE_MANIFEST_FORMAT,
        }
        manifest_object = _encrypt_manifest(
            response.candidate_key,
            self._identity,
            new_object_id(),
            canonical_bytes(manifest),
            spool.name,
            ciphertext,
            nonces,
        )
        total_ciphertext_bytes = manifest_object["cipher_size"] + sum(
            chunk["cipher_size"]
            for entry in encrypted_objects
            for chunk in entry["chunks"]
        )
        ciphertext_identity = {
            "candidate_identity_digest": identity_digest,
            "candidate_key_reference": key_reference,
            "capture_id": self._identity["capture_id"],
            "cipher_suite": CIPHER_SUITE,
            "format": CIPHERTEXT_IDENTITY_FORMAT,
            "manifest_object": manifest_object,
            "objects": encrypted_objects,
            "organization_id": self._identity["organization_id"],
            "processing_mode": "managed",
            "project_id": self._identity["project_id"],
            "required_capabilities": list(self._identity["required_capabilities"]),
            "service_id": self._identity["service_id"],
            "total_ciphertext_bytes": total_ciphertext_bytes,
        }
        validate_ciphertext_identity(ciphertext_identity)
        request = {
            "capture_grant": response.capture_grant,
            "ciphertext_identity": ciphertext_identity,
            "encrypted_candidate_digest": canonical_digest(ciphertext_identity),
        }
        validate_upload_request(request)
        return SealedManagedCandidate(
            request,
            response.candidate_key,
            ciphertext,
            self._identity["deployment_digest"],
            spool,
        )


def _signed_grant_request(
    identity: Mapping[str, object],
    candidate_identity_digest: object,
    deployment_digest: object,
    signer_key_id: str,
    signing_key: bytes,
) -> dict[str, object]:
    request = {
        "candidate_identity_digest": candidate_identity_digest,
        "capture_id": identity["capture_id"],
        "cipher_suite": CIPHER_SUITE,
        "deployment_digest": deployment_digest,
        "organization_id": identity["organization_id"],
        "processing_mode": "managed",
        "project_id": identity["project_id"],
        "service_id": identity["service_id"],
        "signature": "",
        "signer_key_id": signer_key_id,
    }
    request["signature"] = sign_bytes(canonical_bytes(request), signing_key)
    from .managed_transport import _validate_grant_request

    _validate_grant_request(request)
    return request


@dataclass
class SealedManagedCandidate:
    """The sealed upload request plus its private ciphertext spool."""

    request: dict[str, object]
    _candidate_key: bytes = field(repr=False)
    _ciphertext: dict[str, str] = field(repr=False)
    _deployment_digest: str = field(repr=False)
    _spool: tempfile.TemporaryDirectory = field(repr=False)

    def ciphertext_digests(self) -> list[str]:
        return sorted(self._ciphertext)

    def ciphertext_path(self, digest: str) -> str | None:
        return self._ciphertext.get(digest)

    def request_capture_grant_renewal(
        self,
        delivery: ManagedCandidateGrantDelivery,
        signer_key_id: str,
        signing_key: bytes,
    ) -> EncryptionResponse:
        identity = self.request["ciphertext_identity"]
        request = _signed_grant_request(
            identity,
            identity["candidate_identity_digest"],
            self._deployment_digest,
            signer_key_id,
            signing_key,
        )
        return delivery.request_encryption_grant(request, GRANT_TIMEOUT_SECONDS)

    def apply_renewed_capture_grant(
        self,
        response: EncryptionResponse,
        now: str,
        capture_signer_id: str,
        capture_signer_public_key: bytes,
    ) -> None:
        identity = self.request["ciphertext_identity"]
        if (
            response.candidate_key != self._candidate_key
            or response.capture_grant["candidate_key_reference"]
            != identity["candidate_key_reference"]
        ):
            raise ManagedError(
                "CAPTURE_ID_CONFLICT",
                "The renewed managed capture grant does not match the live candidate key.",
            )
        verify_capture_grant(
            response.capture_grant,
            {
                "candidate_identity_digest": identity["candidate_identity_digest"],
                "candidate_key_reference": identity["candidate_key_reference"],
                "capture_id": identity["capture_id"],
                "organization_id": identity["organization_id"],
                "project_id": identity["project_id"],
                "service_id": identity["service_id"],
                "signer_key_id": capture_signer_id,
            },
            now,
            capture_signer_public_key,
        )
        self.request["capture_grant"] = response.capture_grant
        validate_upload_request(self.request)

    def upload(self, delivery: ManagedCandidateIngressDelivery) -> dict[str, object]:
        commit_timeout = _commit_timeout_seconds(
            int(self.request["ciphertext_identity"]["total_ciphertext_bytes"])
        )
        start = delivery.start(self.request, GRANT_TIMEOUT_SECONDS)
        if start["state"] == "COMMITTED":
            return self._verified_commit(
                delivery.commit(
                    start["upload_id"], start["upload_token"], commit_timeout
                )
            )
        if start["state"] not in ("OPEN", "UPLOADING"):
            raise _upload_state_error()
        try:
            self._upload_missing(delivery, start)
        except ManagedError:
            self._cancel_quietly(delivery, start)
            raise
        try:
            commit = delivery.commit(
                start["upload_id"], start["upload_token"], commit_timeout
            )
        except ManagedError:
            self._cancel_quietly(delivery, start)
            raise
        return self._verified_commit(commit)

    def _verified_commit(self, commit: Mapping[str, object]) -> dict[str, object]:
        identity = self.request["ciphertext_identity"]
        if (
            commit["capture_id"] != self.request["capture_grant"]["capture_id"]
            or commit["candidate_identity_digest"]
            != identity["candidate_identity_digest"]
            or commit["candidate_key_reference"] != identity["candidate_key_reference"]
            or commit["encrypted_candidate_digest"]
            != self.request["encrypted_candidate_digest"]
            or commit["state"] != "CLOUD_PROTECTED"
        ):
            raise _upload_state_error()
        return dict(commit)

    def _upload_missing(
        self,
        delivery: ManagedCandidateIngressDelivery,
        start: Mapping[str, object],
    ) -> None:
        limits = start["limits"]
        attempts = limits["object_attempts"]
        page = {
            "missing_objects": list(start["missing_objects"]),
            "next_missing_cursor": start["next_missing_cursor"],
        }
        seen: set[str] = set()
        maximum_pages = -(-len(self._ciphertext) // 100) + 1
        for _ in range(maximum_pages):
            if len(page["missing_objects"]) > 100:
                raise _upload_state_error()
            for missing in page["missing_objects"]:
                digest = missing["cipher_digest"]
                if digest in seen or digest not in self._ciphertext:
                    raise _upload_state_error()
                seen.add(digest)
            for missing in page["missing_objects"]:
                self._upload_one(delivery, missing, attempts)
            cursor = page["next_missing_cursor"]
            if cursor is None:
                return
            page = delivery.missing(
                start["upload_id"], start["upload_token"], cursor, GRANT_TIMEOUT_SECONDS
            )
        raise _upload_state_error()

    def _upload_one(
        self,
        delivery: ManagedCandidateIngressDelivery,
        missing: Mapping[str, object],
        attempts: object,
    ) -> None:
        if type(attempts) is not int or attempts == 0 or attempts > 5:
            raise _upload_state_error()
        digest = missing["cipher_digest"]
        path = self._ciphertext[digest]
        try:
            with open(path, "rb") as source:
                value = source.read(MAX_CHUNK_BYTES + 29)
        except OSError as error:
            raise _local_storage_error() from error
        if digest_bytes(value) != digest:
            raise ManagedError(
                "OBJECT_DIGEST_MISMATCH",
                "The object bytes do not match the bound digest.",
            )
        last_error: ManagedError | None = None
        for _ in range(attempts):
            try:
                delivery.upload_object(
                    missing["upload_url"], digest, value, GRANT_TIMEOUT_SECONDS
                )
                return
            except ManagedError as error:
                if not error.retryable:
                    raise
                last_error = error
        raise last_error if last_error is not None else _upload_state_error()

    @staticmethod
    def _cancel_quietly(
        delivery: ManagedCandidateIngressDelivery, start: Mapping[str, object]
    ) -> None:
        try:
            delivery.cancel(
                start["upload_id"], start["upload_token"], GRANT_TIMEOUT_SECONDS
            )
        except ManagedError:
            pass


def validate_subject_binding(
    candidate: Mapping[str, object], manifest: Mapping[str, object]
) -> None:
    deployment = candidate["deployment"]
    subject = deployment.get("subject") if isinstance(deployment, Mapping) else None
    if not isinstance(subject, Mapping):
        raise incomplete_candidate()
    manifest_digest = canonical_digest(manifest)
    launch = manifest["launch"]
    capabilities = deployment.get("runtime_capabilities")
    if (
        subject.get("artifact_digest") != manifest_digest
        or subject.get("artifact_media_type") != SUBJECT_MANIFEST_MEDIA_TYPE
        or subject.get("architecture") != manifest["architecture"]
        or subject.get("operating_system") != manifest["operating_system"]
        or subject.get("arguments") != launch["arguments"]
        or subject.get("environment_names") != launch["environment_names"]
        or subject.get("executable") != launch["executable"]
        or subject.get("working_directory") != launch["working_directory"]
        or not isinstance(capabilities, list)
        or manifest["architecture"] not in capabilities
        or manifest["operating_system"] not in capabilities
    ):
        raise ManagedError(
            "SUBJECT_DIGEST_MISMATCH",
            "The managed deployment does not match the running subject package.",
        )


def _validate_candidate(candidate: Mapping[str, object]) -> None:
    """Prove the candidate record closure locally, mirroring the Rust gate."""
    if not isinstance(candidate, Mapping):
        raise incomplete_candidate()
    records = candidate.get("records")
    deployment = candidate.get("deployment")
    if (
        candidate.get("format") != "reproit.candidate.v1"
        or not valid_typed_id(candidate.get("capture_id"), "capture_id")
        or not valid_typed_id(candidate.get("operation_id"), "operation_id")
        or not valid_digest(candidate.get("world_id"))
        or not isinstance(records, list)
        or not isinstance(deployment, Mapping)
        or not valid_typed_id(deployment.get("organization_id"), "organization_id")
        or not valid_typed_id(deployment.get("project_id"), "project_id")
        or not valid_typed_id(deployment.get("service_id"), "service_id")
        or candidate.get("processing_mode") != deployment.get("processing_mode")
    ):
        raise incomplete_candidate()
    try:
        decode_base64url(deployment.get("signature"), 64)
    except ManagedError as error:
        raise incomplete_candidate() from error
    failure_record = next(
        (
            record
            for record in records
            if isinstance(record, Mapping) and record.get("kind") == "failure"
        ),
        None,
    )
    failure_payload = _decode_record_payload(failure_record)
    try:
        validate_candidate(
            candidate, failure_payload, _decode_record_payload, canonical_digest
        )
    except (KeyError, StopIteration, TypeError, ValueError) as error:
        raise incomplete_candidate() from error


def _decode_record_payload(record: object) -> dict[str, object]:
    if not isinstance(record, Mapping) or not isinstance(record.get("payload"), str):
        raise incomplete_candidate()
    try:
        decoded = decode_base64url(record["payload"])
        value = parse_strict_json(decoded, MAX_CHUNK_BYTES)
    except ManagedError as error:
        raise incomplete_candidate() from error
    if not isinstance(value, dict):
        raise incomplete_candidate()
    return value


def _push_bytes(
    objects: list[_PreparedObject],
    object_id: str,
    role: str,
    media_type: str,
    content: bytes,
) -> None:
    descriptor = {
        "media_type": media_type,
        "object_id": object_id,
        "plain_digest": digest_bytes(content),
        "plain_size": len(content),
        "role": role,
    }
    objects.append(_PreparedObject(descriptor, content, None))


def _push_file(
    objects: list[_PreparedObject],
    object_id: str,
    media_type: str,
    digest: str,
    size: int,
    path: str,
    role: str,
) -> None:
    descriptor = {
        "media_type": media_type,
        "object_id": object_id,
        "plain_digest": digest,
        "plain_size": size,
        "role": role,
    }
    objects.append(_PreparedObject(descriptor, None, path))


def _push_subject(
    objects: list[_PreparedObject], subject: PythonSubjectPackage
) -> None:
    _push_bytes(
        objects,
        new_object_id(),
        "subject",
        SUBJECT_MANIFEST_MEDIA_TYPE,
        canonical_bytes(subject.manifest),
    )
    declared = {
        entry["digest"]: (entry["media_type"], entry["size"])
        for entry in subject.manifest["objects"]
    }
    if len(declared) != len(subject.objects):
        raise incomplete_candidate()
    for packaged in subject.objects:
        entry = declared.get(packaged.digest)
        if entry is None or entry[1] != packaged.size:
            raise incomplete_candidate()
        _push_file(
            objects,
            new_object_id(),
            entry[0],
            packaged.digest,
            packaged.size,
            packaged.path,
            "subject",
        )


def _push_trigger_and_inputs(
    objects: list[_PreparedObject],
    candidate: Mapping[str, object],
    completion: str,
) -> None:
    records = candidate["records"]
    begin = _decode_record_payload(records[0])
    inputs = []
    for record in records:
        if record.get("kind") != "input":
            continue
        payload = _decode_record_payload(record)
        content = decode_base64url(payload["value"])
        object_id = new_object_id()
        inputs.append(
            {
                "channel": payload["channel"],
                "object_id": object_id,
                "plain_digest": payload["value_digest"],
                "sequence": len(inputs),
            }
        )
        _push_bytes(objects, object_id, "trigger", payload["content_type"], content)
    operation_kind = begin.get("operation_kind")
    allowed = _COMPLETIONS_BY_KIND.get(operation_kind, frozenset())
    adapter_id = begin.get("adapter_id")
    adapter_version = begin.get("adapter_version")
    operation_name = begin.get("operation_name")
    causal_parent_ids = begin.get("causal_parent_ids")
    if (
        not inputs
        or len(inputs) > 1_024
        or completion not in allowed
        or not isinstance(adapter_id, str)
        or not 1 <= len(adapter_id) <= 128
        or not isinstance(adapter_version, str)
        or not 1 <= len(adapter_version) <= 64
        or not isinstance(operation_name, str)
        or not 1 <= len(operation_name) <= 128
        or not isinstance(causal_parent_ids, list)
        or len(causal_parent_ids) > 32
        or len(set(causal_parent_ids)) != len(causal_parent_ids)
        or any(
            not valid_typed_id(parent, "operation_id") for parent in causal_parent_ids
        )
    ):
        raise incomplete_candidate()
    trigger = {
        "adapter_id": begin["adapter_id"],
        "adapter_version": begin["adapter_version"],
        "causal_parent_ids": begin["causal_parent_ids"],
        "completion": completion,
        "format": "reproit.trigger.v1",
        "inputs": inputs,
        "operation_id": candidate["operation_id"],
        "operation_kind": operation_kind,
        "operation_name": begin["operation_name"],
    }
    _push_bytes(
        objects,
        new_object_id(),
        "trigger",
        TRIGGER_MEDIA_TYPE,
        canonical_bytes(trigger),
    )


def _push_failure(
    objects: list[_PreparedObject], candidate: Mapping[str, object]
) -> None:
    record = next(
        (record for record in candidate["records"] if record.get("kind") == "failure"),
        None,
    )
    if record is None:
        raise incomplete_candidate()
    payload = _decode_record_payload(record)
    failure = payload.get("failure")
    if not isinstance(failure, Mapping) or not valid_typed_id(
        failure.get("object_id"), "object_id"
    ):
        raise incomplete_candidate()
    _push_bytes(
        objects,
        failure["object_id"],
        "failure",
        FAILURE_MEDIA_TYPE,
        canonical_bytes(payload),
    )


def _push_capture_artifacts(
    objects: list[_PreparedObject],
    candidate: Mapping[str, object],
    world: Mapping[str, object],
    artifacts: list[ManagedCandidateArtifact],
) -> None:
    dependency_records = [
        record for record in candidate["records"] if record.get("kind") == "dependency"
    ]
    requires_artifacts = bool(expected_world_artifacts(world)) or bool(
        dependency_records
    )
    if not artifacts and requires_artifacts:
        raise incomplete_candidate()
    for artifact in artifacts:
        size, digest = hash_file(artifact.path)
        _push_file(
            objects,
            artifact.object_id,
            artifact.media_type,
            digest,
            size,
            artifact.path,
            artifact.role,
        )
    _validate_dependency_closure(candidate, objects, dependency_records)


def _validate_dependency_closure(
    candidate: Mapping[str, object],
    objects: list[_PreparedObject],
    dependency_records: list[Mapping[str, object]],
) -> None:
    cursors = [_decode_record_payload(record) for record in dependency_records]
    descriptors = {entry.descriptor["object_id"]: entry.descriptor for entry in objects}
    transcripts = []
    for entry in objects:
        descriptor = entry.descriptor
        if (
            descriptor["role"] != "dependency-transcript"
            or descriptor["media_type"] != DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
        ):
            continue
        transcript = validate_transcript_bytes(entry.read())
        for interaction in transcript["interactions"]:
            if (
                interaction["operation_id"] != candidate["operation_id"]
                and interaction["causal_parent_id"] != candidate["operation_id"]
            ) or not (
                _descriptor_matches(
                    descriptors,
                    interaction["request_object_id"],
                    interaction["request_digest"],
                )
                and _descriptor_matches(
                    descriptors,
                    interaction["response_object_id"],
                    interaction["response_digest"],
                )
            ):
                raise incomplete_candidate()
        transcripts.append(transcript)
    if len(cursors) != len(transcripts) or any(
        sum(
            transcript["adapter_id"] == cursor["adapter_id"]
            and transcript["adapter_version"] == cursor["adapter_version"]
            for transcript in transcripts
        )
        != 1
        for cursor in cursors
    ):
        raise incomplete_candidate()


def _descriptor_matches(
    descriptors: Mapping[str, Mapping[str, object]], object_id: object, digest: object
) -> bool:
    descriptor = descriptors.get(object_id)
    return descriptor is not None and descriptor["plain_digest"] == digest


def _verify_local_closure(objects: list[_PreparedObject]) -> None:
    if not 5 <= len(objects) <= 32_767:
        raise incomplete_candidate()
    object_ids: set[str] = set()
    for entry in objects:
        descriptor = entry.descriptor
        if descriptor["object_id"] in object_ids:
            raise incomplete_candidate()
        object_ids.add(descriptor["object_id"])
        if entry.content is not None:
            actual = (len(entry.content), digest_bytes(entry.content))
        else:
            assert entry.path is not None
            size, digest = hash_file(entry.path)
            actual = (size, digest)
        if actual != (descriptor["plain_size"], descriptor["plain_digest"]):
            raise incomplete_candidate()


def _encrypt_object(
    candidate_key: bytes,
    identity: Mapping[str, object],
    entry: _PreparedObject,
    spool_path: str,
    ciphertext: dict[str, str],
    nonces: NonceRegistry,
) -> dict[str, object]:
    descriptor = entry.descriptor
    plain_size = descriptor["plain_size"]
    chunk_count = -(-max(plain_size, 1) // MAX_CHUNK_BYTES)
    if chunk_count > 32_767:
        raise incomplete_candidate()
    context = object_key_context(identity, descriptor["object_id"], descriptor["role"])
    context_digest = canonical_digest(context)
    object_key = derive_object_key(candidate_key, identity["capture_id"], context)
    reader = _ObjectReader(entry)
    plain_hasher = hashlib.sha256()
    chunks = []
    remaining = plain_size
    for index in range(chunk_count):
        chunk_plain_size = min(remaining, MAX_CHUNK_BYTES)
        plaintext = reader.read_exact(chunk_plain_size)
        plain_hasher.update(plaintext)
        chunk_context = chunk_key_context(
            context_digest, chunk_count, index, chunk_plain_size
        )
        chunk_key = derive_chunk_key(object_key, chunk_context)
        nonce = _random_nonce(nonces)
        stored = encrypt_chunk(chunk_key, nonce, plaintext, chunk_context)
        chunks.append(_store_ciphertext(spool_path, ciphertext, index, nonce, stored))
        remaining -= chunk_plain_size
    if (
        remaining != 0
        or not reader.at_end()
        or f"sha256:{plain_hasher.hexdigest()}" != descriptor["plain_digest"]
    ):
        raise incomplete_candidate()
    return {"chunks": chunks, "descriptor": dict(descriptor)}


class _ObjectReader:
    """Bounded chunked reads over an in-memory or spooled prepared object."""

    def __init__(self, entry: _PreparedObject):
        if entry.content is not None:
            self._source = None
            self._content = entry.content
            self._offset = 0
        else:
            assert entry.path is not None
            try:
                self._source = open(entry.path, "rb")
            except OSError as error:
                raise incomplete_candidate() from error
            self._content = b""
            self._offset = 0

    def read_exact(self, size: int) -> bytes:
        if self._source is None:
            value = self._content[self._offset : self._offset + size]
            self._offset += size
        else:
            try:
                value = self._source.read(size)
            except OSError as error:
                raise incomplete_candidate() from error
        if len(value) != size:
            raise incomplete_candidate()
        return value

    def at_end(self) -> bool:
        if self._source is None:
            return self._offset >= len(self._content)
        try:
            trailing = self._source.read(1)
        except OSError:
            return False
        finally:
            self._source.close()
        return not trailing


def _encrypt_manifest(
    candidate_key: bytes,
    identity: Mapping[str, object],
    object_id: str,
    plaintext: bytes,
    spool_path: str,
    ciphertext: dict[str, str],
    nonces: NonceRegistry,
) -> dict[str, object]:
    if len(plaintext) > MAX_CHUNK_BYTES:
        raise incomplete_candidate()
    context = object_key_context(identity, object_id, "capture-batch-manifest")
    chunk_context = chunk_key_context(canonical_digest(context), 1, 0, len(plaintext))
    object_key = derive_object_key(candidate_key, identity["capture_id"], context)
    chunk_key = derive_chunk_key(object_key, chunk_context)
    nonce = _random_nonce(nonces)
    stored = encrypt_chunk(chunk_key, nonce, plaintext, chunk_context)
    chunk = _store_ciphertext(spool_path, ciphertext, 0, nonce, stored)
    return {
        "cipher_digest": chunk["cipher_digest"],
        "cipher_size": chunk["cipher_size"],
        "nonce": chunk["nonce"],
        "object_id": object_id,
    }


def _store_ciphertext(
    spool_path: str,
    ciphertext: dict[str, str],
    index: int,
    nonce: bytes,
    stored: bytes,
) -> dict[str, object]:
    digest = digest_bytes(stored)
    path = os.path.join(spool_path, digest.removeprefix("sha256:"))
    try:
        if not os.path.exists(path):
            with open(path, "wb") as target:
                target.write(stored)
    except OSError as error:
        raise _local_storage_error() from error
    existing = ciphertext.get(digest)
    if existing is not None and existing != path:
        raise ManagedError(
            "OBJECT_DIGEST_MISMATCH",
            "The object bytes do not match the bound digest.",
        )
    ciphertext[digest] = path
    return {
        "cipher_digest": digest,
        "cipher_size": len(stored),
        "index": index,
        "nonce": encode_base64url(nonce),
    }


def _random_nonce(nonces: NonceRegistry) -> bytes:
    nonce = secrets.token_bytes(12)
    nonces.register(nonce)
    return nonce


def _local_storage_error() -> ManagedError:
    return ManagedError(
        "SERVICE_UNAVAILABLE",
        "Repro It could not create the bounded local ciphertext staging area.",
    )


def _upload_state_error() -> ManagedError:
    return ManagedError(
        "SERVICE_UNAVAILABLE",
        "The managed candidate upload did not reach a valid durable state.",
    )
