"""Shared fixtures for the managed-mode capture client tests."""

from __future__ import annotations

import copy
import json
import os
import tempfile

from reproit_sdk import CandidateStart, Sdk, canonical_bytes
from reproit_sdk import managed_protocol as protocol
from reproit_sdk.managed_subject import (
    PythonSubjectPackage,
    package_running_python_subject,
    subject_binding,
)
from reproit_sdk.managed_transport import EncryptionResponse

from memory_sink import MemorySink

SPECS_V1 = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", ".core", "specs", "v1")
)

CAPTURE_ID = "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc"
OPERATION_ID = "op_01890f3e-7b1c-7cc0-8a1b-123456789ab1"
ORGANIZATION_ID = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd"
PROJECT_ID = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"
SERVICE_ID = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
UPLOAD_ID = "upl_01890f3e-7b1c-7cc0-8a1b-123456789ac1"

CAPTURE_SIGNER_SEED = bytes([0x83]) * 32
WORKLOAD_SEED = bytes([0x77]) * 32
CANDIDATE_KEY = bytes([0x42]) * 32
KEY_REFERENCE = protocol.encode_base64url(bytes([0x91]) * 32)
GRANT_ID = protocol.encode_base64url(bytes([0x92]) * 32)
CAPTURE_SIGNER_ID = "managed-candidate-capture-test"
WORKLOAD_KEY_ID = "managed-workload-" + protocol.digest_bytes(
    protocol.encode_base64url(protocol.verification_key(WORKLOAD_SEED)).encode("ascii")
)

_SUBJECT_CACHE: PythonSubjectPackage | None = None
_SCRIPT_DIRECTORY: tempfile.TemporaryDirectory | None = None


def load_protocol_vectors() -> dict:
    path = os.environ.get(
        "REPROIT_PROTOCOL_VECTORS",
        os.path.join(SPECS_V1, "protocol-vectors.json"),
    )
    with open(path, "rb") as source:
        return json.load(source)


def load_cloud_api_vectors() -> dict:
    path = os.environ.get(
        "REPROIT_CLOUD_API_VECTORS",
        os.path.join(SPECS_V1, "cloud-api-vectors.json"),
    )
    with open(path, "rb") as source:
        return json.load(source)


def shared_subject() -> PythonSubjectPackage:
    """Package one running-subject closure and reuse it across tests."""
    global _SCRIPT_DIRECTORY, _SUBJECT_CACHE
    if _SUBJECT_CACHE is None:
        _SCRIPT_DIRECTORY = tempfile.TemporaryDirectory()
        script_path = os.path.join(_SCRIPT_DIRECTORY.name, "fixture.py")
        with open(script_path, "wb") as script:
            script.write(b"raise RuntimeError('captured failure fixture')\n")
        _SUBJECT_CACHE = package_running_python_subject(
            script_path,
            _SCRIPT_DIRECTORY.name,
        )
    return _SUBJECT_CACHE


def empty_world() -> dict:
    return {
        "created_at": "2026-01-01T00:00:00.000Z",
        "format": "reproit.world-checkpoint.v1",
        "points": [],
    }


def bound_deployment(
    subject: PythonSubjectPackage,
    workload_seed: bytes = WORKLOAD_SEED,
    signer_key_id: str = WORKLOAD_KEY_ID,
) -> dict:
    deployment = {
        "format": "reproit.deployment.v1",
        "organization_id": ORGANIZATION_ID,
        "processing_mode": "managed",
        "project_id": PROJECT_ID,
        "repository_id": "source.example/acme/commerce",
        "runtime_capabilities": ["runtime.python"],
        "runtime_endpoint": "https://managed.reproit.example",
        "service_id": SERVICE_ID,
        "service_path": "services/orders",
        "signature": "",
        "signed_at": "2026-01-01T00:00:00.000Z",
        "signer_key_id": signer_key_id,
        "source_revision": "0123456789abcdef",
        "subject": subject_binding(subject.manifest),
    }
    capabilities = deployment["runtime_capabilities"] + [
        subject.manifest["architecture"],
        subject.manifest["operating_system"],
    ]
    deployment["runtime_capabilities"] = sorted(set(capabilities))
    deployment["signature"] = protocol.sign_bytes(
        canonical_bytes(deployment), workload_seed
    )
    return deployment


def captured_candidate(deployment: dict, world_id: str) -> dict:
    """Capture one complete managed candidate through the existing SDK."""
    vectors = load_protocol_vectors()["positive"]
    sink = MemorySink()
    sdk = Sdk(sink)
    start = CandidateStart(CAPTURE_ID, deployment, OPERATION_ID, world_id)
    sdk.begin(start, vectors["operation_begin_payload"]["value"])
    sdk.record_input(OPERATION_ID, vectors["operation_input_payload"]["value"])
    sdk.fail(OPERATION_ID, vectors["failure_payload"]["value"])
    return json.loads(sink.candidates[0])


def signed_capture_grant(
    request: dict,
    key_reference: str = KEY_REFERENCE,
    not_before: str = "2026-01-01T00:00:00.000Z",
    expires_at: str = "2026-01-01T00:01:00.000Z",
    signer_seed: bytes = CAPTURE_SIGNER_SEED,
) -> dict:
    grant = {
        "candidate_identity_digest": request["candidate_identity_digest"],
        "candidate_key_reference": key_reference,
        "capture_id": request["capture_id"],
        "cipher_suite": protocol.CIPHER_SUITE,
        "expires_at": expires_at,
        "format": protocol.CAPTURE_GRANT_FORMAT,
        "grant_id": GRANT_ID,
        "not_before": not_before,
        "operation": "encrypt-and-upload-candidate",
        "organization_id": request["organization_id"],
        "processing_mode": "managed",
        "project_id": request["project_id"],
        "service_id": request["service_id"],
        "signature": "",
        "signer_key_id": CAPTURE_SIGNER_ID,
    }
    grant["signature"] = protocol.sign_bytes(canonical_bytes(grant), signer_seed)
    return grant


class GrantDeliverySpy:
    """A grant delivery double that records every request it receives."""

    def __init__(
        self,
        candidate_key: bytes = CANDIDATE_KEY,
        key_reference: str = KEY_REFERENCE,
    ):
        self.calls: list[dict] = []
        self.candidate_key = candidate_key
        self.key_reference = key_reference

    def request_encryption_grant(self, request, timeout):
        self.calls.append(copy.deepcopy(dict(request)))
        return EncryptionResponse(
            self.candidate_key,
            signed_capture_grant(request, key_reference=self.key_reference),
        )


def open_sealed_object_bytes(sealed, candidate_key: bytes) -> dict[str, bytes]:
    """Independently decrypt every sealed object and verify plain digests."""
    identity = sealed.request["ciphertext_identity"]
    recovered: dict[str, bytes] = {}
    for entry in identity["objects"]:
        descriptor = entry["descriptor"]
        context = protocol.object_key_context(
            identity, descriptor["object_id"], descriptor["role"]
        )
        object_key = protocol.derive_object_key(
            candidate_key, identity["capture_id"], context
        )
        context_digest = protocol.canonical_digest(context)
        content = b""
        for chunk in entry["chunks"]:
            chunk_context = protocol.chunk_key_context(
                context_digest,
                len(entry["chunks"]),
                chunk["index"],
                chunk["cipher_size"] - 28,
            )
            chunk_key = protocol.derive_chunk_key(object_key, chunk_context)
            with open(sealed.ciphertext_path(chunk["cipher_digest"]), "rb") as source:
                stored = source.read()
            content += protocol.decrypt_chunk(chunk_key, stored, chunk_context)
        if protocol.digest_bytes(content) != descriptor["plain_digest"]:
            raise AssertionError("decrypted object digest mismatch")
        recovered[descriptor["object_id"]] = content
    return recovered


def open_sealed_manifest(sealed, candidate_key: bytes) -> dict:
    identity = sealed.request["ciphertext_identity"]
    manifest_object = identity["manifest_object"]
    context = protocol.object_key_context(
        identity, manifest_object["object_id"], "capture-batch-manifest"
    )
    object_key = protocol.derive_object_key(
        candidate_key, identity["capture_id"], context
    )
    chunk_context = protocol.chunk_key_context(
        protocol.canonical_digest(context), 1, 0, manifest_object["cipher_size"] - 28
    )
    chunk_key = protocol.derive_chunk_key(object_key, chunk_context)
    with open(sealed.ciphertext_path(manifest_object["cipher_digest"]), "rb") as source:
        stored = source.read()
    return json.loads(protocol.decrypt_chunk(chunk_key, stored, chunk_context))


def apply_mutation(base: dict, mutation: dict) -> dict:
    """Apply one negative-vector JSON-pointer replace mutation."""
    if mutation["operation"] != "replace":
        raise AssertionError("only replace mutations are supported")
    changed = copy.deepcopy(base)
    parts = mutation["path"].lstrip("/").split("/")
    target = changed
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    leaf = parts[-1]
    if isinstance(target, list):
        target[int(leaf)] = mutation["value"]
    else:
        target[leaf] = mutation["value"]
    return changed
