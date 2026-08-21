"""Managed-mode protocol primitives that mirror the Rust reference.

This module is the Python mirror of the reproit-core pieces the managed
capture client depends on: strict base64url and digest helpers, typed
identifier validation, Ed25519 signing, the AES-256-GCM + HKDF-SHA-256
candidate seal, and the managed candidate schema validators. The Rust
implementation in crates/reproit-core is normative. Every rule here has a
direct counterpart there.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime

from reproit_sdk import canonical_bytes

MAX_CHUNK_BYTES = 8 * 1024 * 1024
MAX_CANDIDATE_OBJECTS = 32_767
MAX_CANDIDATE_PLAINTEXT_BYTES = 1_048_576
MAX_CANDIDATE_CIPHERTEXT_BYTES = 1_048_604
MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES = 274_878_824_448

CIPHER_SUITE = "AES-256-GCM+HKDF-SHA-256"
CAPTURE_GRANT_FORMAT = "reproit.managed-candidate-capture-grant.v1"
CANDIDATE_IDENTITY_FORMAT = "reproit.managed-candidate-identity.v1"
CANDIDATE_MANIFEST_FORMAT = "reproit.managed-candidate-manifest.v1"
CIPHERTEXT_IDENTITY_FORMAT = "reproit.managed-candidate-ciphertext-identity.v1"
OBJECT_KEY_CONTEXT_FORMAT = "reproit.object-key-context.v1"
CHUNK_KEY_CONTEXT_FORMAT = "reproit.chunk-key-context.v1"
CAPTURE_BATCH_FORMAT = "reproit.capture-batch.v1"

CANDIDATE_MEDIA_TYPE = "application/vnd.reproit.candidate.v1+json"
FAILURE_MEDIA_TYPE = "application/vnd.reproit.failure.v1+json"
SUBJECT_MANIFEST_MEDIA_TYPE = "application/vnd.reproit.subject-closure.v1+json"
TRIGGER_MEDIA_TYPE = "application/vnd.reproit.trigger.v1+json"
WORLD_MANIFEST_MEDIA_TYPE = "application/vnd.reproit.world-manifest.v1+json"
DEPENDENCY_TRANSCRIPT_MEDIA_TYPE = (
    "application/vnd.reproit.dependency-transcript.v1+json"
)

_REQUIRED_ROLES = ("candidate", "failure", "subject", "trigger", "world-manifest")
_ROLE_MEDIA_TYPES = (
    ("candidate", CANDIDATE_MEDIA_TYPE),
    ("failure", FAILURE_MEDIA_TYPE),
    ("subject", SUBJECT_MANIFEST_MEDIA_TYPE),
    ("trigger", TRIGGER_MEDIA_TYPE),
    ("world-manifest", WORLD_MANIFEST_MEDIA_TYPE),
)
_LOGICAL_OBJECT_ROLES = frozenset(
    (
        "admission-proof",
        "candidate",
        "debug-symbols",
        "dependency-transcript",
        "failure",
        "replay-capsule-manifest",
        "subject",
        "trigger",
        "world-manifest",
        "world-state",
    )
)

# Wire values of reproit_core::ErrorCode. The transport rejects a server
# error whose code is not in this closed set.
ERROR_CODES = frozenset(
    (
        "ADMISSION_PROOF_BINDING",
        "ADMISSION_PROOF_COUNT",
        "ASSIGNEE_NOT_AUTHORIZED",
        "ARTIFACT_NOT_FOUND",
        "ATTESTATION_REVOKED",
        "ATTESTATION_SCOPE",
        "AUTHENTICATION_REQUIRED",
        "AUTHORIZATION_DENIED",
        "CAPTURE_ID_CONFLICT",
        "CONFIG_CONFLICT",
        "CROSS_TENANT_SCOPE",
        "DECRYPTION_AUTHENTICATION",
        "DEPENDENCY_TRANSCRIPT_MISMATCH",
        "DIFFERENT_FAILURE",
        "EVALUATION_ERROR",
        "FORBIDDEN",
        "INCOMPLETE_CANDIDATE",
        "INCOMPLETE_RECORD_SEQUENCE",
        "LIVE_EGRESS_BLOCKED",
        "KEY_PROVIDER_UNAVAILABLE",
        "KEY_UNWRAP_FAILED",
        "KEEP_DESTINATION_UNAVAILABLE",
        "LEGAL_DELETION_CONFLICT",
        "NONCE_REUSE",
        "NOT_FOUND",
        "OBJECT_DIGEST_MISMATCH",
        "PRIORITY_INVALID",
        "RATE_LIMITED",
        "RUNTIME_QUOTA",
        "SCHEMA_INVALID",
        "SERVICE_UNAVAILABLE",
        "SOURCE_ACCESS_DENIED",
        "SOURCE_CHECKOUT_FAILED",
        "SOURCE_DEPENDENCY_MISSING",
        "SOURCE_REVISION_MISSING",
        "STATE_SCOPE_VIOLATION",
        "SUBJECT_DIGEST_MISMATCH",
        "TRIAGE_CONFLICT",
        "UNSUPPORTED",
        "UNSUPPORTED_CAPABILITY_SET",
        "UPLOAD_EXPIRED",
        "UPLOAD_INCOMPLETE",
        "UPLOAD_LIMIT_EXCEEDED",
        "WORLD_NOT_CLOSED",
        "WORLD_POINT_EXPIRED",
        "WORLD_PROVIDER_MISSING",
    )
)

RETRYABLE_CODES = frozenset(
    (
        "KEY_PROVIDER_UNAVAILABLE",
        "KEEP_DESTINATION_UNAVAILABLE",
        "RATE_LIMITED",
        "RUNTIME_QUOTA",
        "SERVICE_UNAVAILABLE",
        "SOURCE_CHECKOUT_FAILED",
        "UPLOAD_EXPIRED",
        "UPLOAD_INCOMPLETE",
    )
)

_BASE64URL_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_ID_PREFIXES = {
    "capture_id": "cap_",
    "object_id": "obj_",
    "operation_id": "op_",
    "organization_id": "org_",
    "project_id": "prj_",
    "service_id": "svc_",
    "upload_id": "upl_",
}


class ManagedError(Exception):
    """A managed capture step failed with a stable protocol error code."""

    def __init__(self, code: str, message: str, retryable: bool | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = code in RETRYABLE_CODES if retryable is None else retryable


def schema_invalid(
    message: str = "The value does not satisfy the schema.",
) -> ManagedError:
    return ManagedError("SCHEMA_INVALID", message)


def incomplete_candidate() -> ManagedError:
    return ManagedError(
        "INCOMPLETE_CANDIDATE",
        "The managed candidate is incomplete and cannot be uploaded.",
    )


def attestation_error() -> ManagedError:
    return ManagedError(
        "ATTESTATION_SCOPE", "The signature is invalid for this attestation."
    )


def object_digest_mismatch() -> ManagedError:
    return ManagedError(
        "OBJECT_DIGEST_MISMATCH", "The object bytes do not match the bound digest."
    )


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_base64url(value: str, expected_length: int | None = None) -> bytes:
    """Decode strict unpadded base64url and reject non-canonical encodings."""
    if not isinstance(value, str) or "=" in value:
        raise schema_invalid()
    encoded = value.encode("ascii", errors="strict") if value.isascii() else None
    if encoded is None or any(byte not in _BASE64URL_BYTES for byte in encoded):
        raise schema_invalid()
    padding = b"=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(encoded + padding)
    except ValueError as error:
        raise schema_invalid() from error
    if encode_base64url(decoded) != value:
        raise schema_invalid()
    if expected_length is not None and len(decoded) != expected_length:
        raise schema_invalid()
    return decoded


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def canonical_digest(value: object) -> str:
    return digest_bytes(canonical_bytes(value))


def valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def valid_typed_id(value: object, kind: str) -> bool:
    prefix = _ID_PREFIXES[kind]
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    text = value[len(prefix) :]
    try:
        identifier = uuid.UUID(text)
    except ValueError:
        return False
    return identifier.version == 7 and str(identifier) == text


def require_typed_id(value: object, kind: str) -> str:
    if not isinstance(value, str) or not valid_typed_id(value, kind):
        raise schema_invalid()
    return value


def id_uuid_bytes(value: str, kind: str) -> bytes:
    return uuid.UUID(require_typed_id(value, kind)[len(_ID_PREFIXES[kind]) :]).bytes


def new_object_id() -> str:
    return f"obj_{uuid.uuid7()}"


def valid_opaque_reference(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    try:
        decode_base64url(value, 32)
    except ManagedError:
        return False
    return True


def valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 24 or not value.endswith("Z"):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def parse_timestamp(value: object) -> datetime:
    if not valid_timestamp(value):
        raise schema_invalid()
    parsed = datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S.%fZ")
    return parsed.replace(tzinfo=UTC)


def now_timestamp() -> str:
    value = datetime.now(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03}Z"


def valid_capability(value: object) -> bool:
    """Match the canonical capability shape: ^[a-z][a-z0-9.-]*$ up to 128."""
    if not isinstance(value, str) or not value or len(value) > 128:
        return False
    if not "a" <= value[0] <= "z":
        return False
    return all(
        "a" <= character <= "z" or "0" <= character <= "9" or character in ".-"
        for character in value[1:]
    )


def validate_capabilities(values: object) -> None:
    if (
        not isinstance(values, list)
        or len(values) > 64
        or any(not valid_capability(value) for value in values)
        or any(values[index] >= values[index + 1] for index in range(len(values) - 1))
    ):
        raise schema_invalid()


def sign_bytes(value: bytes, signing_key: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if len(signing_key) != 32:
        raise schema_invalid()
    return encode_base64url(
        Ed25519PrivateKey.from_private_bytes(signing_key).sign(value)
    )


def verification_key(signing_key: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    if len(signing_key) != 32:
        raise schema_invalid()
    public = Ed25519PrivateKey.from_private_bytes(signing_key).public_key()
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify_signed_value(value: Mapping[str, object], public_key: bytes) -> None:
    """Verify the detached Ed25519 signature carried in the signature field."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signature_text = value.get("signature")
    if not isinstance(signature_text, str):
        raise schema_invalid()
    signature = decode_base64url(signature_text, 64)
    unsigned = dict(value)
    unsigned["signature"] = ""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, canonical_bytes(unsigned)
        )
    except (ValueError, InvalidSignature) as error:
        raise attestation_error() from error


class NonceRegistry:
    """Reject any nonce reuse within one sealed candidate."""

    def __init__(self) -> None:
        self._used: set[bytes] = set()

    def register(self, nonce: bytes) -> None:
        if len(nonce) != 12 or nonce in self._used:
            raise ManagedError(
                "NONCE_REUSE", "An occurrence cannot reuse an encryption nonce."
            )
        self._used.add(nonce)


def object_key_context(
    identity: Mapping[str, object], object_id: str, role: str
) -> dict[str, object]:
    return {
        "capture_batch_format": CAPTURE_BATCH_FORMAT,
        "capture_id": identity["capture_id"],
        "format": OBJECT_KEY_CONTEXT_FORMAT,
        "object_id": object_id,
        "organization_id": identity["organization_id"],
        "processing_mode": "managed",
        "project_id": identity["project_id"],
        "role": role,
        "service_id": identity["service_id"],
    }


def chunk_key_context(
    object_context_digest: str, chunk_count: int, chunk_index: int, plain_size: int
) -> dict[str, object]:
    return {
        "chunk_count": chunk_count,
        "chunk_index": chunk_index,
        "format": CHUNK_KEY_CONTEXT_FORMAT,
        "object_context_digest": object_context_digest,
        "plain_size": plain_size,
    }


def _hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def _hkdf_expand_32(pseudo_random_key: bytes, info: bytes) -> bytes:
    # One SHA-256 block covers the full 32-byte output.
    return hmac.new(pseudo_random_key, info + b"\x01", hashlib.sha256).digest()


def derive_object_key(
    candidate_key: bytes, capture_id: str, object_context: Mapping[str, object]
) -> bytes:
    """HKDF-SHA-256: extract with the capture UUID salt, expand per object."""
    if len(candidate_key) != 32 or capture_id != object_context.get("capture_id"):
        raise schema_invalid()
    salt = id_uuid_bytes(capture_id, "capture_id")
    return _hkdf_expand_32(
        _hkdf_extract(salt, candidate_key), canonical_bytes(object_context)
    )


def derive_chunk_key(object_key: bytes, context: Mapping[str, object]) -> bytes:
    if len(object_key) != 32:
        raise schema_invalid()
    return _hkdf_expand_32(object_key, canonical_bytes(context))


def encrypt_chunk(
    chunk_key: bytes, nonce: bytes, plaintext: bytes, context: Mapping[str, object]
) -> bytes:
    """AES-256-GCM with the canonical chunk context as associated data."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if (
        len(chunk_key) != 32
        or len(nonce) != 12
        or len(plaintext) > MAX_CHUNK_BYTES
        or context.get("plain_size") != len(plaintext)
    ):
        raise schema_invalid()
    associated_data = canonical_bytes(context)
    return nonce + AESGCM(chunk_key).encrypt(nonce, plaintext, associated_data)


def decrypt_chunk(
    chunk_key: bytes, stored: bytes, context: Mapping[str, object]
) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plain_size = context.get("plain_size")
    if (
        len(chunk_key) != 32
        or not 28 <= len(stored) <= MAX_CHUNK_BYTES + 28
        or not isinstance(plain_size, int)
        or plain_size + 28 != len(stored)
    ):
        raise ManagedError(
            "DECRYPTION_AUTHENTICATION", "Ciphertext authentication failed."
        )
    associated_data = canonical_bytes(context)
    try:
        return AESGCM(chunk_key).decrypt(stored[:12], stored[12:], associated_data)
    except InvalidTag as error:
        raise ManagedError(
            "DECRYPTION_AUTHENTICATION", "Ciphertext authentication failed."
        ) from error


def validate_logical_object(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "media_type",
        "object_id",
        "plain_digest",
        "plain_size",
        "role",
    }:
        raise schema_invalid()
    media_type = value["media_type"]
    plain_size = value["plain_size"]
    if (
        not isinstance(media_type, str)
        or not media_type
        or len(media_type) > 128
        or not valid_typed_id(value["object_id"], "object_id")
        or not valid_digest(value["plain_digest"])
        or type(plain_size) is not int
        or not 0 <= plain_size <= MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES
        or value["role"] not in _LOGICAL_OBJECT_ROLES
    ):
        raise schema_invalid()


def _require_one_manifest(
    objects: list[Mapping[str, object]], role: str, media_type: str
) -> Mapping[str, object]:
    matches = [
        value
        for value in objects
        if value["role"] == role and value["media_type"] == media_type
    ]
    if len(matches) != 1:
        raise schema_invalid()
    return matches[0]


def validate_managed_candidate_identity(value: object) -> None:
    """Mirror reproit-core ManagedCandidateIdentity::validate exactly."""
    if not isinstance(value, Mapping) or set(value) != {
        "candidate_digest",
        "capture_id",
        "deployment_digest",
        "format",
        "objects",
        "organization_id",
        "processing_mode",
        "project_id",
        "required_capabilities",
        "service_id",
        "subject_digest",
        "total_plaintext_bytes",
    }:
        raise schema_invalid()
    objects = value["objects"]
    if (
        value["format"] != CANDIDATE_IDENTITY_FORMAT
        or value["processing_mode"] != "managed"
        or not valid_digest(value["candidate_digest"])
        or not valid_digest(value["deployment_digest"])
        or not valid_digest(value["subject_digest"])
        or not valid_typed_id(value["capture_id"], "capture_id")
        or not valid_typed_id(value["organization_id"], "organization_id")
        or not valid_typed_id(value["project_id"], "project_id")
        or not valid_typed_id(value["service_id"], "service_id")
        or not isinstance(objects, list)
        or not 5 <= len(objects) <= MAX_CANDIDATE_OBJECTS
    ):
        raise schema_invalid()
    validate_capabilities(value["required_capabilities"])
    total_plaintext_bytes = 0
    roles = set()
    for index, entry in enumerate(objects):
        validate_logical_object(entry)
        if index > 0 and objects[index - 1]["object_id"] >= entry["object_id"]:
            raise schema_invalid()
        roles.add(entry["role"])
        total_plaintext_bytes += entry["plain_size"]
    if any(role not in roles for role in _REQUIRED_ROLES):
        raise schema_invalid()
    for role, media_type in _ROLE_MEDIA_TYPES:
        _require_one_manifest(objects, role, media_type)
    candidate = _require_one_manifest(objects, "candidate", CANDIDATE_MEDIA_TYPE)
    subject = _require_one_manifest(objects, "subject", SUBJECT_MANIFEST_MEDIA_TYPE)
    if (
        candidate["plain_digest"] != value["candidate_digest"]
        or candidate["plain_size"] > MAX_CANDIDATE_PLAINTEXT_BYTES
        or subject["plain_digest"] != value["subject_digest"]
        or total_plaintext_bytes != value["total_plaintext_bytes"]
        or total_plaintext_bytes > MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES
    ):
        raise schema_invalid()


def _validate_chunk(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "cipher_digest",
        "cipher_size",
        "index",
        "nonce",
    }:
        raise schema_invalid()
    cipher_size = value["cipher_size"]
    if (
        not valid_digest(value["cipher_digest"])
        or type(cipher_size) is not int
        or not 28 <= cipher_size <= MAX_CHUNK_BYTES + 28
        or type(value["index"]) is not int
        or not isinstance(value["nonce"], str)
        or len(value["nonce"]) != 16
    ):
        raise schema_invalid()
    decode_base64url(value["nonce"], 12)


def _validate_manifest_object(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "cipher_digest",
        "cipher_size",
        "nonce",
        "object_id",
    }:
        raise schema_invalid()
    cipher_size = value["cipher_size"]
    if (
        not valid_digest(value["cipher_digest"])
        or type(cipher_size) is not int
        or not 28 <= cipher_size <= MAX_CHUNK_BYTES + 28
        or not isinstance(value["nonce"], str)
        or len(value["nonce"]) != 16
        or not valid_typed_id(value["object_id"], "object_id")
    ):
        raise schema_invalid()
    decode_base64url(value["nonce"], 12)


def validate_ciphertext_identity(value: object) -> None:
    """Mirror ManagedCandidateCiphertextIdentity::validate exactly."""
    if not isinstance(value, Mapping) or set(value) != {
        "candidate_identity_digest",
        "candidate_key_reference",
        "capture_id",
        "cipher_suite",
        "format",
        "manifest_object",
        "objects",
        "organization_id",
        "processing_mode",
        "project_id",
        "required_capabilities",
        "service_id",
        "total_ciphertext_bytes",
    }:
        raise schema_invalid()
    objects = value["objects"]
    if (
        value["format"] != CIPHERTEXT_IDENTITY_FORMAT
        or value["cipher_suite"] != CIPHER_SUITE
        or value["processing_mode"] != "managed"
        or not valid_opaque_reference(value["candidate_key_reference"])
        or not valid_digest(value["candidate_identity_digest"])
        or not valid_typed_id(value["capture_id"], "capture_id")
        or not valid_typed_id(value["organization_id"], "organization_id")
        or not valid_typed_id(value["project_id"], "project_id")
        or not valid_typed_id(value["service_id"], "service_id")
        or not isinstance(objects, list)
        or not 5 <= len(objects) <= MAX_CANDIDATE_OBJECTS
        or not isinstance(value["required_capabilities"], list)
        or not value["required_capabilities"]
    ):
        raise schema_invalid()
    validate_capabilities(value["required_capabilities"])
    _validate_manifest_object(value["manifest_object"])
    nonces = {value["manifest_object"]["nonce"]}
    chunk_count = 1
    total_ciphertext_bytes = value["manifest_object"]["cipher_size"]
    roles = set()
    descriptors: list[Mapping[str, object]] = []
    for index, entry in enumerate(objects):
        if not isinstance(entry, Mapping) or set(entry) != {"chunks", "descriptor"}:
            raise schema_invalid()
        validate_logical_object(entry["descriptor"])
        descriptors.append(entry["descriptor"])
        if (
            index > 0
            and objects[index - 1]["descriptor"]["object_id"]
            >= entry["descriptor"]["object_id"]
        ):
            raise schema_invalid()
        chunks = entry["chunks"]
        if (
            not isinstance(chunks, list)
            or not 1 <= len(chunks) <= MAX_CANDIDATE_OBJECTS
        ):
            raise schema_invalid()
        roles.add(entry["descriptor"]["role"])
        chunk_count += len(chunks)
        for chunk_index, chunk in enumerate(chunks):
            _validate_chunk(chunk)
            if chunk["index"] != chunk_index or chunk["nonce"] in nonces:
                raise schema_invalid()
            nonces.add(chunk["nonce"])
            total_ciphertext_bytes += chunk["cipher_size"]
    if any(role not in roles for role in _REQUIRED_ROLES):
        raise schema_invalid()
    for role, media_type in _ROLE_MEDIA_TYPES:
        _require_one_manifest(descriptors, role, media_type)
    candidate_chunks = [
        entry["chunks"]
        for entry in objects
        if entry["descriptor"]["role"] == "candidate"
        and entry["descriptor"]["media_type"] == CANDIDATE_MEDIA_TYPE
    ]
    if len(candidate_chunks) != 1:
        raise schema_invalid()
    candidate_ciphertext_bytes = sum(
        chunk["cipher_size"] for chunk in candidate_chunks[0]
    )
    if (
        chunk_count > 32_768
        or total_ciphertext_bytes != value["total_ciphertext_bytes"]
        or total_ciphertext_bytes > MAX_TOTAL_CANDIDATE_CIPHERTEXT_BYTES
        or candidate_ciphertext_bytes > MAX_CANDIDATE_CIPHERTEXT_BYTES
        or any(
            entry["descriptor"]["object_id"] == value["manifest_object"]["object_id"]
            for entry in objects
        )
    ):
        raise schema_invalid()


def validate_capture_grant(value: object) -> None:
    """Mirror ManagedCandidateCaptureGrant::validate exactly."""
    if not isinstance(value, Mapping) or set(value) != {
        "candidate_identity_digest",
        "candidate_key_reference",
        "capture_id",
        "cipher_suite",
        "expires_at",
        "format",
        "grant_id",
        "not_before",
        "operation",
        "organization_id",
        "processing_mode",
        "project_id",
        "service_id",
        "signature",
        "signer_key_id",
    }:
        raise schema_invalid()
    signer_key_id = value["signer_key_id"]
    signature = value["signature"]
    if (
        value["format"] != CAPTURE_GRANT_FORMAT
        or value["cipher_suite"] != CIPHER_SUITE
        or value["operation"] != "encrypt-and-upload-candidate"
        or value["processing_mode"] != "managed"
        or not valid_opaque_reference(value["candidate_key_reference"])
        or not valid_opaque_reference(value["grant_id"])
        or not valid_digest(value["candidate_identity_digest"])
        or not valid_typed_id(value["capture_id"], "capture_id")
        or not valid_typed_id(value["organization_id"], "organization_id")
        or not valid_typed_id(value["project_id"], "project_id")
        or not valid_typed_id(value["service_id"], "service_id")
        or not isinstance(signer_key_id, str)
        or not signer_key_id
        or len(signer_key_id) > 256
        or not isinstance(signature, str)
        or len(signature) != 86
        or parse_timestamp(value["not_before"]) >= parse_timestamp(value["expires_at"])
    ):
        raise schema_invalid()
    decode_base64url(signature, 64)


def verify_capture_grant(
    grant: Mapping[str, object],
    expected: Mapping[str, object],
    now: str,
    public_key: bytes,
) -> None:
    """Mirror verify_managed_candidate_capture_grant exactly."""
    validate_capture_grant(grant)
    current_time = parse_timestamp(now)
    if (
        grant["candidate_identity_digest"] != expected["candidate_identity_digest"]
        or grant["candidate_key_reference"] != expected["candidate_key_reference"]
        or grant["capture_id"] != expected["capture_id"]
        or grant["organization_id"] != expected["organization_id"]
        or grant["project_id"] != expected["project_id"]
        or grant["service_id"] != expected["service_id"]
        or grant["signer_key_id"] != expected["signer_key_id"]
        or current_time < parse_timestamp(grant["not_before"])
        or current_time >= parse_timestamp(grant["expires_at"])
    ):
        raise ManagedError(
            "ATTESTATION_SCOPE",
            "The managed candidate capture grant does not match this capture.",
        )
    verify_signed_value(grant, public_key)


def validate_upload_request(value: object) -> None:
    """Mirror ManagedCandidateUploadRequest::validate exactly."""
    if not isinstance(value, Mapping) or set(value) != {
        "capture_grant",
        "ciphertext_identity",
        "encrypted_candidate_digest",
    }:
        raise schema_invalid()
    grant = value["capture_grant"]
    identity = value["ciphertext_identity"]
    validate_capture_grant(grant)
    validate_ciphertext_identity(identity)
    if (
        grant["candidate_identity_digest"] != identity["candidate_identity_digest"]
        or grant["candidate_key_reference"] != identity["candidate_key_reference"]
        or grant["capture_id"] != identity["capture_id"]
        or grant["organization_id"] != identity["organization_id"]
        or grant["project_id"] != identity["project_id"]
        or grant["service_id"] != identity["service_id"]
        or grant["processing_mode"] != identity["processing_mode"]
        or grant["cipher_suite"] != identity["cipher_suite"]
    ):
        raise ManagedError(
            "ATTESTATION_SCOPE",
            "The capture grant does not cover this ciphertext identity.",
        )
    if canonical_digest(identity) != value["encrypted_candidate_digest"]:
        raise object_digest_mismatch()


def parse_strict_json(value: bytes, maximum_bytes: int) -> object:
    """Parse bounded JSON and reject duplicate keys, NaN, and trailing data."""
    if len(value) > maximum_bytes:
        raise schema_invalid()

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, entry in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = entry
        return result

    try:
        return json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise schema_invalid() from error


def _reject_constant(_value: str) -> object:
    raise ValueError("non-finite numbers are not protocol JSON")
