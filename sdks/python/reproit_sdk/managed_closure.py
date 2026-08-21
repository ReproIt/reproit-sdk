"""The static managed capture closure: world binding and frozen artifacts.

Mirrors the closure half of crates/reproit-sdk-rust/src/managed.rs: the
world checkpoint shape the SDK consumes, the static artifact set proof,
dependency-transcript validation, and freezing artifact bytes into a
private spool so they cannot change between proof and upload.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

from reproit_sdk import canonical_bytes

from .managed_protocol import (
    DEPENDENCY_TRANSCRIPT_MEDIA_TYPE,
    MAX_CHUNK_BYTES,
    ManagedError,
    canonical_digest,
    incomplete_candidate,
    new_object_id,
    parse_strict_json,
    schema_invalid,
    valid_digest,
    valid_timestamp,
    valid_typed_id,
)

MAX_CAPTURE_ARTIFACT_BYTES = 274_878_824_448
MAX_WORLD_MANIFEST_BYTES = 262_144
COPY_BUFFER_BYTES = 64 * 1024

ARTIFACT_ROLES = frozenset(("dependency-transcript", "world-state"))


@dataclass(frozen=True)
class ManagedCandidateArtifact:
    media_type: str
    object_id: str
    path: str
    role: str
    uri: str


@dataclass
class ManagedCaptureClosure:
    """The static capture closure the application proves before upload."""

    artifacts: list[ManagedCandidateArtifact]
    completion: str
    world: dict[str, object]


class FrozenManagedCaptureClosure:
    """A capture closure whose artifact bytes are frozen in a private spool."""

    def __init__(self, closure: ManagedCaptureClosure):
        validate_world_checkpoint(closure.world)
        validate_static_artifact_set(closure.world, closure.artifacts)
        self._spool: tempfile.TemporaryDirectory | None = None
        artifacts = closure.artifacts
        if artifacts:
            self._spool = tempfile.TemporaryDirectory(prefix="reproit-managed-world-")
            artifacts = [
                _freeze_artifact(artifact, self._spool.name)
                for artifact in closure.artifacts
            ]
        validate_static_artifact_set(closure.world, artifacts)
        self.closure = ManagedCaptureClosure(
            artifacts, closure.completion, closure.world
        )

    def world_id(self) -> str:
        validate_world_checkpoint(self.closure.world)
        return canonical_digest(self.closure.world)


def validate_world_checkpoint(value: object) -> None:
    """Validate the bounded world checkpoint shape the SDK consumes."""
    if (
        not isinstance(value, Mapping)
        or set(value) != {"created_at", "format", "points"}
        or value["format"] != "reproit.world-checkpoint.v1"
        or not valid_timestamp(value["created_at"])
        or not isinstance(value["points"], list)
        or len(value["points"]) > 64
    ):
        raise schema_invalid()
    providers = set()
    for point in value["points"]:
        if (
            not isinstance(point, Mapping)
            or point.get("format") != "reproit.recoverable-point.v1"
            or not isinstance(point.get("provider_id"), str)
            or not isinstance(point.get("artifacts"), list)
            or len(point["artifacts"]) > 32_767
            or point["provider_id"] in providers
        ):
            raise schema_invalid()
        providers.add(point["provider_id"])
        for artifact in point["artifacts"]:
            if (
                not isinstance(artifact, Mapping)
                or not valid_digest(artifact.get("digest"))
                or type(artifact.get("size")) is not int
                or artifact["size"] < 0
                or not isinstance(artifact.get("uri"), str)
                or not artifact["uri"]
                or len(artifact["uri"]) > 2_048
                or not isinstance(artifact.get("media_type"), str)
            ):
                raise schema_invalid()
    if len(canonical_bytes(value)) > MAX_WORLD_MANIFEST_BYTES:
        raise schema_invalid()


def expected_world_artifacts(
    world: Mapping[str, object],
) -> set[tuple[str, str, int, str]]:
    return {
        (artifact["uri"], artifact["digest"], artifact["size"], artifact["media_type"])
        for point in world["points"]
        for artifact in point["artifacts"]
    }


def validate_static_artifact_set(
    world: Mapping[str, object], artifacts: list[ManagedCandidateArtifact]
) -> None:
    if len(artifacts) > 32_767:
        raise incomplete_candidate()
    expected_world = expected_world_artifacts(world)
    supplied_world = {
        artifact.uri for artifact in artifacts if artifact.role == "world-state"
    }
    if len(expected_world) != len(supplied_world) or any(
        uri not in supplied_world for uri, _, _, _ in expected_world
    ):
        raise incomplete_candidate()
    object_ids: set[str] = set()
    uris: set[str] = set()
    for artifact in artifacts:
        if (
            artifact.role not in ARTIFACT_ROLES
            or not artifact.uri
            or len(artifact.uri) > 2_048
            or not artifact.media_type
            or len(artifact.media_type) > 256
            or artifact.object_id in object_ids
            or artifact.uri in uris
        ):
            raise incomplete_candidate()
        object_ids.add(artifact.object_id)
        uris.add(artifact.uri)
        size, digest = hash_file(artifact.path)
        if (
            artifact.role == "world-state"
            and (
                artifact.uri,
                digest,
                size,
                artifact.media_type,
            )
            not in expected_world
        ):
            raise incomplete_candidate()
        if (
            artifact.role == "dependency-transcript"
            and artifact.media_type == DEPENDENCY_TRANSCRIPT_MEDIA_TYPE
        ):
            if size > MAX_CHUNK_BYTES:
                raise incomplete_candidate()
            validate_transcript_bytes(read_bounded(artifact.path, size))


def validate_transcript_bytes(value: bytes) -> dict[str, object]:
    """Mirror the DependencyTranscript strict parse and validation."""
    parsed = parse_strict_json(value, MAX_CHUNK_BYTES)
    if (
        not isinstance(parsed, dict)
        or canonical_bytes(parsed) != value
        or set(parsed) != {"adapter_id", "adapter_version", "format", "interactions"}
        or parsed["format"] != "reproit.dependency-transcript.v1"
    ):
        raise schema_invalid()
    adapter_id = parsed["adapter_id"]
    adapter_version = parsed["adapter_version"]
    interactions = parsed["interactions"]
    if (
        not isinstance(adapter_id, str)
        or not adapter_id
        or len(adapter_id) > 128
        or not isinstance(adapter_version, str)
        or not adapter_version
        or len(adapter_version) > 64
        or not isinstance(interactions, list)
        or not 1 <= len(interactions) <= 1_024
    ):
        raise schema_invalid()
    for index, interaction in enumerate(interactions):
        _validate_interaction(interaction, index)
    return parsed


def _validate_interaction(interaction: object, index: int) -> None:
    if (
        not isinstance(interaction, Mapping)
        or set(interaction)
        != {
            "causal_parent_id",
            "operation_id",
            "outcome",
            "request_digest",
            "request_object_id",
            "response_digest",
            "response_object_id",
            "sequence",
            "session_position",
        }
        or interaction["sequence"] != index
        or not valid_typed_id(interaction["operation_id"], "operation_id")
        or not (
            interaction["causal_parent_id"] is None
            or valid_typed_id(interaction["causal_parent_id"], "operation_id")
        )
        or not valid_digest(interaction["request_digest"])
        or not valid_digest(interaction["response_digest"])
        or not valid_typed_id(interaction["request_object_id"], "object_id")
        or not valid_typed_id(interaction["response_object_id"], "object_id")
        or type(interaction["session_position"]) is not int
        or not 0 <= interaction["session_position"] <= 9_007_199_254_740_991
    ):
        raise schema_invalid()


def _freeze_artifact(
    artifact: ManagedCandidateArtifact, spool_path: str
) -> ManagedCandidateArtifact:
    metadata = artifact_metadata(artifact.path)
    temporary = os.path.join(spool_path, f"artifact-{new_object_id()}")
    first_digest, copied = _copy_and_digest(artifact.path, temporary, metadata.st_size)
    second_digest, verified = _digest_file(artifact.path, metadata.st_size)
    if first_digest != second_digest or copied != verified:
        raise incomplete_candidate()
    frozen_path = os.path.join(spool_path, first_digest.removeprefix("sha256:"))
    if os.path.exists(frozen_path):
        stored_digest, stored_size = _digest_file(frozen_path, copied)
        if stored_digest != first_digest or stored_size != copied:
            raise ManagedError(
                "OBJECT_DIGEST_MISMATCH",
                "The object bytes do not match the bound digest.",
            )
        os.remove(temporary)
    else:
        os.replace(temporary, frozen_path)
    return ManagedCandidateArtifact(
        artifact.media_type,
        artifact.object_id,
        frozen_path,
        artifact.role,
        artifact.uri,
    )


def artifact_metadata(path: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise incomplete_candidate() from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size > MAX_CAPTURE_ARTIFACT_BYTES
    ):
        raise incomplete_candidate()
    return metadata


def _copy_and_digest(source: str, target: str, expected: int) -> tuple[str, int]:
    hasher = hashlib.sha256()
    total = 0
    try:
        with open(source, "rb") as reader, open(target, "wb") as writer:
            while True:
                chunk = reader.read(COPY_BUFFER_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected:
                    raise incomplete_candidate()
                hasher.update(chunk)
                writer.write(chunk)
            writer.flush()
    except OSError as error:
        raise ManagedError(
            "SERVICE_UNAVAILABLE",
            "Repro It could not create the bounded local ciphertext staging area.",
        ) from error
    if total != expected:
        raise incomplete_candidate()
    return f"sha256:{hasher.hexdigest()}", total


def _digest_file(path: str, expected: int) -> tuple[str, int]:
    hasher = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as reader:
            while True:
                chunk = reader.read(COPY_BUFFER_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected:
                    raise incomplete_candidate()
                hasher.update(chunk)
    except OSError as error:
        raise incomplete_candidate() from error
    if total != expected:
        raise incomplete_candidate()
    return f"sha256:{hasher.hexdigest()}", total


def read_bounded(path: str, expected: int) -> bytes:
    try:
        with open(path, "rb") as source:
            value = source.read(expected + 1)
    except OSError as error:
        raise incomplete_candidate() from error
    if len(value) != expected:
        raise incomplete_candidate()
    return value


def hash_file(path: str) -> tuple[int, str]:
    """Hash a stable regular file, failing closed if it changes underneath."""
    before = artifact_metadata(path)
    digest, size = _digest_file(path, before.st_size)
    after = artifact_metadata(path)
    if after.st_size != size or after.st_mtime_ns != before.st_mtime_ns:
        raise incomplete_candidate()
    return size, digest
