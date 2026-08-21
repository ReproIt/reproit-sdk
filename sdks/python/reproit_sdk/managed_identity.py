"""Protected local state for one managed workload identity.

The state binds one Ed25519 key, one stable deployment signing time, and one
non-secret Cloud registration receipt to an exact deployment.
"""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass

from reproit_sdk import canonical_bytes

from .managed_protocol import (
    ManagedError,
    canonical_digest,
    digest_bytes,
    parse_strict_json,
    require_typed_id,
    sign_bytes,
    valid_digest,
    valid_timestamp,
    verification_key,
)

WORKLOAD_KEY_BYTES = 32
MAX_MANAGED_DEPLOYMENT_METADATA_BYTES = 256
MAX_MANAGED_WORKLOAD_RECEIPT_BYTES = 512

_WORKLOAD_KEY_FILE = "workload.key"
_DEPLOYMENT_METADATA_FILE = "deployment.json"
_REGISTRATION_RECEIPT_FILE = "registration.json"

__all__ = [
    "MAX_MANAGED_DEPLOYMENT_METADATA_BYTES",
    "MAX_MANAGED_WORKLOAD_RECEIPT_BYTES",
    "ManagedWorkloadIdentityState",
    "ManagedWorkloadRegistrationReceipt",
    "WORKLOAD_KEY_BYTES",
    "load_or_create_managed_workload_key",
    "managed_deployment_binding_digest",
    "managed_workload_key_id",
    "sign_bytes",
    "verification_key",
]


@dataclass(frozen=True)
class ManagedWorkloadRegistrationReceipt:
    """A non-secret receipt for one exact Cloud registration."""

    deployment_digest: str
    service_id: str
    workload_key_id: str

    def value(self) -> dict[str, str]:
        result = {
            "deployment_digest": self.deployment_digest,
            "service_id": self.service_id,
            "workload_key_id": self.workload_key_id,
        }
        _validate_receipt(result)
        return result


class ManagedWorkloadIdentityState:
    """Protected files for one stable managed deployment binding."""

    def __init__(self, directory: str):
        self._directory = directory

    @classmethod
    def from_state_root(
        cls, state_root: str, binding_digest: str
    ) -> ManagedWorkloadIdentityState:
        _validate_digest(binding_digest)
        _ensure_state_root(state_root)
        reproit = os.path.join(state_root, "reproit")
        _ensure_private_directory(reproit)
        workloads = os.path.join(reproit, "workloads")
        _ensure_private_directory(workloads)
        directory = os.path.join(workloads, binding_digest)
        _ensure_private_directory(directory)
        return cls(directory)

    @property
    def directory(self) -> str:
        return self._directory

    def load_or_create_key(self) -> bytes:
        _validate_private_directory(self._directory)
        return load_or_create_managed_workload_key(
            os.path.join(self._directory, _WORKLOAD_KEY_FILE)
        )

    def load_or_create_deployment_signed_at(
        self, binding_digest: str, proposed_signed_at: str
    ) -> str:
        _validate_digest(binding_digest)
        if not valid_timestamp(proposed_signed_at):
            raise _deployment_metadata_invalid()
        expected = {
            "binding_digest": binding_digest,
            "format": 1,
            "signed_at": proposed_signed_at,
        }
        path = os.path.join(self._directory, _DEPLOYMENT_METADATA_FILE)
        stored = _read_json_if_present(
            path,
            MAX_MANAGED_DEPLOYMENT_METADATA_BYTES,
            _deployment_metadata_invalid,
        )
        if stored is not None:
            _validate_deployment_metadata(stored)
            if stored["binding_digest"] != binding_digest:
                raise _deployment_metadata_scope_mismatch()
            return stored["signed_at"]
        created = _atomic_create(path, canonical_bytes(expected))
        if created:
            return proposed_signed_at
        stored = _read_json(
            path,
            MAX_MANAGED_DEPLOYMENT_METADATA_BYTES,
            _deployment_metadata_invalid,
        )
        _validate_deployment_metadata(stored)
        if stored["binding_digest"] != binding_digest:
            raise _deployment_metadata_scope_mismatch()
        return stored["signed_at"]

    def load_registration_receipt(
        self, expected: ManagedWorkloadRegistrationReceipt
    ) -> ManagedWorkloadRegistrationReceipt | None:
        expected_value = expected.value()
        path = os.path.join(self._directory, _REGISTRATION_RECEIPT_FILE)
        stored = _read_json_if_present(
            path,
            MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
            _receipt_invalid,
        )
        if stored is None:
            return None
        _validate_receipt(stored)
        if stored != expected_value:
            raise _receipt_scope_mismatch()
        return expected

    def persist_registration_receipt(
        self, receipt: ManagedWorkloadRegistrationReceipt
    ) -> None:
        value = receipt.value()
        encoded = canonical_bytes(value)
        if not encoded or len(encoded) > MAX_MANAGED_WORKLOAD_RECEIPT_BYTES:
            raise _receipt_invalid()
        path = os.path.join(self._directory, _REGISTRATION_RECEIPT_FILE)
        stored = _read_json_if_present(
            path,
            MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
            _receipt_invalid,
        )
        if stored is not None:
            _validate_receipt(stored)
            if stored != value:
                raise _receipt_scope_mismatch()
            return
        if _atomic_create(path, encoded):
            return
        stored = _read_json(
            path,
            MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
            _receipt_invalid,
        )
        _validate_receipt(stored)
        if stored != value:
            raise _receipt_scope_mismatch()


def managed_workload_key_id(public_key: bytes) -> str:
    """Derive the canonical identity for one Ed25519 public key."""
    from .managed_protocol import encode_base64url

    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise _key_store_invalid()
    return "managed-workload-" + digest_bytes(
        encode_base64url(public_key).encode("ascii")
    )


def managed_deployment_binding_digest(deployment: dict[str, object]) -> str:
    """Bind all deployment fields except its mutable signing state."""
    expected = {
        "format",
        "organization_id",
        "processing_mode",
        "project_id",
        "repository_id",
        "runtime_capabilities",
        "runtime_endpoint",
        "service_id",
        "service_path",
        "signature",
        "signed_at",
        "signer_key_id",
        "source_revision",
        "subject",
    }
    if set(deployment) != expected or deployment.get("processing_mode") != "managed":
        raise _deployment_metadata_invalid()
    stable = {
        key: value
        for key, value in deployment.items()
        if key not in {"signature", "signed_at", "signer_key_id"}
    }
    return canonical_digest(stable)


def load_or_create_managed_workload_key(path: str) -> bytes:
    """Create or load the 32-byte managed workload signing key at path."""
    parent = os.path.dirname(path)
    if not parent:
        raise _key_store_invalid()
    _validate_parent(parent)
    try:
        return _read_key(path, parent)
    except FileNotFoundError:
        pass
    key = os.urandom(WORKLOAD_KEY_BYTES)
    if _atomic_create(path, key):
        return key
    return _read_key(path, parent)


def _read_key(path: str, parent: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise _key_store_unavailable() from error
    try:
        _validate_open_file(path, parent, descriptor, WORKLOAD_KEY_BYTES)
        key = os.read(descriptor, WORKLOAD_KEY_BYTES)
        trailing = os.read(descriptor, 1)
    except OSError as error:
        raise _key_store_unavailable() from error
    finally:
        os.close(descriptor)
    if len(key) != WORKLOAD_KEY_BYTES or trailing:
        raise _key_store_invalid()
    return key


def _ensure_state_root(path: str) -> None:
    if (
        not isinstance(path, str)
        or not os.path.isabs(path)
        or os.path.normpath(path) != path
    ):
        raise _state_root_invalid()
    current = os.path.sep
    for component in path.removeprefix(os.path.sep).split(os.path.sep):
        if not component:
            continue
        current = os.path.join(current, component)
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
            except OSError as error:
                raise _state_root_unavailable() from error
            continue
        except OSError as error:
            raise _state_root_unavailable() from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise _state_root_invalid()
    _validate_parent(path)


def _ensure_private_directory(path: str) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise _state_root_unavailable() from error
    _validate_private_directory(path)


def _validate_private_directory(path: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise _state_root_invalid() from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _state_root_invalid()


def _validate_parent(parent: str) -> None:
    try:
        metadata = os.lstat(parent)
    except OSError as error:
        raise _key_store_invalid() from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise _key_store_invalid()
    if metadata.st_mode & 0o022 != 0:
        raise _key_store_invalid()


def _validate_open_file(
    path: str, parent: str, descriptor: int, expected_size: int | None = None
) -> None:
    metadata = os.fstat(descriptor)
    path_metadata = os.lstat(path)
    parent_metadata = os.stat(parent)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not stat.S_ISREG(path_metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or metadata.st_dev != path_metadata.st_dev
        or metadata.st_ino != path_metadata.st_ino
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != parent_metadata.st_uid
        or (expected_size is not None and metadata.st_size != expected_size)
    ):
        raise _key_store_invalid()


def _atomic_create(path: str, value: bytes) -> bool:
    parent = os.path.dirname(path)
    _validate_parent(parent)
    temporary = os.path.join(
        parent,
        f".{os.path.basename(path)}.{secrets.token_hex(12)}.pending",
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                raise OSError("short write")
            written += count
        os.fsync(descriptor)
        _validate_open_file(temporary, parent, descriptor, len(value))
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path)
            created = True
        except FileExistsError:
            created = False
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return created
    except ManagedError:
        raise
    except OSError as error:
        raise _key_store_unavailable() from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _read_json_if_present(path: str, maximum: int, error_factory):
    try:
        return _read_json(path, maximum, error_factory)
    except FileNotFoundError:
        return None


def _read_json(path: str, maximum: int, error_factory):
    parent = os.path.dirname(path)
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise error_factory() from error
    try:
        metadata = os.fstat(descriptor)
        if not 1 <= metadata.st_size <= maximum:
            raise error_factory()
        _validate_open_file(path, parent, descriptor, metadata.st_size)
        value = os.read(descriptor, maximum + 1)
    except ManagedError:
        raise
    except OSError as error:
        raise error_factory() from error
    finally:
        os.close(descriptor)
    try:
        parsed = parse_strict_json(value, maximum)
        if canonical_bytes(parsed) != value:
            raise error_factory()
        return parsed
    except ManagedError as error:
        raise error_factory() from error


def _validate_deployment_metadata(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"binding_digest", "format", "signed_at"}
        or value["format"] != 1
        or not valid_digest(value["binding_digest"])
        or not valid_timestamp(value["signed_at"])
    ):
        raise _deployment_metadata_invalid()


def _validate_receipt(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"deployment_digest", "service_id", "workload_key_id"}
        or not valid_digest(value["deployment_digest"])
        or not _valid_workload_key_id(value["workload_key_id"])
    ):
        raise _receipt_invalid()
    try:
        require_typed_id(value["service_id"], "service_id")
    except ManagedError as error:
        raise _receipt_invalid() from error


def _validate_digest(value: str) -> None:
    if not valid_digest(value):
        raise _deployment_metadata_invalid()


def _valid_workload_key_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("managed-workload-sha256:")
        and len(value) == 88
        and all(character in "0123456789abcdef" for character in value[24:])
    )


def _key_store_invalid() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT", "The managed workload key file is not private or valid."
    )


def _key_store_unavailable() -> ManagedError:
    return ManagedError(
        "SERVICE_UNAVAILABLE", "The managed workload key file is unavailable."
    )


def _state_root_invalid() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT",
        "The managed workload state directory is not private or valid.",
    )


def _state_root_unavailable() -> ManagedError:
    return ManagedError(
        "SERVICE_UNAVAILABLE", "The managed workload state directory is unavailable."
    )


def _deployment_metadata_invalid() -> ManagedError:
    return ManagedError("CONFIG_CONFLICT", "The managed deployment state is not valid.")


def _deployment_metadata_scope_mismatch() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT", "The managed deployment state belongs to another deployment."
    )


def _receipt_invalid() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT", "The managed workload registration receipt is not valid."
    )


def _receipt_scope_mismatch() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT",
        "The managed workload registration receipt belongs to another deployment.",
    )
