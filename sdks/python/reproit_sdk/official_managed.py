"""Immutable managed Cloud bindings for the released Python SDK."""

from __future__ import annotations

import copy
import os
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .managed_candidate import FrozenManagedCaptureClosure, ManagedCaptureClosure
from .managed_protocol import ManagedError, decode_base64url
from .managed_sink import (
    ManagedCandidateSink,
    ManagedSinkConfiguration,
)
from .managed_subject import PythonSubjectPackage
from .managed_transport import ManagedProjectToken, ManagedTlsClient, ManagedTlsEndpoint

_FIXTURE_CAPTURE_SIGNER_PUBLIC_KEYS = frozenset(
    (
        "1238bj1eePRsVOlCHJedzcDZ0DmBthqGWrICsYCNzpA",
        "Pm6nrLpZVoxfNqy0GBb7FqsrJ6sTq9OLCSTKJpGtZZk",
        "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI",
        "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY",
        "p_bfr484uJuozmSbWU-R5NAf3Ff5yUk99DteUKmYc2c",
    )
)

OFFICIAL_MANAGED_HTTPS_ORIGIN = "__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__"
OFFICIAL_CAPTURE_GRANT_SIGNER_ID = (
    "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_ID_SENTINEL__"
)
OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY = (
    "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY_SENTINEL__"
)


@dataclass(frozen=True)
class OfficialManagedConfiguration:
    """The immutable managed Cloud configuration in one released SDK."""

    capture_signer_id: str
    capture_signer_public_key: bytes
    client: ManagedTlsClient
    managed_origin: str


@dataclass(frozen=True)
class OfficialManagedOperation:
    """Own the identifiers and deployment for one managed operation."""

    capture_id: str
    operation_id: str
    world_id: str
    _deployment: dict[str, object]

    def candidate_sink(
        self,
        closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
        project_token_provider: Callable[[], ManagedProjectToken],
        *,
        subject: PythonSubjectPackage | None = None,
    ) -> ManagedCandidateSink:
        """Bind one complete closure to the installed official package."""
        sink, deployment = _official_managed_candidate_sink(
            closure,
            self._deployment,
            project_token_provider,
            subject=subject,
            operation_id=self.operation_id,
        )
        self._deployment.clear()
        self._deployment.update(deployment)
        return sink

    @property
    def deployment(self) -> dict[str, object]:
        """Return the deployment that the official sink bound."""
        return self._deployment


@dataclass(frozen=True)
class OfficialManagedProject:
    """Bind one reviewed project to an installed official SDK package."""

    _project: dict[str, object]
    _source_revision: str

    @classmethod
    def from_build(
        cls,
        project: Mapping[str, object],
        build_repository_id: str,
        source_revision: str,
    ) -> OfficialManagedProject:
        """Validate the release and exact reviewed build binding."""
        official_managed_configuration()
        copied = copy.deepcopy(dict(project))
        _validate_project(copied, build_repository_id, source_revision)
        return cls(copied, source_revision)

    def start_operation(self, world_id: str) -> OfficialManagedOperation:
        """Create one package-owned operation identity without network work."""
        if not isinstance(world_id, str) or not world_id.startswith("sha256:"):
            raise _project_binding_invalid()
        return OfficialManagedOperation(
            capture_id=f"cap_{uuid.uuid7()}",
            operation_id=f"op_{uuid.uuid7()}",
            world_id=world_id,
            _deployment=_deployment(self._project, self._source_revision),
        )


def official_managed_configuration() -> OfficialManagedConfiguration:
    """Load and validate the immutable managed release binding."""
    _reject_unbound_release()
    _validate_signer_id(OFFICIAL_CAPTURE_GRANT_SIGNER_ID)
    try:
        capture_signer_public_key = decode_base64url(
            OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY, 32
        )
    except ManagedError as error:
        raise _release_binding_invalid() from error
    if (
        not any(capture_signer_public_key)
        or OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY
        in _FIXTURE_CAPTURE_SIGNER_PUBLIC_KEYS
    ):
        raise _release_binding_invalid()
    try:
        endpoint = ManagedTlsEndpoint.official(OFFICIAL_MANAGED_HTTPS_ORIGIN)
    except ManagedError as error:
        raise _release_binding_invalid() from error
    return OfficialManagedConfiguration(
        capture_signer_id=OFFICIAL_CAPTURE_GRANT_SIGNER_ID,
        capture_signer_public_key=capture_signer_public_key,
        client=ManagedTlsClient(endpoint, endpoint),
        managed_origin=OFFICIAL_MANAGED_HTTPS_ORIGIN,
    )


def official_managed_candidate_sink(
    closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
    deployment: dict[str, object],
    project_token_provider: Callable[[], ManagedProjectToken],
    *,
    subject: PythonSubjectPackage | None = None,
    operation_id: str | None = None,
) -> ManagedCandidateSink:
    """Create the official framework-neutral and container-neutral managed sink."""
    sink, _ = _official_managed_candidate_sink(
        closure,
        deployment,
        project_token_provider,
        subject=subject,
        operation_id=operation_id,
    )
    return sink


def _official_managed_candidate_sink(
    closure: ManagedCaptureClosure | FrozenManagedCaptureClosure,
    deployment: dict[str, object],
    project_token_provider: Callable[[], ManagedProjectToken],
    *,
    subject: PythonSubjectPackage | None,
    operation_id: str | None,
) -> tuple[ManagedCandidateSink, dict[str, object]]:
    configuration = official_managed_configuration()
    bound_deployment = copy.deepcopy(deployment)
    bound_deployment["runtime_endpoint"] = configuration.managed_origin
    sink = ManagedCandidateSink(
        configuration.client,
        closure,
        ManagedSinkConfiguration(
            capture_signer_id=configuration.capture_signer_id,
            capture_signer_public_key=configuration.capture_signer_public_key,
            project_token=project_token_provider,
            service_id=_service_id(bound_deployment),
            workload_state_root=_protected_state_root(),
        ),
        subject=subject,
        operation_id=operation_id,
    )
    sink.bind_deployment(bound_deployment)
    return sink, bound_deployment


def _validate_project(
    project: dict[str, object], build_repository_id: str, source_revision: str
) -> None:
    required = {
        "format": 1,
        "profile": "backend",
        "profile_format": 1,
        "processing_mode": "managed",
        "sdk": "python",
    }
    service_path = project.get("service_path")
    if (
        any(project.get(name) != value for name, value in required.items())
        or project.get("repository_id") != build_repository_id
        or not _valid_revision(source_revision)
        or not isinstance(service_path, str)
        or not service_path
        or service_path.startswith("/")
        or any(part == ".." for part in service_path.split("/"))
    ):
        raise _project_binding_invalid()
    for name in ("organization_id", "project_id", "service_id"):
        value = project.get(name)
        if not isinstance(value, str):
            raise _project_binding_invalid()


def _deployment(project: dict[str, object], source_revision: str) -> dict[str, object]:
    return {
        "format": "reproit.deployment.v1",
        "organization_id": project["organization_id"],
        "processing_mode": "managed",
        "project_id": project["project_id"],
        "repository_id": project["repository_id"],
        "runtime_capabilities": ["runtime.python-native"],
        "runtime_endpoint": "pending-official-managed-origin",
        "service_id": project["service_id"],
        "service_path": project["service_path"],
        "signature": "A" * 86,
        "signed_at": "1970-01-01T00:00:00.000Z",
        "signer_key_id": "pending-managed-registration",
        "source_revision": source_revision,
        "subject": {},
    }


def _valid_revision(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) in (40, 64)
        and all(character in "0123456789abcdef" for character in value)
    )


def _service_id(deployment: dict[str, object]) -> str:
    service_id = deployment.get("service_id")
    if not isinstance(service_id, str):
        raise _release_binding_invalid()
    return service_id


def _protected_state_root() -> str:
    if sys.platform != "linux":
        raise ManagedError(
            "UNSUPPORTED",
            "The managed Python capture path requires a supported Linux "
            "application host.",
        )
    configured = os.environ.get("XDG_STATE_HOME")
    if configured:
        state_root = configured
    else:
        home = os.environ.get("HOME")
        if not home:
            raise _state_root_invalid()
        state_root = os.path.join(home, ".local", "state")
    if not os.path.isabs(state_root) or os.path.normpath(state_root) != state_root:
        raise _state_root_invalid()
    return state_root


def _reject_unbound_release() -> None:
    values = (
        OFFICIAL_MANAGED_HTTPS_ORIGIN,
        OFFICIAL_CAPTURE_GRANT_SIGNER_ID,
        OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY,
    )
    if any(_is_release_sentinel(value) for value in values):
        raise ManagedError(
            "CONFIG_CONFLICT",
            "This Repro It SDK has no official managed release binding.",
        )


def _is_release_sentinel(value: str) -> bool:
    return value.startswith("__REPROIT_OFFICIAL_") and value.endswith("_SENTINEL__")


def _validate_signer_id(value: str) -> None:
    if (
        not value
        or len(value) > 256
        or not all(
            character.isascii() and (character.isalnum() or character in "-_.:")
            for character in value
        )
    ):
        raise _release_binding_invalid()


def _release_binding_invalid() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT", "The official managed release binding is invalid."
    )


def _project_binding_invalid() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT", "The managed project build binding is invalid."
    )


def _state_root_invalid() -> ManagedError:
    return ManagedError(
        "CONFIG_CONFLICT", "The protected managed state directory is invalid."
    )
