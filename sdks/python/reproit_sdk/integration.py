"""Framework-neutral managed capture for Python applications."""

from __future__ import annotations

import copy
import hashlib
import os
import subprocess
import tomllib
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import CandidateStart, Sdk, canonical_bytes
from .managed_candidate import ManagedCaptureClosure
from .managed_protocol import digest_bytes, encode_base64url
from .managed_transport import ManagedProjectToken
from .official_managed import OfficialManagedOperation, OfficialManagedProject

MAX_CAPTURED_INPUT_BYTES = 32 * 1_024
MAX_CONTENT_TYPE_BYTES = 256
MAX_DEPENDENCIES = 1_024
MAX_EVENT_BYTES = 65_536
MAX_OPERATION_NAME_BYTES = 128
MAX_PROJECT_CONFIG_BYTES = 65_536
MAX_PROJECT_SEARCH_DEPTH = 64


@dataclass(frozen=True)
class ManagedWorldCapture:
    """Hold one initial World ID and its completion operation."""

    world_id: str
    complete: Callable[[str], ManagedCaptureClosure]


@dataclass
class OperationCapture:
    """Record dependency cursors for one application operation."""

    operation_id: str | None
    _dependencies: list[Mapping[str, Any]] = field(default_factory=list)
    _valid: bool = True

    def record_dependency(self, dependency: Mapping[str, Any]) -> None:
        """Record one bounded dependency cursor without changing application behavior."""
        if not self._valid:
            return
        try:
            copied = copy.deepcopy(dict(dependency))
            if (
                len(self._dependencies) >= MAX_DEPENDENCIES
                or len(canonical_bytes(copied)) > MAX_EVENT_BYTES
            ):
                self._valid = False
                self._dependencies.clear()
                return
            self._dependencies.append(copied)
        except Exception:
            self._valid = False
            self._dependencies.clear()


class ReproIt:
    """Capture application operations through the official managed SDK entry."""

    def __init__(
        self,
        project: Mapping[str, object],
        build_repository_id: str,
        source_revision: str,
        world_capture: Callable[[], ManagedWorldCapture],
    ) -> None:
        self._project = OfficialManagedProject.from_build(
            project, build_repository_id, source_revision
        )
        self._world_capture = world_capture

    @classmethod
    def init(cls) -> ReproIt:
        """Load the reviewed project configuration without changing the application."""
        instance = object.__new__(cls)
        instance._project = None
        instance._world_capture = _automatic_world_capture
        try:
            project_file = _find_project_file(Path.cwd())
            if (
                project_file.parent.is_symlink()
                or project_file.is_symlink()
                or project_file.stat().st_size > MAX_PROJECT_CONFIG_BYTES
            ):
                return instance
            project = tomllib.loads(project_file.read_text(encoding="utf-8"))
            repository_id = project.get("repository_id")
            if not isinstance(repository_id, str):
                return instance
            revision = _git_source_revision(project_file.parent.parent)
            instance._project = OfficialManagedProject.from_build(
                project, repository_id, revision
            )
        except Exception:
            pass
        return instance

    def operation(
        self,
        operation_name: str,
        input_bytes: bytes,
        operation: Callable[[], Any],
    ) -> Any:
        """Run one framework-neutral operation and preserve its exact result."""
        return self.run(
            operation_name,
            "application/octet-stream",
            input_bytes,
            lambda _capture: operation(),
            lambda error: _failure_payload(
                "exception", operation_name, type(error).__name__
            ),
        )

    async def operation_async(
        self,
        operation_name: str,
        input_bytes: bytes,
        operation: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Run one asynchronous framework-neutral operation."""
        return await self.run_async(
            operation_name,
            "application/octet-stream",
            input_bytes,
            lambda _capture: operation(),
            lambda error: _failure_payload(
                "exception", operation_name, type(error).__name__
            ),
        )

    def run(
        self,
        operation_name: str,
        content_type: str,
        input_bytes: bytes,
        operation: Callable[[OperationCapture], Any],
        classify_failure: Callable[[BaseException], Mapping[str, Any] | None],
        *,
        operation_kind: str = "request-response",
    ) -> Any:
        """Run one operation and preserve its exact return or exception."""
        active = self._start(operation_kind, operation_name, content_type, input_bytes)
        context = active.context if active is not None else OperationCapture(None)
        try:
            result = operation(context)
        except BaseException as original:
            self._capture_failure(active, original, classify_failure)
            raise
        return result

    async def run_async(
        self,
        operation_name: str,
        content_type: str,
        input_bytes: bytes,
        operation: Callable[[OperationCapture], Awaitable[Any]],
        classify_failure: Callable[[BaseException], Mapping[str, Any] | None],
        *,
        operation_kind: str = "request-response",
    ) -> Any:
        """Run one asynchronous operation and preserve its exact result."""
        active = self._start(operation_kind, operation_name, content_type, input_bytes)
        context = active.context if active is not None else OperationCapture(None)
        try:
            return await operation(context)
        except BaseException as original:
            self._capture_failure(active, original, classify_failure)
            raise

    def _start(
        self,
        operation_kind: str,
        operation_name: str,
        content_type: str,
        input_bytes: bytes,
    ) -> _ActiveOperation | None:
        try:
            if self._project is None:
                return None
            _validate_boundary(
                operation_kind, operation_name, content_type, input_bytes
            )
            world = self._world_capture()
            operation = self._project.start_operation(world.world_id)
            return _ActiveOperation(
                operation,
                world,
                operation_kind,
                operation_name,
                content_type,
                bytes(input_bytes),
                OperationCapture(operation.operation_id),
            )
        except Exception:
            return None

    @staticmethod
    def _capture_failure(
        active: _ActiveOperation | None,
        original: BaseException,
        classify_failure: Callable[[BaseException], Mapping[str, Any] | None],
    ) -> None:
        if active is None:
            return
        try:
            failure = classify_failure(original)
            if failure is None or not active.context._valid:
                return
            closure = active.world.complete(active.operation.operation_id)
            sink = active.operation.candidate_sink(
                closure,
                _managed_project_token_from_environment,
            )
            sdk = Sdk(sink)
            sdk.begin(
                active.start,
                _operation_begin(active.operation_name, active.operation_kind),
            )
            sdk.record_input(
                active.operation.operation_id,
                _operation_input(active.content_type, active.input_bytes),
            )
            for dependency in active.context._dependencies:
                sdk.record_dependency(active.operation.operation_id, dependency)
            sdk.fail(active.operation.operation_id, failure)
        except Exception:
            return


@dataclass(frozen=True)
class _ActiveOperation:
    operation: OfficialManagedOperation
    world: ManagedWorldCapture
    operation_kind: str
    operation_name: str
    content_type: str
    input_bytes: bytes
    context: OperationCapture

    @property
    def start(self) -> CandidateStart:
        return CandidateStart(
            self.operation.capture_id,
            self.operation.deployment,
            self.operation.operation_id,
            self.operation.world_id,
        )


def _validate_boundary(
    operation_kind: str,
    operation_name: str,
    content_type: str,
    input_bytes: bytes,
) -> None:
    if (
        operation_kind not in ("request-response", "stream", "delivered-work")
        or not isinstance(operation_name, str)
        or not operation_name
        or len(operation_name.encode("utf-8")) > MAX_OPERATION_NAME_BYTES
        or not isinstance(content_type, str)
        or not content_type
        or len(content_type.encode("utf-8")) > MAX_CONTENT_TYPE_BYTES
        or not isinstance(input_bytes, bytes)
        or len(input_bytes) > MAX_CAPTURED_INPUT_BYTES
    ):
        raise ValueError("The operation boundary is invalid.")


def _operation_begin(
    operation_name: str, operation_kind: str = "request-response"
) -> dict[str, object]:
    return {
        "adapter_id": "sdk",
        "adapter_version": "1.0.0",
        "causal_parent_ids": [],
        "format": "reproit.operation-begin.v1",
        "operation_kind": operation_kind,
        "operation_name": operation_name,
    }


def _operation_input(content_type: str, value: bytes) -> dict[str, object]:
    return {
        "channel": "input",
        "content_type": content_type,
        "format": "reproit.operation-input.v1",
        "input_index": 0,
        "value": encode_base64url(value),
        "value_digest": digest_bytes(value),
    }


def _managed_project_token_from_environment() -> ManagedProjectToken:
    return ManagedProjectToken(os.environ["REPROIT_MANAGED_PROJECT_TOKEN"])


def _find_project_file(start: Path) -> Path:
    directory = start.resolve()
    for _ in range(MAX_PROJECT_SEARCH_DEPTH):
        candidate = directory / ".reproit" / "project.toml"
        if candidate.exists():
            return candidate
        parent = directory.parent
        if parent == directory:
            break
        directory = parent
    raise ValueError("Repro It could not load the reviewed project configuration.")


def _git_source_revision(project_root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=project_root,
        check=True,
        capture_output=True,
        timeout=2,
    )
    if result.stderr or len(result.stdout) > 65:
        raise ValueError("Repro It could not identify the deployed source revision.")
    revision = result.stdout.decode("ascii").strip()
    if len(revision) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in revision
    ):
        raise ValueError("Repro It could not identify the deployed source revision.")
    return revision


def _automatic_world_capture() -> ManagedWorldCapture:
    world: dict[str, object] = {
        "created_at": datetime.now(UTC).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "format": "reproit.world-checkpoint.v1",
        "points": [],
    }
    world_id = "sha256:" + hashlib.sha256(canonical_bytes(world)).hexdigest()
    return ManagedWorldCapture(
        world_id,
        lambda _operation_id: ManagedCaptureClosure([], "return", copy.deepcopy(world)),
    )


def _failure_payload(
    category: str, operation_name: str, stable_code: str
) -> dict[str, object]:
    identity = {
        "category": category,
        "cause_types": [],
        "frames": [],
        "operation_kind": "request-response",
        "operation_name": operation_name,
        "runtime_family": "python",
        "schema": "reproit.failure.v1",
        "stable_code": stable_code,
        "type": "HttpFailure" if category == "visible-error" else stable_code,
    }
    identity_digest = "sha256:" + hashlib.sha256(canonical_bytes(identity)).hexdigest()
    return {
        "failure": {
            "category": category,
            "identity": identity_digest,
            "matcher": "exception-exact-v1",
            "object_id": f"obj_{uuid.uuid7()}",
            "schema": "reproit.failure.v1",
        },
        "format": "reproit.failure-payload.v1",
        "identity": identity,
    }
