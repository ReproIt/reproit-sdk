"""Bounded standard-library bridge to the packaged shared SDK engine."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import platform as host_platform
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, NewType

ABI_VERSION = 1
CALL_FORMAT = "reproit.sdk-engine-call.v1"
RESPONSE_FORMAT = "reproit.sdk-engine-response.v1"
MAX_CALL_BYTES = 1_048_576
RESPONSE_CAPACITY = 16_384
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_BYTES = 785_408
MAX_OBSERVATION_ADAPTERS = 7
MAX_OBSERVATION_CHUNK_BYTES = 32_768
MAX_OBSERVATION_RESPONSE_READ_BYTES = 8_192
MAX_OBSERVATION_SESSIONS = 1_024
MAX_OBSERVATION_SESSIONS_PER_OPERATION = 64
MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES = 65_536
MAX_SINK_WAIT_MS = 1_800_000
MAX_SINK_WAITERS = 16
MAX_ARTIFACT_MANIFEST_BYTES = 16_384
ABI_CONTRACT_DIGEST = (
    "sha256:ff608fb795814594fef391607020f8a31fcfb90faba0ff84dcfa72bc8d42afc3"
)
ARTIFACT_MANIFEST_FORMAT = "reproit.sdk-engine-artifacts.v1"
ARTIFACT_MANIFEST_NAME = "sdk-engine-artifacts.json"
_ABI_SYMBOLS = {
    "abi_version": "reproit_sdk_engine_abi_version",
    "call": "reproit_sdk_engine_call",
}
_PLATFORM_LIBRARY_NAMES = {
    "linux-arm64": "libreproit_sdk_engine.so",
    "linux-x86_64": "libreproit_sdk_engine.so",
    "macos-arm64": "libreproit_sdk_engine.dylib",
    "windows-x86_64": "reproit_sdk_engine.dll",
}
_MAX_UNSIGNED_64 = (1 << 64) - 1
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

NativeEngineHandle = NewType("NativeEngineHandle", int)
NativeOperationHandle = NewType("NativeOperationHandle", int)
NativeObservationHandle = NewType("NativeObservationHandle", int)
NativeDependencyHandle = NewType("NativeDependencyHandle", int)
NativeSinkHandle = NewType("NativeSinkHandle", int)
NativeObservationClass = Literal[
    "clock",
    "database",
    "environment",
    "filesystem",
    "outbound-http",
    "queue",
    "randomness",
]
NativeTriggerCompletion = Literal[
    "acknowledgment",
    "return",
    "stream-end",
    "task-end",
]
NativeObservationAction = Literal["capture", "replay"]
NativeObservationOutcome = Literal["error", "response"]
NativeObservationStream = Literal["request", "response"]

_OBSERVATION_ACTIONS = ("capture", "replay")
_DEPENDENCY_CONTRACT = {
    "finish_fields": ["dependency_handle", "response"],
    "finish_result_fields": ["outcome"],
    "open_fields": ["causal_parent_id", "operation_handle", "request"],
    "open_result_fields": ["action", "dependency_handle"],
    "replay_read_operation": "observation-read",
    "request_fields": [
        "encoding",
        "metadata",
        "method",
        "observation_class",
        "operation",
        "payload",
        "protocol",
        "target",
    ],
    "response_fields": [
        "error_code",
        "error_number",
        "metadata",
        "outcome",
        "payload",
        "status",
        "status_code",
    ],
}
_ERROR_BEHAVIOR = {
    "json_error": {
        "error_code_source": "reproit-core-v1",
        "includes_message": False,
        "includes_request": False,
        "maximum_bytes": 256,
        "result": {},
    },
    "native_failures": [
        {
            "code": -4,
            "condition": "response-length-overflow",
            "output_written": False,
        },
        {
            "code": -3,
            "condition": "output-capacity-exceeded",
            "output_written": False,
        },
        {
            "code": -2,
            "condition": "engine-panic",
            "output_written": False,
        },
        {
            "code": -1,
            "condition": "invalid-call-boundary",
            "output_written": False,
        },
    ],
    "success": "response-byte-count",
}
_OBSERVATION_CONTRACT = {
    "adapter_registration_fields": [
        "adapter_id",
        "adapter_version",
        "class",
        "implementation_digest",
    ],
    "finish_fields": ["observation_handle", "outcome", "session_position"],
    "open_fields": ["causal_parent_id", "class", "operation_handle"],
    "open_result_fields": ["observation_handle", "session_position"],
    "read_result_fields": ["chunk", "eof"],
    "write_fields": ["chunk", "observation_handle", "stream"],
}


class _EngineOperation(StrEnum):
    CONTRACT = "contract"
    DEPENDENCY_FINISH = "dependency-finish"
    DEPENDENCY_OPEN = "dependency-open"
    ENGINE_CLOSE = "engine-close"
    ENGINE_OPEN = "engine-open"
    OBSERVATION_ABANDON = "observation-abandon"
    OBSERVATION_DISPATCH = "observation-dispatch"
    OBSERVATION_FINISH = "observation-finish"
    OBSERVATION_OPEN = "observation-open"
    OBSERVATION_READ = "observation-read"
    OBSERVATION_WRITE = "observation-write"
    OPERATION_ABANDON = "operation-abandon"
    OPERATION_BEGIN = "operation-begin"
    OPERATION_CLOSE_WORLD = "operation-close-world"
    OPERATION_FAIL = "operation-fail"
    OPERATION_INPUT = "operation-input"
    OPERATION_SUCCEED = "operation-succeed"
    OPERATION_UNOWNED = "operation-unowned"
    SINK_WAIT = "sink-wait"


_CONTRACT_REQUEST = (
    f'{{"format":"{CALL_FORMAT}","operation":"{_EngineOperation.CONTRACT}"}}'
).encode("ascii")


@dataclass(frozen=True)
class NativeOperation:
    """A shared engine operation handle and its stable operation identity."""

    handle: NativeOperationHandle
    operation_id: str


@dataclass(frozen=True)
class NativeObservation:
    """A shared engine observation session and its ordered position."""

    handle: NativeObservationHandle
    session_position: int


@dataclass(frozen=True)
class NativeDependency:
    """A semantic dependency handle and the engine-selected action."""

    handle: NativeDependencyHandle
    action: NativeObservationAction


class NativeEngineError(RuntimeError):
    """A packaged shared SDK engine call failed local validation."""


class NativeEngineCallError(NativeEngineError):
    """The shared SDK engine rejected a valid bounded call."""

    def __init__(self, error_code: str):
        super().__init__("The shared SDK engine rejected the operation.")
        self.error_code = error_code


class NativeEngineBridge:
    """Call the bounded shared SDK engine ABI without exposing native errors."""

    def __init__(self, library: object):
        abi_version = None
        call = None
        try:
            abi_version = getattr(library, _ABI_SYMBOLS["abi_version"])
            call = getattr(library, _ABI_SYMBOLS["call"])
            abi_version.argtypes = []
            abi_version.restype = ctypes.c_uint32
            call.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_void_p,
                ctypes.c_size_t,
            ]
            call.restype = ctypes.c_ssize_t
        except Exception:
            pass
        if abi_version is None or call is None:
            raise _engine_unavailable()
        self._abi_version = abi_version
        self._call = call

    @classmethod
    def load(cls) -> NativeEngineBridge:
        """Load the packaged engine for this operating system."""
        path = _packaged_library_path()
        library = None
        try:
            library = ctypes.CDLL(os.fspath(path))
        except Exception:
            pass
        if library is None:
            raise _engine_unavailable()
        return cls(library)

    def contract(self) -> dict[str, Any]:
        """Validate the native symbol and JSON contract versions."""
        abi_version = None
        try:
            abi_version = self._abi_version()
        except Exception:
            pass
        if abi_version != ABI_VERSION:
            raise _engine_unavailable()
        response = self._call_bytes(_CONTRACT_REQUEST)
        if (
            response["ok"] is not True
            or response["error_code"] is not None
            or not _valid_contract(response["result"])
        ):
            raise _response_invalid()
        return response

    def call(self, operation: Mapping[str, Any]) -> dict[str, Any]:
        """Call one JSON engine operation through the bounded ABI."""
        request = None
        try:
            request = json.dumps(
                dict(operation),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except Exception:
            pass
        if request is None:
            raise _request_invalid()
        return self._call_bytes(request)

    def engine_open(
        self,
        *,
        build_repository_id: str,
        project_toml: str,
        source_revision: str,
        subject_manifest: Mapping[str, Any],
        subject_objects: Sequence[Mapping[str, Any]],
    ) -> NativeEngineHandle:
        """Open one Python shared engine from an exact packaged subject."""
        from .observation_adapters import _installed_observation_adapters

        result = self._call_result(
            {
                "build_repository_id": build_repository_id,
                "format": CALL_FORMAT,
                "observation_adapters": _installed_observation_adapters(),
                "operation": _EngineOperation.ENGINE_OPEN,
                "project_toml": project_toml,
                "sdk": "python",
                "source_revision": source_revision,
                "subject_manifest": _copy_mapping(subject_manifest),
                "subject_objects": _copy_mappings(subject_objects),
            }
        )
        return NativeEngineHandle(_result_handle(result, "engine_handle"))

    def engine_close(self, engine_handle: NativeEngineHandle) -> None:
        """Close one shared engine and its active operations."""
        self._call_empty(
            _EngineOperation.ENGINE_CLOSE,
            engine_handle=_request_handle(engine_handle),
        )

    def operation_begin(
        self,
        engine_handle: NativeEngineHandle,
        begin: Mapping[str, Any],
    ) -> NativeOperation:
        """Start one operation from an existing Core begin payload."""
        result = self._call_result(
            {
                "begin": _copy_mapping(begin),
                "engine_handle": _request_handle(engine_handle),
                "format": CALL_FORMAT,
                "operation": _EngineOperation.OPERATION_BEGIN,
            }
        )
        if set(result) != {"operation_handle", "operation_id"}:
            raise _response_invalid()
        operation_id = result.get("operation_id")
        if not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 128:
            raise _response_invalid()
        return NativeOperation(
            NativeOperationHandle(
                _result_handle(result, "operation_handle", exact=False)
            ),
            operation_id,
        )

    def operation_input(
        self,
        operation_handle: NativeOperationHandle,
        input_payload: Mapping[str, Any],
    ) -> None:
        """Record one existing Core operation input payload."""
        self._call_empty(
            _EngineOperation.OPERATION_INPUT,
            input=_copy_mapping(input_payload),
            operation_handle=_request_handle(operation_handle),
        )

    def dependency_open(
        self,
        operation_handle: NativeOperationHandle,
        request: Mapping[str, Any],
        causal_parent_id: str | None = None,
    ) -> NativeDependency:
        """Validate and open one semantic dependency in the shared engine."""
        result = self._call_result(
            {
                "causal_parent_id": causal_parent_id,
                "format": CALL_FORMAT,
                "operation": _EngineOperation.DEPENDENCY_OPEN,
                "operation_handle": _request_handle(operation_handle),
                "request": _copy_mapping(request),
            }
        )
        if (
            set(result) != {"action", "dependency_handle"}
            or result.get("action") not in _OBSERVATION_ACTIONS
        ):
            raise _response_invalid()
        return NativeDependency(
            NativeDependencyHandle(
                _result_handle(result, "dependency_handle", exact=False)
            ),
            result["action"],
        )

    def dependency_finish(
        self,
        dependency_handle: NativeDependencyHandle,
        response: Mapping[str, Any] | None,
    ) -> NativeObservationOutcome:
        """Validate and finish one semantic dependency in the shared engine."""
        response_value = None if response is None else _copy_mapping(response)
        result = self._call_result(
            {
                "dependency_handle": _request_handle(dependency_handle),
                "format": CALL_FORMAT,
                "operation": _EngineOperation.DEPENDENCY_FINISH,
                "response": response_value,
            }
        )
        outcome = result.get("outcome")
        if set(result) != {"outcome"} or outcome not in ("error", "response"):
            raise _response_invalid()
        return outcome

    def observation_open(
        self,
        operation_handle: NativeOperationHandle,
        observation_class: NativeObservationClass,
        causal_parent_id: str | None = None,
    ) -> NativeObservation:
        """Open one package-owned semantic observation session."""
        result = self._call_result(
            {
                "causal_parent_id": causal_parent_id,
                "class": observation_class,
                "format": CALL_FORMAT,
                "operation": _EngineOperation.OBSERVATION_OPEN,
                "operation_handle": _request_handle(operation_handle),
            }
        )
        if set(result) != {"observation_handle", "session_position"}:
            raise _response_invalid()
        return NativeObservation(
            NativeObservationHandle(
                _result_handle(result, "observation_handle", exact=False)
            ),
            _result_unsigned_64(result, "session_position"),
        )

    def observation_write(
        self,
        observation_handle: NativeObservationHandle,
        stream: NativeObservationStream,
        chunk: bytes,
    ) -> None:
        """Write one nonempty bounded request or response chunk."""
        self._call_empty(
            _EngineOperation.OBSERVATION_WRITE,
            chunk=_encode_chunk(chunk),
            observation_handle=_request_handle(observation_handle),
            stream=stream,
        )

    def observation_dispatch(
        self,
        observation_handle: NativeObservationHandle,
    ) -> NativeObservationAction:
        """Choose capture or replay after the request is complete."""
        result = self._call_result(
            {
                "format": CALL_FORMAT,
                "observation_handle": _request_handle(observation_handle),
                "operation": _EngineOperation.OBSERVATION_DISPATCH,
            }
        )
        if set(result) != {"action"} or result.get("action") not in (
            _OBSERVATION_ACTIONS
        ):
            raise _response_invalid()
        return result["action"]

    def observation_read(
        self,
        observation_handle: NativeObservationHandle,
    ) -> tuple[bytes, bool]:
        """Read one bounded replay response chunk and its EOF state."""
        result = self._call_result(
            {
                "format": CALL_FORMAT,
                "observation_handle": _request_handle(observation_handle),
                "operation": _EngineOperation.OBSERVATION_READ,
            }
        )
        if set(result) != {"chunk", "eof"} or type(result.get("eof")) is not bool:
            raise _response_invalid()
        chunk = _decode_chunk(result.get("chunk"), allow_empty=result["eof"])
        return chunk, result["eof"]

    def observation_finish(
        self,
        observation_handle: NativeObservationHandle,
        outcome: NativeObservationOutcome,
        session_position: int,
    ) -> None:
        """Finish one complete semantic observation session."""
        self._call_empty(
            _EngineOperation.OBSERVATION_FINISH,
            observation_handle=_request_handle(observation_handle),
            outcome=outcome,
            session_position=_request_unsigned_64(session_position),
        )

    def observation_abandon(
        self,
        observation_handle: NativeObservationHandle,
    ) -> None:
        """Discard one incomplete semantic observation session."""
        self._call_empty(
            _EngineOperation.OBSERVATION_ABANDON,
            observation_handle=_request_handle(observation_handle),
        )

    def operation_unowned(
        self,
        operation_handle: NativeOperationHandle,
        observation_class: NativeObservationClass,
        evidence: bytes,
        causal_parent_id: str | None = None,
    ) -> None:
        """Mark one unsupported automatic observation."""
        self._operation_observation(
            _EngineOperation.OPERATION_UNOWNED,
            operation_handle,
            observation_class,
            evidence,
            causal_parent_id,
        )

    def operation_close_world(
        self,
        operation_handle: NativeOperationHandle,
        completion: NativeTriggerCompletion,
    ) -> None:
        """Close the automatic World for one operation."""
        self._call_empty(
            _EngineOperation.OPERATION_CLOSE_WORLD,
            completion=completion,
            operation_handle=_request_handle(operation_handle),
        )

    def operation_succeed(
        self,
        operation_handle: NativeOperationHandle,
    ) -> None:
        """Discard one successful operation."""
        self._call_empty(
            _EngineOperation.OPERATION_SUCCEED,
            operation_handle=_request_handle(operation_handle),
        )

    def operation_abandon(
        self,
        operation_handle: NativeOperationHandle,
    ) -> None:
        """Discard one incomplete operation."""
        self._call_empty(
            _EngineOperation.OPERATION_ABANDON,
            operation_handle=_request_handle(operation_handle),
        )

    def operation_fail(
        self,
        operation_handle: NativeOperationHandle,
        failure: Mapping[str, Any],
        project_token: str,
    ) -> NativeSinkHandle:
        """Hand one complete failed operation to the shared managed sink."""
        result = self._call_result(
            {
                "failure": _copy_mapping(failure),
                "format": CALL_FORMAT,
                "operation": _EngineOperation.OPERATION_FAIL,
                "operation_handle": _request_handle(operation_handle),
                "project_token": project_token,
            }
        )
        return NativeSinkHandle(_result_handle(result, "sink_handle"))

    def sink_wait(self, sink_handle: NativeSinkHandle, timeout_ms: int) -> bool:
        """Wait for one managed sink within an explicit millisecond bound."""
        result = self._call_result(
            {
                "format": CALL_FORMAT,
                "operation": _EngineOperation.SINK_WAIT,
                "sink_handle": _request_handle(sink_handle),
                "timeout_ms": _request_unsigned_64(timeout_ms),
            }
        )
        if set(result) != {"idle"} or type(result.get("idle")) is not bool:
            raise _response_invalid()
        return result["idle"]

    def _operation_observation(
        self,
        operation: _EngineOperation,
        operation_handle: NativeOperationHandle,
        observation_class: NativeObservationClass,
        evidence: bytes,
        causal_parent_id: str | None,
    ) -> None:
        if type(evidence) is not bytes or len(evidence) > MAX_EVIDENCE_BYTES:
            raise _request_invalid()
        evidence_text = None
        try:
            encoded_evidence = base64.urlsafe_b64encode(evidence).rstrip(b"=")
            evidence_text = encoded_evidence.decode("ascii")
        except Exception:
            pass
        if evidence_text is None:
            raise _request_invalid()
        self._call_empty(
            operation,
            **{
                "causal_parent_id": causal_parent_id,
                "class": observation_class,
                "evidence": evidence_text,
                "operation_handle": _request_handle(operation_handle),
            },
        )

    def _call_empty(self, operation: _EngineOperation, **fields: Any) -> None:
        result = self._call_result(
            {"format": CALL_FORMAT, "operation": operation, **fields}
        )
        if result:
            raise _response_invalid()

    def _call_result(self, operation: Mapping[str, Any]) -> dict[str, Any]:
        response = self.call(operation)
        if not response["ok"]:
            raise NativeEngineCallError(response["error_code"])
        return response["result"]

    def _call_bytes(self, request: bytes) -> dict[str, Any]:
        if not request or len(request) > MAX_CALL_BYTES:
            raise _request_invalid()
        input_buffer = ctypes.create_string_buffer(request)
        output_buffer = (ctypes.c_ubyte * RESPONSE_CAPACITY)()
        written = None
        try:
            written = self._call(
                input_buffer,
                len(request),
                output_buffer,
                RESPONSE_CAPACITY,
            )
        except Exception:
            pass
        if written is None:
            raise _engine_unavailable()
        if type(written) is not int or written < 0:
            raise _engine_unavailable()
        if written == 0 or written > RESPONSE_CAPACITY:
            raise _response_invalid()
        response = bytes(output_buffer[:written])
        return _decode_response(response)


def _valid_contract(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "abi_version",
        "dependency_contract",
        "error_behavior",
        "format",
        "libraries",
        "limits",
        "operations",
        "observation_actions",
        "observation_contract",
        "request",
        "response",
        "symbols",
    }:
        return False
    libraries = value.get("libraries")
    actual_libraries = None
    if (
        isinstance(libraries, list)
        and len(libraries) == len(_PLATFORM_LIBRARY_NAMES)
        and all(
            isinstance(entry, dict) and set(entry) == {"name", "platform"}
            for entry in libraries
        )
    ):
        actual_libraries = {
            entry.get("platform"): entry.get("name")
            for entry in libraries
        }
    operations = value.get("operations")
    return (
        value.get("abi_version") == ABI_VERSION
        and value.get("format") == "reproit.sdk-engine-abi.v1"
        and value.get("error_behavior") == _ERROR_BEHAVIOR
        and value.get("dependency_contract") == _DEPENDENCY_CONTRACT
        and actual_libraries == _PLATFORM_LIBRARY_NAMES
        and value.get("limits")
        == {
            "engines": 64,
            "evidence_bytes": MAX_EVIDENCE_BYTES,
            "observation_adapters": MAX_OBSERVATION_ADAPTERS,
            "observation_chunk_bytes": MAX_OBSERVATION_CHUNK_BYTES,
            "observation_response_read_bytes": (
                MAX_OBSERVATION_RESPONSE_READ_BYTES
            ),
            "observation_sessions": MAX_OBSERVATION_SESSIONS,
            "observation_sessions_per_operation": (
                MAX_OBSERVATION_SESSIONS_PER_OPERATION
            ),
            "operations": 512,
            "semantic_dependency_record_bytes": (
                MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
            ),
            "sink_wait_ms": MAX_SINK_WAIT_MS,
            "sinks": MAX_SINK_WAITERS,
        }
        and isinstance(operations, list)
        and all(isinstance(operation, str) for operation in operations)
        and operations == [operation.value for operation in _EngineOperation]
        and value.get("observation_actions") == list(_OBSERVATION_ACTIONS)
        and value.get("observation_contract") == _OBSERVATION_CONTRACT
        and value.get("request")
        == {"format": CALL_FORMAT, "maximum_bytes": MAX_CALL_BYTES}
        and value.get("response")
        == {
            "format": RESPONSE_FORMAT,
            "output_capacity_bytes": RESPONSE_CAPACITY,
        }
        and value.get("symbols") == _ABI_SYMBOLS
    )


def _packaged_library_path() -> Path:
    platforms = {
        ("darwin", "arm64"): "macos-arm64",
        ("linux", "aarch64"): "linux-arm64",
        ("linux", "arm64"): "linux-arm64",
        ("linux", "amd64"): "linux-x86_64",
        ("linux", "x86_64"): "linux-x86_64",
        ("win32", "amd64"): "windows-x86_64",
        ("win32", "x86_64"): "windows-x86_64",
    }
    platform = platforms.get((sys.platform, host_platform.machine().lower()))
    name = _PLATFORM_LIBRARY_NAMES.get(platform, "")
    if not platform or not name:
        raise _engine_unavailable()
    root = Path(__file__).parent / "_native"
    _validate_artifact_manifest(root, platform, {"engine": name})
    return root / name


def _validate_artifact_manifest(
    root: Path,
    target: str,
    required: Mapping[str, str],
) -> None:
    manifest_path = root / ARTIFACT_MANIFEST_NAME
    manifest_bytes = _read_regular_file(
        manifest_path,
        MAX_ARTIFACT_MANIFEST_BYTES,
    )
    manifest = _decode_json(manifest_bytes, MAX_ARTIFACT_MANIFEST_BYTES)
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {"abi_contract_digest", "artifacts", "format", "target"}
        or manifest.get("abi_contract_digest") != ABI_CONTRACT_DIGEST
        or manifest.get("format") != ARTIFACT_MANIFEST_FORMAT
        or manifest.get("target") != target
        or not isinstance(manifest.get("artifacts"), list)
    ):
        raise _engine_unavailable()
    artifacts = manifest["artifacts"]
    if len(artifacts) != len(required):
        raise _engine_unavailable()
    actual: dict[str, str] = {}
    previous: tuple[str, str] | None = None
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"digest", "file", "role", "size"}
        ):
            raise _engine_unavailable()
        digest = artifact.get("digest")
        file = artifact.get("file")
        role = artifact.get("role")
        size = artifact.get("size")
        current = (role, file) if isinstance(role, str) and isinstance(file, str) else None
        if (
            current is None
            or (previous is not None and current <= previous)
            or role not in required
            or required[role] != file
            or role in actual
            or not _valid_basename(file)
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            or type(size) is not int
            or not 0 < size <= MAX_LIBRARY_BYTES
        ):
            raise _engine_unavailable()
        path = root / file
        metadata = _regular_file_metadata(path, MAX_LIBRARY_BYTES)
        if metadata.st_size != size or _sha256_file(path, size) != digest:
            raise _engine_unavailable()
        actual[role] = file
        previous = current
    if actual != dict(required):
        raise _engine_unavailable()


def _read_regular_file(path: Path, maximum_bytes: int) -> bytes:
    metadata = _regular_file_metadata(path, maximum_bytes)
    value = None
    try:
        with path.open("rb") as file:
            value = file.read(maximum_bytes + 1)
    except OSError:
        pass
    if value is None or len(value) != metadata.st_size:
        raise _engine_unavailable()
    return value


def _regular_file_metadata(path: Path, maximum_bytes: int) -> os.stat_result:
    metadata = None
    try:
        metadata = path.lstat()
    except OSError:
        pass
    if metadata is None:
        raise _engine_unavailable()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > maximum_bytes
    ):
        raise _engine_unavailable()
    return metadata


def _sha256_file(path: Path, expected_size: int) -> str:
    digest = hashlib.sha256()
    total = 0
    failed = False
    try:
        with path.open("rb") as file:
            while chunk := file.read(1_048_576):
                total += len(chunk)
                if total > expected_size:
                    failed = True
                    break
                digest.update(chunk)
    except OSError:
        failed = True
    if failed or total != expected_size:
        raise _engine_unavailable()
    return f"sha256:{digest.hexdigest()}"


def _decode_response(response: bytes) -> dict[str, Any]:
    if not response or len(response) > RESPONSE_CAPACITY:
        raise _response_invalid()

    value = _decode_json(response, RESPONSE_CAPACITY)
    if value is None:
        raise _response_invalid()
    if (
        not isinstance(value, dict)
        or set(value) != {"error_code", "format", "ok", "result"}
        or value.get("format") != RESPONSE_FORMAT
        or type(value.get("ok")) is not bool
        or not isinstance(value.get("result"), dict)
        or not _valid_error_code(value.get("error_code"))
        or (value["ok"] and value["error_code"] is not None)
        or (not value["ok"] and not value["error_code"])
    ):
        raise _response_invalid()
    return value


def _decode_json(value: bytes, maximum_bytes: int) -> Any | None:
    if not value or len(value) > maximum_bytes:
        return None

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError

    decoded = None
    try:
        decoded = json.loads(
            value,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except Exception:
        pass
    return decoded


def _valid_basename(value: str) -> bool:
    return (
        value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and Path(value).name == value
    )


def _copy_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    copied = None
    try:
        copied = dict(value)
    except Exception:
        pass
    if copied is None:
        raise _request_invalid()
    return copied


def _copy_mappings(
    values: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    copied = None
    try:
        copied = [dict(value) for value in values]
    except Exception:
        pass
    if copied is None:
        raise _request_invalid()
    return copied


def _encode_chunk(value: bytes) -> str:
    if (
        type(value) is not bytes
        or not value
        or len(value) > MAX_OBSERVATION_CHUNK_BYTES
    ):
        raise _request_invalid()
    try:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    except Exception:
        raise _request_invalid() from None


def _decode_chunk(value: object, *, allow_empty: bool) -> bytes:
    if not isinstance(value, str):
        raise _response_invalid()
    if value == "":
        if allow_empty:
            return b""
        raise _response_invalid()
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None or len(value) % 4 == 1:
        raise _response_invalid()
    maximum_encoded_bytes = (MAX_OBSERVATION_RESPONSE_READ_BYTES + 2) // 3 * 4
    if len(value) > maximum_encoded_bytes:
        raise _response_invalid()
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except Exception:
        raise _response_invalid() from None
    if (
        not decoded
        or len(decoded) > MAX_OBSERVATION_RESPONSE_READ_BYTES
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        != value
    ):
        raise _response_invalid()
    return decoded


def _request_handle(value: int) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_UNSIGNED_64:
        raise _request_invalid()
    return value


def _request_unsigned_64(value: int) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_UNSIGNED_64:
        raise _request_invalid()
    return value


def _result_handle(
    result: Mapping[str, Any],
    key: str,
    *,
    exact: bool = True,
) -> int:
    if exact and set(result) != {key}:
        raise _response_invalid()
    value = result.get(key)
    if type(value) is not int or not 1 <= value <= _MAX_UNSIGNED_64:
        raise _response_invalid()
    return value


def _result_unsigned_64(result: Mapping[str, Any], key: str) -> int:
    value = result.get(key)
    if type(value) is not int or not 0 <= value <= _MAX_UNSIGNED_64:
        raise _response_invalid()
    return value


def _valid_error_code(value: Any) -> bool:
    return value is None or (
        isinstance(value, str) and _ERROR_CODE.fullmatch(value) is not None
    )


def _engine_unavailable() -> NativeEngineError:
    return NativeEngineError("The packaged shared SDK engine is unavailable.")


def _request_invalid() -> NativeEngineError:
    return NativeEngineError("The shared SDK engine request is invalid.")


def _response_invalid() -> NativeEngineError:
    return NativeEngineError("The shared SDK engine response is invalid.")
