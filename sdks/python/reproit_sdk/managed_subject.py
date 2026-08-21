"""Python subject-closure packaging for managed capture."""

from __future__ import annotations

import os
import platform
import sys
import tempfile
from dataclasses import dataclass, field

from reproit_sdk import canonical_bytes

from .managed_protocol import (
    ManagedError,
    canonical_digest,
    digest_bytes,
    schema_invalid,
    valid_capability,
)
from .managed_subject_files import capture_python_subject_files

SUBJECT_FILE_MEDIA_TYPE = "application/vnd.reproit.subject-file.v1"
SUBJECT_LAUNCH_MEDIA_TYPE = "application/vnd.reproit.subject-launch.v1+json"
MODULE_IDENTITY_MEDIA_TYPE = "application/vnd.reproit.subject-module-identity.v1+json"

MAX_ARGUMENTS = 128
MAX_ENVIRONMENT_NAMES = 256
MAX_SUBJECT_OBJECTS = 32_767
MAX_SUBJECT_OBJECT_BYTES = 274_878_824_448

_SUPPORTED_INTERPRETER_FLAGS = frozenset(
    {
        "-B",
        "-E",
        "-I",
        "-O",
        "-OO",
        "-P",
        "-b",
        "-bb",
        "-d",
        "-q",
        "-s",
        "-S",
        "-u",
        "-v",
    }
)

_ARCHITECTURES = {
    "aarch64": "architecture.arm64",
    "amd64": "architecture.x86-64",
    "arm64": "architecture.arm64",
    "x86_64": "architecture.x86-64",
}
_OPERATING_SYSTEMS = {
    "darwin": "operating-system.macos",
    "linux": "operating-system.linux",
}


@dataclass(frozen=True)
class PackagedSubjectObject:
    digest: str
    path: str
    size: int


@dataclass
class PythonSubjectPackage:
    """The frozen manifest plus content-addressed object files in a spool."""

    manifest: dict[str, object]
    objects: list[PackagedSubjectObject]
    _spool: tempfile.TemporaryDirectory = field(repr=False)


def package_running_python_subject(
    entry_script: str | None = None,
    application_root: str | None = None,
) -> PythonSubjectPackage:
    """Freeze and hash the running Python subject closure locally."""
    script_path = entry_script if entry_script is not None else sys.argv[0]
    if not isinstance(script_path, str) or not script_path:
        raise _subject_unsupported()
    spool = tempfile.TemporaryDirectory(prefix="reproit-python-subject-")
    try:
        captured = capture_python_subject_files(
            script_path,
            application_root,
            spool.name,
        )
    except BaseException:
        spool.cleanup()
        raise
    script_file = next(
        (file for file in captured.files if file.path == captured.entry_path),
        None,
    )
    if script_file is None:
        spool.cleanup()
        raise _subject_unsupported()
    script_subject_path = script_file.path

    interpreter = captured.interpreter
    interpreter_bytes = canonical_bytes(interpreter)
    interpreter_digest = digest_bytes(interpreter_bytes)
    dependencies = captured.dependencies
    dependency_bytes = canonical_bytes(dependencies)
    dependency_digest = digest_bytes(dependency_bytes)

    launch = {
        "arguments": _launch_arguments(script_subject_path, script_path),
        "environment_names": _environment_names(),
        "executable": captured.interpreter_path,
        "working_directory": "/reproit/subject/work",
    }
    launch_bytes = canonical_bytes(launch)
    launch_digest = digest_bytes(launch_bytes)

    file_objects = tuple(
        (
            captured_file.digest,
            captured_file.kind,
            SUBJECT_FILE_MEDIA_TYPE,
            captured_file.size,
        )
        for captured_file in captured.files
    )
    objects = _assemble_objects(
        *file_objects,
        (
            interpreter_digest,
            "module-identity",
            MODULE_IDENTITY_MEDIA_TYPE,
            len(interpreter_bytes),
        ),
        (
            dependency_digest,
            "module-identity",
            MODULE_IDENTITY_MEDIA_TYPE,
            len(dependency_bytes),
        ),
        (launch_digest, "launch-data", SUBJECT_LAUNCH_MEDIA_TYPE, len(launch_bytes)),
    )
    if (
        len(objects) > MAX_SUBJECT_OBJECTS
        or sum(entry["size"] for entry in objects) > MAX_SUBJECT_OBJECT_BYTES
    ):
        spool.cleanup()
        raise _subject_unbounded()
    files = sorted(
        (
            *(
                {
                    "executable": captured_file.executable,
                    "object_digest": captured_file.digest,
                    "path": captured_file.path,
                }
                for captured_file in captured.files
            ),
            {
                "executable": False,
                "object_digest": launch_digest,
                "path": "/reproit/subject/launch.json",
            },
            {
                "executable": False,
                "object_digest": dependency_digest,
                "path": "/reproit/subject/python/dependencies.json",
            },
            {
                "executable": False,
                "object_digest": interpreter_digest,
                "path": "/reproit/subject/python/interpreter.json",
            },
        ),
        key=lambda file: file["path"],
    )
    modules = sorted(
        (
            *(
                {
                    "identity": captured_file.digest,
                    "module_digest": captured_file.digest,
                    "path": captured_file.path,
                }
                for captured_file in captured.files
                if captured_file.module
            ),
            {
                "identity": interpreter["identity"],
                "module_digest": interpreter_digest,
                "path": "/reproit/subject/python/interpreter.json",
            },
        ),
        key=lambda module: module["path"],
    )
    debug_artifacts = sorted(
        (
            {
                "artifact_digest": captured_file.digest,
                "kind": "interpreted-source-identity",
                "module_digest": captured_file.digest,
                "path": captured_file.path,
            }
            for captured_file in captured.files
            if captured_file.module and captured_file.path.endswith(".py")
        ),
        key=lambda artifact: artifact["path"],
    )
    manifest = {
        "architecture": _architecture(),
        "debug_artifacts": debug_artifacts,
        "files": files,
        "format": "reproit.subject-closure.v1",
        "launch": launch,
        "modules": modules,
        "objects": objects,
        "operating_system": _operating_system(),
        "runtime_family": "python",
        "total_bytes": sum(entry["size"] for entry in objects),
    }
    validate_subject_closure_manifest(manifest)
    metadata_objects = _spool_objects(
        spool.name,
        {
            interpreter_digest: interpreter_bytes,
            dependency_digest: dependency_bytes,
            launch_digest: launch_bytes,
        },
    )
    packaged_by_digest = {
        captured_file.digest: PackagedSubjectObject(
            captured_file.digest,
            captured_file.spool_path,
            captured_file.size,
        )
        for captured_file in captured.files
    }
    for packaged in metadata_objects:
        packaged_by_digest[packaged.digest] = packaged
    packaged = [packaged_by_digest[digest] for digest in sorted(packaged_by_digest)]
    return PythonSubjectPackage(manifest, packaged, spool)


def _assemble_objects(
    *entries: tuple[str, str, str, int],
) -> list[dict[str, object]]:
    merged: dict[str, dict[str, object]] = {}
    for digest, kind, media_type, size in entries:
        existing = merged.get(digest)
        candidate = {
            "digest": digest,
            "kind": kind,
            "media_type": media_type,
            "size": size,
        }
        if existing is not None and existing != candidate:
            raise _subject_unsupported()
        merged[digest] = candidate
    return [merged[digest] for digest in sorted(merged)]


def _spool_objects(
    spool_path: str, contents: dict[str, bytes]
) -> list[PackagedSubjectObject]:
    packaged = []
    for digest, value in contents.items():
        path = os.path.join(spool_path, _digest_name(digest))
        if not os.path.exists(path):
            with open(path, "wb") as target:
                target.write(value)
        packaged.append(PackagedSubjectObject(digest, path, len(value)))
    return packaged


def _launch_arguments(script_subject_path: str, source_script_path: str) -> list[str]:
    interpreter_arguments = _running_interpreter_arguments(source_script_path)
    arguments = [*interpreter_arguments, script_subject_path, *sys.argv[1:]]
    if len(arguments) > MAX_ARGUMENTS or any(
        not isinstance(argument, str) or len(argument) > 4_096 for argument in arguments
    ):
        raise _subject_unsupported()
    return list(arguments)


def _running_interpreter_arguments(source_script_path: str) -> list[str]:
    original = getattr(sys, "orig_argv", None)
    if not isinstance(original, list) or not all(
        isinstance(argument, str) for argument in original
    ):
        return []
    source = os.path.realpath(source_script_path)
    for index, argument in enumerate(original[1:], start=1):
        if os.path.isfile(argument) and os.path.realpath(argument) == source:
            flags = original[1:index]
            if any(flag not in _SUPPORTED_INTERPRETER_FLAGS for flag in flags):
                raise _subject_unsupported()
            return flags
    running_script = sys.argv[0] if sys.argv else ""
    if running_script and os.path.isfile(running_script):
        if os.path.realpath(running_script) == source and any(
            argument in ("-c", "-m") for argument in original[1:]
        ):
            raise _subject_unsupported()
    return []


def _environment_names() -> list[str]:
    names = sorted(set(os.environ))
    if len(names) > MAX_ENVIRONMENT_NAMES:
        raise _subject_unbounded()
    for name in names:
        if (
            not name
            or len(name) > 256
            or not all(33 <= ord(character) <= 126 for character in name)
            or "=" in name
        ):
            raise _subject_unsupported()
    return names


def _architecture() -> str:
    machine = platform.machine().lower()
    capability = _ARCHITECTURES.get(machine)
    if capability is None:
        raise _unsupported_host()
    return capability


def _operating_system() -> str:
    capability = _OPERATING_SYSTEMS.get(sys.platform)
    if capability is None:
        raise _unsupported_host()
    return capability


def validate_subject_closure_manifest(value: object) -> None:
    """Mirror reproit-core SubjectClosureManifest::validate."""
    from collections.abc import Mapping

    if not isinstance(value, Mapping) or set(value) != {
        "architecture",
        "debug_artifacts",
        "files",
        "format",
        "launch",
        "modules",
        "objects",
        "operating_system",
        "runtime_family",
        "total_bytes",
    }:
        raise schema_invalid()
    if (
        value["format"] != "reproit.subject-closure.v1"
        or value["runtime_family"] not in ("dotnet", "go", "node", "python", "rust")
        or not valid_capability(value["architecture"])
        or not valid_capability(value["operating_system"])
    ):
        raise schema_invalid()
    objects = value["objects"]
    files = value["files"]
    modules = value["modules"]
    debug_artifacts = value["debug_artifacts"]
    if (
        not isinstance(objects, list)
        or not 1 <= len(objects) <= 32_767
        or not isinstance(files, list)
        or not 1 <= len(files) <= 32_767
        or not isinstance(modules, list)
        or not 1 <= len(modules) <= 4_096
        or not isinstance(debug_artifacts, list)
        or not 1 <= len(debug_artifacts) <= 4_096
    ):
        raise schema_invalid()
    _validate_launch(value["launch"])
    object_kinds = _validate_objects(objects, value["total_bytes"])
    file_digests = _validate_files(files, object_kinds)
    module_digests = _validate_modules(modules, file_digests, object_kinds)
    _validate_debug_artifacts(
        debug_artifacts, file_digests, object_kinds, module_digests
    )
    launch = value["launch"]
    if not any(
        file["path"] == launch["executable"] and file["executable"] is True
        for file in files
    ):
        raise schema_invalid()


def _validate_launch(value: object) -> None:
    from collections.abc import Mapping

    if not isinstance(value, Mapping) or set(value) != {
        "arguments",
        "environment_names",
        "executable",
        "working_directory",
    }:
        raise schema_invalid()
    arguments = value["arguments"]
    names = value["environment_names"]
    if (
        not isinstance(arguments, list)
        or len(arguments) > MAX_ARGUMENTS
        or any(
            not isinstance(argument, str) or len(argument) > 4_096
            for argument in arguments
        )
        or not isinstance(names, list)
        or len(names) > MAX_ENVIRONMENT_NAMES
        or any(names[index] >= names[index + 1] for index in range(len(names) - 1))
        or any(
            not isinstance(name, str)
            or not name
            or len(name) > 256
            or "=" in name
            or not all(33 <= ord(character) <= 126 for character in name)
            for name in names
        )
        or not _valid_subject_path(value["executable"])
        or not _valid_subject_path(value["working_directory"])
    ):
        raise schema_invalid()


def _validate_objects(objects: list, total_bytes: object) -> dict[str, str]:
    kinds = {}
    total = 0
    previous = None
    for entry in objects:
        if not isinstance(entry, dict) or set(entry) != {
            "digest",
            "kind",
            "media_type",
            "size",
        }:
            raise schema_invalid()
        size = entry["size"]
        media_type = entry["media_type"]
        if (
            type(size) is not int
            or size < 0
            or size > MAX_SUBJECT_OBJECT_BYTES
            or not isinstance(media_type, str)
            or not media_type
            or len(media_type) > 128
            or entry["kind"]
            not in (
                "application",
                "debug-artifact",
                "launch-data",
                "module-identity",
                "native-dependency",
                "runtime",
            )
        ):
            raise schema_invalid()
        if previous is not None and previous >= entry["digest"]:
            raise schema_invalid()
        previous = entry["digest"]
        total += size
        kinds[entry["digest"]] = entry["kind"]
    if total != total_bytes or total > MAX_SUBJECT_OBJECT_BYTES:
        raise schema_invalid()
    return kinds


def _validate_files(files: list, object_kinds: dict[str, str]) -> dict[str, str]:
    digests = {}
    previous = None
    for entry in files:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"executable", "object_digest", "path"}
            or not isinstance(entry["executable"], bool)
            or not _valid_subject_path(entry["path"])
            or entry["object_digest"] not in object_kinds
        ):
            raise schema_invalid()
        if previous is not None and previous >= entry["path"]:
            raise schema_invalid()
        previous = entry["path"]
        digests[entry["path"]] = entry["object_digest"]
    return digests


def _validate_modules(
    modules: list, file_digests: dict[str, str], object_kinds: dict[str, str]
) -> set[str]:
    module_digests = set()
    previous = None
    for entry in modules:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"identity", "module_digest", "path"}
            or not isinstance(entry["identity"], str)
            or not entry["identity"]
            or len(entry["identity"]) > 512
            or not _valid_subject_path(entry["path"])
            or file_digests.get(entry["path"]) != entry["module_digest"]
            or entry["module_digest"] not in object_kinds
        ):
            raise schema_invalid()
        if previous is not None and previous >= entry["path"]:
            raise schema_invalid()
        previous = entry["path"]
        module_digests.add(entry["module_digest"])
    return module_digests


def _validate_debug_artifacts(
    debug_artifacts: list,
    file_digests: dict[str, str],
    object_kinds: dict[str, str],
    module_digests: set[str],
) -> None:
    previous = None
    for entry in debug_artifacts:
        if not isinstance(entry, dict) or set(entry) != {
            "artifact_digest",
            "kind",
            "module_digest",
            "path",
        }:
            raise schema_invalid()
        kind = entry["kind"]
        artifact_kind = object_kinds.get(entry["artifact_digest"])
        if kind == "interpreted-source-identity":
            valid_kind = artifact_kind is not None
        elif kind == "dwarf" and entry["artifact_digest"] == entry["module_digest"]:
            valid_kind = artifact_kind is not None
        elif kind in ("dwarf", "portable-pdb", "source-map"):
            valid_kind = artifact_kind == "debug-artifact"
        else:
            valid_kind = False
        if (
            not _valid_subject_path(entry["path"])
            or file_digests.get(entry["path"]) != entry["artifact_digest"]
            or not valid_kind
            or entry["module_digest"] not in module_digests
        ):
            raise schema_invalid()
        if previous is not None and previous >= entry["path"]:
            raise schema_invalid()
        previous = entry["path"]


def _valid_subject_path(path: object) -> bool:
    if not isinstance(path, str) or not path.startswith("/reproit/subject/"):
        return False
    relative = path[len("/reproit/subject/") :]
    return (
        bool(relative)
        and len(path) <= 4_096
        and "\x00" not in path
        and all(part and part not in (".", "..") for part in relative.split("/"))
    )


def subject_binding(manifest: dict[str, object]) -> dict[str, object]:
    """Build the deployment Subject descriptor bound to this manifest."""
    launch = manifest["launch"]
    manifest_digest = canonical_digest(manifest)
    return {
        "architecture": manifest["architecture"],
        "arguments": list(launch["arguments"]),
        "artifact_digest": manifest_digest,
        "artifact_media_type": "application/vnd.reproit.subject-closure.v1+json",
        "artifact_uri": f"reproit-managed://{manifest_digest}",
        "environment_names": list(launch["environment_names"]),
        "executable": launch["executable"],
        "format": "reproit.subject.v1",
        "operating_system": manifest["operating_system"],
        "working_directory": launch["working_directory"],
    }


def _digest_name(digest: str) -> str:
    return digest.removeprefix("sha256:")


def _subject_unbounded() -> ManagedError:
    return ManagedError(
        "UPLOAD_LIMIT_EXCEEDED",
        "The running Python subject exceeds a Backend v1 bound.",
    )


def _subject_unsupported() -> ManagedError:
    return ManagedError(
        "UNSUPPORTED",
        "The running Python subject has an unsupported file or launch identity.",
    )


def _unsupported_host() -> ManagedError:
    return ManagedError(
        "UNSUPPORTED",
        "This host cannot package a Backend v1 Python production subject.",
    )
