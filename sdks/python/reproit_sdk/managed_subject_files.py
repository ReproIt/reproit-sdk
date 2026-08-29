"""Bounded filesystem capture for an exact managed Python subject."""

from __future__ import annotations

import ast
import ctypes
import hashlib
import importlib.metadata
import importlib.util
import os
import platform
import re
import stat
import sys
import sysconfig
import tempfile
import weakref
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from .encoding import canonical_bytes
from .process_resources import PROCESS_RESOURCES
from .subject_protocol import ManagedError, digest_bytes

COPY_BUFFER_BYTES = 64 * 1024
MAX_CAPTURED_FILES = 32_764
MAX_CAPTURED_MODULES = 4_095
MAX_DEPENDENCIES = 4_096
MAX_DISCOVERED_PATHS = 65_536
MAX_RUNTIME_FILES = 32_767
MAX_SUBJECT_OBJECT_BYTES = 512 * 1024 * 1024
MAX_SUBJECT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SUBJECT_PATH_BYTES = 4_096
MAX_LINUX_MAPS_BYTES = 1_048_576
MAX_NATIVE_MODULE_PATH_CODE_UNITS = 32_767

_IGNORED_DIRECTORY_NAMES = frozenset({"__pycache__"})
_IGNORED_DEPENDENCY_NAMES = frozenset({"REQUESTED", "py.typed"})
_REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_RUNTIME_SUBJECT_ROOT = "/reproit/subject/runtime/python"


@dataclass(frozen=True)
class CapturedPythonFile:
    digest: str
    executable: bool
    kind: str
    module: bool
    path: str
    size: int
    spool_path: str


@dataclass(frozen=True)
class CapturedPythonFiles:
    dependencies: dict[str, object]
    entry_path: str
    files: tuple[CapturedPythonFile, ...]
    interpreter: dict[str, object]
    interpreter_path: str
    reserved_bytes: int


@dataclass(frozen=True)
class _StableIdentity:
    digest: str
    mode: int
    size: int


class _ClosureBuilder:
    def __init__(self, spool_path: str, subject_root: str):
        self._files: dict[str, CapturedPythonFile] = {}
        self._objects: dict[str, tuple[str, int, str]] = {}
        self._spool_path = spool_path
        self._subject_root = subject_root
        self._discovered_paths = 0
        self._total_bytes = 0
        self._reserved_bytes = 0
        self._reservation = [0]
        self._reservation_finalizer = weakref.finalize(
            self, _release_subject_reservation, self._reservation
        )
        self._modules = 0

    @property
    def files(self) -> tuple[CapturedPythonFile, ...]:
        return tuple(self._files[path] for path in sorted(self._files))

    def record_discovery(self) -> None:
        self._discovered_paths += 1
        if self._discovered_paths > MAX_DISCOVERED_PATHS:
            raise _subject_unbounded()

    def capture(
        self,
        source_path: str,
        relative_path: str,
        *,
        allow_empty: bool = False,
        base_path: str | None = None,
        entry: bool = False,
        executable: bool | None = None,
        kind: str | None = None,
        module: bool = False,
    ) -> CapturedPythonFile:
        if len(self._files) >= MAX_CAPTURED_FILES:
            raise _subject_unbounded()
        relative = _valid_relative_path(relative_path)
        subject_path = f"{base_path or self._subject_root}/{relative}"
        if not subject_path.startswith("/reproit/subject/"):
            raise _subject_unsupported()
        object_kind = kind or (
            "native-dependency" if _is_native_extension(relative) else "application"
        )
        if len(subject_path) > MAX_SUBJECT_PATH_BYTES:
            raise _subject_unbounded()
        if subject_path in self._files:
            existing = self._files[subject_path]
            identity = _hash_stable_file(source_path, allow_empty=allow_empty)
            if (
                identity.digest != existing.digest
                or identity.size != existing.size
                or object_kind != existing.kind
            ):
                raise _subject_unsupported()
            return existing
        remaining = MAX_SUBJECT_TOTAL_BYTES - self._total_bytes
        identity, spool_path, reserved_bytes = _spool_stable_file(
            source_path,
            self._spool_path,
            remaining,
            allow_empty=allow_empty,
        )
        self._reserved_bytes += reserved_bytes
        self._reservation[0] += reserved_bytes
        existing_object = self._objects.get(identity.digest)
        if existing_object is not None:
            if existing_object[1] != identity.size:
                raise _subject_unsupported()
            object_kind = _merged_object_kind(existing_object[0], object_kind)
            self._objects[identity.digest] = (
                object_kind,
                identity.size,
                existing_object[2],
            )
            for path, captured_file in self._files.items():
                if captured_file.digest == identity.digest:
                    self._files[path] = replace(captured_file, kind=object_kind)
            spool_path = existing_object[2]
        else:
            self._objects[identity.digest] = (
                object_kind,
                identity.size,
                spool_path,
            )
            self._total_bytes += identity.size
        if module:
            self._modules += 1
            if self._modules > MAX_CAPTURED_MODULES:
                raise _subject_unbounded()
        captured = CapturedPythonFile(
            digest=identity.digest,
            executable=(entry or bool(identity.mode & 0o111))
            if executable is None
            else executable,
            kind=object_kind,
            module=module,
            path=subject_path,
            size=identity.size,
            spool_path=spool_path,
        )
        self._files[subject_path] = captured
        return captured


def capture_python_subject_files(
    entry_script: str,
    application_root: str | None,
    spool_path: str,
) -> CapturedPythonFiles:
    """Capture one bounded application, dependency, and runtime identity."""
    entry_script = _regular_path(entry_script)
    entry_identity = _hash_stable_file(entry_script, allow_empty=False)
    subject_root = (
        f"/reproit/subject/application/{entry_identity.digest.removeprefix('sha256:')}"
    )
    builder = _ClosureBuilder(spool_path, subject_root)
    if application_root is None:
        imported_names = _validate_implicit_application(entry_script)
        relative_entry = os.path.basename(entry_script)
        builder.capture(entry_script, relative_entry, entry=True, module=True)
        root = None
    else:
        root = _application_root(application_root, entry_script)
        imported_names = _capture_application_root(builder, root, entry_script)
        relative_entry = os.path.relpath(entry_script, root)
    interpreter, interpreter_path, dependency_root = _capture_interpreter(builder)
    dependencies = _capture_installed_distributions(
        builder,
        imported_names,
        root,
        dependency_root,
    )
    entry_path = f"{subject_root}/{_valid_relative_path(relative_entry)}"
    captured = CapturedPythonFiles(
        dependencies,
        entry_path,
        builder.files,
        interpreter,
        interpreter_path,
        builder._reserved_bytes,
    )
    builder._reservation_finalizer.detach()
    return captured


def _release_subject_reservation(reservation: list[int]) -> None:
    if reservation[0] > 0:
        PROCESS_RESOURCES.release_logical(reservation[0])
        reservation[0] = 0


def _capture_application_root(
    builder: _ClosureBuilder,
    root: str,
    entry_script: str,
) -> set[str]:
    entry_seen = False
    python_sources = []
    for directory, names, file_names in os.walk(
        root,
        topdown=True,
        onerror=_walk_error,
        followlinks=False,
    ):
        directory_before = _required_directory_metadata(directory)
        names.sort()
        file_names.sort()
        kept_names = []
        for name in names:
            builder.record_discovery()
            path = os.path.join(directory, name)
            _required_directory_metadata(path)
            if name not in _IGNORED_DIRECTORY_NAMES:
                kept_names.append(name)
        names[:] = kept_names
        for name in file_names:
            builder.record_discovery()
            source = os.path.join(directory, name)
            if name.endswith((".pyc", ".pyo")):
                continue
            relative = os.path.relpath(source, root)
            is_entry = os.path.abspath(source) == entry_script
            entry_seen = entry_seen or is_entry
            builder.capture(
                source,
                relative,
                allow_empty=True,
                entry=is_entry,
                module=is_entry or name.endswith(".py"),
            )
            if is_entry or name.endswith(".py"):
                python_sources.append(source)
        _verify_directory_unchanged(directory, directory_before)
    if not entry_seen:
        raise _subject_unsupported()
    return _collect_import_roots(python_sources, allow_relative=True)


def _capture_installed_distributions(
    builder: _ClosureBuilder,
    imported_names: set[str],
    application_root: str | None,
    dependency_root: str,
) -> dict[str, object]:
    distributions = []
    installed = list(importlib.metadata.distributions())
    if len(installed) > MAX_DEPENDENCIES:
        raise _subject_unbounded()
    by_name = _select_installed_distributions(installed)
    package_distributions = importlib.metadata.packages_distributions()
    roots_by_distribution = _roots_by_distribution(package_distributions)
    required = set()
    for imported_name in imported_names:
        if imported_name in sys.stdlib_module_names:
            continue
        if application_root is not None and _local_import_exists(
            application_root, imported_name
        ):
            continue
        names = package_distributions.get(imported_name)
        if not names:
            raise _subject_unsupported()
        required.update(_normalized_distribution_name(name) for name in names)
    queue = sorted(required)
    while queue:
        dependency_name = queue.pop()
        distribution = by_name.get(dependency_name)
        if distribution is None:
            continue
        for requirement in distribution.requires or ():
            match = _REQUIREMENT_NAME.match(requirement)
            if match is None:
                raise _subject_unreadable()
            required_name = _normalized_distribution_name(match.group(0))
            if required_name in by_name and required_name not in required:
                required.add(required_name)
                queue.append(required_name)
    for dependency_name in sorted(required):
        distribution = by_name.get(dependency_name)
        if distribution is None:
            raise _subject_unreadable()
        name = distribution.metadata["Name"]
        version = distribution.version
        files = distribution.files
        if files is None:
            raise _subject_unreadable()
        for package_path in sorted(files, key=str):
            relative = PurePosixPath(str(package_path))
            if _ignored_dependency_path(relative):
                continue
            if relative.is_absolute() or ".." in relative.parts:
                continue
            source = os.fspath(distribution.locate_file(package_path))
            builder.capture(
                source,
                relative.as_posix(),
                allow_empty=True,
                base_path=dependency_root,
                executable=False,
                module=relative.suffix == ".py" or _is_native_extension(str(relative)),
            )
        for root_name in sorted(roots_by_distribution.get(dependency_name, ())):
            _capture_import_root(builder, root_name, dependency_root)
        distributions.append({"name": name, "version": version})
    distributions.sort(key=lambda entry: (entry["name"].casefold(), entry["version"]))
    return {
        "distributions": distributions,
        "format": "reproit.python-dependency-closure.v2",
        "site_packages_path": dependency_root,
    }


def _validate_implicit_application(entry_script: str) -> set[str]:
    imported_names = _collect_import_roots([entry_script], allow_relative=False)
    installed_names = importlib.metadata.packages_distributions()
    entry_directory = os.path.dirname(entry_script)
    for root_name in imported_names:
        if root_name in sys.stdlib_module_names or root_name in installed_names:
            continue
        local_file = os.path.join(entry_directory, f"{root_name}.py")
        local_package = os.path.join(entry_directory, root_name, "__init__.py")
        if os.path.exists(local_file) or os.path.exists(local_package):
            raise _subject_root_required()
        raise _subject_unsupported()
    return imported_names


def _collect_import_roots(
    source_paths: list[str],
    *,
    allow_relative: bool,
) -> set[str]:
    imported_names = set()
    for source_path in source_paths:
        imported_names.update(_source_import_roots(source_path, allow_relative))
    return imported_names


def _source_import_roots(source_path: str, allow_relative: bool) -> set[str]:
    try:
        with open(source_path, "rb") as source:
            parsed = ast.parse(source.read(), filename=source_path)
    except (OSError, SyntaxError, ValueError) as error:
        raise _subject_unreadable() from error
    imported_names = set()
    for node in ast.walk(parsed):
        if isinstance(node, ast.ImportFrom) and node.level and not allow_relative:
            raise _subject_root_required()
        if isinstance(node, ast.Import):
            imported = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported = [node.module]
        else:
            imported = []
        for module_name in imported:
            root_name = module_name.partition(".")[0]
            imported_names.add(root_name)
        if isinstance(node, ast.Call) and _is_dynamic_import(node.func):
            raise _subject_root_required()
    return imported_names


def _local_import_exists(application_root: str, imported_name: str) -> bool:
    module_path = os.path.join(application_root, f"{imported_name}.py")
    package_path = os.path.join(application_root, imported_name, "__init__.py")
    return os.path.isfile(module_path) or os.path.isfile(package_path)


def _roots_by_distribution(
    package_distributions: dict[str, list[str]],
) -> dict[str, set[str]]:
    roots: dict[str, set[str]] = {}
    for root_name, distribution_names in package_distributions.items():
        if not root_name.isidentifier() or not isinstance(distribution_names, list):
            raise _subject_unreadable()
        for distribution_name in distribution_names:
            normalized = _normalized_distribution_name(distribution_name)
            roots.setdefault(normalized, set()).add(root_name)
    return roots


def _capture_import_root(
    builder: _ClosureBuilder,
    root_name: str,
    dependency_root: str,
) -> None:
    try:
        specification = importlib.util.find_spec(root_name)
    except (AttributeError, ImportError, ModuleNotFoundError, ValueError) as error:
        raise _subject_unreadable() from error
    if specification is None:
        raise _subject_unreadable()
    locations = specification.submodule_search_locations
    if locations is not None:
        captured = False
        for location in sorted(set(os.fspath(path) for path in locations)):
            builder.record_discovery()
            _capture_dependency_tree(
                builder,
                _regular_directory(location),
                root_name,
                dependency_root,
            )
            captured = True
        if not captured:
            raise _subject_unsupported()
        return
    origin = specification.origin
    if origin in (None, "built-in", "frozen"):
        raise _subject_unsupported()
    builder.record_discovery()
    builder.capture(
        _regular_path(origin),
        os.path.basename(origin),
        allow_empty=True,
        base_path=dependency_root,
        executable=False,
        module=True,
    )


def _capture_dependency_tree(
    builder: _ClosureBuilder,
    root: str,
    root_name: str,
    dependency_root: str,
) -> None:
    for directory, names, file_names in os.walk(
        root,
        topdown=True,
        onerror=_walk_error,
        followlinks=False,
    ):
        directory_before = _required_directory_metadata(directory)
        names.sort()
        file_names.sort()
        kept_names = []
        for name in names:
            builder.record_discovery()
            path = os.path.join(directory, name)
            _required_directory_metadata(path)
            if name not in _IGNORED_DIRECTORY_NAMES:
                kept_names.append(name)
        names[:] = kept_names
        for name in file_names:
            builder.record_discovery()
            source = os.path.join(directory, name)
            relative = PurePosixPath(os.path.relpath(source, root))
            dependency_path = PurePosixPath(root_name, relative)
            if _ignored_dependency_path(dependency_path):
                continue
            builder.capture(
                source,
                dependency_path.as_posix(),
                allow_empty=True,
                base_path=dependency_root,
                executable=False,
                module=(
                    dependency_path.suffix == ".py"
                    or _is_native_extension(str(dependency_path))
                ),
            )
        _verify_directory_unchanged(directory, directory_before)


def _normalized_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _select_installed_distributions(installed) -> dict[str, object]:
    """Select the active distribution by deterministic import-path order."""
    search_paths = tuple(_canonical_search_path(entry) for entry in sys.path)
    grouped: dict[str, list[tuple[int, str, tuple[object, ...], object]]] = {}
    for distribution in installed:
        name = distribution.metadata.get("Name")
        version = distribution.version
        files = distribution.files
        if not name or not version or files is None:
            raise _subject_unreadable()
        root = os.path.realpath(os.fspath(distribution.locate_file("")))
        if not os.path.isabs(root):
            raise _subject_unreadable()
        try:
            rank = search_paths.index(root)
        except ValueError:
            rank = len(search_paths)
        fingerprint = (
            root,
            name.casefold(),
            version,
            tuple(sorted(str(path) for path in files)),
        )
        key = _normalized_distribution_name(name)
        grouped.setdefault(key, []).append((rank, root, fingerprint, distribution))
    selected = {}
    for key, candidates in grouped.items():
        unique = {candidate[2]: candidate for candidate in candidates}
        ordered = sorted(unique.values(), key=lambda candidate: candidate[:3])
        first = ordered[0]
        active = [
            candidate
            for candidate in ordered
            if candidate[0] == first[0] and candidate[1] == first[1]
        ]
        if len(active) != 1 or (len(ordered) > 1 and first[0] == len(search_paths)):
            raise _subject_unsupported()
        selected[key] = first[3]
    return selected


def _canonical_search_path(value: str) -> str:
    path = value if value else os.getcwd()
    return os.path.realpath(path)


def _merged_object_kind(existing: str, requested: str) -> str:
    ranks = {"application": 0, "runtime": 1, "native-dependency": 2}
    if existing not in ranks or requested not in ranks:
        raise _subject_unsupported()
    return max((existing, requested), key=ranks.__getitem__)


def _is_dynamic_import(function: ast.expr) -> bool:
    if isinstance(function, ast.Name):
        return function.id == "__import__"
    return isinstance(function, ast.Attribute) and function.attr == "import_module"


def _capture_interpreter(
    builder: _ClosureBuilder,
) -> tuple[dict[str, object], str, str]:
    implementation = platform.python_implementation().lower()
    version = platform.python_version()
    runtime_root = _regular_directory(os.path.realpath(sys.base_prefix))
    executable = _runtime_member(runtime_root, os.path.realpath(sys.executable))
    stdlib = _regular_directory(sysconfig.get_path("stdlib"))
    executable_file = _capture_runtime_file(
        builder,
        runtime_root,
        executable,
        entry=True,
    )
    entries = {executable_file.path: _runtime_entry(executable_file)}
    library_directory = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    if isinstance(library_directory, str) and isinstance(library_name, str):
        library_path = os.path.join(library_directory, library_name)
        if os.path.exists(library_path):
            captured = _capture_runtime_file(builder, runtime_root, library_path)
            entries[captured.path] = _runtime_entry(captured)
    for captured in _capture_runtime_tree(builder, runtime_root, stdlib):
        entries[captured.path] = _runtime_entry(captured)
    for captured in _capture_runtime_native_roots(builder, runtime_root):
        entries[captured.path] = _runtime_entry(captured)
    for captured in _capture_loaded_native_modules(builder, runtime_root):
        entries[captured.path] = _runtime_entry(captured)
    ordered_entries = [entries[path] for path in sorted(entries)]
    if len(ordered_entries) > MAX_RUNTIME_FILES:
        raise _subject_unbounded()
    closure_bytes = canonical_bytes(
        {"files": ordered_entries, "format": "reproit.python-runtime-closure.v1"}
    )
    closure_digest = digest_bytes(closure_bytes)
    identity = {
        "abi_flags": sys.abiflags,
        "byte_order": sys.byteorder,
        "cache_tag": sys.implementation.cache_tag,
        "executable_digest": executable_file.digest,
        "executable_size": executable_file.size,
        "format": "reproit.python-interpreter-identity.v2",
        "identity": f"{implementation}-{version}-{closure_digest}",
        "implementation": implementation,
        "platform": sysconfig.get_platform(),
        "runtime_closure_digest": closure_digest,
        "runtime_file_count": len(ordered_entries),
        "runtime_files": ordered_entries,
        "runtime_total_bytes": sum(entry["size"] for entry in ordered_entries),
        "soabi": sysconfig.get_config_var("SOABI") or "",
        "version": version,
    }
    stdlib_relative = os.path.relpath(stdlib, runtime_root).replace(os.sep, "/")
    dependency_root = f"{_RUNTIME_SUBJECT_ROOT}/{stdlib_relative}/site-packages"
    return identity, executable_file.path, dependency_root


def _capture_runtime_tree(
    builder: _ClosureBuilder,
    runtime_root: str,
    root: str,
) -> list[CapturedPythonFile]:
    captured_files = []
    for directory, names, file_names in os.walk(
        root,
        topdown=True,
        onerror=_walk_error,
        followlinks=False,
    ):
        directory_before = _required_directory_metadata(directory)
        names.sort()
        file_names.sort()
        kept_names = []
        for name in names:
            builder.record_discovery()
            path = os.path.join(directory, name)
            _required_directory_metadata(path)
            if name not in _IGNORED_DIRECTORY_NAMES and name not in (
                "site-packages",
                "dist-packages",
            ):
                kept_names.append(name)
        names[:] = kept_names
        for name in file_names:
            if name.endswith((".pyc", ".pyo")):
                continue
            builder.record_discovery()
            if len(captured_files) >= MAX_RUNTIME_FILES:
                raise _subject_unbounded()
            source = os.path.join(directory, name)
            captured_files.append(_capture_runtime_file(builder, runtime_root, source))
        _verify_directory_unchanged(directory, directory_before)
    return captured_files


def _capture_runtime_native_roots(
    builder: _ClosureBuilder,
    runtime_root: str,
) -> list[CapturedPythonFile]:
    captured = []
    roots = {os.path.dirname(os.path.realpath(sys.executable))}
    library_directory = sysconfig.get_config_var("LIBDIR")
    if isinstance(library_directory, str):
        roots.add(library_directory)
    dll_directory = os.path.join(runtime_root, "DLLs")
    if os.path.isdir(dll_directory):
        roots.add(dll_directory)
    for root in sorted(roots):
        root = _regular_directory(root)
        directory_before = _required_directory_metadata(root)
        try:
            names = sorted(os.listdir(root))
        except OSError as error:
            raise _subject_unreadable() from error
        for name in names:
            source = os.path.join(root, name)
            if not _is_native_extension(name) or not os.path.isfile(source):
                continue
            builder.record_discovery()
            captured.append(_capture_runtime_file(builder, runtime_root, source))
        _verify_directory_unchanged(root, directory_before)
    return captured


def _capture_runtime_file(
    builder: _ClosureBuilder,
    runtime_root: str,
    source_path: str,
    *,
    entry: bool = False,
) -> CapturedPythonFile:
    source = _runtime_member(runtime_root, os.path.realpath(source_path))
    original = _runtime_member(runtime_root, os.path.abspath(source_path))
    relative = os.path.relpath(original, runtime_root).replace(os.sep, "/")
    runtime_path = f"runtime/python/{_valid_relative_path(relative)}"
    kind = "native-dependency" if _is_native_extension(runtime_path) else "runtime"
    return builder.capture(
        source,
        runtime_path,
        allow_empty=True,
        base_path="/reproit/subject",
        entry=entry,
        executable=entry,
        kind=kind,
        module=kind == "native-dependency",
    )


def _capture_loaded_native_modules(
    builder: _ClosureBuilder,
    runtime_root: str,
) -> list[CapturedPythonFile]:
    paths = _loaded_native_module_paths()
    captured = []
    for source in sorted(paths):
        try:
            inside_runtime = os.path.commonpath((runtime_root, source)) == runtime_root
        except ValueError as error:
            raise _subject_unsupported() from error
        if inside_runtime:
            continue
        identity = _hash_stable_file(source, allow_empty=False)
        relative = (
            f"{identity.digest.removeprefix('sha256:')}/{os.path.basename(source)}"
        )
        is_loader = os.path.basename(source).startswith(("ld-linux-", "ld-musl-"))
        builder.record_discovery()
        captured.append(
            builder.capture(
                source,
                relative,
                base_path="/reproit/subject/native",
                executable=is_loader,
                kind="native-dependency",
                module=True,
            )
        )
    if _loaded_native_module_paths() != paths:
        raise _subject_changing()
    return captured


def _loaded_native_module_paths() -> set[str]:
    if sys.platform.startswith("linux"):
        return _loaded_linux_module_paths()
    if sys.platform == "darwin":
        return _loaded_macos_module_paths()
    if sys.platform == "win32":
        return _loaded_windows_module_paths()
    raise _subject_unsupported()


def _loaded_linux_module_paths() -> set[str]:
    try:
        with open("/proc/self/maps", "rb") as source:
            value = source.read(MAX_LINUX_MAPS_BYTES + 1)
    except OSError as error:
        raise _subject_unreadable() from error
    if len(value) > MAX_LINUX_MAPS_BYTES:
        raise _subject_unbounded()
    try:
        lines = value.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise _subject_unsupported() from error
    paths = set()
    for line in lines:
        if line.endswith(" (deleted)"):
            raise _subject_changing()
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or "x" not in fields[1]:
            continue
        path = fields[5]
        if path.startswith("/"):
            paths.add(os.path.realpath(path))
        if len(paths) > MAX_RUNTIME_FILES:
            raise _subject_unbounded()
    return paths


def _loaded_macos_module_paths() -> set[str]:
    try:
        process = ctypes.CDLL(None)
        image_count = process._dyld_image_count
        image_count.argtypes = []
        image_count.restype = ctypes.c_uint32
        image_name = process._dyld_get_image_name
        image_name.argtypes = [ctypes.c_uint32]
        image_name.restype = ctypes.c_char_p
        count = image_count()
    except (AttributeError, OSError) as error:
        raise _subject_unreadable() from error
    if count == 0 or count > MAX_RUNTIME_FILES:
        raise _subject_unbounded()
    paths: set[str] = set()
    for index in range(count):
        raw = image_name(index)
        if raw is None:
            raise _subject_unreadable()
        source = os.path.realpath(os.fsdecode(raw))
        if not os.path.isabs(source):
            raise _subject_unsupported()
        if source.startswith(("/System/Library/", "/usr/lib/")):
            continue
        paths.add(source)
    return paths


def _loaded_windows_module_paths() -> set[str]:
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.EnumProcessModules.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        psapi.EnumProcessModules.restype = ctypes.c_int
        psapi.GetModuleFileNameExW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar),
            ctypes.c_ulong,
        ]
        psapi.GetModuleFileNameExW.restype = ctypes.c_ulong
        process = kernel32.GetCurrentProcess()
        modules = (ctypes.c_void_p * MAX_RUNTIME_FILES)()
        needed = ctypes.c_ulong()
        buffer_bytes = ctypes.sizeof(modules)
        if not psapi.EnumProcessModules(
            process,
            modules,
            buffer_bytes,
            ctypes.byref(needed),
        ):
            raise _subject_unreadable()
        pointer_bytes = ctypes.sizeof(ctypes.c_void_p)
        if (
            needed.value == 0
            or needed.value > buffer_bytes
            or needed.value % pointer_bytes != 0
        ):
            raise _subject_unbounded()
        count = needed.value // pointer_bytes
        system_root = os.environ.get("SystemRoot")
        if not system_root or not os.path.isabs(system_root):
            raise _subject_unsupported()
        system_root = os.path.normcase(os.path.realpath(system_root))
        paths: set[str] = set()
        for index in range(count):
            buffer = ctypes.create_unicode_buffer(
                MAX_NATIVE_MODULE_PATH_CODE_UNITS
            )
            length = psapi.GetModuleFileNameExW(
                process,
                modules[index],
                buffer,
                len(buffer),
            )
            if length == 0 or length >= len(buffer):
                raise _subject_unreadable()
            source = os.path.realpath(buffer.value)
            if not os.path.isabs(source):
                raise _subject_unsupported()
            normalized = os.path.normcase(source)
            try:
                inside_system = (
                    os.path.commonpath((system_root, normalized))
                    == system_root
                )
            except ValueError as error:
                raise _subject_unsupported() from error
            if not inside_system:
                paths.add(source)
        return paths
    except OSError as error:
        raise _subject_unreadable() from error


def _runtime_member(runtime_root: str, path: str) -> str:
    try:
        common = os.path.commonpath((runtime_root, path))
    except ValueError as error:
        raise _subject_unsupported() from error
    if common != runtime_root:
        raise _subject_unsupported()
    return path


def _runtime_entry(captured: CapturedPythonFile) -> dict[str, object]:
    return {
        "digest": captured.digest,
        "executable": captured.executable,
        "kind": captured.kind,
        "path": captured.path,
        "size": captured.size,
    }


def _spool_stable_file(
    source_path: str,
    spool_path: str,
    remaining_bytes: int,
    *,
    allow_empty: bool,
) -> tuple[_StableIdentity, str, int]:
    metadata = _required_regular_metadata(source_path)
    if metadata.st_size == 0 and not allow_empty:
        raise _subject_unsupported()
    if (
        metadata.st_size > remaining_bytes
        or metadata.st_size > MAX_SUBJECT_OBJECT_BYTES
    ):
        raise _subject_unbounded()
    if not PROCESS_RESOURCES.reserve_logical(metadata.st_size):
        raise _subject_unbounded()
    reserved = True
    descriptor, temporary = tempfile.mkstemp(prefix=".subject-", dir=spool_path)
    hasher = hashlib.sha256()
    copied = 0
    try:
        with os.fdopen(descriptor, "wb") as target, open(source_path, "rb") as source:
            opened = os.fstat(source.fileno())
            if not _same_file(metadata, opened):
                raise _subject_changing()
            while True:
                chunk = source.read(COPY_BUFFER_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > metadata.st_size:
                    raise _subject_changing()
                target.write(chunk)
                hasher.update(chunk)
            final_open = os.fstat(source.fileno())
        final_path = os.lstat(source_path)
        if copied != metadata.st_size or not _same_file(metadata, final_open):
            raise _subject_changing()
        if not _same_file(metadata, final_path):
            raise _subject_changing()
        digest = f"sha256:{hasher.hexdigest()}"
        destination = os.path.join(spool_path, digest.removeprefix("sha256:"))
        if os.path.exists(destination):
            os.unlink(temporary)
            PROCESS_RESOURCES.release_logical(metadata.st_size)
            reserved = False
        else:
            os.replace(temporary, destination)
        return (
            _StableIdentity(digest, metadata.st_mode, copied),
            destination,
            metadata.st_size if reserved else 0,
        )
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        if reserved:
            PROCESS_RESOURCES.release_logical(metadata.st_size)
        raise


def _hash_stable_file(path: str, *, allow_empty: bool) -> _StableIdentity:
    metadata = _required_regular_metadata(path)
    if metadata.st_size == 0 and not allow_empty:
        raise _subject_unsupported()
    if metadata.st_size > MAX_SUBJECT_OBJECT_BYTES:
        raise _subject_unbounded()
    hasher = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as source:
            opened = os.fstat(source.fileno())
            if not _same_file(metadata, opened):
                raise _subject_changing()
            while True:
                chunk = source.read(COPY_BUFFER_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > metadata.st_size:
                    raise _subject_changing()
                hasher.update(chunk)
            final_open = os.fstat(source.fileno())
        final_path = os.lstat(path)
    except OSError as error:
        raise _subject_unreadable() from error
    if total != metadata.st_size or not _same_file(metadata, final_open):
        raise _subject_changing()
    if not _same_file(metadata, final_path):
        raise _subject_changing()
    return _StableIdentity(f"sha256:{hasher.hexdigest()}", metadata.st_mode, total)


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        stat.S_ISREG(after.st_mode)
        and before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
    )


def _required_directory_metadata(path: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise _subject_unreadable() from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise _subject_unsupported()
    return metadata


def _verify_directory_unchanged(path: str, before: os.stat_result) -> None:
    after = _required_directory_metadata(path)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise _subject_changing()


def _walk_error(error: OSError) -> None:
    raise _subject_unreadable() from error


def _application_root(application_root: str, entry_script: str) -> str:
    root = _regular_directory(application_root)
    try:
        common = os.path.commonpath((root, entry_script))
    except ValueError as error:
        raise _subject_unsupported() from error
    if common != root:
        raise _subject_unsupported()
    return root


def _regular_directory(path: str | None) -> str:
    if not isinstance(path, str) or not path:
        raise _subject_unsupported()
    _required_directory_metadata(path)
    return os.path.realpath(path)


def _regular_path(path: str | None) -> str:
    if not isinstance(path, str) or not path:
        raise _subject_unsupported()
    try:
        original = os.lstat(path)
    except OSError as error:
        raise _subject_unreadable() from error
    if stat.S_ISLNK(original.st_mode) or not stat.S_ISREG(original.st_mode):
        raise _subject_unsupported()
    absolute = os.path.realpath(path)
    _required_regular_metadata(absolute)
    return absolute


def _required_regular_metadata(path: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise _subject_unreadable() from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise _subject_unsupported()
    return metadata


def _valid_relative_path(value: str) -> str:
    normalized = value.replace(os.sep, "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise _subject_unsupported()
    return path.as_posix()


def _ignored_dependency_path(path: PurePosixPath) -> bool:
    if any(part == "__pycache__" for part in path.parts):
        return True
    if path.suffix in (".pyc", ".pyo"):
        return True
    return path.name in _IGNORED_DEPENDENCY_NAMES


def _is_native_extension(path: str) -> bool:
    suffixes = tuple(
        suffix
        for suffix in (
            sysconfig.get_config_var("EXT_SUFFIX"),
            ".so",
            ".dylib",
            ".dll",
            ".pyd",
        )
        if suffix
    )
    return path.endswith(suffixes) or ".so." in os.path.basename(path)


def _subject_unreadable() -> ManagedError:
    return ManagedError(
        "INCOMPLETE_CANDIDATE",
        "The running Python subject is not completely readable.",
    )


def _subject_changing() -> ManagedError:
    return ManagedError(
        "INCOMPLETE_CANDIDATE",
        "The running Python subject changed during local packaging.",
    )


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


def _subject_root_required() -> ManagedError:
    return ManagedError(
        "UNSUPPORTED",
        "The running Python subject requires one explicit application root.",
    )
