from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from reproit_sdk import (
    automatic_adapters,
    managed_subject,
    managed_subject_files,
    subject_protocol,
)
from reproit_sdk.managed_subject import (
    PythonSubjectPackage,
    package_running_python_subject,
    validate_subject_closure_manifest,
)
from reproit_sdk.managed_subject_files import _select_installed_distributions


class Distribution:
    def __init__(
        self,
        root: str,
        name: str,
        version: str,
        files: tuple[str, ...],
    ) -> None:
        self._root = root
        self.metadata = {"Name": name}
        self.version = version
        self.files = tuple(PurePosixPath(value) for value in files)

    def locate_file(self, path: PurePosixPath) -> Path:
        return Path(self._root, os.fspath(path))


class DistributionDiscoveryTests(unittest.TestCase):
    def test_normalized_name_selects_the_first_import_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory, "first")
            second = Path(directory, "second")
            first.mkdir()
            second.mkdir()
            active = Distribution(
                str(first),
                "Example_Package",
                "1.0",
                ("example.py",),
            )
            shadowed = Distribution(
                str(second),
                "example-package",
                "2.0",
                ("example.py",),
            )
            duplicate = Distribution(
                str(first),
                "Example_Package",
                "1.0",
                ("example.py",),
            )
            with mock.patch.object(sys, "path", [str(first), str(second)]):
                selected = _select_installed_distributions(
                    [shadowed, duplicate, active]
                )
        self.assertEqual(set(selected), {"example-package"})
        self.assertEqual(selected["example-package"].version, "1.0")

    def test_ambiguous_distribution_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            cases = (
                (
                    [
                        Distribution(
                            str(first), "example", "1.0", ("example.py",)
                        ),
                        Distribution(
                            str(first), "example", "2.0", ("example.py",)
                        ),
                    ],
                    [str(first)],
                ),
                (
                    [
                        Distribution(
                            str(first), "example", "1.0", ("example.py",)
                        ),
                        Distribution(
                            str(second), "example", "2.0", ("example.py",)
                        ),
                    ],
                    [],
                ),
            )
            for distributions, search_path in cases:
                with (
                    self.subTest(search_path=search_path),
                    mock.patch.object(sys, "path", search_path),
                    self.assertRaises(subject_protocol.ManagedError) as raised,
                ):
                    _select_installed_distributions(distributions)
                self.assertEqual(raised.exception.code, "UNSUPPORTED")


class ManagedSubjectPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.application.cleanup)
        root = Path(cls.application.name)
        package_root = root / "orders"
        package_root.mkdir()
        cls.script = root / "main.py"
        cls.script.write_text(
            "from orders.value import read_value\nprint(read_value())\n",
            encoding="utf-8",
        )
        (package_root / "__init__.py").write_text(
            "APPLICATION = 'orders'\n",
            encoding="utf-8",
        )
        (package_root / "value.py").write_text(
            "from pathlib import Path\n"
            "def read_value():\n"
            "    return Path(__file__).with_name('value.txt').read_text().strip()\n",
            encoding="utf-8",
        )
        (package_root / "value.txt").write_text(
            "captured-value\n",
            encoding="utf-8",
        )
        (root / "empty.txt").touch()
        cls.subject = cls._package(cls.script, root)
        cls.addClassCleanup(cls.subject.close)

    @staticmethod
    def _package(script: Path, root: Path) -> PythonSubjectPackage:
        with (
            mock.patch.object(sys, "argv", [str(script)]),
            mock.patch.object(
                sys,
                "orig_argv",
                [sys.executable, str(script)],
                create=True,
            ),
        ):
            return package_running_python_subject(str(script), str(root))

    def test_manifest_is_complete_and_content_addressed(self) -> None:
        manifest = self.subject.manifest
        validate_subject_closure_manifest(manifest)
        self.assertEqual(manifest["format"], "reproit.subject-closure.v1")
        self.assertEqual(manifest["runtime_family"], "python")
        manifest_objects = {
            entry["digest"]: entry for entry in manifest["objects"]
        }
        packaged_objects = {
            entry.digest: entry for entry in self.subject.objects
        }
        self.assertEqual(set(manifest_objects), set(packaged_objects))
        for digest, packaged in packaged_objects.items():
            content = Path(packaged.path).read_bytes()
            self.assertEqual(subject_protocol.digest_bytes(content), digest)
            self.assertEqual(len(content), packaged.size)
            self.assertEqual(manifest_objects[digest]["size"], packaged.size)
        self.assertEqual(
            manifest["total_bytes"],
            sum(entry["size"] for entry in manifest_objects.values()),
        )
        file_digests = {
            entry["object_digest"] for entry in manifest["files"]
        }
        self.assertTrue(file_digests <= set(manifest_objects))
        self.assertTrue(
            any(
                entry["path"] == manifest["launch"]["executable"]
                and entry["executable"]
                for entry in manifest["files"]
            )
        )

    def test_application_root_replays_local_imports_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as replay_directory:
            replay_root = Path(replay_directory)
            destinations = self._materialize_application(replay_root)
            script_path = next(
                destination
                for source, destination in destinations.items()
                if source.endswith("/main.py")
            )
            completed = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=script_path.parent,
                capture_output=True,
                check=False,
                timeout=30,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b"captured-value\n")

    def test_interpreter_identity_binds_the_runtime_closure(self) -> None:
        identity = self._subject_json(
            "/reproit/subject/python/interpreter.json"
        )
        self.assertEqual(
            identity["format"],
            "reproit.python-interpreter-identity.v2",
        )
        self.assertRegex(
            identity["runtime_closure_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertIn(identity["runtime_closure_digest"], identity["identity"])
        runtime_files = identity["runtime_files"]
        self.assertEqual(identity["runtime_file_count"], len(runtime_files))
        self.assertGreater(identity["runtime_file_count"], 0)
        self.assertEqual(
            identity["runtime_total_bytes"],
            sum(entry["size"] for entry in runtime_files),
        )
        executable = self.subject.manifest["launch"]["executable"]
        executable_file = next(
            entry
            for entry in self.subject.manifest["files"]
            if entry["path"] == executable
        )
        self.assertEqual(
            identity["executable_digest"],
            executable_file["object_digest"],
        )
        python_prefix = "/reproit/subject/runtime/python/"
        native_prefix = "/reproit/subject/native/"
        self.assertTrue(
            all(
                entry["path"].startswith((python_prefix, native_prefix))
                for entry in runtime_files
            )
        )
        self.assertTrue(
            any(entry["path"].startswith(python_prefix) for entry in runtime_files)
        )

    def test_empty_application_file_is_preserved(self) -> None:
        empty_file = next(
            entry
            for entry in self.subject.manifest["files"]
            if entry["path"].endswith("/empty.txt")
        )
        empty_object = next(
            entry
            for entry in self.subject.manifest["objects"]
            if entry["digest"] == empty_file["object_digest"]
        )
        packaged = next(
            entry
            for entry in self.subject.objects
            if entry.digest == empty_file["object_digest"]
        )
        self.assertEqual(empty_object["size"], 0)
        self.assertEqual(packaged.size, 0)
        self.assertEqual(
            empty_file["object_digest"],
            subject_protocol.digest_bytes(b""),
        )

    def test_imported_distribution_files_are_included(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            script.write_text(
                "import reproit_sdk.automatic_adapters\n",
                encoding="utf-8",
            )
            subject = self._package(script, root)
            try:
                paths = {
                    entry["path"] for entry in subject.manifest["files"]
                }
                dependencies = self._subject_json_from(
                    subject,
                    "/reproit/subject/python/dependencies.json",
                )
                names = {
                    entry["name"].replace("_", "-").lower()
                    for entry in dependencies["distributions"]
                }
                self.assertEqual(
                    dependencies["format"],
                    "reproit.python-dependency-closure.v2",
                )
                self.assertIn("reproit-sdk", names)
                self.assertTrue(
                    any(
                        path.endswith("/reproit_sdk/__init__.py")
                        for path in paths
                    )
                )
                self.assertTrue(
                    all(
                        path.startswith(dependencies["site_packages_path"] + "/")
                        for path in paths
                        if "/reproit_sdk/" in path
                    )
                )
                module_digests = {
                    entry["module_digest"]
                    for entry in subject.manifest["modules"]
                }
                self.assertIn(
                    automatic_adapters._IMPLEMENTATION_DIGEST,
                    module_digests,
                )
            finally:
                subject.close()

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            target = root / "target.txt"
            target.write_text("target\n", encoding="utf-8")
            (root / "linked.txt").symlink_to(target)
            with self.assertRaises(subject_protocol.ManagedError) as raised:
                self._package(script, root)
        self.assertEqual(raised.exception.code, "UNSUPPORTED")

    def test_changing_entry_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            with (
                mock.patch(
                    "reproit_sdk.managed_subject_files._same_file",
                    return_value=False,
                ),
                self.assertRaises(subject_protocol.ManagedError) as raised,
            ):
                self._package(script, root)
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")

    def test_changing_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            changing = subject_protocol.ManagedError(
                "INCOMPLETE_CANDIDATE",
                "The running Python subject changed during local packaging.",
            )
            with (
                mock.patch(
                    "reproit_sdk.managed_subject_files._verify_directory_unchanged",
                    side_effect=changing,
                ),
                self.assertRaises(subject_protocol.ManagedError) as raised,
            ):
                self._package(script, root)
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")

    def test_changing_loaded_module_set_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime_root = root / "runtime"
            runtime_root.mkdir()
            first = root / "libfirst.so"
            second = root / "libsecond.so"
            first.write_bytes(b"first native module")
            second.write_bytes(b"second native module")
            spool = root / "spool"
            spool.mkdir()
            builder = managed_subject_files._ClosureBuilder(
                str(spool),
                "/reproit/subject/application/test",
            )
            try:
                with (
                    mock.patch.object(
                        managed_subject_files.sys,
                        "platform",
                        "linux",
                    ),
                    mock.patch(
                        "reproit_sdk.managed_subject_files._loaded_linux_module_paths",
                        side_effect=[
                            {str(first)},
                            {str(first), str(second)},
                        ],
                    ),
                    self.assertRaises(
                        subject_protocol.ManagedError
                    ) as raised,
                ):
                    managed_subject_files._capture_loaded_native_modules(
                        builder,
                        str(runtime_root),
                    )
            finally:
                builder._reservation_finalizer()
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")

    def test_subject_size_policy_constants_are_exact(self) -> None:
        object_bytes = 512 * 1024 * 1024
        total_bytes = 2 * 1024 * 1024 * 1024
        self.assertEqual(managed_subject.MAX_SUBJECT_OBJECT_BYTES, object_bytes)
        self.assertEqual(managed_subject.MAX_SUBJECT_TOTAL_BYTES, total_bytes)
        self.assertEqual(
            managed_subject_files.MAX_SUBJECT_OBJECT_BYTES,
            object_bytes,
        )
        self.assertEqual(
            managed_subject_files.MAX_SUBJECT_TOTAL_BYTES,
            total_bytes,
        )

    def _materialize_application(
        self,
        replay_root: Path,
    ) -> dict[str, Path]:
        objects = {entry.digest: entry.path for entry in self.subject.objects}
        destinations = {}
        for entry in self.subject.manifest["files"]:
            source_path = entry["path"]
            if "/application/" not in source_path:
                continue
            relative = source_path.removeprefix("/reproit/subject/")
            destination = replay_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(
                Path(objects[entry["object_digest"]]).read_bytes()
            )
            destinations[source_path] = destination
        return destinations

    def _subject_json(self, path: str) -> dict[str, object]:
        return self._subject_json_from(self.subject, path)

    @staticmethod
    def _subject_json_from(
        subject: PythonSubjectPackage,
        path: str,
    ) -> dict[str, object]:
        descriptor = next(
            entry for entry in subject.manifest["files"] if entry["path"] == path
        )
        packaged = next(
            entry
            for entry in subject.objects
            if entry.digest == descriptor["object_digest"]
        )
        value = json.loads(Path(packaged.path).read_bytes())
        if not isinstance(value, dict):
            raise AssertionError("The subject metadata object must be a map.")
        return value
