from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from reproit_sdk.register import _USAGE_ERROR

_SCRIPT_SOURCE = """
import json
import sys
import time
from unittest import mock

from reproit_sdk import automatic_adapters, engine_operation


class Subject:
    manifest = {}
    objects = []

    def close(self):
        pass


class Bridge:
    def contract(self):
        pass

    def engine_open(self, **values):
        return 7

    def engine_close(self, handle):
        pass


before = automatic_adapters._OPEN_PROJECTS
with mock.patch.object(
    engine_operation,
    "package_running_python_subject",
    return_value=Subject(),
):
    project = engine_operation.ManagedEngineProject._open_with(
        project_toml="[project]",
        build_repository_id="repository",
        source_revision="revision",
        project_token_provider=lambda: "unused-test-value",
        entry_script=__file__,
        application_root=None,
        bridge=Bridge(),
    )
    during = automatic_adapters._OPEN_PROJECTS
    project.close()
after = automatic_adapters._OPEN_PROJECTS
print(json.dumps({
    "argv": sys.argv,
    "file": __file__,
    "hook": time.time_ns is automatic_adapters._time_ns,
    "leases": [before, during, after],
    "name": __name__,
    "path0": sys.path[0],
    "spec_is_none": __spec__ is None,
}, sort_keys=True))
"""

_MODULE_SOURCE = """
import json
import sys
import time

from reproit_sdk import automatic_adapters

print(json.dumps({
    "argv": sys.argv,
    "file": __file__,
    "hook": time.time_ns is automatic_adapters._time_ns,
    "leases": automatic_adapters._OPEN_PROJECTS,
    "name": __name__,
    "path0": sys.path[0],
    "spec_name": __spec__.name,
}, sort_keys=True))
"""


class RegisterLaunchTests(unittest.TestCase):
    def test_script_starts_with_hooks_and_preserves_python_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "application.py"
            script.write_text(_SCRIPT_SOURCE, encoding="utf-8")
            completed = self._run(root, str(script), "first", "--flag")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["argv"], [str(script), "first", "--flag"])
        self.assertEqual(result["file"], str(script))
        self.assertEqual(result["name"], "__main__")
        self.assertTrue(result["spec_is_none"])
        self.assertEqual(result["path0"], str(root))
        self.assertTrue(result["hook"])
        self.assertEqual(result["leases"], [1, 2, 1])

    def test_module_starts_with_hooks_and_preserves_python_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "launch_fixture"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            module = package / "application.py"
            module.write_text(_MODULE_SOURCE, encoding="utf-8")
            completed = self._run(
                root,
                "-m",
                "launch_fixture.application",
                "second",
                "--value",
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["argv"], [str(module.resolve()), "second", "--value"]
        )
        self.assertEqual(result["file"], str(module.resolve()))
        self.assertEqual(result["name"], "__main__")
        self.assertEqual(result["spec_name"], "launch_fixture.application")
        self.assertEqual(result["path0"], str(root.resolve()))
        self.assertTrue(result["hook"])
        self.assertEqual(result["leases"], 1)

    def test_application_exit_status_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "failure.py"
            script.write_text("raise SystemExit(17)\n", encoding="utf-8")
            completed = self._run(root, str(script))
        self.assertEqual(completed.returncode, 17)

    def test_invalid_and_unbounded_forms_use_one_error(self) -> None:
        cases = (
            (),
            ("application.py",),
            ("--",),
            ("--", "-c", "print('value')"),
            ("--", "-m"),
            ("--", "-m", "-invalid"),
            ("--", "-m", "orders.café"),
            ("extra", "--", "application.py"),
            ("--", "application.py\nsecond.py"),
            ("--", "application.py", *("value" for _ in range(127))),
            ("--", "application.py", "x" * 4_097),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for arguments in cases:
                with self.subTest(arguments=arguments[:3]):
                    completed = self._run_raw(root, *arguments)
                    self.assertEqual(completed.returncode, 2)
                    self.assertEqual(completed.stdout, "")
                    self.assertEqual(completed.stderr, f"{_USAGE_ERROR}\n")

    def test_wheel_contains_the_startup_module(self) -> None:
        source_root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build_root = root / "source"
            build_root.mkdir()
            shutil.copy2(source_root / "README.md", build_root / "README.md")
            shutil.copy2(source_root / "pyproject.toml", build_root / "pyproject.toml")
            shutil.copytree(source_root / "reproit_sdk", build_root / "reproit_sdk")
            output = root / "dist"
            completed = subprocess.run(
                ["uv", "build", str(build_root), "--out-dir", str(output)],
                capture_output=True,
                check=False,
                text=True,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            wheel = next(output.glob("*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                self.assertIn("reproit_sdk/register.py", archive.namelist())

    @staticmethod
    def _run(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return RegisterLaunchTests._run_raw(root, "--", *arguments)

    @staticmethod
    def _run_raw(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "reproit_sdk.register", *arguments],
            cwd=root,
            capture_output=True,
            check=False,
            text=True,
            timeout=60,
        )


if __name__ == "__main__":
    unittest.main()
