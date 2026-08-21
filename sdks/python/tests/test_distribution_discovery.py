import os
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from reproit_sdk import managed_protocol
from reproit_sdk.managed_subject_files import _select_installed_distributions


class Distribution:
    def __init__(self, root: str, name: str, version: str, files: tuple[str, ...]):
        self._root = root
        self.metadata = {"Name": name}
        self.version = version
        self.files = tuple(PurePosixPath(value) for value in files)

    def locate_file(self, path):
        return Path(self._root, os.fspath(path))


class DistributionDiscoveryTests(unittest.TestCase):
    def test_shadowed_normalized_distribution_selects_first_import_path(self):
        with tempfile.TemporaryDirectory() as directory:
            first = str(Path(directory, "first"))
            second = str(Path(directory, "second"))
            Path(first).mkdir()
            Path(second).mkdir()
            active = Distribution(first, "Example_Package", "1.0", ("example.py",))
            shadowed = Distribution(second, "example-package", "2.0", ("example.py",))
            with mock.patch("sys.path", [first, second]):
                selected = _select_installed_distributions([shadowed, active])
            self.assertIs(selected["example-package"], active)

    def test_exact_duplicate_metadata_is_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            distribution = Distribution(directory, "example", "1.0", ("example.py",))
            duplicate = Distribution(directory, "example", "1.0", ("example.py",))
            with mock.patch("sys.path", [directory]):
                selected = _select_installed_distributions([duplicate, distribution])
            self.assertEqual(selected["example"].version, "1.0")

    def test_same_active_root_with_distinct_metadata_fails_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Distribution(directory, "example", "1.0", ("example.py",))
            second = Distribution(directory, "example", "2.0", ("example.py",))
            with (
                mock.patch("sys.path", [directory]),
                self.assertRaises(managed_protocol.ManagedError) as raised,
            ):
                _select_installed_distributions([second, first])
            self.assertEqual(raised.exception.code, "UNSUPPORTED")

    def test_unranked_distinct_distributions_fail_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory, "first")
            second = Path(directory, "second")
            first.mkdir()
            second.mkdir()
            candidates = [
                Distribution(str(first), "example", "1.0", ("example.py",)),
                Distribution(str(second), "example", "2.0", ("example.py",)),
            ]
            with (
                mock.patch("sys.path", []),
                self.assertRaises(managed_protocol.ManagedError) as raised,
            ):
                _select_installed_distributions(candidates)
            self.assertEqual(raised.exception.code, "UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
