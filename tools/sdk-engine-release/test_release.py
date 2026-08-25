import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("release.py")
SPEC = importlib.util.spec_from_file_location("sdk_engine_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


class ReleaseBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name)
        (self.workspace / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        contract = SCRIPT.parents[2] / "crates/reproit-sdk-engine/sdk-engine-abi.json"
        destination = self.workspace / "crates/reproit-sdk-engine/sdk-engine-abi.json"
        destination.parent.mkdir(parents=True)
        destination.write_bytes(contract.read_bytes())
        self.output = self.workspace / "target/sdk-engine-releases"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_build_stages_one_verified_canonical_bundle(self) -> None:
        target = release.TARGETS["macos-arm64"]
        loader = self.workspace / release.NODE_LOADER_NAME
        loader.write_bytes(b"node-loader")
        calls = []

        def cargo(command, **options):
            calls.append((command, options))
            artifact = (
                self.workspace
                / "target"
                / target.rust
                / "release"
                / target.engine_file
            )
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"engine")

        with (
            mock.patch.object(release, "host_target", return_value="macos-arm64"),
            mock.patch.object(release.subprocess, "run", side_effect=cargo),
        ):
            digest, bundle = release.build_release(
                self.workspace, self.output, "macos-arm64", loader
            )

        self.assertEqual(len(calls), 1)
        self.assertEqual(bundle.name, digest.replace(":", "-"))
        manifest_bytes = (bundle / release.ARTIFACT_MANIFEST_NAME).read_bytes()
        self.assertEqual(release.sha256_bytes(manifest_bytes), digest)
        manifest = json.loads(manifest_bytes)
        self.assertEqual(
            manifest,
            {
                "abi_contract_digest": release.sha256_bytes(
                    (
                        self.workspace
                        / "crates/reproit-sdk-engine/sdk-engine-abi.json"
                    ).read_bytes()
                ),
                "artifacts": [
                    {
                        "digest": release.sha256_bytes(b"engine"),
                        "file": target.engine_file,
                        "role": "engine",
                        "size": 6,
                    },
                    {
                        "digest": release.sha256_bytes(b"node-loader"),
                        "file": release.NODE_LOADER_NAME,
                        "role": "node-loader",
                        "size": 11,
                    },
                ],
                "format": release.ARTIFACT_MANIFEST_FORMAT,
                "target": "macos-arm64",
            },
        )
        self.assertFalse(any(path.name.startswith(".staging-") for path in self.output.iterdir()))

    def test_non_native_and_unknown_targets_are_rejected_before_build(self) -> None:
        with mock.patch.object(release, "host_target", return_value="linux-arm64"):
            with self.assertRaisesRegex(release.ReleaseError, "matching native host"):
                release.build_release(self.workspace, self.output, "macos-arm64")
        with self.assertRaisesRegex(release.ReleaseError, "unsupported"):
            release.build_release(self.workspace, self.output, "freebsd-x86_64")

    def test_unexpected_filenames_are_rejected(self) -> None:
        loader = self.workspace / "unexpected.node"
        loader.write_bytes(b"loader")
        with mock.patch.object(release, "host_target", return_value="macos-arm64"):
            with self.assertRaisesRegex(release.ReleaseError, "loader filename"):
                release.build_release(self.workspace, self.output, "macos-arm64", loader)

        contract_path = self.workspace / "crates/reproit-sdk-engine/sdk-engine-abi.json"
        contract = json.loads(contract_path.read_bytes())
        contract["libraries"][0]["name"] = "unexpected.so"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        with mock.patch.object(release, "host_target", return_value="macos-arm64"):
            with self.assertRaisesRegex(release.ReleaseError, "unexpected library names"):
                release.build_release(self.workspace, self.output, "macos-arm64")


if __name__ == "__main__":
    unittest.main()
