#!/usr/bin/env python3
"""Build one native SDK engine artifact and create its verified release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ABI_CONTRACT_FORMAT = "reproit.sdk-engine-abi.v1"
ARTIFACT_MANIFEST_FORMAT = "reproit.sdk-engine-artifacts.v1"
ARTIFACT_MANIFEST_NAME = "sdk-engine-artifacts.json"
ENGINE_PACKAGE = "reproit-sdk-engine"
MAX_ABI_CONTRACT_BYTES = 16_384
MAX_ARTIFACT_BYTES = 512 * 1_024 * 1_024
MAX_ARTIFACTS = 2
MAX_MANIFEST_BYTES = 4_096
BUILD_TIMEOUT_SECONDS = 1_800
NODE_LOADER_NAME = "reproit-sdk-engine-loader.node"


class ReleaseError(Exception):
    """Report one bounded release construction failure."""


@dataclass(frozen=True)
class Target:
    product: str
    rust: str
    engine_file: str


TARGETS = {
    "linux-arm64": Target(
        "linux-arm64", "aarch64-unknown-linux-gnu", "libreproit_sdk_engine.so"
    ),
    "linux-x86_64": Target(
        "linux-x86_64", "x86_64-unknown-linux-gnu", "libreproit_sdk_engine.so"
    ),
    "macos-arm64": Target(
        "macos-arm64", "aarch64-apple-darwin", "libreproit_sdk_engine.dylib"
    ),
    "windows-x86_64": Target(
        "windows-x86_64", "x86_64-pc-windows-msvc", "reproit_sdk_engine.dll"
    ),
}


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_file(path: Path) -> str:
    size = path.stat().st_size
    if size <= 0 or size > MAX_ARTIFACT_BYTES:
        raise ReleaseError("An artifact has an invalid size.")
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        while chunk := artifact.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def host_target() -> str | None:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin" and machine in {"arm64", "aarch64"}:
        return "macos-arm64"
    if system == "linux" and machine in {"arm64", "aarch64"}:
        return "linux-arm64"
    if system == "linux" and machine in {"amd64", "x86_64"}:
        return "linux-x86_64"
    if system == "windows" and machine in {"amd64", "x86_64"}:
        return "windows-x86_64"
    return None


def load_abi_contract(workspace: Path) -> tuple[bytes, dict[str, object]]:
    path = workspace / "crates" / ENGINE_PACKAGE / "sdk-engine-abi.json"
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_ABI_CONTRACT_BYTES:
            raise ReleaseError("The SDK engine ABI contract has an invalid size.")
        raw = path.read_bytes()
        contract = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError("The SDK engine ABI contract is unavailable.") from error
    if not isinstance(contract, dict) or contract.get("format") != ABI_CONTRACT_FORMAT:
        raise ReleaseError("The SDK engine ABI contract has an invalid format.")
    libraries = contract.get("libraries")
    expected = [
        {"name": target.engine_file, "platform": target.product}
        for target in TARGETS.values()
    ]
    expected.sort(key=lambda value: value["platform"])
    if libraries != expected:
        raise ReleaseError("The SDK engine ABI contract has unexpected library names.")
    return raw, contract


def validate_workspace(workspace: Path, output_root: Path) -> None:
    if not (workspace / "Cargo.toml").is_file():
        raise ReleaseError("The Repro It workspace is unavailable.")
    try:
        output_root.relative_to(workspace)
    except ValueError as error:
        raise ReleaseError("The release output must stay inside the workspace.") from error


def copy_artifact(source: Path, destination: Path, role: str) -> dict[str, object]:
    if not source.is_file() or source.is_symlink():
        raise ReleaseError("A release artifact is unavailable.")
    size = source.stat().st_size
    digest = sha256_file(source)
    shutil.copyfile(source, destination)
    if destination.stat().st_size != size or sha256_file(destination) != digest:
        raise ReleaseError("A staged release artifact changed during copy.")
    return {
        "digest": digest,
        "file": destination.name,
        "role": role,
        "size": size,
    }


def validate_existing_release(release: Path, manifest_bytes: bytes) -> None:
    manifest_path = release / ARTIFACT_MANIFEST_NAME
    try:
        if manifest_path.read_bytes() != manifest_bytes:
            raise ReleaseError("A digest-named release contains a different manifest.")
        manifest = json.loads(manifest_bytes)
        expected_files = {ARTIFACT_MANIFEST_NAME}
        for artifact in manifest["artifacts"]:
            path = release / artifact["file"]
            expected_files.add(artifact["file"])
            if path.stat().st_size != artifact["size"]:
                raise ReleaseError("A released artifact has an invalid size.")
            if sha256_file(path) != artifact["digest"]:
                raise ReleaseError("A released artifact has an invalid digest.")
        actual_files = {path.name for path in release.iterdir() if path.is_file()}
        if actual_files != expected_files or any(path.is_dir() for path in release.iterdir()):
            raise ReleaseError("A digest-named release contains unexpected files.")
    except (KeyError, OSError, json.JSONDecodeError, TypeError) as error:
        raise ReleaseError("A digest-named release is invalid.") from error


def build_release(
    workspace: Path,
    output_root: Path,
    product_target: str,
    node_loader: Path | None = None,
) -> tuple[str, Path]:
    workspace = workspace.resolve()
    output_root = output_root.resolve()
    validate_workspace(workspace, output_root)
    target = TARGETS.get(product_target)
    if target is None:
        raise ReleaseError("The requested SDK engine target is unsupported.")
    if host_target() != product_target:
        raise ReleaseError("Build the SDK engine on its matching native host.")
    abi_bytes, _ = load_abi_contract(workspace)

    if node_loader is not None:
        node_loader = node_loader.resolve()
        if node_loader.name != NODE_LOADER_NAME:
            raise ReleaseError("The Node loader filename is invalid.")

    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(workspace / "target")
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "--target",
        target.rust,
        "--package",
        ENGINE_PACKAGE,
    ]
    try:
        subprocess.run(
            command,
            cwd=workspace,
            env=environment,
            check=True,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseError("The native SDK engine build failed.") from error

    engine = workspace / "target" / target.rust / "release" / target.engine_file
    if not engine.is_file() or engine.name != target.engine_file:
        raise ReleaseError("Cargo produced an unexpected SDK engine artifact.")

    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".staging-", dir=output_root) as temporary:
        bundle = Path(temporary) / "bundle"
        bundle.mkdir()
        artifacts = [copy_artifact(engine, bundle / target.engine_file, "engine")]
        if node_loader is not None:
            if len(artifacts) >= MAX_ARTIFACTS:
                raise ReleaseError("The release contains too many artifacts.")
            artifacts.append(copy_artifact(node_loader, bundle / NODE_LOADER_NAME, "node-loader"))
        artifacts.sort(key=lambda value: (value["role"], value["file"]))
        manifest = {
            "abi_contract_digest": sha256_bytes(abi_bytes),
            "artifacts": artifacts,
            "format": ARTIFACT_MANIFEST_FORMAT,
            "target": product_target,
        }
        manifest_bytes = canonical_json(manifest)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ReleaseError("The SDK engine artifact manifest is too large.")
        (bundle / ARTIFACT_MANIFEST_NAME).write_bytes(manifest_bytes)

        manifest_digest = sha256_bytes(manifest_bytes)
        release = output_root / manifest_digest.replace(":", "-")
        if release.exists():
            validate_existing_release(release, manifest_bytes)
        else:
            bundle.replace(release)
    return manifest_digest, release


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build one native Repro It SDK engine release."
    )
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--node-loader", type=Path)
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    workspace = Path(__file__).resolve().parents[2]
    output_root = workspace / "target" / "sdk-engine-releases"
    try:
        digest, _ = build_release(
            workspace,
            output_root,
            options.target,
            options.node_loader,
        )
    except ReleaseError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Built {options.target} SDK engine release {digest}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
