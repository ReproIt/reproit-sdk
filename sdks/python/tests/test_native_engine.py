from __future__ import annotations

import base64
import copy
import ctypes
import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import reproit_sdk
from reproit_sdk.native_engine import (
    ABI_VERSION,
    ABI_CONTRACT_DIGEST,
    ARTIFACT_MANIFEST_FORMAT,
    RESPONSE_CAPACITY,
    NativeEngineBridge,
    NativeEngineCallError,
    NativeDependencyHandle,
    NativeEngineError,
    NativeEngineHandle,
    NativeObservationHandle,
    NativeOperationHandle,
    NativeSinkHandle,
    _validate_artifact_manifest,
)

ABI_PATH = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "reproit-sdk-engine"
    / "sdk-engine-abi.json"
)
ABI_CONTRACT = json.loads(ABI_PATH.read_bytes())
SUCCESS = json.dumps(
    {
        "error_code": None,
        "format": "reproit.sdk-engine-response.v1",
        "ok": True,
        "result": ABI_CONTRACT,
    },
    separators=(",", ":"),
    sort_keys=True,
).encode()


class FakeFunction:
    def __init__(self, operation):
        self.operation = operation
        self.argtypes = None
        self.restype = None

    def __call__(self, *arguments):
        return self.operation(*arguments)


class FakeLibrary:
    def __init__(
        self,
        response: bytes | Callable[[dict[str, object]], bytes] = SUCCESS,
        *,
        abi_version: int = ABI_VERSION,
        written: int | None = None,
    ):
        self.response = response
        self.requests: list[dict[str, object]] = []
        self.written = written
        self.reproit_sdk_engine_abi_version = FakeFunction(lambda: abi_version)
        self.reproit_sdk_engine_call = FakeFunction(self._call)

    def _call(self, input_pointer, input_length, output_pointer, output_capacity):
        request_bytes = ctypes.string_at(input_pointer, input_length)
        request = json.loads(request_bytes)
        self.requests.append(request)
        response = self.response(request) if callable(self.response) else self.response
        written = len(response) if self.written is None else self.written
        if 0 <= written <= output_capacity and len(response) >= written:
            ctypes.memmove(output_pointer, response, written)
        return written


def engine_response(
    result: dict[str, object],
    *,
    error_code: str | None = None,
) -> bytes:
    return json.dumps(
        {
            "error_code": error_code,
            "format": "reproit.sdk-engine-response.v1",
            "ok": error_code is None,
            "result": result,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def artifact_manifest(file: str, content: bytes) -> dict[str, object]:
    return {
        "abi_contract_digest": ABI_CONTRACT_DIGEST,
        "artifacts": [
            {
                "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
                "file": file,
                "role": "engine",
                "size": len(content),
            }
        ],
        "format": ARTIFACT_MANIFEST_FORMAT,
        "target": "linux-arm64",
    }


class NativeEngineBridgeTests(unittest.TestCase):
    def test_typed_bridge_is_not_exported_from_the_package(self):
        self.assertFalse(hasattr(reproit_sdk, "NativeEngineBridge"))
        self.assertFalse(hasattr(reproit_sdk, "NativeEngineCallError"))

    def test_contract_uses_abi_version_one_and_the_exact_json_call(self):
        library = FakeLibrary()
        response = NativeEngineBridge(library).contract()
        self.assertEqual(response["result"], ABI_CONTRACT)
        self.assertEqual(
            library.requests,
            [{"format": "reproit.sdk-engine-call.v1", "operation": "contract"}],
        )

    def test_real_engine_returns_the_full_contract_when_available(self):
        library_name = {
            "darwin": "libreproit_sdk_engine.dylib",
            "linux": "libreproit_sdk_engine.so",
        }.get(__import__("sys").platform)
        target = Path(__file__).resolve().parents[3] / "target"
        platform_release = {
            "darwin": target / "aarch64-apple-darwin" / "release",
            "linux": target / "release",
        }.get(__import__("sys").platform, target / "release")
        library_path = platform_release / (library_name or "")
        if library_name is None or not library_path.is_file():
            self.skipTest("A native shared SDK engine is not built on this host.")
        bridge = NativeEngineBridge(ctypes.CDLL(str(library_path)))
        self.assertEqual(bridge.contract()["result"], ABI_CONTRACT)

    def test_abi_version_mismatch_is_rejected(self):
        with self.assertRaises(NativeEngineError):
            NativeEngineBridge(FakeLibrary(abi_version=2)).contract()

    def test_contract_rejects_changed_observation_rules(self):
        invalid_contracts = []
        missing_operation = copy.deepcopy(ABI_CONTRACT)
        missing_operation["operations"].remove("observation-read")
        invalid_contracts.append(missing_operation)
        wrong_limit = copy.deepcopy(ABI_CONTRACT)
        wrong_limit["limits"]["observation_response_read_bytes"] = 8_193
        invalid_contracts.append(wrong_limit)
        wrong_action = copy.deepcopy(ABI_CONTRACT)
        wrong_action["observation_actions"] = ["capture", "unknown"]
        invalid_contracts.append(wrong_action)
        missing_class = copy.deepcopy(ABI_CONTRACT)
        missing_class["required_observation_classes"].remove("queue")
        invalid_contracts.append(missing_class)
        reordered_classes = copy.deepcopy(ABI_CONTRACT)
        reordered_classes["required_observation_classes"].reverse()
        invalid_contracts.append(reordered_classes)
        added_class = copy.deepcopy(ABI_CONTRACT)
        added_class["required_observation_classes"].append("extra")
        invalid_contracts.append(added_class)
        wrong_fields = copy.deepcopy(ABI_CONTRACT)
        wrong_fields["observation_contract"]["read_result_fields"] = ["chunk"]
        invalid_contracts.append(wrong_fields)
        wrong_error_behavior = copy.deepcopy(ABI_CONTRACT)
        wrong_error_behavior["error_behavior"]["json_error"][
            "includes_request"
        ] = True
        invalid_contracts.append(wrong_error_behavior)

        for contract in invalid_contracts:
            with self.subTest(contract=contract):
                with self.assertRaises(NativeEngineError):
                    NativeEngineBridge(
                        FakeLibrary(engine_response(contract))
                    ).contract()

    def test_missing_packaged_library_has_a_fixed_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "libreproit_sdk_engine.so"
            with mock.patch(
                "reproit_sdk.native_engine._packaged_library_path",
                return_value=missing,
            ):
                with mock.patch(
                    "reproit_sdk.native_engine.ctypes.CDLL",
                    side_effect=OSError("private local path"),
                ):
                    with self.assertRaises(NativeEngineError) as raised:
                        NativeEngineBridge.load()
        self.assertEqual(
            str(raised.exception),
            "The packaged shared SDK engine is unavailable.",
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_malformed_response_is_rejected_without_echo(self):
        secret = "do-not-echo-this-secret"
        with self.assertRaises(NativeEngineError) as raised:
            NativeEngineBridge(FakeLibrary(secret.encode())).contract()
        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(
            str(raised.exception),
            "The shared SDK engine response is invalid.",
        )

    def test_response_one_byte_over_the_bound_is_rejected(self):
        oversized = b"x" * (RESPONSE_CAPACITY + 1)
        with self.assertRaises(NativeEngineError) as raised:
            NativeEngineBridge(
                FakeLibrary(oversized, written=RESPONSE_CAPACITY + 1)
            ).contract()
        self.assertEqual(
            str(raised.exception),
            "The shared SDK engine response is invalid.",
        )

    def test_native_failure_does_not_echo_request_values(self):
        bridge = NativeEngineBridge(FakeLibrary(written=-1))
        secret = "local-project-token-value"
        with self.assertRaises(NativeEngineError) as raised:
            bridge.call(
                {
                    "format": "reproit.sdk-engine-call.v1",
                    "operation": "unknown",
                    "project_token": secret,
                }
            )
        self.assertNotIn(secret, str(raised.exception))

    def test_typed_calls_cover_the_shared_engine_lifecycle(self):
        results = {
            "dependency-open": {"action": "capture", "dependency_handle": 15},
            "dependency-finish": {"outcome": "response"},
            "engine-open": {"engine_handle": 11},
            "engine-close": {},
            "observation-open": {
                "observation_handle": 14,
                "session_position": 0,
            },
            "observation-write": {},
            "observation-dispatch": {"action": "replay"},
            "observation-read": {"chunk": "", "eof": True},
            "observation-finish": {},
            "observation-abandon": {},
            "operation-begin": {
                "operation_handle": 12,
                "operation_id": "operation-id",
            },
            "operation-input": {},
            "operation-unowned": {},
            "operation-close-world": {},
            "operation-succeed": {},
            "operation-abandon": {},
            "operation-fail": {"sink_handle": 13},
            "sink-wait": {"idle": True},
        }
        library = FakeLibrary(lambda request: engine_response(results[request["operation"]]))
        bridge = NativeEngineBridge(library)

        engine = bridge.engine_open(
            build_repository_id="repository",
            project_toml="format = 1",
            source_revision="revision",
            subject_manifest={"format": "reproit.subject-closure.v1"},
            subject_objects=[{"digest": "sha256:00", "path": "subject", "size": 1}],
        )
        operation = bridge.operation_begin(
            engine,
            {"format": "reproit.operation-begin.v1"},
        )
        bridge.operation_input(
            operation.handle,
            {"format": "reproit.operation-input.v1"},
        )
        dependency = bridge.dependency_open(
            operation.handle,
            {"observation_class": "database"},
            "dependency-parent",
        )
        self.assertEqual(
            bridge.dependency_finish(
                dependency.handle,
                {"outcome": "response"},
            ),
            "response",
        )
        observation = bridge.observation_open(
            operation.handle,
            "outbound-http",
            "parent-id",
        )
        bridge.observation_write(observation.handle, "request", b"request")
        self.assertEqual(
            bridge.observation_dispatch(observation.handle),
            "replay",
        )
        self.assertEqual(
            bridge.observation_read(observation.handle),
            (b"", True),
        )
        bridge.observation_finish(
            observation.handle,
            "response",
            observation.session_position,
        )
        bridge.observation_abandon(observation.handle)
        bridge.operation_unowned(
            operation.handle,
            "filesystem",
            b"unowned evidence",
        )
        bridge.operation_close_world(operation.handle, "return")
        bridge.operation_succeed(operation.handle)
        bridge.operation_abandon(operation.handle)
        sink = bridge.operation_fail(
            operation.handle,
            {"schema": "failure"},
            "project-token",
        )
        self.assertTrue(bridge.sink_wait(sink, 250))
        bridge.engine_close(engine)

        self.assertEqual(engine, NativeEngineHandle(11))
        self.assertEqual(operation.handle, NativeOperationHandle(12))
        self.assertEqual(operation.operation_id, "operation-id")
        self.assertEqual(dependency.handle, NativeDependencyHandle(15))
        self.assertEqual(dependency.action, "capture")
        self.assertEqual(observation.handle, NativeObservationHandle(14))
        self.assertEqual(observation.session_position, 0)
        self.assertEqual(sink, NativeSinkHandle(13))
        self.assertEqual(
            library.requests[0],
            {
                "build_repository_id": "repository",
                "format": "reproit.sdk-engine-call.v1",
                "observation_adapters": [],
                "operation": "engine-open",
                "project_toml": "format = 1",
                "sdk": "python",
                "source_revision": "revision",
                "subject_manifest": {"format": "reproit.subject-closure.v1"},
                "subject_objects": [
                    {"digest": "sha256:00", "path": "subject", "size": 1}
                ],
            },
        )
        self.assertEqual(
            library.requests[3],
            {
                "causal_parent_id": "dependency-parent",
                "format": "reproit.sdk-engine-call.v1",
                "operation": "dependency-open",
                "operation_handle": 12,
                "request": {"observation_class": "database"},
            },
        )
        self.assertEqual(
            library.requests[4],
            {
                "dependency_handle": 15,
                "format": "reproit.sdk-engine-call.v1",
                "operation": "dependency-finish",
                "response": {"outcome": "response"},
            },
        )
        self.assertEqual(
            library.requests[5],
            {
                "causal_parent_id": "parent-id",
                "class": "outbound-http",
                "format": "reproit.sdk-engine-call.v1",
                "operation": "observation-open",
                "operation_handle": 12,
            },
        )
        self.assertEqual(
            library.requests[6],
            {
                "chunk": base64.urlsafe_b64encode(b"request")
                .rstrip(b"=")
                .decode(),
                "format": "reproit.sdk-engine-call.v1",
                "observation_handle": 14,
                "operation": "observation-write",
                "stream": "request",
            },
        )
        self.assertEqual(
            library.requests[9],
            {
                "format": "reproit.sdk-engine-call.v1",
                "observation_handle": 14,
                "operation": "observation-finish",
                "outcome": "response",
                "session_position": 0,
            },
        )
        self.assertEqual(
            [request["operation"] for request in library.requests],
            [
                "engine-open",
                "operation-begin",
                "operation-input",
                "dependency-open",
                "dependency-finish",
                "observation-open",
                "observation-write",
                "observation-dispatch",
                "observation-read",
                "observation-finish",
                "observation-abandon",
                "operation-unowned",
                "operation-close-world",
                "operation-succeed",
                "operation-abandon",
                "operation-fail",
                "sink-wait",
                "engine-close",
            ],
        )

    def test_engine_rejection_is_typed_and_does_not_echo_the_token(self):
        secret = "do-not-echo-project-token"
        library = FakeLibrary(
            engine_response({}, error_code="SCHEMA_INVALID")
        )
        bridge = NativeEngineBridge(library)
        with self.assertRaises(NativeEngineCallError) as raised:
            bridge.operation_fail(
                NativeOperationHandle(1),
                {"schema": "failure"},
                secret,
            )
        self.assertEqual(raised.exception.error_code, "SCHEMA_INVALID")
        self.assertEqual(
            str(raised.exception),
            "The shared SDK engine rejected the operation.",
        )
        self.assertNotIn(secret, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_typed_calls_reject_invalid_results_and_handles(self):
        library = FakeLibrary(engine_response({"engine_handle": True}))
        bridge = NativeEngineBridge(library)
        with self.assertRaises(NativeEngineError):
            bridge.engine_open(
                build_repository_id="repository",
                project_toml="format = 1",
                source_revision="revision",
                subject_manifest={},
                subject_objects=[],
            )
        with self.assertRaises(NativeEngineError) as raised:
            bridge.engine_close(NativeEngineHandle(0))
        self.assertEqual(
            str(raised.exception),
            "The shared SDK engine request is invalid.",
        )
        request_count = len(library.requests)
        with self.assertRaises(NativeEngineError):
            bridge.observation_write(
                NativeObservationHandle(1),
                "request",
                b"x" * 32_769,
            )
        self.assertEqual(len(library.requests), request_count)

    def test_observation_chunk_bound_and_replay_eof_are_exact(self):
        read_at_limit = base64.urlsafe_b64encode(b"r" * 8_192).rstrip(b"=").decode()
        results = {"observation-write": {}}
        library = FakeLibrary(
            lambda request: engine_response(results[request["operation"]])
        )
        bridge = NativeEngineBridge(library)
        bridge.observation_write(
            NativeObservationHandle(1),
            "request",
            b"x" * 32_768,
        )
        request_count = len(library.requests)
        with self.assertRaises(NativeEngineError):
            bridge.observation_write(
                NativeObservationHandle(1),
                "request",
                b"x" * 32_769,
            )
        self.assertEqual(len(library.requests), request_count)

        replay = NativeEngineBridge(
            FakeLibrary(
                engine_response({"chunk": read_at_limit, "eof": False})
            )
        )
        self.assertEqual(
            replay.observation_read(NativeObservationHandle(1)),
            (b"r" * 8_192, False),
        )
        eof = NativeEngineBridge(
            FakeLibrary(engine_response({"chunk": "", "eof": True}))
        )
        self.assertEqual(
            eof.observation_read(NativeObservationHandle(1)),
            (b"", True),
        )
        read_one_over = base64.urlsafe_b64encode(b"r" * 8_193).rstrip(b"=").decode()
        with self.assertRaises(NativeEngineError):
            NativeEngineBridge(
                FakeLibrary(
                    engine_response({"chunk": read_one_over, "eof": False})
                )
            ).observation_read(NativeObservationHandle(1))

    def test_invalid_replay_chunk_does_not_echo_secret_bytes(self):
        secret = "local-observation-secret"
        bridge = NativeEngineBridge(
            FakeLibrary(
                engine_response({"chunk": secret + "=", "eof": False})
            )
        )
        with self.assertRaises(NativeEngineError) as raised:
            bridge.observation_read(NativeObservationHandle(1))
        self.assertEqual(
            str(raised.exception),
            "The shared SDK engine response is invalid.",
        )
        self.assertNotIn(secret, str(raised.exception))

    def test_malformed_engine_error_code_is_rejected_without_echo(self):
        secret = "secret-error-value"
        response = engine_response({}, error_code=secret)
        with self.assertRaises(NativeEngineError) as raised:
            NativeEngineBridge(FakeLibrary(response)).engine_close(
                NativeEngineHandle(1)
            )
        self.assertEqual(
            str(raised.exception),
            "The shared SDK engine response is invalid.",
        )
        self.assertNotIn(secret, str(raised.exception))

    def test_artifact_manifest_accepts_the_exact_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "libreproit_sdk_engine.so"
            content = b"exact engine bytes"
            (root / name).write_bytes(content)
            (root / "sdk-engine-artifacts.json").write_text(
                json.dumps(artifact_manifest(name, content))
            )
            _validate_artifact_manifest(
                root,
                "linux-arm64",
                {"engine": name},
            )

    def test_artifact_manifest_rejects_invalid_or_linked_artifacts(self):
        name = "libreproit_sdk_engine.so"
        content = b"exact engine bytes"
        valid = artifact_manifest(name, content)
        invalid = []
        wrong_target = copy.deepcopy(valid)
        wrong_target["target"] = "linux-x86_64"
        invalid.append(wrong_target)
        wrong_digest = copy.deepcopy(valid)
        wrong_digest["artifacts"][0]["digest"] = "sha256:" + "0" * 64
        invalid.append(wrong_digest)
        wrong_size = copy.deepcopy(valid)
        wrong_size["artifacts"][0]["size"] = len(content) + 1
        invalid.append(wrong_size)
        extra_field = copy.deepcopy(valid)
        extra_field["unexpected"] = True
        invalid.append(extra_field)
        path_escape = copy.deepcopy(valid)
        path_escape["artifacts"][0]["file"] = f"../{name}"
        invalid.append(path_escape)
        missing_role = copy.deepcopy(valid)
        missing_role["artifacts"] = []
        invalid.append(missing_role)
        extra_artifact = copy.deepcopy(valid)
        extra_artifact["artifacts"].append(
            copy.deepcopy(extra_artifact["artifacts"][0])
        )
        invalid.append(extra_artifact)
        oversized_artifact = copy.deepcopy(valid)
        oversized_artifact["artifacts"][0]["size"] = 256 * 1024 * 1024 + 1
        invalid.append(oversized_artifact)

        for manifest in invalid:
            with self.subTest(manifest=manifest):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / name).write_bytes(content)
                    (root / "sdk-engine-artifacts.json").write_text(
                        json.dumps(manifest)
                    )
                    with self.assertRaises(NativeEngineError) as raised:
                        _validate_artifact_manifest(
                            root,
                            "linux-arm64",
                            {"engine": name},
                        )
                    self.assertEqual(
                        str(raised.exception),
                        "The packaged shared SDK engine is unavailable.",
                    )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "engine-target"
            target.write_bytes(content)
            (root / name).symlink_to(target)
            (root / "sdk-engine-artifacts.json").write_text(
                json.dumps(valid)
            )
            with self.assertRaises(NativeEngineError):
                _validate_artifact_manifest(
                    root,
                    "linux-arm64",
                    {"engine": name},
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / name).mkdir()
            (root / "sdk-engine-artifacts.json").write_text(
                json.dumps(valid)
            )
            with self.assertRaises(NativeEngineError):
                _validate_artifact_manifest(
                    root,
                    "linux-arm64",
                    {"engine": name},
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / name).write_bytes(content)
            (root / "sdk-engine-artifacts.json").write_bytes(b"x" * 16_385)
            with self.assertRaises(NativeEngineError):
                _validate_artifact_manifest(
                    root,
                    "linux-arm64",
                    {"engine": name},
                )


if __name__ == "__main__":
    unittest.main()
