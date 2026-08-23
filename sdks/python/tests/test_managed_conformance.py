import copy
import io
import inspect
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import managed_fixtures as fixtures
from reproit_sdk import ReproIt, canonical_bytes, managed_subject_files
from reproit_sdk import managed_protocol as protocol
from reproit_sdk import official_managed as official
from reproit_sdk.managed_candidate import (
    ManagedCaptureClosure,
    PreparedManagedCandidate,
)
from reproit_sdk.managed_identity import (
    MAX_MANAGED_WORKLOAD_RECEIPT_BYTES,
    ManagedWorkloadIdentityState,
    ManagedWorkloadRegistrationReceipt,
    load_or_create_managed_workload_key,
    managed_deployment_binding_digest,
    managed_workload_key_id,
)
from reproit_sdk.managed_subject import (
    package_running_python_subject,
    subject_binding,
)
from reproit_sdk.managed_transport import (
    ManagedProjectToken,
    ManagedTlsEndpoint,
    _read_response,
    _validate_grant_request,
    _validate_registration_result,
    _validate_workload_registration,
)

GRANT_VERIFICATION_TIME = "2026-01-01T00:00:30.000Z"


class ManagedVectorConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol_vectors = fixtures.load_protocol_vectors()
        cls.cloud_vectors = fixtures.load_cloud_api_vectors()
        cls.positive = cls.protocol_vectors["positive"]
        cls.cloud_positive = cls.cloud_vectors["positive"]

    def test_candidate_identity_digest_matches_the_canonical_vector(self):
        identity = self.positive["managed_candidate_identity"]["value"]
        protocol.validate_managed_candidate_identity(identity)
        self.assertEqual(
            protocol.canonical_digest(identity),
            self.protocol_vectors["canonical_sha256"]["managed_candidate_identity"],
        )

    def test_ciphertext_identity_digest_binds_the_commit_vector(self):
        identity = self.positive["managed_candidate_ciphertext_identity"]["value"]
        protocol.validate_ciphertext_identity(identity)
        digest = protocol.canonical_digest(identity)
        self.assertEqual(
            digest,
            self.protocol_vectors["canonical_sha256"][
                "managed_candidate_ciphertext_identity"
            ],
        )
        commit = self.cloud_positive["managed_candidate_commit"]["value"]
        self.assertEqual(digest, commit["encrypted_candidate_digest"])

    def test_capture_grant_verifies_with_the_published_key(self):
        grant = self.positive["managed_candidate_capture_grant"]["value"]
        public_key = protocol.decode_base64url(
            self.protocol_vectors["verification_keys"][
                "managed-candidate-capture-test"
            ],
            32,
        )
        protocol.verify_capture_grant(
            grant,
            {
                "candidate_identity_digest": grant["candidate_identity_digest"],
                "candidate_key_reference": grant["candidate_key_reference"],
                "capture_id": grant["capture_id"],
                "organization_id": grant["organization_id"],
                "project_id": grant["project_id"],
                "service_id": grant["service_id"],
                "signer_key_id": grant["signer_key_id"],
            },
            GRANT_VERIFICATION_TIME,
            public_key,
        )

    def test_capture_grant_negative_vectors_are_rejected(self):
        grant = self.positive["managed_candidate_capture_grant"]["value"]
        public_key = protocol.decode_base64url(
            self.protocol_vectors["verification_keys"][
                "managed-candidate-capture-test"
            ],
            32,
        )
        expectation = {
            "candidate_identity_digest": grant["candidate_identity_digest"],
            "candidate_key_reference": grant["candidate_key_reference"],
            "capture_id": grant["capture_id"],
            "organization_id": grant["organization_id"],
            "project_id": grant["project_id"],
            "service_id": grant["service_id"],
            "signer_key_id": grant["signer_key_id"],
        }
        mutations = [
            entry
            for entry in self.protocol_vectors["negative"]
            if entry.get("base") == "managed_candidate_capture_grant"
        ]
        self.assertEqual(len(mutations), 3)
        for mutation in mutations:
            changed = fixtures.apply_mutation(grant, mutation)
            with self.assertRaises(protocol.ManagedError) as context:
                protocol.verify_capture_grant(
                    changed, expectation, GRANT_VERIFICATION_TIME, public_key
                )
            self.assertEqual(
                context.exception.code, mutation["expected"], mutation["name"]
            )

    def test_upload_request_vector_validates(self):
        request = self.cloud_positive["managed_candidate_upload_request"]["value"]
        protocol.validate_upload_request(request)

    def test_upload_request_key_reference_mutation_is_rejected(self):
        request = self.cloud_positive["managed_candidate_upload_request"]["value"]
        mutation = next(
            entry
            for entry in self.cloud_vectors["negative"]
            if entry.get("name")
            == "managed-candidate-key-reference-differs-from-capture-grant"
        )
        changed = fixtures.apply_mutation(request, mutation)
        with self.assertRaises(protocol.ManagedError) as context:
            protocol.validate_upload_request(changed)
        self.assertEqual(context.exception.code, "ATTESTATION_SCOPE")

    def test_encryption_response_vector_decodes(self):
        response = self.cloud_positive["managed_candidate_encryption_response"]["value"]
        self.assertEqual(set(response), {"candidate_key", "capture_grant"})
        candidate_key = protocol.decode_base64url(response["candidate_key"], 32)
        self.assertEqual(len(candidate_key), 32)
        protocol.validate_capture_grant(response["capture_grant"])
        grant_request = self.cloud_positive[
            "managed_candidate_encryption_grant_request"
        ]["value"]
        self.assertEqual(
            grant_request["candidate_identity_digest"],
            response["capture_grant"]["candidate_identity_digest"],
        )

    def test_signed_workload_registration_vectors_validate(self):
        request = self.cloud_positive["workload_key_registration"]["value"]
        result = self.cloud_positive["workload_key_registration_result"]["value"]
        _validate_workload_registration(request)
        _validate_registration_result(result, request)
        self.assertEqual(
            protocol.canonical_digest(request),
            self.cloud_vectors["canonical_sha256"]["workload_key_registration"],
        )

    def test_signed_grant_request_vector_validates(self):
        request = self.cloud_positive["managed_candidate_encryption_grant_request"][
            "value"
        ]
        registration = self.cloud_positive["workload_key_registration"]["value"]
        _validate_grant_request(request)
        protocol.verify_signed_value(
            request, protocol.decode_base64url(registration["public_key"], 32)
        )
        self.assertEqual(
            protocol.canonical_digest(request),
            self.cloud_vectors["canonical_sha256"][
                "managed_candidate_encryption_grant_request"
            ],
        )

    def test_key_context_vectors_match_canonical_digests(self):
        for name in ("object_key_context", "chunk_key_context"):
            value = self.positive[name]["value"]
            self.assertEqual(
                protocol.canonical_digest(value),
                self.protocol_vectors["canonical_sha256"][name],
                name,
            )

    def test_signing_matches_the_rust_reference_signature(self):
        # The vector grant was signed by reproit-core with the test seed
        # 0x83 * 32. Deterministic Ed25519 over identical canonical bytes
        # must reproduce the exact signature.
        grant = dict(self.positive["managed_candidate_capture_grant"]["value"])
        seed = bytes([0x83]) * 32
        self.assertEqual(
            protocol.encode_base64url(protocol.verification_key(seed)),
            self.protocol_vectors["verification_keys"][
                "managed-candidate-capture-test"
            ],
        )
        unsigned = dict(grant)
        unsigned["signature"] = ""
        self.assertEqual(
            protocol.sign_bytes(canonical_bytes(unsigned), seed), grant["signature"]
        )

    def test_seal_matches_the_rust_reference_ciphertext(self):
        # Pinned cross-implementation vector. The expected bytes were
        # produced by reproit-core (derive_object_key, derive_chunk_key,
        # encrypt_chunk) with these exact inputs, so this test proves the
        # HKDF-SHA-256 and AES-256-GCM AAD contract byte for byte.
        context = {
            "capture_batch_format": "reproit.capture-batch.v1",
            "capture_id": "cap_01890f3e-7b1c-7cc0-8a1b-123456789abc",
            "format": "reproit.object-key-context.v1",
            "object_id": "obj_01890f3e-7b1c-7cc0-8a1b-123456789ab4",
            "organization_id": "org_01890f3e-7b1c-7cc0-8a1b-123456789abd",
            "processing_mode": "managed",
            "project_id": "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe",
            "role": "trigger",
            "service_id": "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf",
        }
        candidate_key = bytes([0x42]) * 32
        plaintext = b"cross-language managed seal vector"
        object_key = protocol.derive_object_key(
            candidate_key, context["capture_id"], context
        )
        chunk_context = protocol.chunk_key_context(
            protocol.canonical_digest(context), 1, 0, len(plaintext)
        )
        self.assertEqual(
            chunk_context["object_context_digest"],
            "sha256:06e6fa3d4a4185d0eff5cd92e01ed2d5aa3dc873f5b5cdead8313556855afa84",
        )
        chunk_key = protocol.derive_chunk_key(object_key, chunk_context)
        stored = protocol.encrypt_chunk(
            chunk_key, bytes([0x07]) * 12, plaintext, chunk_context
        )
        self.assertEqual(
            stored.hex(),
            "0707070707070707070707076feaeb515f76709f385b2542dff02ead97170a34"
            "b32eba411bf935a7e778ce0dbb1b49d747d17d71f9b507a035d4647f312f",
        )
        self.assertEqual(
            protocol.decrypt_chunk(chunk_key, stored, chunk_context), plaintext
        )

    def test_managed_candidate_manifest_vector_binds_its_identity(self):
        manifest = self.positive["managed_candidate_manifest"]["value"]
        protocol.validate_managed_candidate_identity(manifest["candidate_identity"])
        self.assertEqual(
            protocol.canonical_digest(manifest["candidate_identity"]),
            manifest["candidate_identity_digest"],
        )
        self.assertEqual(
            protocol.canonical_digest(manifest),
            self.protocol_vectors["canonical_sha256"]["managed_candidate_manifest"],
        )


class ManagedWorkloadKeyFile(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        os.chmod(self.directory.name, 0o700)
        self.path = os.path.join(self.directory.name, "workload.key")

    def tearDown(self):
        self.directory.cleanup()

    def test_create_and_reload_round_trip(self):
        key = load_or_create_managed_workload_key(self.path)
        self.assertEqual(len(key), 32)
        mode = stat.S_IMODE(os.lstat(self.path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(load_or_create_managed_workload_key(self.path), key)

    def test_reject_world_readable_key(self):
        load_or_create_managed_workload_key(self.path)
        os.chmod(self.path, 0o644)
        with self.assertRaises(protocol.ManagedError) as context:
            load_or_create_managed_workload_key(self.path)
        self.assertEqual(context.exception.code, "CONFIG_CONFLICT")

    def test_reject_symlink_key(self):
        target = os.path.join(self.directory.name, "target.key")
        with open(target, "wb") as handle:
            handle.write(b"\x00" * 32)
        os.chmod(target, 0o600)
        os.symlink(target, self.path)
        with self.assertRaises(protocol.ManagedError) as context:
            load_or_create_managed_workload_key(self.path)
        self.assertEqual(context.exception.code, "CONFIG_CONFLICT")

    def test_reject_wrong_size(self):
        with open(self.path, "wb") as handle:
            handle.write(b"\x00" * 16)
        os.chmod(self.path, 0o600)
        with self.assertRaises(protocol.ManagedError) as context:
            load_or_create_managed_workload_key(self.path)
        self.assertEqual(context.exception.code, "CONFIG_CONFLICT")

    def test_reject_group_writable_parent(self):
        os.chmod(self.directory.name, 0o770)
        with self.assertRaises(protocol.ManagedError) as context:
            load_or_create_managed_workload_key(self.path)
        self.assertEqual(context.exception.code, "CONFIG_CONFLICT")


class ManagedWorkloadProtectedState(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        os.chmod(self.root.name, 0o700)
        self.binding_digest = "sha256:" + "1" * 64
        self.state = ManagedWorkloadIdentityState.from_state_root(
            os.path.realpath(self.root.name), self.binding_digest
        )

    def tearDown(self):
        self.root.cleanup()

    def receipt(self):
        key_id = managed_workload_key_id(
            protocol.verification_key(fixtures.WORKLOAD_SEED)
        )
        return ManagedWorkloadRegistrationReceipt(
            deployment_digest="sha256:" + "2" * 64,
            service_id=fixtures.SERVICE_ID,
            workload_key_id=key_id,
        )

    def test_signed_time_and_registration_receipt_survive_restart(self):
        first = self.state.load_or_create_deployment_signed_at(
            self.binding_digest, "2026-01-01T00:00:00.000Z"
        )
        second = self.state.load_or_create_deployment_signed_at(
            self.binding_digest, "2026-02-01T00:00:00.000Z"
        )
        receipt = self.receipt()
        self.assertEqual(first, second)
        self.assertIsNone(self.state.load_registration_receipt(receipt))
        self.state.persist_registration_receipt(receipt)
        restarted = ManagedWorkloadIdentityState.from_state_root(
            os.path.realpath(self.root.name), self.binding_digest
        )
        self.assertEqual(restarted.load_registration_receipt(receipt), receipt)

    def test_corrupt_or_oversize_receipt_fails_closed(self):
        path = os.path.join(self.state.directory, "registration.json")
        for value in (b"not-json", b"x" * (MAX_MANAGED_WORKLOAD_RECEIPT_BYTES + 1)):
            with open(path, "wb") as target:
                target.write(value)
            os.chmod(path, 0o600)
            with self.assertRaises(protocol.ManagedError) as raised:
                self.state.load_registration_receipt(self.receipt())
            self.assertEqual(raised.exception.code, "CONFIG_CONFLICT")

    def test_binding_digest_ignores_only_signing_state(self):
        deployment = copy.deepcopy(
            fixtures.load_cloud_api_vectors()["positive"]["workload_key_registration"][
                "value"
            ]["deployment"]
        )
        digest = managed_deployment_binding_digest(deployment)
        deployment["signature"] = "x"
        deployment["signed_at"] = "2026-02-01T00:00:00.000Z"
        deployment["signer_key_id"] = "other"
        self.assertEqual(managed_deployment_binding_digest(deployment), digest)
        deployment["repository_id"] = "source.example/acme/other"
        self.assertNotEqual(managed_deployment_binding_digest(deployment), digest)

    def test_state_root_rejects_a_symlink_component(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = os.path.realpath(directory)
            target = os.path.join(directory, "target")
            linked = os.path.join(directory, "linked")
            os.mkdir(target, 0o700)
            os.symlink(target, linked)
            with self.assertRaises(protocol.ManagedError) as raised:
                ManagedWorkloadIdentityState.from_state_root(
                    os.path.join(linked, "state"), self.binding_digest
                )
        self.assertEqual(raised.exception.code, "CONFIG_CONFLICT")


class ManagedSubjectPackaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.subject = fixtures.shared_subject()

    def test_running_subject_is_complete_and_content_addressed(self):
        manifest = self.subject.manifest
        self.assertEqual(manifest["runtime_family"], "python")
        self.assertEqual(manifest["format"], "reproit.subject-closure.v1")
        self.assertEqual(len(manifest["debug_artifacts"]), 1)
        self.assertEqual(
            manifest["debug_artifacts"][0]["kind"], "interpreted-source-identity"
        )
        executable = manifest["launch"]["executable"]
        self.assertTrue(executable.startswith("/reproit/subject/runtime/python/"))
        self.assertTrue(manifest["launch"]["arguments"][0].endswith("/fixture.py"))
        self.assertTrue(
            any(
                entry["path"] == executable and entry["executable"]
                for entry in manifest["files"]
            )
        )
        for packaged in self.subject.objects:
            with open(packaged.path, "rb") as source:
                content = source.read()
            self.assertEqual(protocol.digest_bytes(content), packaged.digest)
            self.assertEqual(len(content), packaged.size)

    def test_subject_binding_matches_manifest(self):
        binding = subject_binding(self.subject.manifest)
        self.assertEqual(
            binding["artifact_digest"],
            protocol.canonical_digest(self.subject.manifest),
        )
        self.assertEqual(
            binding["executable"], self.subject.manifest["launch"]["executable"]
        )
        self.assertEqual(
            binding["operating_system"], self.subject.manifest["operating_system"]
        )

    def test_application_root_replays_local_imports_and_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package_root = root / "orders"
            package_root.mkdir()
            (root / "main.py").write_text(
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
                "    return "
                "Path(__file__).with_name('value.txt').read_text().strip()\n",
                encoding="utf-8",
            )
            (package_root / "value.txt").write_text(
                "captured-value\n", encoding="utf-8"
            )
            subject = package_running_python_subject(str(root / "main.py"), directory)

            with tempfile.TemporaryDirectory() as replay_directory:
                command = self._materialize_application(subject, replay_directory)
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, b"captured-value\n")

    def test_imported_distribution_files_are_part_of_the_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_text(
                "import reproit_sdk\nprint(reproit_sdk.__name__)\n",
                encoding="utf-8",
            )
            subject = package_running_python_subject(str(script), directory)
        with tempfile.TemporaryDirectory() as replay_directory:
            command = self._materialize_application(subject, replay_directory)
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                timeout=30,
            )
        paths = {entry["path"] for entry in subject.manifest["files"]}
        dependency = self._subject_json(
            subject,
            "/reproit/subject/python/dependencies.json",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b"reproit_sdk\n")
        self.assertTrue(
            any(path.endswith("/reproit_sdk/__init__.py") for path in paths)
        )
        self.assertTrue(any("/cryptography/" in path for path in paths))
        self.assertTrue(
            all(
                path.startswith(dependency["site_packages_path"] + "/")
                for path in paths
                if "/reproit_sdk/" in path or "/cryptography/" in path
            )
        )
        module_paths = {entry["path"] for entry in subject.manifest["modules"]}
        self.assertTrue(any("_cffi_backend" in path for path in module_paths))

    def test_interpreter_identity_binds_the_runtime_closure(self):
        identity = self._subject_json(
            self.subject,
            "/reproit/subject/python/interpreter.json",
        )
        self.assertEqual(identity["format"], "reproit.python-interpreter-identity.v2")
        self.assertRegex(identity["runtime_closure_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertGreater(identity["runtime_file_count"], 1)
        self.assertGreater(identity["runtime_total_bytes"], identity["executable_size"])
        self.assertIn(identity["runtime_closure_digest"], identity["identity"])
        self.assertEqual(identity["runtime_file_count"], len(identity["runtime_files"]))
        runtime_paths = {entry["path"] for entry in identity["runtime_files"]}
        self.assertIn(self.subject.manifest["launch"]["executable"], runtime_paths)
        self.assertTrue(any(entry["size"] == 0 for entry in identity["runtime_files"]))

    def test_missing_runtime_root_is_rejected_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            missing = str(Path(directory) / "missing-stdlib")
            original = managed_subject_files.sysconfig.get_path

            def configured_path(name):
                return missing if name == "stdlib" else original(name)

            with mock.patch(
                "reproit_sdk.managed_subject_files.sysconfig.get_path",
                side_effect=configured_path,
            ):
                with self.assertRaises(protocol.ManagedError) as raised:
                    package_running_python_subject(str(script), directory)
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")

    def test_identical_file_bytes_preserve_distinct_executable_bits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            alias = root / "alias.py"
            script.write_text("print('same')\n", encoding="utf-8")
            alias.write_text("print('same')\n", encoding="utf-8")
            script.chmod(0o755)
            alias.chmod(0o644)
            subject = package_running_python_subject(str(script), directory)
        files = {
            Path(entry["path"]).name: entry
            for entry in subject.manifest["files"]
            if "/reproit/subject/application/" in entry["path"]
            if Path(entry["path"]).name in ("main.py", "alias.py")
        }
        self.assertEqual(
            files["main.py"]["object_digest"], files["alias.py"]["object_digest"]
        )
        self.assertTrue(files["main.py"]["executable"])
        self.assertFalse(files["alias.py"]["executable"])

    def test_implicit_root_rejects_a_local_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            script.write_text("import helper\n", encoding="utf-8")
            (root / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
            with self.assertRaises(protocol.ManagedError) as raised:
                package_running_python_subject(str(script))
        self.assertEqual(raised.exception.code, "UNSUPPORTED")

    def test_supported_interpreter_flags_are_preserved_before_the_script(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            with (
                mock.patch.object(
                    sys,
                    "orig_argv",
                    [sys.executable, "-B", "-O", str(script)],
                ),
                mock.patch.object(sys, "argv", [str(script), "app-argument"]),
            ):
                subject = package_running_python_subject(str(script), directory)
        arguments = subject.manifest["launch"]["arguments"]
        self.assertEqual(arguments[:2], ["-B", "-O"])
        self.assertTrue(arguments[2].endswith("/main.py"))
        self.assertEqual(arguments[3:], ["app-argument"])

    def test_host_path_interpreter_flag_is_rejected_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            with (
                mock.patch.object(
                    sys,
                    "orig_argv",
                    [
                        sys.executable,
                        "-X",
                        f"pycache_prefix={directory}",
                        str(script),
                    ],
                ),
                mock.patch.object(sys, "argv", [str(script)]),
            ):
                with self.assertRaises(protocol.ManagedError) as raised:
                    package_running_python_subject(str(script), directory)
        self.assertEqual(raised.exception.code, "UNSUPPORTED")

    def test_application_root_preserves_empty_files_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            (root / "empty.txt").touch()
            subject = package_running_python_subject(str(script), directory)
            empty_file = next(
                entry
                for entry in subject.manifest["files"]
                if entry["path"].endswith("/empty.txt")
            )
            empty_object = next(
                entry
                for entry in subject.manifest["objects"]
                if entry["digest"] == empty_file["object_digest"]
            )
            self.assertEqual(empty_object["size"], 0)
            target = root / "target.txt"
            target.write_text("target\n", encoding="utf-8")
            (root / "linked.txt").symlink_to(target)
            with self.assertRaises(protocol.ManagedError) as raised:
                package_running_python_subject(str(script), directory)
        self.assertEqual(raised.exception.code, "UNSUPPORTED")

    def test_application_file_count_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            (root / "one.txt").write_text("one\n", encoding="utf-8")
            (root / "two.txt").write_text("two\n", encoding="utf-8")
            with mock.patch(
                "reproit_sdk.managed_subject_files.MAX_CAPTURED_FILES",
                2,
            ):
                with self.assertRaises(protocol.ManagedError) as raised:
                    package_running_python_subject(str(script), directory)
        self.assertEqual(raised.exception.code, "UPLOAD_LIMIT_EXCEEDED")

    def test_single_file_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_bytes(b"12345")
            with mock.patch(
                "reproit_sdk.managed_subject_files.MAX_SUBJECT_OBJECT_BYTES",
                4,
            ):
                with self.assertRaises(protocol.ManagedError) as raised:
                    package_running_python_subject(str(script), directory)
        self.assertEqual(raised.exception.code, "UPLOAD_LIMIT_EXCEEDED")

    def test_changing_entry_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            with mock.patch(
                "reproit_sdk.managed_subject_files._same_file",
                return_value=False,
            ):
                with self.assertRaises(protocol.ManagedError) as raised:
                    package_running_python_subject(str(script), directory)
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")

    def test_changing_walked_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            changing = protocol.ManagedError(
                "INCOMPLETE_CANDIDATE",
                "The running Python subject changed during local packaging.",
            )
            with mock.patch(
                "reproit_sdk.managed_subject_files._verify_directory_unchanged",
                side_effect=changing,
            ):
                with self.assertRaises(protocol.ManagedError) as raised:
                    package_running_python_subject(str(script), directory)
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")

    def test_changing_linux_loaded_module_set_is_rejected(self):
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
            with (
                mock.patch.object(managed_subject_files.sys, "platform", "linux"),
                mock.patch(
                    "reproit_sdk.managed_subject_files._loaded_linux_module_paths",
                    side_effect=[{str(first)}, {str(first), str(second)}],
                ),
            ):
                with self.assertRaises(protocol.ManagedError) as raised:
                    managed_subject_files._capture_loaded_native_modules(
                        builder,
                        str(runtime_root),
                    )
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")

    def _materialize_application(self, subject, replay_directory):
        objects = {entry.digest: entry.path for entry in subject.objects}
        application_files = [
            entry
            for entry in subject.manifest["files"]
            if entry["path"].startswith("/reproit/subject/")
        ]
        prefix = "/reproit/subject/"
        for entry in application_files:
            relative = entry["path"].removeprefix(prefix)
            destination = Path(replay_directory) / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(Path(objects[entry["object_digest"]]).read_bytes())
            destination.chmod(0o555 if entry["executable"] else 0o444)
        launch = subject.manifest["launch"]
        command = [launch["executable"], *launch["arguments"]]
        return [
            str(Path(replay_directory) / value.removeprefix(prefix))
            if value.startswith(prefix)
            else value
            for value in command
        ]

    def _subject_json(self, subject, path):
        descriptor = next(
            entry for entry in subject.manifest["files"] if entry["path"] == path
        )
        packaged = next(
            entry
            for entry in subject.objects
            if entry.digest == descriptor["object_digest"]
        )
        return json.loads(Path(packaged.path).read_bytes())


class ManagedPrepareAndSeal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.subject = fixtures.shared_subject()
        cls.world = fixtures.empty_world()
        cls.world_id = protocol.canonical_digest(cls.world)
        cls.deployment = fixtures.bound_deployment(cls.subject)
        cls.candidate = fixtures.captured_candidate(cls.deployment, cls.world_id)

    def closure(self):
        return ManagedCaptureClosure([], "return", copy.deepcopy(self.world))

    def test_corrupt_runtime_bytes_stop_before_any_grant_request(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "main.py"
            script.write_text("print('failure')\n", encoding="utf-8")
            subject = package_running_python_subject(str(script), directory)
            deployment = fixtures.bound_deployment(subject)
            candidate = fixtures.captured_candidate(deployment, self.world_id)
        runtime_digest = next(
            entry["digest"]
            for entry in subject.manifest["objects"]
            if entry["kind"] == "runtime"
        )
        packaged = next(
            entry for entry in subject.objects if entry.digest == runtime_digest
        )
        Path(packaged.path).write_bytes(b"corrupt runtime")
        delivery = fixtures.GrantDeliverySpy()

        with self.assertRaises(protocol.ManagedError) as raised:
            PreparedManagedCandidate.prepare_complete(
                candidate,
                subject,
                self.closure(),
            )
        self.assertEqual(raised.exception.code, "INCOMPLETE_CANDIDATE")
        self.assertEqual(delivery.calls, [])

    def prepared(self):
        return PreparedManagedCandidate.prepare_complete(
            copy.deepcopy(self.candidate), self.subject, self.closure()
        )

    def request_grant(self, prepared, delivery):
        return prepared.request_encryption_grant(
            delivery, fixtures.WORKLOAD_KEY_ID, fixtures.WORKLOAD_SEED
        )

    def request_renewal(self, sealed, delivery):
        return sealed.request_capture_grant_renewal(
            delivery, fixtures.WORKLOAD_KEY_ID, fixtures.WORKLOAD_SEED
        )

    def sealed(self, delivery=None):
        delivery = delivery if delivery is not None else fixtures.GrantDeliverySpy()
        prepared = self.prepared()
        response = self.request_grant(prepared, delivery)
        return prepared.seal(
            response,
            GRANT_VERIFICATION_TIME,
            fixtures.CAPTURE_SIGNER_ID,
            protocol.verification_key(fixtures.CAPTURE_SIGNER_SEED),
        )

    def test_key_request_occurs_only_after_exact_local_closure(self):
        delivery = fixtures.GrantDeliverySpy()
        incomplete = copy.deepcopy(self.candidate)
        incomplete["world_id"] = "sha256:" + "a" * 64
        with self.assertRaises(protocol.ManagedError) as context:
            PreparedManagedCandidate.prepare_complete(
                incomplete, self.subject, self.closure()
            )
        self.assertEqual(context.exception.code, "INCOMPLETE_CANDIDATE")
        self.assertEqual(delivery.calls, [])

        prepared = self.prepared()
        self.request_grant(prepared, delivery)
        self.assertEqual(len(delivery.calls), 1)
        self.assertEqual(
            delivery.calls[0]["candidate_identity_digest"],
            protocol.canonical_digest(prepared.identity),
        )
        self.assertEqual(delivery.calls[0]["processing_mode"], "managed")
        self.assertEqual(
            delivery.calls[0]["deployment_digest"],
            protocol.canonical_digest(self.deployment),
        )
        self.assertEqual(delivery.calls[0]["signer_key_id"], fixtures.WORKLOAD_KEY_ID)
        protocol.verify_signed_value(
            delivery.calls[0], protocol.verification_key(fixtures.WORKLOAD_SEED)
        )

    def test_incomplete_record_sequence_stops_before_any_request(self):
        delivery = fixtures.GrantDeliverySpy()
        incomplete = copy.deepcopy(self.candidate)
        incomplete["records"].pop()
        with self.assertRaises(protocol.ManagedError) as context:
            PreparedManagedCandidate.prepare_complete(
                incomplete, self.subject, self.closure()
            )
        self.assertEqual(context.exception.code, "INCOMPLETE_CANDIDATE")
        self.assertEqual(delivery.calls, [])

    def test_seal_round_trip_and_key_secrecy(self):
        sealed = self.sealed()
        for digest in sealed.ciphertext_digests():
            with open(sealed.ciphertext_path(digest), "rb") as source:
                self.assertEqual(protocol.digest_bytes(source.read()), digest)
        recovered = fixtures.open_sealed_object_bytes(sealed, fixtures.CANDIDATE_KEY)
        identity = sealed.request["ciphertext_identity"]
        candidate_object = next(
            entry["descriptor"]
            for entry in identity["objects"]
            if entry["descriptor"]["media_type"]
            == "application/vnd.reproit.candidate.v1+json"
        )
        self.assertEqual(
            json.loads(recovered[candidate_object["object_id"]]), self.candidate
        )
        manifest = fixtures.open_sealed_manifest(sealed, fixtures.CANDIDATE_KEY)
        self.assertEqual(
            manifest["candidate_identity_digest"],
            identity["candidate_identity_digest"],
        )
        self.assertEqual(
            manifest["candidate_key_reference"], identity["candidate_key_reference"]
        )
        request_bytes = canonical_bytes(sealed.request)
        self.assertNotIn(
            protocol.encode_base64url(fixtures.CANDIDATE_KEY).encode("ascii"),
            request_bytes,
        )
        with self.assertRaises(protocol.ManagedError):
            fixtures.open_sealed_object_bytes(sealed, bytes([0x43]) * 32)

    def test_seal_rejects_identity_digest_mismatch(self):
        prepared = self.prepared()
        delivery = fixtures.GrantDeliverySpy()
        response = self.request_grant(prepared, delivery)
        tampered_request = dict(delivery.calls[0])
        tampered_request["candidate_identity_digest"] = "sha256:" + "9" * 64
        tampered = fixtures.GrantDeliverySpy()
        tampered_response = tampered.request_encryption_grant(tampered_request, 5.0)
        with self.assertRaises(protocol.ManagedError) as context:
            prepared.seal(
                tampered_response,
                GRANT_VERIFICATION_TIME,
                fixtures.CAPTURE_SIGNER_ID,
                protocol.verification_key(fixtures.CAPTURE_SIGNER_SEED),
            )
        self.assertEqual(context.exception.code, "ATTESTATION_SCOPE")
        del response

    def test_renewal_cannot_rotate_key_or_reference(self):
        sealed = self.sealed()
        ingress = RecordingIngress(self)

        rotated_key = fixtures.GrantDeliverySpy(candidate_key=bytes([0x43]) * 32)
        renewal = self.request_renewal(sealed, rotated_key)
        with self.assertRaises(protocol.ManagedError) as context:
            sealed.apply_renewed_capture_grant(
                renewal,
                GRANT_VERIFICATION_TIME,
                fixtures.CAPTURE_SIGNER_ID,
                protocol.verification_key(fixtures.CAPTURE_SIGNER_SEED),
            )
        self.assertEqual(context.exception.code, "CAPTURE_ID_CONFLICT")

        rotated_reference = fixtures.GrantDeliverySpy(
            key_reference=protocol.encode_base64url(bytes([0x96]) * 32)
        )
        renewal = self.request_renewal(sealed, rotated_reference)
        with self.assertRaises(protocol.ManagedError) as context:
            sealed.apply_renewed_capture_grant(
                renewal,
                GRANT_VERIFICATION_TIME,
                fixtures.CAPTURE_SIGNER_ID,
                protocol.verification_key(fixtures.CAPTURE_SIGNER_SEED),
            )
        self.assertEqual(context.exception.code, "CAPTURE_ID_CONFLICT")
        self.assertEqual(ingress.sequence, [])

    def test_valid_renewal_is_accepted(self):
        sealed = self.sealed()
        renewal = self.request_renewal(sealed, fixtures.GrantDeliverySpy())
        sealed.apply_renewed_capture_grant(
            renewal,
            GRANT_VERIFICATION_TIME,
            fixtures.CAPTURE_SIGNER_ID,
            protocol.verification_key(fixtures.CAPTURE_SIGNER_SEED),
        )
        protocol.validate_upload_request(sealed.request)

    def test_upload_session_success(self):
        sealed = self.sealed()
        ingress = RecordingIngress(self)
        commit = sealed.upload(ingress)
        self.assertEqual(commit["state"], "CLOUD_PROTECTED")
        expected = set(sealed.ciphertext_digests())
        self.assertEqual(ingress.uploaded_digests, expected)
        self.assertEqual(ingress.sequence[0], "start")
        self.assertEqual(ingress.sequence[-1], "commit")
        self.assertEqual(ingress.sequence.count("upload_object"), len(expected))
        self.assertNotIn("cancel", ingress.sequence)

    def test_upload_cancels_on_failure(self):
        sealed = self.sealed()
        failing = RecordingIngress(self, fail_object_uploads=True)
        with self.assertRaises(protocol.ManagedError):
            sealed.upload(failing)
        self.assertIn("cancel", failing.sequence)
        self.assertNotIn("commit", failing.sequence)

        failing_commit = RecordingIngress(self, fail_commit=True)
        with self.assertRaises(protocol.ManagedError):
            sealed.upload(failing_commit)
        self.assertEqual(failing_commit.sequence[-1], "cancel")


class RecordingIngress:
    """An in-memory ingress double that verifies the upload session order."""

    def __init__(self, test, fail_object_uploads=False, fail_commit=False):
        self.test = test
        self.sequence = []
        self.expected_digests = set()
        self.uploaded_digests = set()
        self.request = None
        self.missing_entries = []
        self.fail_object_uploads = fail_object_uploads
        self.fail_commit = fail_commit

    def start(self, request, timeout):
        protocol.validate_upload_request(request)
        self.sequence.append("start")
        self.request = copy.deepcopy(dict(request))
        identity = request["ciphertext_identity"]
        self.expected_digests = {identity["manifest_object"]["cipher_digest"]}
        for entry in identity["objects"]:
            for chunk in entry["chunks"]:
                self.expected_digests.add(chunk["cipher_digest"])
        self.missing_entries = [
            {
                "cipher_digest": digest,
                "expires_at": "2026-01-01T00:01:00.000Z",
                "upload_url": f"https://upload.reproit.example/{digest}",
            }
            for digest in sorted(self.expected_digests)
        ]
        return {
            "expires_at": "2026-01-01T00:01:00.000Z",
            "limits": fixtures.load_cloud_api_vectors()["positive"][
                "managed_candidate_limits"
            ]["value"],
            "missing_objects": self.missing_entries[:100],
            "next_missing_cursor": "100" if len(self.missing_entries) > 100 else None,
            "state": "OPEN",
            "upload_id": fixtures.UPLOAD_ID,
            "upload_token": protocol.encode_base64url(bytes([0x93]) * 32),
        }

    def missing(self, upload_id, upload_token, cursor, timeout):
        self.test.assertEqual(upload_id, fixtures.UPLOAD_ID)
        offset = int(cursor)
        next_offset = offset + 100
        return {
            "missing_objects": self.missing_entries[offset:next_offset],
            "next_missing_cursor": str(next_offset)
            if next_offset < len(self.missing_entries)
            else None,
        }

    def upload_object(self, upload_url, digest, value, timeout):
        self.sequence.append("upload_object")
        if self.fail_object_uploads:
            raise protocol.schema_invalid("the double rejects this object")
        self.test.assertEqual(protocol.digest_bytes(value), digest)
        self.test.assertIn(digest, self.expected_digests)
        self.uploaded_digests.add(digest)

    def commit(self, upload_id, upload_token, timeout):
        self.sequence.append("commit")
        if self.fail_commit:
            raise protocol.schema_invalid("the double rejects this commit")
        self.test.assertEqual(self.expected_digests, self.uploaded_digests)
        identity = self.request["ciphertext_identity"]
        return {
            "candidate_identity_digest": identity["candidate_identity_digest"],
            "candidate_key_reference": identity["candidate_key_reference"],
            "capture_id": identity["capture_id"],
            "encrypted_candidate_digest": self.request["encrypted_candidate_digest"],
            "state": "CLOUD_PROTECTED",
            "upload_id": upload_id,
        }

    def cancel(self, upload_id, upload_token, timeout):
        self.sequence.append("cancel")
        return {"cancelled": True}


class ManagedTransportValidation(unittest.TestCase):
    def test_project_token_rules(self):
        ManagedProjectToken("a-valid-token")
        for invalid in ("", "with space", "control\x01", "x" * 1_025):
            with self.assertRaises(protocol.ManagedError):
                ManagedProjectToken(invalid)

    def test_endpoint_requires_tls13_and_a_valid_ca(self):
        endpoint = ManagedTlsEndpoint(
            "127.0.0.1",
            443,
            "managed.reproit.example",
            "managed.reproit.example",
            _self_signed_ca_path(self),
        )
        context = endpoint._tls
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_3)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_endpoint_rejects_bad_ca_files(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        empty = os.path.join(directory.name, "empty.pem")
        with open(empty, "wb"):
            pass
        garbage = os.path.join(directory.name, "garbage.pem")
        with open(garbage, "wb") as handle:
            handle.write(b"not a certificate")
        valid = _self_signed_ca_path(self)
        linked = os.path.join(directory.name, "linked.pem")
        os.symlink(valid, linked)
        for path in (empty, garbage, linked, os.path.join(directory.name, "absent")):
            with self.assertRaises(protocol.ManagedError):
                ManagedTlsEndpoint("127.0.0.1", 443, "example", "example", path)

    def test_endpoint_rejects_invalid_authority(self):
        valid = _self_signed_ca_path(self)
        for authority in ("", "bad/authority", "user@host", "with space", "x" * 513):
            with self.assertRaises(protocol.ManagedError):
                ManagedTlsEndpoint("127.0.0.1", 443, "example", authority, valid)

    def test_official_endpoint_accepts_only_one_normalized_https_origin(self):
        endpoint = ManagedTlsEndpoint.official("https://capture.reproit.example")
        self.assertEqual(endpoint.origin, "https://capture.reproit.example")
        for origin in (
            "http://capture.reproit.example",
            "https://CAPTURE.reproit.example",
            "https://capture.reproit.example:443",
            "https://capture.reproit.example/path",
            "https://user@capture.reproit.example",
        ):
            with self.assertRaises(protocol.ManagedError):
                ManagedTlsEndpoint.official(origin)

    def test_response_reader_rejects_invalid_responses(self):
        cases = [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n",
            b"garbage without terminator",
        ]
        for raw in cases:
            left, right = socket.socketpair()
            self.addCleanup(left.close)
            self.addCleanup(right.close)
            left.sendall(raw)
            left.shutdown(socket.SHUT_WR)
            with self.assertRaises(protocol.ManagedError):
                _read_response(right)

    def test_response_reader_accepts_a_bounded_body(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        left.shutdown(socket.SHUT_WR)
        response = _read_response(right)
        self.assertEqual(response.status, 204)
        self.assertEqual(response.body, b"")


class FrameworkNeutralOperation(unittest.IsolatedAsyncioTestCase):
    async def test_operation_preserves_the_exact_application_exception(self):
        original = RuntimeError("customer failure")

        async def fail():
            raise original

        with self.assertRaises(RuntimeError) as raised:
            await ReproIt.init().operation_async(
                "todos.create", b'{"title":"trigger-bug"}', fail
            )
        self.assertIs(raised.exception, original)


class OfficialManagedReleaseBinding(unittest.TestCase):
    def test_workspace_project_fails_before_project_or_capture_use(self):
        with self.assertRaises(protocol.ManagedError) as raised:
            official.OfficialManagedProject.from_build({}, "invalid", "invalid")
        self.assertEqual(raised.exception.code, "CONFIG_CONFLICT")

    def test_public_integration_fails_before_world_capture_when_unbound(self):
        world_accessed = False

        def capture_world():
            nonlocal world_accessed
            world_accessed = True

        with self.assertRaises(protocol.ManagedError) as raised:
            ReproIt({}, "invalid", "invalid", capture_world)
        self.assertEqual(raised.exception.code, "CONFIG_CONFLICT")
        self.assertFalse(world_accessed)

    def test_workspace_binding_fails_closed_before_project_token_access(self):
        accessed = False
        deployment = {"runtime_endpoint": "unchanged"}

        def token_provider():
            nonlocal accessed
            accessed = True
            return ManagedProjectToken("must-not-be-read")

        with self.assertRaises(protocol.ManagedError) as raised:
            official.official_managed_candidate_sink(
                ManagedCaptureClosure([], "return", fixtures.empty_world()),
                deployment,
                token_provider,
            )
        self.assertEqual(raised.exception.code, "CONFIG_CONFLICT")
        self.assertFalse(accessed)
        self.assertEqual(deployment, {"runtime_endpoint": "unchanged"})

    def test_official_entry_exposes_no_release_binding_input(self):
        parameters = inspect.signature(
            official.official_managed_candidate_sink
        ).parameters
        forbidden = {
            "ca_certificate_path",
            "capture_signer_id",
            "capture_signer_public_key",
            "managed_origin",
            "workload_state_root",
        }
        self.assertTrue(forbidden.isdisjoint(parameters))


_CA_PATH_CACHE: str | None = None


def _self_signed_ca_path(test) -> str:
    """Generate one self-signed CA certificate PEM for endpoint tests."""
    global _CA_PATH_CACHE
    if _CA_PATH_CACHE is not None and os.path.exists(_CA_PATH_CACHE):
        return _CA_PATH_CACHE
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "reproit-managed-test-ca")]
    )
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    handle = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    handle.close()
    _CA_PATH_CACHE = handle.name
    return handle.name


if __name__ == "__main__":
    unittest.main()


def test_commit_timeout_scales_with_the_declared_closure_and_stays_bounded():
    from reproit_sdk.managed_candidate import _commit_timeout_seconds

    assert _commit_timeout_seconds(0) == 5.0
    assert _commit_timeout_seconds(1) == 6.0
    assert _commit_timeout_seconds(4 * 1024 * 1024) == 6.0
    assert _commit_timeout_seconds(512 * 1024 * 1024) == 133.0
    assert _commit_timeout_seconds(2**63) == 180.0
