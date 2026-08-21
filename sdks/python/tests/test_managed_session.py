import copy
import hashlib
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import managed_fixtures as fixtures

from reproit_sdk import CandidateStart, Sdk, canonical_bytes
from reproit_sdk import managed_protocol as protocol
from reproit_sdk.managed_candidate import ManagedCaptureClosure
from reproit_sdk.managed_identity import managed_workload_key_id
from reproit_sdk.managed_sink import ManagedCandidateSink, ManagedSinkConfiguration
from reproit_sdk.managed_transport import (
    ManagedProjectToken,
    ManagedTlsClient,
    ManagedTlsEndpoint,
    _validate_grant_request,
    _validate_workload_registration,
)

PROJECT_TOKEN = "test-project-token"
UPLOAD_TOKEN = "managed-upload-token-1"


def _test_configuration(test, project_token=True):
    state_root = tempfile.TemporaryDirectory()
    test.addCleanup(state_root.cleanup)
    os.chmod(state_root.name, 0o700)
    return ManagedSinkConfiguration(
        capture_signer_id=fixtures.CAPTURE_SIGNER_ID,
        capture_signer_public_key=protocol.verification_key(
            fixtures.CAPTURE_SIGNER_SEED
        ),
        project_token=ManagedProjectToken(PROJECT_TOKEN) if project_token else None,
        service_id=fixtures.SERVICE_ID,
        workload_state_root=os.path.realpath(state_root.name),
    )


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03}Z"


class PlainHttpEndpoint(ManagedTlsEndpoint):
    """A loopback endpoint that skips TLS. Unit-test double only."""

    def __init__(self, host: str, port: int, authority: str):
        self._host = host
        self._port = port
        self._authority = authority
        self._origin = f"https://{authority}"

    def _connect(self, timeout: float) -> socket.socket:
        return socket.create_connection((self._host, self._port), timeout=timeout)


class LoopbackHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *arguments):
        del arguments

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def _reply(self, status: int, value=None) -> None:
        body = canonical_bytes(value) if value is not None else b""
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _reject(self, status: int, code: str, message: str) -> None:
        self._reply(
            status,
            {"code": code, "message": message, "retryable": status in (429, 503)},
        )

    def _authorized(self, expected: str) -> bool:
        return self.headers.get("Authorization") == expected

    def do_POST(self):  # noqa: N802 - http.server naming
        state = self.server.state
        path = urlsplit(self.path).path
        body = self._body()
        state["requests"].append(("POST", path))
        if path == "/v1/workload-keys":
            self._register_workload_key(body)
        elif path == "/v1/managed-candidate-encryption-grants":
            self._issue_grant(body)
        elif path == "/v1/managed-candidates":
            self._start_upload(body)
        elif path == f"/v1/managed-candidates/{fixtures.UPLOAD_ID}/commit":
            self._commit()
        else:
            self._reject(404, "NOT_FOUND", "Unknown route.")

    def do_GET(self):  # noqa: N802 - http.server naming
        state = self.server.state
        parts = urlsplit(self.path)
        state["requests"].append(("GET", parts.path))
        expected_path = f"/v1/managed-candidates/{fixtures.UPLOAD_ID}/missing"
        if parts.path != expected_path or not self._authorized(
            f"Bearer {UPLOAD_TOKEN}"
        ):
            self._reject(404, "NOT_FOUND", "Unknown missing-object page.")
            return
        query = parse_qs(parts.query)
        try:
            offset = int(query.get("cursor", ["0"])[0])
        except ValueError:
            self._reject(400, "SCHEMA_INVALID", "Invalid missing-object cursor.")
            return
        self._reply(200, self._missing_page(offset))

    def do_PUT(self):  # noqa: N802 - http.server naming
        state = self.server.state
        parts = urlsplit(self.path)
        body = self._body()
        state["requests"].append(("PUT", parts.path))
        prefix = f"/v1/managed-candidates/{fixtures.UPLOAD_ID}/objects/"
        if not parts.path.startswith(prefix) or parts.query != "token=up":
            self._reject(404, "NOT_FOUND", "Unknown object route.")
            return
        digest = parts.path[len(prefix) :]
        if (
            digest not in state["expected"]
            or f"sha256:{hashlib.sha256(body).hexdigest()}" != digest
        ):
            self._reject(400, "OBJECT_DIGEST_MISMATCH", "Digest mismatch.")
            return
        state["uploaded"].add(digest)
        self._reply(204)

    def do_DELETE(self):  # noqa: N802 - http.server naming
        state = self.server.state
        path = urlsplit(self.path).path
        state["requests"].append(("DELETE", path))
        upload_request = state.get("upload_request")
        if path != f"/v1/managed-candidates/{fixtures.UPLOAD_ID}" or not upload_request:
            self._reject(404, "NOT_FOUND", "Unknown upload.")
            return
        identity = upload_request["ciphertext_identity"]
        self._reply(
            200,
            {
                "candidate_identity_digest": identity["candidate_identity_digest"],
                "candidate_key_reference": identity["candidate_key_reference"],
                "capture_id": identity["capture_id"],
                "encrypted_candidate_digest": upload_request[
                    "encrypted_candidate_digest"
                ],
                "expires_at": None,
                "missing_digests": [],
                "state": "CANCELLED",
                "upload_id": fixtures.UPLOAD_ID,
            },
        )

    def _register_workload_key(self, body: bytes) -> None:
        if not self._authorized(f"Bearer {PROJECT_TOKEN}"):
            self._reject(401, "AUTHENTICATION_REQUIRED", "Missing project token.")
            return
        value = json.loads(body)
        try:
            _validate_workload_registration(value)
        except protocol.ManagedError:
            self._reject(400, "SCHEMA_INVALID", "Invalid registration.")
            return
        public_key = protocol.decode_base64url(value["public_key"], 32)
        key_id = managed_workload_key_id(public_key)
        self.server.state["registration"] = value
        self.server.state["registered_public_key"] = value["public_key"]
        self._reply(
            200,
            {
                "deployment_digest": protocol.canonical_digest(value["deployment"]),
                "key_id": key_id,
                "service_id": fixtures.SERVICE_ID,
            },
        )

    def _issue_grant(self, body: bytes) -> None:
        state = self.server.state
        if self.headers.get("Authorization") is not None:
            self._reject(401, "AUTHENTICATION_REQUIRED", "Unexpected credential.")
            return
        if state.get("grant_failure_status"):
            status = state["grant_failure_status"]
            self._reject(status, "SERVICE_UNAVAILABLE", "Grant unavailable.")
            return
        request = json.loads(body)
        try:
            _validate_grant_request(request)
            registration = state["registration"]
            public_key = protocol.decode_base64url(registration["public_key"], 32)
            if (
                request["deployment_digest"]
                != protocol.canonical_digest(registration["deployment"])
                or request["signer_key_id"]
                != registration["deployment"]["signer_key_id"]
            ):
                raise protocol.attestation_error()
            protocol.verify_signed_value(request, public_key)
        except protocol.ManagedError:
            self._reject(400, "SCHEMA_INVALID", "Invalid grant request.")
            return
        state["grant_requests"].append(request)
        now = datetime.now(UTC)
        grant = fixtures.signed_capture_grant(
            request,
            not_before=_timestamp(now - timedelta(minutes=5)),
            expires_at=_timestamp(now + timedelta(minutes=5)),
        )
        state["issued_grants"].append(grant)
        self._reply(
            200,
            {
                "candidate_key": protocol.encode_base64url(fixtures.CANDIDATE_KEY),
                "capture_grant": grant,
            },
        )

    def _start_upload(self, body: bytes) -> None:
        state = self.server.state
        request = json.loads(body)
        try:
            protocol.validate_upload_request(request)
        except protocol.ManagedError:
            self._reject(400, "SCHEMA_INVALID", "Invalid upload request.")
            return
        if (
            not state["issued_grants"]
            or request["capture_grant"] not in state["issued_grants"]
        ):
            self._reject(403, "ATTESTATION_SCOPE", "Unknown capture grant.")
            return
        state["upload_request"] = request
        identity = request["ciphertext_identity"]
        expected = {identity["manifest_object"]["cipher_digest"]}
        for entry in identity["objects"]:
            for chunk in entry["chunks"]:
                expected.add(chunk["cipher_digest"])
        state["expected"] = expected
        state["uploaded"] = set()
        origin = f"https://{state['authority']}"
        state["missing_entries"] = [
            {
                "cipher_digest": digest,
                "expires_at": _timestamp(datetime.now(UTC) + timedelta(minutes=1)),
                "upload_url": (
                    f"{origin}/v1/managed-candidates/{fixtures.UPLOAD_ID}"
                    f"/objects/{digest}?token=up"
                ),
            }
            for digest in sorted(expected)
        ]
        response = self._missing_page(0)
        response.update(
            {
                "expires_at": _timestamp(datetime.now(UTC) + timedelta(minutes=1)),
                "limits": state["limits"],
                "state": "OPEN",
                "upload_id": fixtures.UPLOAD_ID,
                "upload_token": UPLOAD_TOKEN,
            }
        )
        self._reply(
            200,
            response,
        )

    def _missing_page(self, offset: int) -> dict[str, object]:
        entries = self.server.state["missing_entries"]
        next_offset = offset + 100
        return {
            "missing_objects": entries[offset:next_offset],
            "next_missing_cursor": str(next_offset)
            if next_offset < len(entries)
            else None,
        }

    def _commit(self) -> None:
        state = self.server.state
        if not self._authorized(f"Bearer {UPLOAD_TOKEN}"):
            self._reject(401, "AUTHENTICATION_REQUIRED", "Missing upload token.")
            return
        if state["expected"] != state["uploaded"]:
            self._reject(409, "UPLOAD_INCOMPLETE", "Objects are missing.")
            return
        request = state["upload_request"]
        identity = request["ciphertext_identity"]
        self._reply(
            200,
            {
                "candidate_identity_digest": identity["candidate_identity_digest"],
                "candidate_key_reference": identity["candidate_key_reference"],
                "capture_id": identity["capture_id"],
                "encrypted_candidate_digest": request["encrypted_candidate_digest"],
                "state": "CLOUD_PROTECTED",
                "upload_id": fixtures.UPLOAD_ID,
            },
        )


class LoopbackManagedService:
    """One loopback HTTP double for the key service and managed ingress."""

    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), LoopbackHandler)
        host, port = self.server.server_address[0], self.server.server_address[1]
        self.authority = f"{host}:{port}"
        self.server.state = {
            "authority": self.authority,
            "expected": set(),
            "grant_requests": [],
            "issued_grants": [],
            "limits": fixtures.load_cloud_api_vectors()["positive"][
                "managed_candidate_limits"
            ]["value"],
            "missing_entries": [],
            "requests": [],
            "uploaded": set(),
        }
        self.thread = threading.Thread(
            target=self.server.serve_forever, name="reproit-loopback", daemon=True
        )
        self.thread.start()
        self.endpoint = PlainHttpEndpoint(host, port, self.authority)
        self.client = ManagedTlsClient(self.endpoint, self.endpoint)

    @property
    def state(self):
        return self.server.state

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2.0)


class ManagedLoopbackSession(unittest.TestCase):
    def setUp(self):
        self.service = LoopbackManagedService()
        self.addCleanup(self.service.close)
        self.subject = fixtures.shared_subject()
        self.world = fixtures.empty_world()
        self.world_id = protocol.canonical_digest(self.world)
        self.state_root = tempfile.TemporaryDirectory()
        self.addCleanup(self.state_root.cleanup)
        os.chmod(self.state_root.name, 0o700)
        self.configuration = ManagedSinkConfiguration(
            capture_signer_id=fixtures.CAPTURE_SIGNER_ID,
            capture_signer_public_key=protocol.verification_key(
                fixtures.CAPTURE_SIGNER_SEED
            ),
            project_token=ManagedProjectToken(PROJECT_TOKEN),
            service_id=fixtures.SERVICE_ID,
            workload_state_root=os.path.realpath(self.state_root.name),
        )
        self.sink = ManagedCandidateSink(
            self.service.client,
            ManagedCaptureClosure([], "return", copy.deepcopy(self.world)),
            self.configuration,
            subject=self.subject,
        )

    def _bound_deployment(self) -> dict:
        deployment = {
            "format": "reproit.deployment.v1",
            "organization_id": fixtures.ORGANIZATION_ID,
            "processing_mode": "managed",
            "project_id": fixtures.PROJECT_ID,
            "repository_id": "source.example/acme/commerce",
            "runtime_capabilities": ["runtime.python"],
            "runtime_endpoint": "https://managed.reproit.example",
            "service_id": fixtures.SERVICE_ID,
            "service_path": "services/orders",
            "signature": "",
            "signed_at": "2026-01-01T00:00:00.000Z",
            "signer_key_id": "",
            "source_revision": "0123456789abcdef",
            "subject": {},
        }
        self.sink.bind_deployment(deployment)
        return deployment

    def _capture_failure(self, deployment: dict) -> None:
        vectors = fixtures.load_protocol_vectors()["positive"]
        sdk = Sdk(self.sink)
        start = CandidateStart(
            fixtures.CAPTURE_ID, deployment, fixtures.OPERATION_ID, self.world_id
        )
        sdk.begin(start, vectors["operation_begin_payload"]["value"])
        sdk.record_input(
            fixtures.OPERATION_ID, vectors["operation_input_payload"]["value"]
        )
        sdk.fail(fixtures.OPERATION_ID, vectors["failure_payload"]["value"])

    def test_registration_binds_the_exact_signed_deployment(self):
        deployment = self._bound_deployment()
        self.assertEqual(self.service.state["requests"], [])
        self._capture_failure(deployment)
        self.assertTrue(self.sink.wait_until_idle(10.0))
        self.assertEqual(
            self.sink.workload_key_id,
            managed_workload_key_id(self.sink.workload_public_key),
        )
        self.assertEqual(
            self.service.state["requests"][0], ("POST", "/v1/workload-keys")
        )
        self.assertEqual(
            self.service.state["requests"].count(("POST", "/v1/workload-keys")),
            1,
        )
        self.assertEqual(
            self.service.state["registered_public_key"],
            protocol.encode_base64url(self.sink.workload_public_key),
        )
        registration = self.service.state["registration"]
        self.assertEqual(registration["deployment"], deployment)
        self.assertEqual(
            registration["deployment"]["signer_key_id"], self.sink.workload_key_id
        )
        protocol.verify_signed_value(
            registration["deployment"], self.sink.workload_public_key
        )

    def test_successful_operation_makes_no_cloud_request(self):
        deployment = self._bound_deployment()
        vectors = fixtures.load_protocol_vectors()["positive"]
        sdk = Sdk(self.sink)
        start = CandidateStart(
            fixtures.CAPTURE_ID, deployment, fixtures.OPERATION_ID, self.world_id
        )
        sdk.begin(start, vectors["operation_begin_payload"]["value"])
        sdk.succeed(fixtures.OPERATION_ID)
        self.assertEqual(self.service.state["requests"], [])

    def test_incomplete_operation_makes_no_cloud_request(self):
        deployment = self._bound_deployment()
        candidate = fixtures.captured_candidate(deployment, self.world_id)
        candidate["records"].pop()
        self.assertTrue(
            self.sink.try_send(fixtures.CAPTURE_ID, canonical_bytes(candidate))
        )
        self.assertTrue(self.sink.wait_until_idle(10.0))
        self.assertEqual(self.service.state["requests"], [])

    def test_complete_candidate_reaches_cloud_protected(self):
        deployment = self._bound_deployment()
        self._capture_failure(deployment)
        self.assertTrue(self.sink.wait_until_idle(10.0))
        counters = self.sink.recall_counters
        self.assertEqual(counters["candidate_durably_accepted"], 1)
        self.assertEqual(counters["candidate_incomplete"], 0)
        self.assertEqual(counters["candidate_rejected"], 0)
        self.assertEqual(self.sink.queued_bytes, 0)

        requests = self.service.state["requests"]
        self.assertEqual(requests[0], ("POST", "/v1/workload-keys"))
        self.assertEqual(
            requests[1], ("POST", "/v1/managed-candidate-encryption-grants")
        )
        self.assertEqual(
            requests[2], ("POST", "/v1/managed-candidate-encryption-grants")
        )
        self.assertEqual(requests[3], ("POST", "/v1/managed-candidates"))
        object_puts = [entry for entry in requests if entry[0] == "PUT"]
        self.assertEqual(len(object_puts), len(self.service.state["expected"]))
        self.assertEqual(
            requests[-1],
            ("POST", f"/v1/managed-candidates/{fixtures.UPLOAD_ID}/commit"),
        )
        self.assertEqual(self.service.state["expected"], self.service.state["uploaded"])

        grant_requests = self.service.state["grant_requests"]
        self.assertEqual(len(grant_requests), 2)
        self.assertEqual(grant_requests[0], grant_requests[1])
        upload_request = self.service.state["upload_request"]
        self.assertEqual(
            grant_requests[0]["candidate_identity_digest"],
            upload_request["ciphertext_identity"]["candidate_identity_digest"],
        )

    def test_incomplete_candidate_stops_locally_with_a_counter(self):
        deployment = self._bound_deployment()
        self._capture_failure(deployment)
        self.assertTrue(self.sink.wait_until_idle(10.0))
        requests_before = len(self.service.state["requests"])

        vectors = fixtures.load_protocol_vectors()["positive"]
        sdk = Sdk(self.sink)
        start = CandidateStart(
            "cap_01890f3e-7b1c-7cc0-8a1b-123456789ac3",
            deployment,
            "op_01890f3e-7b1c-7cc0-8a1b-123456789ac4",
            "sha256:" + "a" * 64,
        )
        sdk.begin(start, vectors["operation_begin_payload"]["value"])
        sdk.fail(start.operation_id, vectors["failure_payload"]["value"])
        self.assertTrue(self.sink.wait_until_idle(10.0))
        counters = self.sink.recall_counters
        self.assertEqual(counters["candidate_incomplete"], 1)
        self.assertEqual(counters["candidate_durably_accepted"], 1)
        self.assertEqual(len(self.service.state["requests"]), requests_before)

    def test_non_canonical_candidate_is_refused_without_enqueue(self):
        deployment = self._bound_deployment()
        candidate = fixtures.captured_candidate(deployment, self.world_id)
        raw = canonical_bytes(candidate) + b" "
        self.assertFalse(self.sink.try_send(fixtures.CAPTURE_ID, raw))
        self.assertEqual(self.sink.recall_counters["candidate_incomplete"], 1)

    def test_foreign_workload_signature_is_refused(self):
        deployment = self._bound_deployment()
        deployment["signature"] = protocol.sign_bytes(
            canonical_bytes({**deployment, "signature": ""}), bytes([0x55]) * 32
        )
        candidate = fixtures.captured_candidate(deployment, self.world_id)
        self.assertFalse(
            self.sink.try_send(fixtures.CAPTURE_ID, canonical_bytes(candidate))
        )
        self.assertEqual(self.sink.recall_counters["candidate_incomplete"], 1)

    def test_grant_outage_is_fail_open_and_counted_as_retryable(self):
        self.service.state["grant_failure_status"] = 503
        deployment = self._bound_deployment()
        self._capture_failure(deployment)
        self.assertTrue(self.sink.wait_until_idle(10.0))
        counters = self.sink.recall_counters
        self.assertEqual(counters["candidate_durably_accepted"], 0)
        self.assertEqual(counters["candidate_delivery_expired"], 1)
        self.assertNotIn(
            ("POST", "/v1/managed-candidates"), self.service.state["requests"]
        )

    def test_restart_reuses_the_registration_receipt_without_a_project_token(self):
        deployment = self._bound_deployment()
        self._capture_failure(deployment)
        self.assertTrue(self.sink.wait_until_idle(10.0))

        restarted_configuration = ManagedSinkConfiguration(
            capture_signer_id=fixtures.CAPTURE_SIGNER_ID,
            capture_signer_public_key=protocol.verification_key(
                fixtures.CAPTURE_SIGNER_SEED
            ),
            project_token=None,
            service_id=fixtures.SERVICE_ID,
            workload_state_root=os.path.realpath(self.state_root.name),
        )
        restarted = ManagedCandidateSink(
            self.service.client,
            ManagedCaptureClosure([], "return", copy.deepcopy(self.world)),
            restarted_configuration,
            subject=self.subject,
        )
        restarted_deployment = copy.deepcopy(deployment)
        restarted_deployment["signed_at"] = "2026-02-01T00:00:00.000Z"
        restarted.bind_deployment(restarted_deployment)
        self.assertEqual(restarted_deployment, deployment)
        vectors = fixtures.load_protocol_vectors()["positive"]
        sdk = Sdk(restarted)
        sdk.begin(
            CandidateStart(
                fixtures.CAPTURE_ID,
                restarted_deployment,
                fixtures.OPERATION_ID,
                self.world_id,
            ),
            vectors["operation_begin_payload"]["value"],
        )
        sdk.record_input(
            fixtures.OPERATION_ID, vectors["operation_input_payload"]["value"]
        )
        sdk.fail(fixtures.OPERATION_ID, vectors["failure_payload"]["value"])
        self.assertTrue(restarted.wait_until_idle(10.0))
        registrations = [
            request
            for request in self.service.state["requests"]
            if request == ("POST", "/v1/workload-keys")
        ]
        self.assertEqual(len(registrations), 1)


class _StubRegistrationClient:
    """A client double that registers and then blocks grant delivery."""

    def __init__(self):
        self.release = threading.Event()
        self.grant_calls = 0

    def register_workload_key(self, project_token, request, timeout):
        del project_token, timeout
        return {
            "deployment_digest": protocol.canonical_digest(request["deployment"]),
            "key_id": request["deployment"]["signer_key_id"],
            "service_id": request["service_id"],
        }

    def request_encryption_grant(self, request, timeout):
        del request, timeout
        self.grant_calls += 1
        self.release.wait(10.0)
        raise protocol.ManagedError("SCHEMA_INVALID", "The double refuses grants.")


class ManagedSinkBounds(unittest.TestCase):
    def test_queue_bound_counts_queue_full_and_stays_fail_open(self):
        client = _StubRegistrationClient()
        subject = fixtures.shared_subject()
        world = fixtures.empty_world()
        configuration = _test_configuration(self)
        sink = ManagedCandidateSink(
            client,
            ManagedCaptureClosure([], "return", world),
            configuration,
            subject=subject,
        )
        deployment = fixtures.bound_deployment(subject)
        sink.bind_deployment(deployment)
        candidate = fixtures.captured_candidate(
            deployment, protocol.canonical_digest(world)
        )
        raw = canonical_bytes(candidate)
        accepted = sum(sink.try_send(fixtures.CAPTURE_ID, raw) for _ in range(17))
        self.assertEqual(accepted, 16)
        self.assertEqual(sink.recall_counters["candidate_queue_full"], 1)
        client.release.set()
        self.assertTrue(sink.wait_until_idle(20.0))
        counters = sink.recall_counters
        terminal = (
            counters["candidate_rejected"]
            + counters["candidate_delivery_expired"]
            + counters["candidate_incomplete"]
            + counters["candidate_durably_accepted"]
        )
        self.assertEqual(terminal, 16)
        self.assertEqual(counters["candidate_durably_accepted"], 0)
        self.assertEqual(sink.queued_bytes, 0)

    def test_processing_modes_are_managed_only(self):
        client = _StubRegistrationClient()
        sink = ManagedCandidateSink(
            client,
            ManagedCaptureClosure([], "return", fixtures.empty_world()),
            _test_configuration(self),
            subject=fixtures.shared_subject(),
        )
        self.assertEqual(sink.processing_modes, frozenset(("managed",)))


class ManagedDeliveryExpiry(unittest.TestCase):
    def test_expired_queue_entries_are_counted_not_delivered(self):
        from reproit_sdk import managed_sink as sink_module

        client = _StubRegistrationClient()
        client.release.set()
        subject = fixtures.shared_subject()
        world = fixtures.empty_world()
        sink = ManagedCandidateSink(
            client,
            ManagedCaptureClosure([], "return", world),
            _test_configuration(self),
            subject=subject,
        )
        deployment = fixtures.bound_deployment(subject)
        sink.bind_deployment(deployment)
        candidate = fixtures.captured_candidate(
            deployment, protocol.canonical_digest(world)
        )
        original = sink_module.CANDIDATE_DELIVERY_LIFETIME_SECONDS
        sink_module.CANDIDATE_DELIVERY_LIFETIME_SECONDS = 0.0
        try:
            self.assertTrue(
                sink.try_send(fixtures.CAPTURE_ID, canonical_bytes(candidate))
            )
            deadline = time.monotonic() + 5.0
            while (
                sink.recall_counters["candidate_delivery_expired"] == 0
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
        finally:
            sink_module.CANDIDATE_DELIVERY_LIFETIME_SECONDS = original
        self.assertEqual(sink.recall_counters["candidate_delivery_expired"], 1)
        self.assertEqual(client.grant_calls, 0)


if __name__ == "__main__":
    unittest.main()
