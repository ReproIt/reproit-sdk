"""Managed key-service and ingress HTTP client with strict bounds.

Mirrors crates/reproit-sdk-rust/src/managed_transport.rs: TLS 1.3 only,
HTTP/1.1 with Connection: close, bounded request and response sizes, the
exact routes and JSON bodies the Rust client sends, and typed rejection of
every invalid response.
"""

from __future__ import annotations

import os
import socket
import ssl
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from reproit_sdk import canonical_bytes

from .managed_protocol import (
    ERROR_CODES,
    ManagedError,
    canonical_digest,
    decode_base64url,
    digest_bytes,
    parse_strict_json,
    require_typed_id,
    schema_invalid,
    valid_digest,
    valid_opaque_reference,
    valid_timestamp,
    valid_typed_id,
    validate_capabilities,
    validate_capture_grant,
    verify_signed_value,
)

MAX_CA_BYTES = 1_048_576
MAX_HEADER_BYTES = 8_192
MAX_JSON_RESPONSE_BYTES = 8_388_608
MAX_PROJECT_TOKEN_BYTES = 1_024
MAX_REGISTRATION_BYTES = 3_372_783

_UPLOAD_STATES = frozenset(
    ("CANCELLED", "COMMITTED", "COMMITTING", "EXPIRED", "OPEN", "UPLOADING")
)
_DURABILITY_STATES = frozenset(("CLOUD_PROTECTED", "LOCAL_ONLY"))
_LIMIT_KEYS = frozenset(
    (
        "max_candidate_bytes",
        "max_object_bytes",
        "max_objects",
        "max_total_ciphertext_bytes",
        "missing_page_size",
        "object_attempts",
        "upload_lifetime_ms",
    )
)


class ManagedProjectToken:
    """A project token that authorizes one managed workload registration."""

    def __init__(self, value: str):
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_PROJECT_TOKEN_BYTES
            or not all(33 <= ord(character) <= 126 for character in value)
        ):
            raise schema_invalid("The managed project token is invalid.")
        self._value = value

    def authorization(self) -> str:
        return f"Bearer {self._value}"


@dataclass(frozen=True)
class HttpResponse:
    body: bytes
    status: int


@dataclass(frozen=True)
class EncryptionResponse:
    """The managed candidate key and its signed capture grant."""

    candidate_key: bytes
    capture_grant: dict[str, object]


class ManagedTlsEndpoint:
    """One TLS 1.3 origin for the managed key service or managed ingress."""

    def __init__(
        self,
        host: str,
        port: int,
        server_name: str,
        authority: str,
        ca_certificate_path: str,
    ):
        if (
            not isinstance(host, str)
            or not host
            or len(host) > 253
            or not isinstance(port, int)
            or not 1 <= port <= 65_535
            or not isinstance(server_name, str)
            or not server_name
            or len(server_name) > 253
        ):
            raise _endpoint_invalid()
        _validate_authority(authority)
        self._host = host
        self._port = port
        self._server_name = server_name
        self._authority = authority
        self._origin = f"https://{authority}"
        self._tls = _tls_context(ca_certificate_path)

    @classmethod
    def official(cls, origin: str) -> ManagedTlsEndpoint:
        """Create one platform-verified endpoint from a release-bound origin."""
        authority, host, port = _official_origin(origin)
        endpoint = cls.__new__(cls)
        endpoint._host = host
        endpoint._port = port
        endpoint._server_name = host
        endpoint._authority = authority
        endpoint._origin = origin
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        except (ssl.SSLError, ValueError) as error:
            raise _service_unavailable() from error
        endpoint._tls = context
        return endpoint

    @property
    def origin(self) -> str:
        return self._origin

    def request(
        self,
        method: str,
        target: str,
        authorization: str | None,
        content_type: str | None,
        body: bytes,
        timeout: float,
    ) -> HttpResponse:
        _validate_request_component(method)
        _validate_target(target)
        if authorization is not None:
            _validate_header_value(authorization)
        if content_type is not None:
            _validate_header_value(content_type)
        header = (
            f"{method} {target} HTTP/1.1\r\n"
            f"Host: {self._authority}\r\nConnection: close\r\n"
        )
        if authorization is not None:
            header += f"Authorization: {authorization}\r\n"
        if content_type is not None:
            header += f"Content-Type: {content_type}\r\n"
        header += f"Content-Length: {len(body)}\r\n\r\n"
        try:
            with self._connect(timeout) as connection:
                connection.sendall(header.encode("ascii") + body)
                return _read_response(connection)
        except ssl.SSLError as error:
            raise _endpoint_invalid() from error
        except OSError as error:
            raise _service_unavailable() from error

    def upload_target(self, upload_url: str) -> str:
        if not isinstance(upload_url, str) or not upload_url.startswith(self._origin):
            raise _endpoint_invalid()
        target = upload_url[len(self._origin) :]
        _validate_target(target)
        return target

    def _connect(self, timeout: float) -> socket.socket:
        connection = socket.create_connection((self._host, self._port), timeout=timeout)
        try:
            return self._tls.wrap_socket(connection, server_hostname=self._server_name)
        except BaseException:
            connection.close()
            raise


def _tls_context(ca_certificate_path: str) -> ssl.SSLContext:
    try:
        metadata = os.lstat(ca_certificate_path)
    except OSError as error:
        raise _endpoint_invalid() from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_CA_BYTES
    ):
        raise _endpoint_invalid()
    with open(ca_certificate_path, "rb") as source:
        certificate = source.read(MAX_CA_BYTES + 1)
    if len(certificate) != metadata.st_size:
        raise _endpoint_invalid()
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=certificate.decode("ascii"))
    except (ssl.SSLError, UnicodeDecodeError, ValueError) as error:
        raise _endpoint_invalid() from error
    return context


def _official_origin(origin: str) -> tuple[str, str, int]:
    if not isinstance(origin, str) or len(origin) > 2_048:
        raise _endpoint_invalid()
    try:
        parsed = urlsplit(origin)
        port = parsed.port or 443
    except ValueError as error:
        raise _endpoint_invalid() from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname.lower() != parsed.hostname
        or parsed.netloc != parsed.hostname
    ):
        raise _endpoint_invalid()
    _validate_authority(parsed.netloc)
    return parsed.netloc, parsed.hostname, port


class ManagedTlsClient:
    """The SDK-side client for the managed key service and managed ingress."""

    def __init__(
        self,
        key_service: ManagedTlsEndpoint,
        ingress: ManagedTlsEndpoint,
    ):
        self._ingress = ingress
        self._key_service = key_service

    def register_workload_key(
        self,
        project_token: ManagedProjectToken,
        request: Mapping[str, object],
        timeout: float,
    ) -> dict[str, object]:
        _validate_workload_registration(request)
        body = canonical_bytes(request)
        if len(body) > MAX_REGISTRATION_BYTES:
            raise schema_invalid()
        response = self._key_service.request(
            "POST",
            "/v1/workload-keys",
            project_token.authorization(),
            "application/json",
            body,
            timeout,
        )
        registration = _decode_json(response, 200)
        _validate_registration_result(registration, request)
        return registration

    def request_encryption_grant(
        self, request: Mapping[str, object], timeout: float
    ) -> EncryptionResponse:
        _validate_grant_request(request)
        response = self._key_service.request(
            "POST",
            "/v1/managed-candidate-encryption-grants",
            None,
            "application/json",
            canonical_bytes(request),
            timeout,
        )
        value = _decode_json(response, 200)
        if not isinstance(value, dict) or set(value) != {
            "candidate_key",
            "capture_grant",
        }:
            raise _response_invalid()
        candidate_key = decode_base64url(value["candidate_key"], 32)
        validate_capture_grant(value["capture_grant"])
        return EncryptionResponse(candidate_key, value["capture_grant"])

    def start(self, request: Mapping[str, object], timeout: float) -> dict[str, object]:
        from .managed_protocol import validate_upload_request

        validate_upload_request(request)
        response = self._ingress.request(
            "POST",
            "/v1/managed-candidates",
            None,
            "application/json",
            canonical_bytes(request),
            timeout,
        )
        return _validate_start(_decode_json(response, 200))

    def missing(
        self,
        upload_id: str,
        upload_token: str,
        cursor: str | None,
        timeout: float,
    ) -> dict[str, object]:
        require_typed_id(upload_id, "upload_id")
        _validate_token(upload_token)
        if cursor is not None:
            _validate_cursor(cursor)
        target = f"/v1/managed-candidates/{upload_id}/missing?limit=100"
        if cursor is not None:
            target += f"&cursor={cursor}"
        response = self._ingress.request(
            "GET", target, f"Bearer {upload_token}", None, b"", timeout
        )
        return _validate_missing_page(_decode_json(response, 200))

    def upload_object(
        self, upload_url: str, digest: str, value: bytes, timeout: float
    ) -> None:
        if digest_bytes(value) != digest:
            raise ManagedError(
                "OBJECT_DIGEST_MISMATCH",
                "The object bytes do not match the bound digest.",
            )
        target = self._ingress.upload_target(upload_url)
        response = self._ingress.request(
            "PUT", target, None, "application/octet-stream", value, timeout
        )
        _expect_empty(response, 204)

    def commit(
        self, upload_id: str, upload_token: str, timeout: float
    ) -> dict[str, object]:
        require_typed_id(upload_id, "upload_id")
        _validate_token(upload_token)
        response = self._ingress.request(
            "POST",
            f"/v1/managed-candidates/{upload_id}/commit",
            f"Bearer {upload_token}",
            None,
            b"",
            timeout,
        )
        return _validate_commit(_decode_json(response, 200))

    def cancel(
        self, upload_id: str, upload_token: str, timeout: float
    ) -> dict[str, object]:
        require_typed_id(upload_id, "upload_id")
        _validate_token(upload_token)
        response = self._ingress.request(
            "DELETE",
            f"/v1/managed-candidates/{upload_id}",
            f"Bearer {upload_token}",
            None,
            b"",
            timeout,
        )
        return _validate_status(_decode_json(response, 200))


def _validate_grant_request(value: Mapping[str, object]) -> None:
    from .managed_protocol import CIPHER_SUITE

    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "candidate_identity_digest",
            "capture_id",
            "cipher_suite",
            "deployment_digest",
            "organization_id",
            "processing_mode",
            "project_id",
            "service_id",
            "signature",
            "signer_key_id",
        }
        or value["processing_mode"] != "managed"
        or value["cipher_suite"] != CIPHER_SUITE
        or not valid_digest(value["candidate_identity_digest"])
        or not valid_digest(value["deployment_digest"])
        or not valid_typed_id(value["capture_id"], "capture_id")
        or not valid_typed_id(value["organization_id"], "organization_id")
        or not valid_typed_id(value["project_id"], "project_id")
        or not valid_typed_id(value["service_id"], "service_id")
        or not _valid_workload_key_id(value["signer_key_id"])
    ):
        raise schema_invalid()
    decode_base64url(value["signature"], 64)


def _validate_workload_registration(value: Mapping[str, object]) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "algorithm",
        "deployment",
        "public_key",
        "service_id",
    }:
        raise schema_invalid()
    deployment = value["deployment"]
    public_key = decode_base64url(value["public_key"], 32)
    service_id = require_typed_id(value["service_id"], "service_id")
    if value["algorithm"] != "Ed25519" or not isinstance(deployment, Mapping):
        raise schema_invalid()
    _validate_registration_deployment(deployment)
    from .managed_identity import managed_workload_key_id

    if deployment["service_id"] != service_id or deployment[
        "signer_key_id"
    ] != managed_workload_key_id(public_key):
        raise schema_invalid()
    verify_signed_value(deployment, public_key)


def _validate_registration_deployment(value: Mapping[str, object]) -> None:
    expected = {
        "format",
        "organization_id",
        "processing_mode",
        "project_id",
        "repository_id",
        "runtime_capabilities",
        "runtime_endpoint",
        "service_id",
        "service_path",
        "signature",
        "signed_at",
        "signer_key_id",
        "source_revision",
        "subject",
    }
    if (
        set(value) != expected
        or value["format"] != "reproit.deployment.v1"
        or value["processing_mode"] != "managed"
        or not valid_typed_id(value["organization_id"], "organization_id")
        or not valid_typed_id(value["project_id"], "project_id")
        or not valid_typed_id(value["service_id"], "service_id")
        or not _bounded_text(value["repository_id"], 256)
        or not _bounded_text(value["runtime_endpoint"], 2_048)
        or not _valid_service_path(value["service_path"])
        or not _bounded_text(value["source_revision"], 256)
        or not valid_timestamp(value["signed_at"])
        or not _valid_workload_key_id(value["signer_key_id"])
        or not isinstance(value["subject"], Mapping)
    ):
        raise schema_invalid()
    validate_capabilities(value["runtime_capabilities"])
    decode_base64url(value["signature"], 64)


def _validate_registration_result(value: object, request: Mapping[str, object]) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"deployment_digest", "key_id", "service_id"}
        or value["deployment_digest"] != canonical_digest(request["deployment"])
        or value["key_id"] != request["deployment"]["signer_key_id"]
        or value["service_id"] != request["service_id"]
        or not valid_digest(value["deployment_digest"])
        or not _valid_workload_key_id(value["key_id"])
        or not valid_typed_id(value["service_id"], "service_id")
    ):
        raise _response_invalid()


def _valid_workload_key_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("managed-workload-sha256:")
        and len(value) == 88
        and all(character in "0123456789abcdef" for character in value[24:])
    )


def _bounded_text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= maximum


def _valid_service_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 1_024
        and not value.startswith("/")
        and all(part != ".." for part in value.split("/"))
    )


def _validate_missing_object(value: object) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"cipher_digest", "expires_at", "upload_url"}
        or not valid_digest(value["cipher_digest"])
        or not valid_timestamp(value["expires_at"])
        or not isinstance(value["upload_url"], str)
        or not value["upload_url"]
        or len(value["upload_url"]) > 4_096
    ):
        raise _response_invalid()


def _validate_limits(value: object) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != _LIMIT_KEYS
        or any(type(value[key]) is not int or value[key] < 0 for key in _LIMIT_KEYS)
    ):
        raise _response_invalid()


def _validate_start(value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "expires_at",
            "limits",
            "missing_objects",
            "next_missing_cursor",
            "state",
            "upload_id",
            "upload_token",
        }
        or not valid_timestamp(value["expires_at"])
        or value["state"] not in _UPLOAD_STATES
        or not valid_typed_id(value["upload_id"], "upload_id")
        or not isinstance(value["missing_objects"], list)
    ):
        raise _response_invalid()
    _validate_limits(value["limits"])
    _validate_token(value["upload_token"])
    if value["next_missing_cursor"] is not None:
        _validate_cursor(value["next_missing_cursor"])
    for missing in value["missing_objects"]:
        _validate_missing_object(missing)
    return value


def _validate_missing_page(value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != {"missing_objects", "next_missing_cursor"}
        or not isinstance(value["missing_objects"], list)
    ):
        raise _response_invalid()
    if value["next_missing_cursor"] is not None:
        _validate_cursor(value["next_missing_cursor"])
    for missing in value["missing_objects"]:
        _validate_missing_object(missing)
    return value


def _validate_commit(value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "candidate_identity_digest",
            "candidate_key_reference",
            "capture_id",
            "encrypted_candidate_digest",
            "state",
            "upload_id",
        }
        or not valid_digest(value["candidate_identity_digest"])
        or not valid_opaque_reference(value["candidate_key_reference"])
        or not valid_typed_id(value["capture_id"], "capture_id")
        or not valid_digest(value["encrypted_candidate_digest"])
        or value["state"] not in _DURABILITY_STATES
        or not valid_typed_id(value["upload_id"], "upload_id")
    ):
        raise _response_invalid()
    return value


def _validate_status(value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "candidate_identity_digest",
            "candidate_key_reference",
            "capture_id",
            "encrypted_candidate_digest",
            "expires_at",
            "missing_digests",
            "state",
            "upload_id",
        }
        or not valid_digest(value["candidate_identity_digest"])
        or not valid_opaque_reference(value["candidate_key_reference"])
        or not valid_typed_id(value["capture_id"], "capture_id")
        or not valid_digest(value["encrypted_candidate_digest"])
        or not (value["expires_at"] is None or valid_timestamp(value["expires_at"]))
        or not isinstance(value["missing_digests"], list)
        or any(not valid_digest(digest) for digest in value["missing_digests"])
        or value["state"] not in _UPLOAD_STATES
        or not valid_typed_id(value["upload_id"], "upload_id")
    ):
        raise _response_invalid()
    return value


def _decode_json(response: HttpResponse, expected_status: int) -> object:
    if response.status != expected_status:
        raise _decode_server_error(response.status, response.body)
    if not response.body:
        raise _response_invalid()
    try:
        return parse_strict_json(response.body, MAX_JSON_RESPONSE_BYTES)
    except ManagedError as error:
        raise _response_invalid() from error


def _expect_empty(response: HttpResponse, expected_status: int) -> None:
    if response.status != expected_status:
        raise _decode_server_error(response.status, response.body)
    if response.body:
        raise _response_invalid()


def _decode_server_error(status: int, body: bytes) -> ManagedError:
    if body:
        try:
            value = parse_strict_json(body, MAX_JSON_RESPONSE_BYTES)
        except ManagedError:
            value = None
        if (
            isinstance(value, dict)
            and set(value) == {"code", "message", "retryable"}
            and value["code"] in ERROR_CODES
            and isinstance(value["message"], str)
            and isinstance(value["retryable"], bool)
        ):
            return ManagedError(value["code"], value["message"], value["retryable"])
    if status in (429, 502, 503, 504):
        return _service_unavailable()
    return _response_invalid()


def _read_response(connection: socket.socket) -> HttpResponse:
    header = bytearray()
    while len(header) < MAX_HEADER_BYTES:
        byte = connection.recv(1)
        if not byte:
            raise _response_invalid()
        header += byte
        if header.endswith(b"\r\n\r\n"):
            break
    if not header.endswith(b"\r\n\r\n"):
        raise _response_invalid()
    try:
        text = header.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _response_invalid() from error
    lines = text.split("\r\n")
    status_parts = lines[0].split()
    if len(status_parts) < 2 or not status_parts[1].isdigit():
        raise _response_invalid()
    status = int(status_parts[1])
    content_length: int | None = None
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        if not _:
            raise _response_invalid()
        if name.lower() == "transfer-encoding":
            raise _response_invalid()
        if name.lower() == "content-length":
            if content_length is not None or not value.strip().isdigit():
                raise _response_invalid()
            content_length = int(value.strip())
    content_length = content_length or 0
    if content_length > MAX_JSON_RESPONSE_BYTES:
        raise _response_invalid()
    body = bytearray()
    while len(body) < content_length:
        chunk = connection.recv(min(65_536, content_length - len(body)))
        if not chunk:
            raise _service_unavailable()
        body += chunk
    return HttpResponse(bytes(body), status)


def _validate_authority(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or not all(
            33 <= ord(character) <= 126 and character not in "/?#@"
            for character in value
        )
    ):
        raise _endpoint_invalid()


def _validate_request_component(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 16
        or not all("A" <= character <= "Z" for character in value)
    ):
        raise _endpoint_invalid()


def _validate_target(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or len(value) > 4_096
        or "#" in value
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise _endpoint_invalid()


def _validate_header_value(value: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4_096
        or not all(32 <= ord(character) <= 126 for character in value)
    ):
        raise _endpoint_invalid()


def _validate_token(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or not all(
            character.isascii() and (character.isalnum() or character in "-_")
            for character in value
        )
    ):
        raise _response_invalid()


def _validate_cursor(value: object) -> None:
    _validate_token(value)


def _endpoint_invalid() -> ManagedError:
    return ManagedError(
        "SCHEMA_INVALID", "The managed TLS endpoint configuration is invalid."
    )


def _response_invalid() -> ManagedError:
    return ManagedError("SCHEMA_INVALID", "The managed service response is invalid.")


def _service_unavailable() -> ManagedError:
    return ManagedError(
        "SERVICE_UNAVAILABLE", "The managed capture service is unavailable."
    )
