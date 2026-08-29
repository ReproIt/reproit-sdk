"""Validate and propagate bounded distributed fuzz context."""

from __future__ import annotations

import base64
import contextvars
import datetime
import hashlib
import json
import re
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, replace

FUZZ_CONTEXT_HTTP_HEADER = "ReproIt-Fuzz-Context"
FUZZ_PARENT_HTTP_HEADER = "ReproIt-Parent-Operation"
FUZZ_CONTEXT_QUEUE_METADATA = "reproit.fuzz.context"
FUZZ_PARENT_QUEUE_METADATA = "reproit.parent.operation"
_MAX_CONTEXT_BYTES = 4_096
_UUID7 = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_CAMPAIGN_ID = re.compile(rf"fc_{_UUID7}\Z")
_CASE_ID = re.compile(rf"case_{_UUID7}\Z")
_PROJECT_ID = re.compile(rf"prj_{_UUID7}\Z")
_SERVICE_ID = re.compile(rf"svc_{_UUID7}\Z")
_OPERATION_ID = re.compile(rf"op_{_UUID7}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")
_FIELDS = frozenset(
    {
        "campaign_id",
        "case_id",
        "expires_at",
        "format",
        "project_id",
        "service_id",
        "signature",
    }
)


class FuzzContextError(ValueError):
    """The fuzz context failed bounded validation."""


@dataclass(frozen=True)
class FuzzCampaignContext:
    """A validated context and its native signature-verification input."""

    campaign_id: str
    case_id: str
    context_digest: str
    encoded: str
    now: str
    parent_operation_id: str | None
    project_id: str
    service_id: str
    verification_key: str

    def with_parent(self, operation_id: str) -> FuzzCampaignContext:
        """Return the context for a causal child operation."""
        if not _OPERATION_ID.fullmatch(operation_id):
            raise FuzzContextError("The parent operation ID is invalid.")
        return replace(self, parent_operation_id=operation_id)

    def native_input(self) -> dict[str, str]:
        """Return the bounded input that the shared engine verifies."""
        return {
            "encoded": self.encoded,
            "now": self.now,
            "project_id": self.project_id,
            "service_id": self.service_id,
            "verification_key": self.verification_key,
        }

    def begin_identity(self) -> dict[str, str]:
        """Return the bounded identity stored in OperationBegin v2."""
        return {
            "campaign_id": self.campaign_id,
            "case_id": self.case_id,
            "context_digest": self.context_digest,
        }


@dataclass(frozen=True)
class FuzzContextValidator:
    """Validate context structure before native signature verification."""

    project_id: str
    verification_key: str

    def validate(self, encoded: str, now: str) -> FuzzCampaignContext:
        """Validate one opaque context and prepare native verification."""
        try:
            raw = _decode_base64url(encoded)
            key = _decode_base64url(self.verification_key)
            value = json.loads(raw, object_pairs_hook=_unique_object)
            canonical = _canonical_bytes(value)
            signature = _decode_base64url(value["signature"])
            if not _TIMESTAMP.fullmatch(now) or not _TIMESTAMP.fullmatch(
                value["expires_at"]
            ):
                raise ValueError
            current = datetime.datetime.strptime(
                now,
                "%Y-%m-%dT%H:%M:%S.%fZ",
            ).replace(tzinfo=datetime.UTC)
            expires = datetime.datetime.strptime(
                value["expires_at"],
                "%Y-%m-%dT%H:%M:%S.%fZ",
            ).replace(tzinfo=datetime.UTC)
        except (KeyError, TypeError, ValueError, UnicodeError) as error:
            raise FuzzContextError("The fuzz context is invalid.") from error
        if (
            len(raw) > _MAX_CONTEXT_BYTES
            or len(key) != 32
            or len(signature) != 64
            or canonical != raw
            or set(value) != _FIELDS
            or value["format"] != "reproit.fuzz-context.v1"
            or not _CAMPAIGN_ID.fullmatch(value["campaign_id"])
            or not _CASE_ID.fullmatch(value["case_id"])
            or not _PROJECT_ID.fullmatch(value["project_id"])
            or not _SERVICE_ID.fullmatch(value["service_id"])
            or value["project_id"] != self.project_id
            or current >= expires
        ):
            raise FuzzContextError("The fuzz context is invalid.")
        return FuzzCampaignContext(
            campaign_id=value["campaign_id"],
            case_id=value["case_id"],
            context_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            encoded=encoded,
            now=now,
            parent_operation_id=None,
            project_id=value["project_id"],
            service_id=value["service_id"],
            verification_key=self.verification_key,
        )


_ACTIVE_FUZZ_CONTEXT: contextvars.ContextVar[FuzzCampaignContext | None] = (
    contextvars.ContextVar("reproit_fuzz_context", default=None)
)


def extract_http_fuzz_context(
    headers: Mapping[str, str],
    validator: FuzzContextValidator,
    now: str,
) -> FuzzCampaignContext | None:
    """Validate inbound HTTP metadata without starting an operation."""
    encoded = _header(headers, FUZZ_CONTEXT_HTTP_HEADER)
    parent = _header(headers, FUZZ_PARENT_HTTP_HEADER)
    if encoded is None:
        if parent is not None:
            raise FuzzContextError("The fuzz parent has no fuzz context.")
        return None
    context = validator.validate(encoded, now)
    if parent is None:
        return context
    return context.with_parent(parent)


def extract_queue_fuzz_context(
    metadata: Mapping[str, str],
    validator: FuzzContextValidator,
    now: str,
) -> FuzzCampaignContext | None:
    """Validate inbound delivered-work metadata."""
    translated: dict[str, str] = {}
    if FUZZ_CONTEXT_QUEUE_METADATA in metadata:
        translated[FUZZ_CONTEXT_HTTP_HEADER] = metadata[FUZZ_CONTEXT_QUEUE_METADATA]
    if FUZZ_PARENT_QUEUE_METADATA in metadata:
        translated[FUZZ_PARENT_HTTP_HEADER] = metadata[FUZZ_PARENT_QUEUE_METADATA]
    return extract_http_fuzz_context(translated, validator, now)


def propagate_queue_fuzz_context(metadata: MutableMapping[str, str]) -> None:
    """Add the active context to outbound delivered-work metadata."""
    context = _ACTIVE_FUZZ_CONTEXT.get()
    if context is None:
        return
    metadata[FUZZ_CONTEXT_QUEUE_METADATA] = context.encoded
    if context.parent_operation_id is not None:
        metadata[FUZZ_PARENT_QUEUE_METADATA] = context.parent_operation_id


def _current_fuzz_context() -> FuzzCampaignContext | None:
    return _ACTIVE_FUZZ_CONTEXT.get()


def _activate_fuzz_context(
    context: FuzzCampaignContext | None,
) -> contextvars.Token[FuzzCampaignContext | None]:
    return _ACTIVE_FUZZ_CONTEXT.set(context)


def _reset_fuzz_context(
    token: contextvars.Token[FuzzCampaignContext | None],
) -> None:
    _ACTIVE_FUZZ_CONTEXT.reset(token)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    selected = [value for key, value in headers.items() if key.lower() == name.lower()]
    if not selected:
        return None
    if len(selected) != 1 or not isinstance(selected[0], str) or not selected[0]:
        raise FuzzContextError("The fuzz header is invalid.")
    return selected[0]


def _decode_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 5_462:
        raise ValueError
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, element in pairs:
        if key in value:
            raise ValueError
        value[key] = element
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8", "strict")
