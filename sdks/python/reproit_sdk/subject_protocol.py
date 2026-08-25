"""Thin validation and digest rules for subject discovery."""

from __future__ import annotations

import hashlib

from .encoding import canonical_bytes


class ManagedError(Exception):
    """Subject discovery failed with one stable local error code."""

    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def schema_invalid(
    message: str = "The value does not satisfy the schema.",
) -> ManagedError:
    return ManagedError("SCHEMA_INVALID", message)


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def canonical_digest(value: object) -> str:
    return digest_bytes(canonical_bytes(value))


def valid_capability(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 128:
        return False
    if not "a" <= value[0] <= "z":
        return False
    return all(
        "a" <= character <= "z"
        or "0" <= character <= "9"
        or character in ".-"
        for character in value[1:]
    )
