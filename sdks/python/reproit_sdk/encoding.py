"""Deterministic protocol encoding for Python subject discovery."""

from __future__ import annotations

import json
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """Encode one JSON value with deterministic key ordering."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
