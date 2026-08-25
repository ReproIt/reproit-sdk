"""Shared test configuration for the Python SDK test suite.

The canonical protocol vectors come from the Core revision in core-pin.json.
The repository test command prepares the ignored .core checkout.
"""

import os
import time

import pytest

import reproit_sdk

_SPECS_V1 = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", ".core", "specs", "v1")
)

os.environ.setdefault(
    "REPROIT_PROTOCOL_VECTORS", os.path.join(_SPECS_V1, "protocol-vectors.json")
)


@pytest.fixture(autouse=True)
def isolated_process_resources(monkeypatch):
    resources = reproit_sdk._PROCESS_RESOURCES
    with resources.lock:
        resources.active_bytes = 0
        resources.active_operations.clear()
        resources.queued_bytes = 0
        resources.queued_candidates = 0
        resources.logical_bytes = 0
        resources.storm_admitted.clear()
        resources.storm_last_refill = time.monotonic()
        resources.storm_token_rejections = 0
        resources.storm_tokens = reproit_sdk.FAILURE_TOKEN_CAPACITY
    original_init = reproit_sdk.Sdk.__init__

    def test_init(self, sink):
        original_init(self, sink)
        self._allow_private_for_tests = True

    monkeypatch.setattr(reproit_sdk.Sdk, "__init__", test_init)
os.environ.setdefault(
    "REPROIT_CLOUD_API_VECTORS", os.path.join(_SPECS_V1, "cloud-api-vectors.json")
)
