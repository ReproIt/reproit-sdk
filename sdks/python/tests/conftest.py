"""Shared test configuration for the Python SDK test suite.

The canonical protocol vectors come from the Core revision in core-pin.json.
The repository test command prepares the ignored .core checkout.
"""

import os

_SPECS_V1 = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", ".core", "specs", "v1")
)

os.environ.setdefault(
    "REPROIT_PROTOCOL_VECTORS", os.path.join(_SPECS_V1, "protocol-vectors.json")
)
os.environ.setdefault(
    "REPROIT_CLOUD_API_VECTORS", os.path.join(_SPECS_V1, "cloud-api-vectors.json")
)
