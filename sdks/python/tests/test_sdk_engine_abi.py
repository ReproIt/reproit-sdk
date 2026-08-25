from __future__ import annotations

import hashlib
import json
from pathlib import Path

from reproit_sdk import native_engine


ABI_PATH = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "reproit-sdk-engine"
    / "sdk-engine-abi.json"
)


def test_native_bridge_constants_match_the_canonical_abi() -> None:
    abi_bytes = ABI_PATH.read_bytes()
    abi = json.loads(abi_bytes)
    libraries = {
        value["platform"]: value["name"] for value in abi["libraries"]
    }
    assert native_engine.ABI_VERSION == abi["abi_version"]
    assert native_engine.CALL_FORMAT == abi["request"]["format"]
    assert native_engine.MAX_CALL_BYTES == abi["request"]["maximum_bytes"]
    assert native_engine.MAX_EVIDENCE_BYTES == abi["limits"]["evidence_bytes"]
    assert (
        native_engine.MAX_OBSERVATION_ADAPTERS
        == abi["limits"]["observation_adapters"]
    )
    assert (
        native_engine.MAX_OBSERVATION_CHUNK_BYTES
        == abi["limits"]["observation_chunk_bytes"]
    )
    assert (
        native_engine.MAX_OBSERVATION_RESPONSE_READ_BYTES
        == abi["limits"]["observation_response_read_bytes"]
    )
    assert (
        native_engine.MAX_OBSERVATION_SESSIONS
        == abi["limits"]["observation_sessions"]
    )
    assert (
        native_engine.MAX_OBSERVATION_SESSIONS_PER_OPERATION
        == abi["limits"]["observation_sessions_per_operation"]
    )
    assert (
        native_engine.MAX_SEMANTIC_DEPENDENCY_RECORD_BYTES
        == abi["limits"]["semantic_dependency_record_bytes"]
    )
    assert native_engine.MAX_SINK_WAIT_MS == abi["limits"]["sink_wait_ms"]
    assert native_engine.MAX_SINK_WAITERS == abi["limits"]["sinks"]
    assert native_engine.RESPONSE_FORMAT == abi["response"]["format"]
    assert (
        native_engine.RESPONSE_CAPACITY
        == abi["response"]["output_capacity_bytes"]
    )
    assert native_engine._ABI_SYMBOLS == abi["symbols"]
    assert native_engine._PLATFORM_LIBRARY_NAMES == libraries
    assert sorted(operation.value for operation in native_engine._EngineOperation) == sorted(
        abi["operations"]
    )
    assert list(native_engine._OBSERVATION_ACTIONS) == abi["observation_actions"]
    assert native_engine._OBSERVATION_CONTRACT == abi["observation_contract"]
    assert native_engine._DEPENDENCY_CONTRACT == abi["dependency_contract"]
    assert native_engine.ABI_CONTRACT_DIGEST == (
        f"sha256:{hashlib.sha256(abi_bytes).hexdigest()}"
    )
    assert json.loads(native_engine._CONTRACT_REQUEST) == {
        "format": abi["request"]["format"],
        "operation": "contract",
    }
