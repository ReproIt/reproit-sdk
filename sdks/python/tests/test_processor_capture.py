"""Processor capture conformance tests."""

import json
import os
import struct
import sys
import unittest

from reproit_sdk import processor_capture
from reproit_sdk.processor_capture import (
    capture_processor_capabilities,
    derive_capabilities,
    parse_auxv_hwcap,
)

_MACHINES = {
    "architecture.x86-64": "x86_64",
    "architecture.arm64": "aarch64",
}


def _capture_contract() -> dict:
    path = os.environ.get(
        "REPROIT_PROCESSOR_CAPTURE",
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            ".core",
            "specs",
            "v1",
            "processor-capture.json",
        ),
    )
    with open(path, "rb") as source:
        return json.load(source)


class ProcessorCaptureConformance(unittest.TestCase):
    def test_capture_matches_every_pinned_vector(self) -> None:
        for vector in _capture_contract()["capture_vectors"]:
            derived = derive_capabilities(
                _MACHINES[vector["architecture"]], vector["cpuinfo"], vector["hwcap"]
            )
            self.assertEqual(derived, vector["expected_capabilities"], vector["name"])

    def test_embedded_tables_match_the_contract(self) -> None:
        contract = _capture_contract()
        flag_groups = {
            flag: group.lower().replace("_", "-")
            for flag, group in contract["x86_64"]["cpuinfo_flag_groups"].items()
        }
        self.assertEqual(processor_capture._X86_FLAG_GROUPS, flag_groups)
        bit_groups = {
            int(bit): group.lower().replace("_", "-")
            for bit, group in contract["arm64"]["hwcap_bit_groups"].items()
        }
        self.assertEqual(processor_capture._ARM64_HWCAP_GROUPS, bit_groups)

    def test_auxv_parser_is_bounded_and_stops_at_terminator(self) -> None:
        auxv = struct.pack("<QQQQQQ", 6, 4096, 16, 0b1010, 0, 0)
        self.assertEqual(parse_auxv_hwcap(auxv), 0b1010)
        self.assertIsNone(parse_auxv_hwcap(auxv[:16]))
        self.assertIsNone(parse_auxv_hwcap(b""))
        self.assertIsNone(parse_auxv_hwcap(b"\x01\x02\x03"))
        terminated = struct.pack("<QQQQ", 0, 0, 16, 7)
        self.assertIsNone(parse_auxv_hwcap(terminated))

    def test_unknown_flags_are_ignored_and_output_is_canonical(self) -> None:
        derived = derive_capabilities(
            "x86_64", "flags\t: futureflag avx2 avx2 unknownflag\n", None
        )
        self.assertEqual(derived, ["processor.feature.avx2"])

    def test_live_capture_is_safe_on_every_host(self) -> None:
        captured = capture_processor_capabilities()
        self.assertEqual(captured, sorted(set(captured)))
        self.assertTrue(all(value.startswith("processor.") for value in captured))
        self.assertLessEqual(len(captured), 64)
        if sys.platform == "linux":
            self.assertTrue(captured)


if __name__ == "__main__":
    unittest.main()
