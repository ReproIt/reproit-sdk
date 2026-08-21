"""SDK-side processor capture.

The canonical Linux capture rule is pinned by specs/v1/processor-capture.json.
Every SDK derives the same sorted capability list from the same host. Capture
maps raw views through curated tables and never removes a captured value. A
non-Linux host captures nothing. A read or parse failure captures nothing,
because capture may only add real information and a failed SDK must never
change application behavior.
"""

from __future__ import annotations

import platform
import struct
import sys

_FEATURE_PREFIX = "processor.feature."
_OS_STATE_PREFIX = "processor.os-state."
_IDENTITY_PREFIX = "processor.identity."

_X86_FLAG_GROUPS = {
    "aes": "aes",
    "avx": "avx",
    "avx2": "avx2",
    "avx512bw": "avx512bw",
    "avx512dq": "avx512dq",
    "avx512f": "avx512f",
    "avx512vl": "avx512vl",
    "bmi1": "bmi1",
    "bmi2": "bmi2",
    "fma": "fma",
    "pclmulqdq": "pclmulqdq",
    "pni": "sse3",
    "sse2": "sse2",
    "sse4_1": "sse4-1",
    "sse4_2": "sse4-2",
    "ssse3": "ssse3",
}

_ARM64_HWCAP_GROUPS = {
    1: "asimd",
    3: "aes",
    6: "sha2",
    7: "crc32",
    22: "sve",
}

_X86_IDENTITY_FIELDS = ("vendor_id", "cpu family", "model", "stepping", "microcode")
_ARM_IDENTITY_FIELDS = ("CPU implementer", "CPU variant", "CPU part", "CPU revision")

_AT_HWCAP = 16


def capture_processor_capabilities() -> list[str]:
    """Capture this host's process-visible processor view as sorted
    processor.* capability strings."""
    machine = platform.machine()
    if sys.platform != "linux" or machine not in ("x86_64", "aarch64"):
        return []
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as source:
            cpuinfo = source.read()
    except OSError:
        cpuinfo = ""
    try:
        with open("/proc/self/auxv", "rb") as source:
            hwcap = parse_auxv_hwcap(source.read())
    except OSError:
        hwcap = None
    return derive_capabilities(machine, cpuinfo, hwcap)


def derive_capabilities(machine: str, cpuinfo: str, hwcap: int | None) -> list[str]:
    """Pure derivation over raw views, shared with the capture vectors."""
    capabilities: list[str] = []
    if machine == "x86_64":
        flags = _x86_flags(cpuinfo)
        for flag, group in _X86_FLAG_GROUPS.items():
            if flag in flags:
                capabilities.append(_FEATURE_PREFIX + group)
        if "osxsave" in flags:
            capabilities.append(_OS_STATE_PREFIX + "osxsave")
        if "avx" in flags:
            capabilities.append(_OS_STATE_PREFIX + "xcr0.avx")
        if "avx512f" in flags:
            capabilities.append(_OS_STATE_PREFIX + "xcr0.avx512")
        identity = _identity_token(
            cpuinfo, _X86_IDENTITY_FIELDS, "x86", numeric=(1, 2, 3)
        )
    elif machine == "aarch64":
        if hwcap is not None:
            for bit, group in _ARM64_HWCAP_GROUPS.items():
                if hwcap & (1 << bit):
                    capabilities.append(_FEATURE_PREFIX + group)
            capabilities.append(_OS_STATE_PREFIX + "auxv.hwcaps")
        identity = _identity_token(cpuinfo, _ARM_IDENTITY_FIELDS, "arm", numeric=())
    else:
        return []
    if identity is not None:
        capabilities.append(_IDENTITY_PREFIX + identity)
    return sorted(set(capabilities))


def parse_auxv_hwcap(auxv: bytes) -> int | None:
    """Extract AT_HWCAP from raw /proc/self/auxv bytes: little-endian
    16-byte entries of key then value, terminated by a zero key."""
    for offset in range(0, len(auxv) - 15, 16):
        key, value = struct.unpack_from("<QQ", auxv, offset)
        if key == 0:
            return None
        if key == _AT_HWCAP:
            return value
    return None


def _x86_flags(cpuinfo: str) -> set[str]:
    flags: set[str] = set()
    for line in cpuinfo.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip() == "flags":
            flags.update(value.split())
    return flags


def _identity_token(
    cpuinfo: str, fields: tuple[str, ...], prefix: str, numeric: tuple[int, ...]
) -> str | None:
    """Encode the canonical lowercase identity token, or None when a field
    is missing, malformed, or disagrees between processor blocks."""
    blocks: list[tuple[str, ...]] = []
    for block in cpuinfo.split("\n\n"):
        if not block.strip():
            continue
        values: list[str] = []
        for field in fields:
            found = None
            for line in block.splitlines():
                name, separator, value = line.partition(":")
                if separator and name.strip() == field:
                    found = value.strip()
                    break
            if not found:
                return None
            values.append(found)
        blocks.append(tuple(values))
    if not blocks or any(block != blocks[0] for block in blocks):
        return None
    lowered = [value.lower() for value in blocks[0]]
    for value in lowered:
        if not value or any(
            not ("a" <= c <= "z" or "0" <= c <= "9" or c == "-") for c in value
        ):
            return None
    for index in numeric:
        if not lowered[index].isdigit() or int(lowered[index]) > 0xFFFF_FFFF:
            return None
    return ".".join([prefix, *lowered])
