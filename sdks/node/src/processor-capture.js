// Capture the process-visible processor capabilities.
//
// The canonical Linux rule is in specs/v1/processor-capture.json. Capture
// maps raw host views through fixed tables. It returns an empty list when the
// platform is unsupported or a view cannot be read safely.

import { readFileSync } from "node:fs";
import { arch, platform } from "node:os";

const FEATURE_PREFIX = "processor.feature.";
const OS_STATE_PREFIX = "processor.os-state.";
const IDENTITY_PREFIX = "processor.identity.";
const AT_HWCAP = 16n;

const X86_FLAG_GROUPS = new Map([
  ["aes", "aes"],
  ["avx", "avx"],
  ["avx2", "avx2"],
  ["avx512bw", "avx512bw"],
  ["avx512dq", "avx512dq"],
  ["avx512f", "avx512f"],
  ["avx512vl", "avx512vl"],
  ["bmi1", "bmi1"],
  ["bmi2", "bmi2"],
  ["fma", "fma"],
  ["pclmulqdq", "pclmulqdq"],
  ["pni", "sse3"],
  ["sse2", "sse2"],
  ["sse4_1", "sse4-1"],
  ["sse4_2", "sse4-2"],
  ["ssse3", "ssse3"],
]);

const ARM64_HWCAP_GROUPS = new Map([
  [1n, "asimd"],
  [3n, "aes"],
  [6n, "sha2"],
  [7n, "crc32"],
  [22n, "sve"],
]);

const X86_IDENTITY_FIELDS = [
  "vendor_id",
  "cpu family",
  "model",
  "stepping",
  "microcode",
];
const ARM_IDENTITY_FIELDS = [
  "CPU implementer",
  "CPU variant",
  "CPU part",
  "CPU revision",
];

export function captureProcessorCapabilities() {
  const machineByArch = new Map([
    ["x64", "x86_64"],
    ["arm64", "aarch64"],
  ]);
  const machine = machineByArch.get(arch());
  if (platform() !== "linux" || machine === undefined) {
    return [];
  }
  let cpuinfo = "";
  try {
    cpuinfo = readFileSync("/proc/cpuinfo", "utf8");
  } catch {
    cpuinfo = "";
  }
  let hwcap = null;
  try {
    hwcap = parseAuxvHwcap(readFileSync("/proc/self/auxv"));
  } catch {
    hwcap = null;
  }
  return deriveProcessorCapabilities(machine, cpuinfo, hwcap);
}

export function deriveProcessorCapabilities(machine, cpuinfo, hwcap) {
  const unique = new Set();
  let identity = null;
  if (machine === "x86_64") {
    const flags = x86Flags(cpuinfo);
    for (const [flag, group] of X86_FLAG_GROUPS) {
      if (flags.has(flag)) {
        unique.add(FEATURE_PREFIX + group);
      }
    }
    if (flags.has("osxsave")) {
      unique.add(OS_STATE_PREFIX + "osxsave");
    }
    if (flags.has("avx")) {
      unique.add(OS_STATE_PREFIX + "xcr0.avx");
    }
    if (flags.has("avx512f")) {
      unique.add(OS_STATE_PREFIX + "xcr0.avx512");
    }
    identity = identityToken(cpuinfo, X86_IDENTITY_FIELDS, "x86", [1, 2, 3]);
  } else if (machine === "aarch64") {
    if (hwcap !== null) {
      for (const [bit, group] of ARM64_HWCAP_GROUPS) {
        if ((hwcap & (1n << bit)) !== 0n) {
          unique.add(FEATURE_PREFIX + group);
        }
      }
      unique.add(OS_STATE_PREFIX + "auxv.hwcaps");
    }
    identity = identityToken(cpuinfo, ARM_IDENTITY_FIELDS, "arm", []);
  } else {
    return [];
  }
  if (identity !== null) {
    unique.add(IDENTITY_PREFIX + identity);
  }
  return [...unique].sort();
}

export function parseAuxvHwcap(auxv) {
  for (let offset = 0; offset + 16 <= auxv.length; offset += 16) {
    const key = auxv.readBigUInt64LE(offset);
    if (key === 0n) {
      return null;
    }
    if (key === AT_HWCAP) {
      return auxv.readBigUInt64LE(offset + 8);
    }
  }
  return null;
}

function x86Flags(cpuinfo) {
  const flags = new Set();
  for (const line of cpuinfo.split("\n")) {
    const separator = line.indexOf(":");
    if (separator < 0 || line.slice(0, separator).trim() !== "flags") {
      continue;
    }
    for (const flag of line.slice(separator + 1).trim().split(/\s+/)) {
      if (flag !== "") {
        flags.add(flag);
      }
    }
  }
  return flags;
}

function identityToken(cpuinfo, fields, prefix, numeric) {
  const blocks = [];
  for (const block of cpuinfo.split("\n\n")) {
    if (block.trim() === "") {
      continue;
    }
    const values = [];
    for (const field of fields) {
      let found = null;
      for (const line of block.split("\n")) {
        const separator = line.indexOf(":");
        if (separator >= 0 && line.slice(0, separator).trim() === field) {
          found = line.slice(separator + 1).trim();
          break;
        }
      }
      if (found === null || found === "") {
        return null;
      }
      values.push(found);
    }
    blocks.push(values);
  }
  if (blocks.length === 0) {
    return null;
  }
  const first = JSON.stringify(blocks[0]);
  if (blocks.some((block) => JSON.stringify(block) !== first)) {
    return null;
  }
  const lowered = blocks[0].map((value) => value.toLowerCase());
  if (lowered.some((value) => !/^[a-z0-9-]+$/.test(value))) {
    return null;
  }
  for (const index of numeric) {
    if (!/^[0-9]+$/.test(lowered[index]) || Number(lowered[index]) > 0xffffffff) {
      return null;
    }
  }
  return [prefix, ...lowered].join(".");
}
