package reproit

// SDK-side processor capture.
//
// The canonical Linux capture rule is pinned by
// specs/v1/processor-capture.json. Every SDK derives the same sorted
// capability list from the same host. Capture maps raw views through
// curated tables and never removes a captured value. A non-Linux host
// captures nothing. A read or parse failure captures nothing, because
// capture may only add real information and a failed SDK must never change
// application behavior.

import (
	"encoding/binary"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	processorFeaturePrefix  = "processor.feature."
	processorOsStatePrefix  = "processor.os-state."
	processorIdentityPrefix = "processor.identity."
	atHwcap                 = 16
)

var x86FlagGroups = map[string]string{
	"aes":       "aes",
	"avx":       "avx",
	"avx2":      "avx2",
	"avx512bw":  "avx512bw",
	"avx512dq":  "avx512dq",
	"avx512f":   "avx512f",
	"avx512vl":  "avx512vl",
	"bmi1":      "bmi1",
	"bmi2":      "bmi2",
	"fma":       "fma",
	"pclmulqdq": "pclmulqdq",
	"pni":       "sse3",
	"sse2":      "sse2",
	"sse4_1":    "sse4-1",
	"sse4_2":    "sse4-2",
	"ssse3":     "ssse3",
}

var arm64HwcapGroups = map[uint]string{
	1:  "asimd",
	3:  "aes",
	6:  "sha2",
	7:  "crc32",
	22: "sve",
}

var x86IdentityFields = []string{"vendor_id", "cpu family", "model", "stepping", "microcode"}

var armIdentityFields = []string{"CPU implementer", "CPU variant", "CPU part", "CPU revision"}

// CaptureProcessorCapabilities captures this host's process-visible
// processor view as sorted processor.* capability strings.
func CaptureProcessorCapabilities() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	machine := ""
	switch runtime.GOARCH {
	case "amd64":
		machine = "x86_64"
	case "arm64":
		machine = "aarch64"
	default:
		return nil
	}
	cpuinfo := ""
	if raw, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		cpuinfo = string(raw)
	}
	var hwcap *uint64
	if raw, err := os.ReadFile("/proc/self/auxv"); err == nil {
		hwcap = parseAuxvHwcap(raw)
	}
	return deriveProcessorCapabilities(machine, cpuinfo, hwcap)
}

// deriveProcessorCapabilities is the pure derivation over raw views, shared
// with the capture vectors.
func deriveProcessorCapabilities(machine, cpuinfo string, hwcap *uint64) []string {
	unique := map[string]bool{}
	var identity string
	switch machine {
	case "x86_64":
		flags := x86Flags(cpuinfo)
		for flag, group := range x86FlagGroups {
			if flags[flag] {
				unique[processorFeaturePrefix+group] = true
			}
		}
		if flags["osxsave"] {
			unique[processorOsStatePrefix+"osxsave"] = true
		}
		if flags["avx"] {
			unique[processorOsStatePrefix+"xcr0.avx"] = true
		}
		if flags["avx512f"] {
			unique[processorOsStatePrefix+"xcr0.avx512"] = true
		}
		identity = identityToken(cpuinfo, x86IdentityFields, "x86", []int{1, 2, 3})
	case "aarch64":
		if hwcap != nil {
			for bit, group := range arm64HwcapGroups {
				if *hwcap&(uint64(1)<<bit) != 0 {
					unique[processorFeaturePrefix+group] = true
				}
			}
			unique[processorOsStatePrefix+"auxv.hwcaps"] = true
		}
		identity = identityToken(cpuinfo, armIdentityFields, "arm", nil)
	default:
		return nil
	}
	if identity != "" {
		unique[processorIdentityPrefix+identity] = true
	}
	capabilities := make([]string, 0, len(unique))
	for capability := range unique {
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	return capabilities
}

// parseAuxvHwcap extracts AT_HWCAP from raw /proc/self/auxv bytes:
// little-endian 16-byte entries of key then value, terminated by a zero key.
func parseAuxvHwcap(auxv []byte) *uint64 {
	for offset := 0; offset+16 <= len(auxv); offset += 16 {
		key := binary.LittleEndian.Uint64(auxv[offset:])
		if key == 0 {
			return nil
		}
		if key == atHwcap {
			value := binary.LittleEndian.Uint64(auxv[offset+8:])
			return &value
		}
	}
	return nil
}

func x86Flags(cpuinfo string) map[string]bool {
	flags := map[string]bool{}
	for _, line := range strings.Split(cpuinfo, "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != "flags" {
			continue
		}
		for _, flag := range strings.Fields(value) {
			flags[flag] = true
		}
	}
	return flags
}

// identityToken encodes the canonical lowercase identity token, or empty
// when a field is missing, malformed, or disagrees between processor
// blocks.
func identityToken(cpuinfo string, fields []string, prefix string, numeric []int) string {
	var blocks [][]string
	for _, block := range strings.Split(cpuinfo, "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		values := make([]string, 0, len(fields))
		for _, field := range fields {
			found := ""
			for _, line := range strings.Split(block, "\n") {
				name, value, ok := strings.Cut(line, ":")
				if ok && strings.TrimSpace(name) == field {
					found = strings.TrimSpace(value)
					break
				}
			}
			if found == "" {
				return ""
			}
			values = append(values, found)
		}
		blocks = append(blocks, values)
	}
	if len(blocks) == 0 {
		return ""
	}
	for _, block := range blocks[1:] {
		for index, value := range block {
			if value != blocks[0][index] {
				return ""
			}
		}
	}
	lowered := make([]string, len(blocks[0]))
	for index, value := range blocks[0] {
		lowered[index] = strings.ToLower(value)
		for _, character := range lowered[index] {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return ""
			}
		}
	}
	for _, index := range numeric {
		if _, err := strconv.ParseUint(lowered[index], 10, 32); err != nil {
			return ""
		}
	}
	return prefix + "." + strings.Join(lowered, ".")
}
