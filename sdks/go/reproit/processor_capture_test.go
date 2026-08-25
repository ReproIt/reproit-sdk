package reproit

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type captureContract struct {
	CaptureVectors []struct {
		Name                 string   `json:"name"`
		Architecture         string   `json:"architecture"`
		Cpuinfo              string   `json:"cpuinfo"`
		Hwcap                *uint64  `json:"hwcap"`
		ExpectedCapabilities []string `json:"expected_capabilities"`
	} `json:"capture_vectors"`
	X86 struct {
		CpuinfoFlagGroups map[string]string `json:"cpuinfo_flag_groups"`
	} `json:"x86_64"`
	Arm64 struct {
		HwcapBitGroups map[string]string `json:"hwcap_bit_groups"`
	} `json:"arm64"`
}

func loadCaptureContract(t *testing.T) captureContract {
	t.Helper()
	path := os.Getenv("REPROIT_PROCESSOR_CAPTURE")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var contract captureContract
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return contract
}

func TestCaptureMatchesEveryPinnedVector(t *testing.T) {
	machines := map[string]string{
		"architecture.x86-64": "x86_64",
		"architecture.arm64":  "aarch64",
	}
	for _, vector := range loadCaptureContract(t).CaptureVectors {
		derived := deriveProcessorCapabilities(
			machines[vector.Architecture], vector.Cpuinfo, vector.Hwcap,
		)
		expected := vector.ExpectedCapabilities
		if len(derived) != len(expected) {
			t.Fatalf("%s: derived %v, expected %v", vector.Name, derived, expected)
		}
		for index, value := range derived {
			if value != expected[index] {
				t.Fatalf("%s: derived %v, expected %v", vector.Name, derived, expected)
			}
		}
	}
}

func TestTheEmbeddedTablesMatchThePinnedContract(t *testing.T) {
	contract := loadCaptureContract(t)
	if len(contract.X86.CpuinfoFlagGroups) != len(x86FlagGroups) {
		t.Fatalf("x86 table size differs from the contract")
	}
	for flag, group := range contract.X86.CpuinfoFlagGroups {
		suffix := strings.ReplaceAll(strings.ToLower(group), "_", "-")
		if x86FlagGroups[flag] != suffix {
			t.Fatalf("x86 flag %s maps to %s, contract says %s", flag, x86FlagGroups[flag], suffix)
		}
	}
	if len(contract.Arm64.HwcapBitGroups) != len(arm64HwcapGroups) {
		t.Fatalf("arm64 table size differs from the contract")
	}
	for bit, group := range contract.Arm64.HwcapBitGroups {
		suffix := strings.ReplaceAll(strings.ToLower(group), "_", "-")
		parsed, err := strconv.ParseUint(bit, 10, 8)
		if err != nil {
			t.Fatalf("contract bit %s: %v", bit, err)
		}
		if arm64HwcapGroups[uint(parsed)] != suffix {
			t.Fatalf(
				"arm64 bit %s maps to %s, contract says %s",
				bit, arm64HwcapGroups[uint(parsed)], suffix,
			)
		}
	}
}

func TestAuxvParsingReadsHwcapAndStopsAtTheTerminator(t *testing.T) {
	auxv := make([]byte, 48)
	binary.LittleEndian.PutUint64(auxv[0:], 6)
	binary.LittleEndian.PutUint64(auxv[8:], 4096)
	binary.LittleEndian.PutUint64(auxv[16:], 16)
	binary.LittleEndian.PutUint64(auxv[24:], 0b1010)
	value := parseAuxvHwcap(auxv)
	if value == nil || *value != 0b1010 {
		t.Fatalf("hwcap not read")
	}
	if parseAuxvHwcap(auxv[:16]) != nil {
		t.Fatalf("truncated auxv must yield nothing")
	}
	if parseAuxvHwcap(nil) != nil || parseAuxvHwcap([]byte{1, 2, 3}) != nil {
		t.Fatalf("malformed auxv must yield nothing")
	}
	terminated := make([]byte, 32)
	binary.LittleEndian.PutUint64(terminated[16:], 16)
	binary.LittleEndian.PutUint64(terminated[24:], 7)
	if parseAuxvHwcap(terminated) != nil {
		t.Fatalf("entries after the zero key must not be read")
	}
}

func TestUnknownFlagsAreIgnoredAndOutputIsSortedUnique(t *testing.T) {
	derived := deriveProcessorCapabilities(
		"x86_64", "flags\t: futureflag avx2 avx2 unknownflag\n", nil,
	)
	if len(derived) != 1 || derived[0] != "processor.feature.avx2" {
		t.Fatalf("derived %v", derived)
	}
}

func TestLiveCaptureIsSafeOnEveryHost(t *testing.T) {
	captured := CaptureProcessorCapabilities()
	sorted := append([]string(nil), captured...)
	sort.Strings(sorted)
	for index, value := range captured {
		if value != sorted[index] || !strings.HasPrefix(value, "processor.") {
			t.Fatalf("captured %v", captured)
		}
	}
	if len(captured) > 64 {
		t.Fatalf("captured list exceeds the capability bound")
	}
	if runtime.GOOS == "linux" && len(captured) == 0 {
		t.Fatalf("a Linux host must capture at least one processor capability")
	}
}
