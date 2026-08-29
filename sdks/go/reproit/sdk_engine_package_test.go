package reproit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSDKEnginePackageVerifiesExactArtifact(t *testing.T) {
	root := t.TempDir()
	libraryPath := writeSDKEngineTestPackage(t, root, []byte("exact engine bytes"))
	resolved, err := packagedSDKEnginePathAt(root, "linux", "amd64")
	if err != nil || resolved != libraryPath {
		t.Fatal("The SDK engine package rejected its exact artifact.")
	}
}

func TestSDKEnginePackageRejectsArtifactMismatchAndLinks(t *testing.T) {
	root := t.TempDir()
	libraryPath := writeSDKEngineTestPackage(t, root, []byte("exact engine bytes"))
	if err := os.WriteFile(libraryPath, []byte("changed engine bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := packagedSDKEnginePathAt(root, "linux", "amd64"); err == nil {
		t.Fatal("The SDK engine package accepted a digest mismatch.")
	}

	root = t.TempDir()
	libraryPath = writeSDKEngineTestPackage(t, root, []byte("exact engine bytes"))
	realLibrary := libraryPath + ".real"
	if err := os.Rename(libraryPath, realLibrary); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realLibrary, libraryPath); err != nil {
		t.Skip("This host cannot create the package-link control.")
	}
	if _, err := packagedSDKEnginePathAt(root, "linux", "amd64"); err == nil {
		t.Fatal("The SDK engine package accepted a linked artifact.")
	}
}

func TestSDKEnginePackageRejectsManifestExtras(t *testing.T) {
	root := t.TempDir()
	libraryPath := writeSDKEngineTestPackage(t, root, []byte("exact engine bytes"))
	manifestPath := filepath.Join(filepath.Dir(libraryPath), sdkEngineArtifactManifestName)
	value, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	value = []byte(strings.Replace(string(value), `"target":`, `"extra":true,"target":`, 1))
	if err := os.WriteFile(manifestPath, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := packagedSDKEnginePathAt(root, "linux", "amd64"); err == nil {
		t.Fatal("The SDK engine package accepted an unknown manifest field.")
	}
}

func TestGoSDKEngineConstantsMatchCanonicalABI(t *testing.T) {
	abiPath := filepath.Join(
		"..", "..", "..", "crates", "reproit-sdk-engine", "sdk-engine-abi.json",
	)
	value, err := os.ReadFile(abiPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(value)
	if fmt.Sprintf("sha256:%x", digest) != sdkEngineABIContractDigest {
		t.Fatal("The Go SDK engine ABI digest differs from the canonical contract.")
	}
	var abi struct {
		ABIVersion uint32 `json:"abi_version"`
		Libraries  []struct {
			Name     string `json:"name"`
			Platform string `json:"platform"`
		} `json:"libraries"`
		Operations                 []string `json:"operations"`
		RequiredObservationClasses []string `json:"required_observation_classes"`
		Limits                     struct {
			EvidenceBytes int `json:"evidence_bytes"`
			Sinks         int `json:"sinks"`
			SinkWaitMS    int `json:"sink_wait_ms"`
		} `json:"limits"`
		Request struct {
			Format       string `json:"format"`
			MaximumBytes int    `json:"maximum_bytes"`
		} `json:"request"`
		Response struct {
			Format              string `json:"format"`
			OutputCapacityBytes int    `json:"output_capacity_bytes"`
		} `json:"response"`
		Symbols struct {
			ABIVersion   string `json:"abi_version"`
			Call         string `json:"call"`
			CaptureProbe string `json:"capture_probe"`
		} `json:"symbols"`
	}
	if err := json.Unmarshal(value, &abi); err != nil {
		t.Fatal(err)
	}
	parsedContract, err := parseStrictJSON(value, sdkEngineMaxCallBytes)
	canonicalContract, ok := parsedContract.(map[string]any)
	if err != nil || !ok {
		t.Fatal(err)
	}
	equal, err := canonicalEqual(canonicalContract, expectedSDKEngineContract())
	if err != nil || !equal {
		t.Fatal("The Go SDK engine bridge does not validate the complete canonical ABI.")
	}
	libraries := make(map[string]string, len(abi.Libraries))
	for _, library := range abi.Libraries {
		libraries[library.Platform] = library.Name
	}
	wantLibraries := map[string]string{
		"linux-arm64":    sdkEngineLinuxLibrary,
		"linux-x86_64":   sdkEngineLinuxLibrary,
		"macos-arm64":    sdkEngineMacOSLibrary,
		"windows-x86_64": sdkEngineWindowsLibrary,
	}
	if abi.ABIVersion != sdkEngineABIVersion ||
		abi.Limits.EvidenceBytes != sdkEngineMaxEvidenceBytes ||
		abi.Limits.Sinks != sdkEngineMaxSinkWaiters ||
		abi.Limits.SinkWaitMS != int(sdkEngineSinkWaitMilliseconds) ||
		abi.Request.Format != sdkEngineCallFormat ||
		abi.Request.MaximumBytes != sdkEngineMaxCallBytes ||
		abi.Response.Format != engineResponseFormat ||
		abi.Response.OutputCapacityBytes != sdkEngineOutputCapacity ||
		abi.Symbols.ABIVersion != sdkEngineABIVersionSymbol ||
		abi.Symbols.Call != sdkEngineCallSymbol ||
		abi.Symbols.CaptureProbe != sdkEngineCaptureProbeSymbol ||
		!reflect.DeepEqual(abi.Operations, sdkEngineOperationNames) ||
		!reflect.DeepEqual(abi.RequiredObservationClasses, []string{
			"clock", "database", "environment", "filesystem", "outbound-http", "queue",
			"randomness",
		}) ||
		!reflect.DeepEqual(libraries, wantLibraries) {
		t.Fatal("The Go SDK engine bridge differs from the canonical ABI contract.")
	}
}

func writeSDKEngineTestPackage(t *testing.T, root string, library []byte) string {
	t.Helper()
	targetDirectory := filepath.Join(root, sdkEnginePackageDirectory, "linux-x86_64")
	if err := os.MkdirAll(targetDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	libraryPath := filepath.Join(targetDirectory, sdkEngineLinuxLibrary)
	if err := os.WriteFile(libraryPath, library, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(library)
	manifest := fmt.Sprintf(
		`{"abi_contract_digest":%q,"artifacts":[{"digest":"sha256:%x",`+
			`"file":%q,"role":"engine","size":%d}],"format":%q,"target":"linux-x86_64"}`,
		sdkEngineABIContractDigest,
		digest,
		sdkEngineLinuxLibrary,
		len(library),
		sdkEngineArtifactManifestFormat,
	)
	manifestPath := filepath.Join(targetDirectory, sdkEngineArtifactManifestName)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return libraryPath
}
