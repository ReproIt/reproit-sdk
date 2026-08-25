package reproit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	sdkEngineArtifactManifestFormat = "reproit.sdk-engine-artifacts.v1"
	sdkEngineArtifactManifestName   = "sdk-engine-artifacts.json"
	sdkEnginePackageDirectory       = "reproit-sdk-engine"
	sdkEngineMaxLibraryBytes        = int64(256 * 1024 * 1024)
	sdkEngineMaxManifestBytes       = 64 * 1024
	sdkEngineLinuxLibrary           = "libreproit_sdk_engine.so"
	sdkEngineMacOSLibrary           = "libreproit_sdk_engine.dylib"
	sdkEngineWindowsLibrary         = "reproit_sdk_engine.dll"
)

type sdkEngineTarget struct {
	library string
	name    string
}

var sdkEngineTargets = map[string]sdkEngineTarget{
	"darwin/arm64":  {sdkEngineMacOSLibrary, "macos-arm64"},
	"linux/amd64":   {sdkEngineLinuxLibrary, "linux-x86_64"},
	"linux/arm64":   {sdkEngineLinuxLibrary, "linux-arm64"},
	"windows/amd64": {sdkEngineWindowsLibrary, "windows-x86_64"},
}

func packagedSDKEnginePath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", errSDKEngineUnavailable
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errSDKEngineUnavailable
	}
	return packagedSDKEnginePathAt(filepath.Dir(resolved), runtime.GOOS, runtime.GOARCH)
}

func packagedSDKEnginePathAt(
	root string,
	operatingSystem string,
	architecture string,
) (string, error) {
	target, ok := sdkEngineTargets[operatingSystem+"/"+architecture]
	if !ok || !filepath.IsAbs(root) {
		return "", errSDKEngineUnavailable
	}
	packageDirectory := filepath.Join(root, sdkEnginePackageDirectory)
	targetDirectory := filepath.Join(packageDirectory, target.name)
	if !regularDirectory(packageDirectory) || !regularDirectory(targetDirectory) {
		return "", errSDKEngineUnavailable
	}
	manifestPath := filepath.Join(targetDirectory, sdkEngineArtifactManifestName)
	manifestBytes, err := readStableSDKEngineFile(manifestPath, sdkEngineMaxManifestBytes)
	if err != nil {
		return "", errSDKEngineUnavailable
	}
	library, size, digest, err := parseSDKEngineArtifactManifest(
		manifestBytes, target.name, target.library,
	)
	if err != nil {
		return "", errSDKEngineUnavailable
	}
	libraryPath := filepath.Join(targetDirectory, library)
	if err := verifySDKEngineLibrary(libraryPath, size, digest); err != nil {
		return "", errSDKEngineUnavailable
	}
	return libraryPath, nil
}

func parseSDKEngineArtifactManifest(
	value []byte,
	target string,
	library string,
) (string, int64, string, error) {
	parsed, err := parseStrictJSON(value, sdkEngineMaxManifestBytes)
	manifest, ok := parsed.(map[string]any)
	if err != nil || !ok || !hasExactKeys(
		manifest, "abi_contract_digest", "artifacts", "format", "target",
	) || manifest["abi_contract_digest"] != sdkEngineABIContractDigest ||
		manifest["format"] != sdkEngineArtifactManifestFormat || manifest["target"] != target {
		return "", 0, "", errSDKEngineUnavailable
	}
	artifacts, ok := manifest["artifacts"].([]any)
	if !ok || len(artifacts) != 1 {
		return "", 0, "", errSDKEngineUnavailable
	}
	artifact, ok := artifacts[0].(map[string]any)
	if !ok || !hasExactKeys(artifact, "digest", "file", "role", "size") ||
		artifact["role"] != "engine" || artifact["file"] != library {
		return "", 0, "", errSDKEngineUnavailable
	}
	file, fileOK := artifact["file"].(string)
	digest, digestOK := artifact["digest"].(string)
	size, sizeOK := integerValue(artifact["size"])
	if !fileOK || filepath.Base(file) != file || strings.ContainsAny(file, `/\\`) ||
		!digestOK || !validSDKEngineDigest(digest) || !sizeOK || size <= 0 ||
		size > sdkEngineMaxLibraryBytes {
		return "", 0, "", errSDKEngineUnavailable
	}
	return file, size, digest, nil
}

func verifySDKEngineLibrary(path string, expectedSize int64, expectedDigest string) error {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() != expectedSize {
		return errSDKEngineUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return errSDKEngineUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != expectedSize ||
		!os.SameFile(metadata, opened) {
		return errSDKEngineUnavailable
	}
	hasher := sha256.New()
	written, err := io.CopyN(hasher, file, expectedSize+1)
	if err != nil && err != io.EOF {
		return errSDKEngineUnavailable
	}
	if written != expectedSize || fmt.Sprintf("sha256:%x", hasher.Sum(nil)) != expectedDigest {
		return errSDKEngineUnavailable
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != expectedSize {
		return errSDKEngineUnavailable
	}
	return nil
}

func readStableSDKEngineFile(path string, maximumBytes int) ([]byte, error) {
	metadata, err := os.Lstat(path)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() <= 0 ||
		metadata.Size() > int64(maximumBytes) {
		return nil, errSDKEngineUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errSDKEngineUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(metadata, opened) || !opened.Mode().IsRegular() {
		return nil, errSDKEngineUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if err != nil || len(value) == 0 || len(value) > maximumBytes {
		return nil, errSDKEngineUnavailable
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(value)) {
		return nil, errSDKEngineUnavailable
	}
	return value, nil
}

func regularDirectory(path string) bool {
	metadata, err := os.Lstat(path)
	return err == nil && metadata.IsDir() && metadata.Mode()&os.ModeSymlink == 0
}

func validSDKEngineDigest(value string) bool {
	hexDigest, found := strings.CutPrefix(value, "sha256:")
	if !found || len(hexDigest) != 64 || strings.ToLower(hexDigest) != hexDigest {
		return false
	}
	_, err := hex.DecodeString(hexDigest)
	return err == nil
}
