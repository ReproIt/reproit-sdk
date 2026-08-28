// Go subject-closure packaging for managed capture.
//
// Mirrors crates/reproit-sdk-rust/src/subject.rs for the language-neutral
// manifest shape. Go uses the running executable as the default subject
// root, plus launch data, the Go runtime
// and module-dependency identity, and the executable's own DWARF debug
// artifact. A missing, unreadable, changing, or unbounded subject fails
// locally before any candidate network request.
package reproit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	subjectFileMediaType     = "application/vnd.reproit.subject-file.v1"
	subjectLaunchMediaType   = "application/vnd.reproit.subject-launch.v1+json"
	subjectManifestMediaType = "application/vnd.reproit.subject-closure.v1+json"
	moduleIdentityMediaType  = "application/vnd.reproit.subject-module-identity.v1+json"
	managedCopyBufferBytes   = 64 * 1024
	maxSubjectArguments      = 128
	maxSubjectDependencies   = 4_096
	maxSubjectEnvironment    = 256
	maxSubjectObjectBytes    = int64(512 * 1024 * 1024)
	maxSubjectTotalBytes     = int64(2 * 1024 * 1024 * 1024)
	subjectWorkingDirectory  = "/reproit/subject/work"
	subjectLaunchPath        = "/reproit/subject/launch.json"
	subjectBuildIdentityPath = "/reproit/subject/go/build-info.json"
)

// dwarfMarkers identify embedded DWARF debug information: the Mach-O
// __DWARF segment on macOS and the ELF .debug_info / .zdebug_info section
// names on Linux.
var dwarfMarkers = [][]byte{[]byte("__DWARF"), []byte(".debug_info"), []byte(".zdebug_info")}

var subjectArchitectures = map[string]string{
	"amd64": "architecture.x86-64",
	"arm64": "architecture.arm64",
}

var subjectOperatingSystems = map[string]string{
	"darwin": "operating-system.macos",
	"linux":  "operating-system.linux",
}

var subjectObjectKinds = map[string]bool{
	"application": true, "debug-artifact": true, "launch-data": true,
	"module-identity": true, "native-dependency": true, "runtime": true,
}

var subjectRuntimeFamilies = map[string]bool{
	"dotnet": true, "go": true, "node": true, "python": true, "rust": true,
}

// PackagedSubjectObject is one content-addressed subject object file in the
// private spool.
type PackagedSubjectObject struct {
	Digest string
	Path   string
	Size   int64
}

// GoSubjectPackage is the frozen manifest plus content-addressed object
// files in a spool.
type GoSubjectPackage struct {
	Manifest                    map[string]any
	Objects                     []PackagedSubjectObject
	adapterImplementationDigest string
	reservedBytes               int64
	spool                       string
}

// Close removes the private subject spool.
func (subject *GoSubjectPackage) Close() {
	if subject.spool != "" {
		_ = os.RemoveAll(subject.spool)
	}
	if subject.reservedBytes > 0 {
		subjectResources.release(subject.reservedBytes)
		subject.reservedBytes = 0
	}
}

// PackageRunningGoSubject freezes and hashes the running Go subject closure
// locally. An empty executablePath uses the running executable. An explicit
// path supports the one-explicit-subject-root case the plan allows for
// adapters that cannot prove the default root.
func PackageRunningGoSubject(executablePath string) (*GoSubjectPackage, error) {
	reservedBytes := int64(0)
	complete := false
	defer func() {
		if !complete && reservedBytes > 0 {
			subjectResources.release(reservedBytes)
		}
	}()
	if executablePath == "" {
		running, err := os.Executable()
		if err != nil {
			return nil, errSubjectUnreadable()
		}
		executablePath = running
	}
	resolved, err := filepath.EvalSymlinks(executablePath)
	if err != nil {
		return nil, errSubjectUnreadable()
	}
	metadata, err := os.Lstat(resolved)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() <= 0 ||
		metadata.Size() > maxSubjectObjectBytes {
		return nil, errSubjectUnbounded()
	}
	if !subjectResources.reserve(metadata.Size()) {
		return nil, errSubjectUnbounded()
	}
	reservedBytes = metadata.Size()
	executableBytes, err := readStableSubjectFile(resolved)
	if err != nil {
		return nil, err
	}
	if !containsDwarfMarker(executableBytes) {
		return nil, newManagedError(
			"UNSUPPORTED",
			"The running Go subject does not contain the required DWARF artifact.",
		)
	}
	executableDigest := digestBytes(executableBytes)
	executableName := filepath.Base(resolved)
	if executableName == "" || executableName == "." || executableName == "/" {
		executableName = "application"
	}
	executableSubjectPath := "/reproit/subject/application/" +
		digestName(executableDigest) + "/" + executableName

	buildIdentity, err := goBuildIdentity()
	if err != nil {
		return nil, err
	}
	buildIdentityBytes, err := CanonicalBytes(buildIdentity)
	if err != nil {
		return nil, errSubjectUnsupported()
	}
	buildIdentityDigest := digestBytes(buildIdentityBytes)

	arguments, err := unicodeSubjectArguments()
	if err != nil {
		return nil, err
	}
	environmentNames, err := subjectEnvironmentNames()
	if err != nil {
		return nil, err
	}
	launch := map[string]any{
		"arguments":         arguments,
		"environment_names": environmentNames,
		"executable":        executableSubjectPath,
		"working_directory": subjectWorkingDirectory,
	}
	launchBytes, err := CanonicalBytes(launch)
	if err != nil {
		return nil, errSubjectUnsupported()
	}
	launchDigest := digestBytes(launchBytes)

	architecture, architectureOK := subjectArchitectures[runtime.GOARCH]
	operatingSystem, operatingSystemOK := subjectOperatingSystems[runtime.GOOS]
	if !architectureOK || !operatingSystemOK {
		return nil, newManagedError(
			"UNSUPPORTED", "This host cannot package a Backend v1 Go production subject.",
		)
	}

	objects, err := assembleSubjectObjects([]subjectObjectEntry{
		{executableDigest, "application", subjectFileMediaType, int64(len(executableBytes))},
		{buildIdentityDigest, "module-identity", moduleIdentityMediaType, int64(len(buildIdentityBytes))},
		{launchDigest, "launch-data", subjectLaunchMediaType, int64(len(launchBytes))},
	})
	if err != nil {
		return nil, err
	}
	files := []map[string]any{
		{"executable": true, "object_digest": executableDigest, "path": executableSubjectPath},
		{"executable": false, "object_digest": buildIdentityDigest, "path": subjectBuildIdentityPath},
		{"executable": false, "object_digest": launchDigest, "path": subjectLaunchPath},
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left]["path"].(string) < files[right]["path"].(string)
	})
	modules := []map[string]any{
		{
			"identity":      executableDigest,
			"module_digest": executableDigest,
			"path":          executableSubjectPath,
		},
		{
			"identity":      buildIdentity["identity"],
			"module_digest": buildIdentityDigest,
			"path":          subjectBuildIdentityPath,
		},
	}
	sort.Slice(modules, func(left, right int) bool {
		return modules[left]["path"].(string) < modules[right]["path"].(string)
	})
	debugArtifacts := []map[string]any{
		{
			"artifact_digest": executableDigest,
			"kind":            "dwarf",
			"module_digest":   executableDigest,
			"path":            executableSubjectPath,
		},
	}
	totalBytes := int64(0)
	for _, object := range objects {
		size, _ := integerValue(object["size"])
		totalBytes += size
	}
	if totalBytes > maxSubjectTotalBytes {
		return nil, errSubjectUnbounded()
	}
	additionalBytes := totalBytes - reservedBytes
	if additionalBytes > 0 && !subjectResources.reserve(additionalBytes) {
		return nil, errSubjectUnbounded()
	}
	reservedBytes = totalBytes
	manifest := map[string]any{
		"architecture":     architecture,
		"debug_artifacts":  debugArtifacts,
		"files":            files,
		"format":           "reproit.subject-closure.v1",
		"launch":           launch,
		"modules":          modules,
		"objects":          objects,
		"operating_system": operatingSystem,
		"runtime_family":   "go",
		"total_bytes":      totalBytes,
	}
	if err := validateSubjectClosureManifest(manifest); err != nil {
		return nil, err
	}
	spool, err := os.MkdirTemp("", "reproit-go-subject-")
	if err != nil {
		return nil, errSubjectUnreadable()
	}
	packaged, err := spoolSubjectObjects(spool, map[string][]byte{
		executableDigest:    executableBytes,
		buildIdentityDigest: buildIdentityBytes,
		launchDigest:        launchBytes,
	})
	if err != nil {
		_ = os.RemoveAll(spool)
		return nil, err
	}
	complete = true
	return &GoSubjectPackage{
		Manifest:                    manifest,
		Objects:                     packaged,
		adapterImplementationDigest: executableDigest,
		reservedBytes:               reservedBytes,
		spool:                       spool,
	}, nil
}

func containsDwarfMarker(value []byte) bool {
	for _, marker := range dwarfMarkers {
		if bytes.Contains(value, marker) {
			return true
		}
	}
	return false
}

type subjectObjectEntry struct {
	digest    string
	kind      string
	mediaType string
	size      int64
}

func assembleSubjectObjects(entries []subjectObjectEntry) ([]map[string]any, error) {
	merged := make(map[string]map[string]any)
	for _, entry := range entries {
		if entry.size == 0 {
			return nil, errSubjectUnsupported()
		}
		candidate := map[string]any{
			"digest":     entry.digest,
			"kind":       entry.kind,
			"media_type": entry.mediaType,
			"size":       entry.size,
		}
		if existing, present := merged[entry.digest]; present {
			if equal, err := canonicalEqual(existing, candidate); err != nil || !equal {
				return nil, errSubjectUnsupported()
			}
			continue
		}
		merged[entry.digest] = candidate
	}
	digests := make([]string, 0, len(merged))
	for digest := range merged {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	objects := make([]map[string]any, 0, len(digests))
	for _, digest := range digests {
		objects = append(objects, merged[digest])
	}
	return objects, nil
}

func spoolSubjectObjects(
	spoolPath string, contents map[string][]byte,
) ([]PackagedSubjectObject, error) {
	digests := make([]string, 0, len(contents))
	for digest := range contents {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	packaged := make([]PackagedSubjectObject, 0, len(digests))
	for _, digest := range digests {
		value := contents[digest]
		path := filepath.Join(spoolPath, digestName(digest))
		if _, err := os.Lstat(path); err != nil {
			if err := os.WriteFile(path, value, 0o600); err != nil {
				return nil, errSubjectUnreadable()
			}
		}
		packaged = append(packaged, PackagedSubjectObject{
			Digest: digest, Path: path, Size: int64(len(value)),
		})
	}
	return packaged, nil
}

// readStableSubjectFile reads a bounded regular file and fails closed if it
// changes underneath.
func readStableSubjectFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errSubjectUnreadable()
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() == 0 || before.Size() > maxSubjectObjectBytes {
		return nil, errSubjectUnbounded()
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errSubjectUnreadable()
	}
	defer file.Close()
	hasher := sha256.New()
	content := make([]byte, 0, before.Size())
	buffer := make([]byte, managedCopyBufferBytes)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			content = append(content, buffer[:count]...)
			hasher.Write(buffer[:count])
			if int64(len(content)) > before.Size() {
				return nil, errSubjectChanging()
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, errSubjectUnreadable()
		}
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, errSubjectUnreadable()
	}
	beforeStat, beforeStatOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterStatOK := after.Sys().(*syscall.Stat_t)
	if int64(len(content)) != before.Size() || after.Size() != before.Size() ||
		!after.ModTime().Equal(before.ModTime()) ||
		!beforeStatOK || !afterStatOK ||
		beforeStat.Ino != afterStat.Ino || beforeStat.Dev != afterStat.Dev {
		return nil, errSubjectChanging()
	}
	return content, nil
}

// goBuildIdentity records the Go runtime and installed module closure as
// bounded identity facts.
func goBuildIdentity() (map[string]any, error) {
	version := runtime.Version()
	if version == "" || len(version) > 512 {
		return nil, errSubjectUnsupported()
	}
	mainPath := ""
	dependencies := make([]any, 0)
	if information, ok := debug.ReadBuildInfo(); ok {
		mainPath = information.Main.Path
		if len(information.Deps) > maxSubjectDependencies {
			return nil, errSubjectUnbounded()
		}
		modules := make([]map[string]any, 0, len(information.Deps))
		for _, dependency := range information.Deps {
			resolved := dependency
			if resolved.Replace != nil {
				resolved = resolved.Replace
			}
			if resolved.Path == "" {
				return nil, errSubjectUnreadable()
			}
			modules = append(modules, map[string]any{
				"path": resolved.Path, "version": resolved.Version,
			})
		}
		sort.Slice(modules, func(left, right int) bool {
			if modules[left]["path"].(string) != modules[right]["path"].(string) {
				return modules[left]["path"].(string) < modules[right]["path"].(string)
			}
			return modules[left]["version"].(string) < modules[right]["version"].(string)
		})
		for _, module := range modules {
			dependencies = append(dependencies, module)
		}
	}
	return map[string]any{
		"format":    "reproit.go-build-identity.v1",
		"identity":  version,
		"main_path": mainPath,
		"modules":   dependencies,
		"version":   version,
	}, nil
}

func unicodeSubjectArguments() ([]any, error) {
	arguments := os.Args[1:]
	if len(arguments) > maxSubjectArguments {
		return nil, errSubjectUnsupported()
	}
	values := make([]any, 0, len(arguments))
	for _, argument := range arguments {
		if len(argument) > 4_096 || !validUTF8String(argument) {
			return nil, errSubjectUnsupported()
		}
		values = append(values, argument)
	}
	return values, nil
}

func subjectEnvironmentNames() ([]any, error) {
	seen := make(map[string]bool)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		seen[name] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > maxSubjectEnvironment {
		return nil, errSubjectUnbounded()
	}
	values := make([]any, 0, len(names))
	for _, name := range names {
		if name == "" || len(name) > 256 || strings.Contains(name, "=") {
			return nil, errSubjectUnsupported()
		}
		for index := 0; index < len(name); index++ {
			if name[index] < 33 || name[index] > 126 {
				return nil, errSubjectUnsupported()
			}
		}
		values = append(values, name)
	}
	return values, nil
}

// validateSubjectClosureManifest mirrors the reproit-core
// SubjectClosureManifest::validate rules.
func validateSubjectClosureManifest(value any) error {
	manifest, ok := value.(map[string]any)
	if !ok || !hasExactKeys(manifest,
		"architecture", "debug_artifacts", "files", "format", "launch", "modules",
		"objects", "operating_system", "runtime_family", "total_bytes",
	) {
		return errSchemaInvalid()
	}
	family, familyOK := manifest["runtime_family"].(string)
	if manifest["format"] != "reproit.subject-closure.v1" ||
		!familyOK || !subjectRuntimeFamilies[family] ||
		!validCapability(manifest["architecture"]) ||
		!validCapability(manifest["operating_system"]) {
		return errSchemaInvalid()
	}
	objects, objectsOK := candidateRecords(manifest["objects"])
	files, filesOK := candidateRecords(manifest["files"])
	modules, modulesOK := candidateRecords(manifest["modules"])
	debugArtifacts, debugArtifactsOK := candidateRecords(manifest["debug_artifacts"])
	if !objectsOK || len(objects) < 1 || len(objects) > 32_767 ||
		!filesOK || len(files) < 1 || len(files) > 32_767 ||
		!modulesOK || len(modules) < 1 || len(modules) > 4_096 ||
		!debugArtifactsOK || len(debugArtifacts) < 1 || len(debugArtifacts) > 4_096 {
		return errSchemaInvalid()
	}
	if err := validateSubjectLaunch(manifest["launch"]); err != nil {
		return err
	}
	objectKinds, err := validateSubjectObjects(objects, manifest["total_bytes"])
	if err != nil {
		return err
	}
	fileDigests, err := validateSubjectFiles(files, objectKinds)
	if err != nil {
		return err
	}
	moduleDigests, err := validateSubjectModules(modules, fileDigests, objectKinds)
	if err != nil {
		return err
	}
	if err := validateSubjectDebugArtifacts(
		debugArtifacts, fileDigests, objectKinds, moduleDigests,
	); err != nil {
		return err
	}
	launch := manifest["launch"].(map[string]any)
	for _, file := range files {
		if file["path"] == launch["executable"] && file["executable"] == true {
			return nil
		}
	}
	return errSchemaInvalid()
}

func validateSubjectLaunch(value any) error {
	launch, ok := value.(map[string]any)
	if !ok || !hasExactKeys(launch,
		"arguments", "environment_names", "executable", "working_directory",
	) {
		return errSchemaInvalid()
	}
	arguments, argumentsOK := anyList(launch["arguments"])
	names, namesOK := anyList(launch["environment_names"])
	if !argumentsOK || len(arguments) > maxSubjectArguments ||
		!namesOK || len(names) > maxSubjectEnvironment ||
		!validSubjectPath(launch["executable"]) ||
		!validSubjectPath(launch["working_directory"]) {
		return errSchemaInvalid()
	}
	for _, argument := range arguments {
		text, textOK := argument.(string)
		if !textOK || len(text) > 4_096 {
			return errSchemaInvalid()
		}
	}
	previous := ""
	for index, name := range names {
		text, textOK := name.(string)
		if !textOK || text == "" || len(text) > 256 || strings.Contains(text, "=") {
			return errSchemaInvalid()
		}
		for position := 0; position < len(text); position++ {
			if text[position] < 33 || text[position] > 126 {
				return errSchemaInvalid()
			}
		}
		if index > 0 && previous >= text {
			return errSchemaInvalid()
		}
		previous = text
	}
	return nil
}

func validateSubjectObjects(
	objects []map[string]any, totalBytes any,
) (map[string]string, error) {
	kinds := make(map[string]string)
	total := int64(0)
	previous := ""
	for _, entry := range objects {
		if !hasExactKeys(entry, "digest", "kind", "media_type", "size") {
			return nil, errSchemaInvalid()
		}
		size, sizeOK := integerValue(entry["size"])
		mediaType, mediaTypeOK := entry["media_type"].(string)
		kind, kindOK := entry["kind"].(string)
		digest, digestOK := entry["digest"].(string)
		if !sizeOK || size <= 0 || size > maxSubjectObjectBytes ||
			!mediaTypeOK || mediaType == "" || len(mediaType) > 128 ||
			!kindOK || !subjectObjectKinds[kind] || !digestOK || !validDigest(digest) {
			return nil, errSchemaInvalid()
		}
		if previous != "" && previous >= digest {
			return nil, errSchemaInvalid()
		}
		previous = digest
		total += size
		kinds[digest] = kind
	}
	declaredTotal, declaredTotalOK := integerValue(totalBytes)
	if !declaredTotalOK || total != declaredTotal || total > maxSubjectTotalBytes {
		return nil, errSchemaInvalid()
	}
	return kinds, nil
}

func validateSubjectFiles(
	files []map[string]any, objectKinds map[string]string,
) (map[string]string, error) {
	digests := make(map[string]string)
	previous := ""
	for _, entry := range files {
		if !hasExactKeys(entry, "executable", "object_digest", "path") {
			return nil, errSchemaInvalid()
		}
		_, executableOK := entry["executable"].(bool)
		path, pathOK := entry["path"].(string)
		objectDigest, objectDigestOK := entry["object_digest"].(string)
		if !executableOK || !pathOK || !validSubjectPath(path) ||
			!objectDigestOK || objectKinds[objectDigest] == "" {
			return nil, errSchemaInvalid()
		}
		if previous != "" && previous >= path {
			return nil, errSchemaInvalid()
		}
		previous = path
		digests[path] = objectDigest
	}
	return digests, nil
}

func validateSubjectModules(
	modules []map[string]any, fileDigests map[string]string, objectKinds map[string]string,
) (map[string]bool, error) {
	moduleDigests := make(map[string]bool)
	previous := ""
	for _, entry := range modules {
		if !hasExactKeys(entry, "identity", "module_digest", "path") {
			return nil, errSchemaInvalid()
		}
		identity, identityOK := entry["identity"].(string)
		path, pathOK := entry["path"].(string)
		moduleDigest, moduleDigestOK := entry["module_digest"].(string)
		if !identityOK || identity == "" || len(identity) > 512 ||
			!pathOK || !validSubjectPath(path) ||
			!moduleDigestOK || fileDigests[path] != moduleDigest ||
			objectKinds[moduleDigest] == "" {
			return nil, errSchemaInvalid()
		}
		if previous != "" && previous >= path {
			return nil, errSchemaInvalid()
		}
		previous = path
		moduleDigests[moduleDigest] = true
	}
	return moduleDigests, nil
}

func validateSubjectDebugArtifacts(
	debugArtifacts []map[string]any,
	fileDigests map[string]string,
	objectKinds map[string]string,
	moduleDigests map[string]bool,
) error {
	previous := ""
	for _, entry := range debugArtifacts {
		if !hasExactKeys(entry, "artifact_digest", "kind", "module_digest", "path") {
			return errSchemaInvalid()
		}
		kind, kindOK := entry["kind"].(string)
		path, pathOK := entry["path"].(string)
		artifactDigest, artifactDigestOK := entry["artifact_digest"].(string)
		moduleDigest, moduleDigestOK := entry["module_digest"].(string)
		if !kindOK || !pathOK || !artifactDigestOK || !moduleDigestOK {
			return errSchemaInvalid()
		}
		artifactKind := objectKinds[artifactDigest]
		validKind := false
		switch {
		case kind == "interpreted-source-identity":
			validKind = artifactKind != ""
		case kind == "dwarf" && artifactDigest == moduleDigest:
			validKind = artifactKind != ""
		case kind == "dwarf" || kind == "portable-pdb" || kind == "source-map":
			validKind = artifactKind == "debug-artifact"
		}
		if !validSubjectPath(path) || fileDigests[path] != artifactDigest ||
			!validKind || !moduleDigests[moduleDigest] {
			return errSchemaInvalid()
		}
		if previous != "" && previous >= path {
			return errSchemaInvalid()
		}
		previous = path
	}
	return nil
}

func validSubjectPath(value any) bool {
	path, ok := value.(string)
	if !ok || !strings.HasPrefix(path, "/reproit/subject/") {
		return false
	}
	relative := path[len("/reproit/subject/"):]
	if relative == "" || len(path) > 4_096 || strings.ContainsRune(path, 0) {
		return false
	}
	for _, part := range strings.Split(relative, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// subjectBinding builds the deployment Subject descriptor bound to this
// manifest.
func subjectBinding(manifest map[string]any) (map[string]any, error) {
	launch, ok := manifest["launch"].(map[string]any)
	if !ok {
		return nil, errSchemaInvalid()
	}
	manifestDigest, err := canonicalDigest(manifest)
	if err != nil {
		return nil, err
	}
	arguments, _ := anyList(launch["arguments"])
	environmentNames, _ := anyList(launch["environment_names"])
	return map[string]any{
		"architecture":        manifest["architecture"],
		"arguments":           append([]any{}, arguments...),
		"artifact_digest":     manifestDigest,
		"artifact_media_type": subjectManifestMediaType,
		"artifact_uri":        "reproit-managed://" + manifestDigest,
		"environment_names":   append([]any{}, environmentNames...),
		"executable":          launch["executable"],
		"format":              "reproit.subject.v1",
		"operating_system":    manifest["operating_system"],
		"working_directory":   launch["working_directory"],
	}, nil
}

func validUTF8String(value string) bool {
	return utf8.ValidString(value)
}

func digestName(digest string) string {
	return strings.TrimPrefix(digest, "sha256:")
}

func candidateRecords(value any) ([]map[string]any, bool) {
	switch records := value.(type) {
	case []map[string]any:
		return records, true
	case []any:
		result := make([]map[string]any, len(records))
		for index, record := range records {
			mapped, ok := record.(map[string]any)
			if !ok {
				return nil, false
			}
			result[index] = mapped
		}
		return result, true
	default:
		return nil, false
	}
}

func errSubjectUnreadable() *ManagedError {
	return newManagedError(
		"INCOMPLETE_CANDIDATE", "The running Go subject is not completely readable.",
	)
}

func errSubjectChanging() *ManagedError {
	return newManagedError(
		"INCOMPLETE_CANDIDATE", "The running Go subject changed during local packaging.",
	)
}

func errSubjectUnbounded() *ManagedError {
	return newManagedError(
		"UPLOAD_LIMIT_EXCEEDED", "The running Go subject exceeds a Backend v1 bound.",
	)
}

func errSubjectUnsupported() *ManagedError {
	return newManagedError(
		"UNSUPPORTED", "The running Go subject has an unsupported file or launch identity.",
	)
}
