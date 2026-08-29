// Node.js subject-closure packaging for managed capture.
//
// Mirrors crates/reproit-sdk-rust/src/subject.rs for the language-neutral
// manifest shape. The Node subject closure contains the application files,
// installed dependency files, required source maps, Node.js identity, and
// launch data.

import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalBytes } from "./encoding.js";
import {
  ManagedError,
  canonicalDigest,
  digestBytes,
  sameKeys,
  schemaInvalid,
  validCapability,
} from "./subject-protocol.js";
import {
  MAX_SUBJECT_FILES,
  MAX_SUBJECT_OBJECT_BYTES,
  MAX_SUBJECT_TOTAL_BYTES,
  captureTree,
  compareText,
  digestName,
  sourceMapReference,
  subjectPath,
  subjectUnbounded,
  subjectUnreadable,
  subjectUnsupported,
} from "./managed-subject-files.js";
import {
  captureRuntimeClosure,
  interpreterIdentity,
  runningRuntimeEvidence,
  verifyRuntimeEvidence,
} from "./managed-subject-runtime.js";
import { releaseLogical, reserveLogical } from "./process-resources.js";

export {
  COPY_BUFFER_BYTES,
  MAX_SUBJECT_OBJECT_BYTES,
} from "./managed-subject-files.js";

export const SUBJECT_FILE_MEDIA_TYPE = "application/vnd.reproit.subject-file.v1";
export const SUBJECT_LAUNCH_MEDIA_TYPE =
  "application/vnd.reproit.subject-launch.v1+json";
export const MODULE_IDENTITY_MEDIA_TYPE =
  "application/vnd.reproit.subject-module-identity.v1+json";

export const MAX_ARGUMENTS = 128;
export const MAX_DEPENDENCIES = 4_096;
export const MAX_ENVIRONMENT_NAMES = 256;
const MAX_PACKAGE_MANIFEST_BYTES = 1_048_576;
const MAX_NODE_MODULES_ANCESTORS = 64;
const MAX_SUBJECT_MODULES = 4_096;

const NODE_MODULE_EXTENSIONS = new Set([
  ".cjs",
  ".cts",
  ".js",
  ".mjs",
  ".mts",
  ".node",
  ".ts",
]);

const ARCHITECTURES = {
  arm64: "architecture.arm64",
  x64: "architecture.x86-64",
};
const OPERATING_SYSTEMS = {
  darwin: "operating-system.macos",
  linux: "operating-system.linux",
  win32: "operating-system.windows",
};

// The frozen manifest plus content-addressed object files in a spool.
export class NodeSubjectPackage {
  #spool;
  #reservedBytes;

  constructor(manifest, objects, spool, reservedBytes) {
    this.manifest = manifest;
    this.objects = objects;
    this.#spool = spool;
    this.#reservedBytes = reservedBytes;
  }

  dispose() {
    if (this.#spool !== null) {
      rmSync(this.#spool, { force: true, recursive: true });
      this.#spool = null;
    }
    if (this.#reservedBytes > 0) {
      releaseLogical(this.#reservedBytes);
      this.#reservedBytes = 0;
    }
  }
}

// Freeze and hash the running Node.js subject closure locally.
export function packageRunningNodeSubject(entryScript) {
  return packageNodeSubjectWithRuntimeEvidence(
    entryScript,
    runningRuntimeEvidence(),
  );
}

// Package explicit runtime evidence for focused conformance tests. This
// operation is intentionally not exported by the public package entry point.
export function packageNodeSubjectWithRuntimeEvidence(
  entryScript,
  runtimeEvidence,
) {
  let scriptPath = entryScript !== undefined ? entryScript : process.argv[1];
  if (typeof scriptPath !== "string" || scriptPath.length === 0) {
    throw subjectUnsupported();
  }
  try {
    scriptPath = realpathSync(scriptPath);
  } catch {
    throw subjectUnreadable();
  }
  const spool = mkdtempSync(path.join(os.tmpdir(), "reproit-node-subject-"));
  let captureState;
  try {
    captureState = {
      entries: 0,
      logicalBytes: 0,
      packaged: new Map(),
      reservedBytes: 0,
      temporaryIndex: 0,
    };
    const applicationRoot = findApplicationRoot(scriptPath);
    const applicationFiles = captureTree(
      applicationRoot,
      spool,
      captureState,
      true,
    );
    const script = applicationFiles.find(
      (entry) => entry.sourcePath === scriptPath,
    );
    if (script === undefined) {
      throw subjectUnreadable();
    }
    const applicationPrefix =
      `/reproit/subject/application/${digestName(script.digest)}`;
    for (const entry of applicationFiles) {
      entry.subjectPath = subjectPath(applicationPrefix, entry.relativePath);
      entry.kind = "application";
      entry.mediaType = SUBJECT_FILE_MEDIA_TYPE;
    }

    const dependencyRoot = findNodeModules(path.dirname(scriptPath));
    const dependencyFiles =
      dependencyRoot === null
        ? []
        : captureTree(dependencyRoot, spool, captureState, false);
    for (const entry of dependencyFiles) {
      entry.subjectPath = subjectPath(
        `${applicationPrefix}/node_modules`,
        entry.relativePath,
      );
      entry.kind =
        path.extname(entry.sourcePath).toLowerCase() === ".node"
          ? "native-dependency"
          : "application";
      entry.mediaType = SUBJECT_FILE_MEDIA_TYPE;
    }
    const subjectFiles = [...applicationFiles, ...dependencyFiles];
    const runtime = captureRuntimeClosure(
      runtimeEvidence,
      subjectFiles,
      spool,
      captureState,
      SUBJECT_FILE_MEDIA_TYPE,
    );
    verifyRuntimeEvidence(runtimeEvidence);
    const capturedFiles = [...subjectFiles, ...runtime.files];
    if (capturedFiles.length + 3 > MAX_SUBJECT_FILES) {
      throw subjectUnbounded();
    }

    const interpreter = interpreterIdentity(runtime);
    const interpreterBytes = canonicalBytes(interpreter);
    const interpreterDigest = digestBytes(interpreterBytes);
    const dependencies = dependencyClosure(dependencyFiles);
    const dependencyBytes = canonicalBytes(dependencies);
    const dependencyDigest = digestBytes(dependencyBytes);
    const scriptSubjectPath = script.subjectPath;
    const launch = {
      arguments: unicodeArguments(scriptSubjectPath),
      environment_names: environmentNames(),
      executable: runtime.executable.subjectPath,
      working_directory: applicationPrefix,
    };
    const launchBytes = canonicalBytes(launch);
    const launchDigest = digestBytes(launchBytes);

    const { debugArtifacts, modules } = subjectModules(
      subjectFiles,
      script,
      interpreter,
      interpreterDigest,
    );
    const objectEntries = capturedFiles.map((entry) => [
      entry.digest,
      entry.kind,
      entry.mediaType,
      entry.size,
    ]);
    objectEntries.push(
      [
        interpreterDigest,
        "module-identity",
        MODULE_IDENTITY_MEDIA_TYPE,
        interpreterBytes.length,
      ],
      [
        dependencyDigest,
        "module-identity",
        MODULE_IDENTITY_MEDIA_TYPE,
        dependencyBytes.length,
      ],
      [
        launchDigest,
        "launch-data",
        SUBJECT_LAUNCH_MEDIA_TYPE,
        launchBytes.length,
      ],
    );
    const objects = assembleObjects(...objectEntries);
    const totalBytes = objects.reduce((total, entry) => total + entry.size, 0);
    if (
      objects.length > MAX_SUBJECT_FILES ||
      totalBytes > MAX_SUBJECT_TOTAL_BYTES
    ) {
      throw subjectUnbounded();
    }
    const files = [
      ...capturedFiles.map((entry) => ({
        executable: entry.executable,
        object_digest: entry.digest,
        path: entry.subjectPath,
      })),
      {
        executable: false,
        object_digest: launchDigest,
        path: "/reproit/subject/launch.json",
      },
      {
        executable: false,
        object_digest: dependencyDigest,
        path: "/reproit/subject/node/dependencies.json",
      },
      {
        executable: false,
        object_digest: interpreterDigest,
        path: "/reproit/subject/node/interpreter.json",
      },
    ].sort((left, right) => compareText(left.path, right.path));
    const manifest = {
      architecture: architecture(),
      debug_artifacts: debugArtifacts,
      files,
      format: "reproit.subject-closure.v1",
      launch,
      modules,
      objects,
      operating_system: operatingSystem(),
      runtime_family: "node",
      total_bytes: totalBytes,
    };
    validateSubjectClosureManifest(manifest);
    spoolObjects(spool, captureState.packaged, [
      [interpreterDigest, interpreterBytes],
      [dependencyDigest, dependencyBytes],
      [launchDigest, launchBytes],
    ]);
    const packaged = [...captureState.packaged.values()].sort((left, right) =>
      compareText(left.digest, right.digest),
    );
    if (packaged.length !== objects.length) {
      throw subjectUnreadable();
    }
    const additionalBytes = Math.max(0, totalBytes - captureState.reservedBytes);
    if (!reserveLogical(additionalBytes)) throw subjectUnbounded();
    captureState.reservedBytes += additionalBytes;
    return new NodeSubjectPackage(
      manifest,
      packaged,
      spool,
      captureState.reservedBytes,
    );
  } catch (error) {
    rmSync(spool, { force: true, recursive: true });
    if (captureState?.reservedBytes > 0) {
      releaseLogical(captureState.reservedBytes);
    }
    throw error;
  }
}

function assembleObjects(...entries) {
  const merged = new Map();
  for (const [digest, kind, mediaType, size] of entries) {
    const candidate = { digest, kind, media_type: mediaType, size };
    const existing = merged.get(digest);
    if (existing !== undefined) {
      if (existing.size !== size) throw subjectUnreadable();
      if (objectKindPriority(candidate.kind) > objectKindPriority(existing.kind)) {
        merged.set(digest, candidate);
      }
    } else {
      merged.set(digest, candidate);
    }
  }
  return [...merged.keys()]
    .sort(compareText)
    .map((digest) => merged.get(digest));
}

function objectKindPriority(kind) {
  return [
    "application",
    "module-identity",
    "launch-data",
    "native-dependency",
    "runtime",
    "debug-artifact",
  ].indexOf(kind);
}

function spoolObjects(spoolPath, packaged, contents) {
  for (const [digest, value] of contents) {
    const objectPath = path.join(spoolPath, digestName(digest));
    const existing = packaged.get(digest);
    if (existing === undefined) {
      writeFileSync(objectPath, value);
      packaged.set(digest, {
        digest,
        path: objectPath,
        size: value.length,
      });
    } else if (existing.size !== value.length) {
      throw subjectUnreadable();
    }
  }
}

function findApplicationRoot(scriptPath) {
  let directory = path.dirname(scriptPath);
  for (let depth = 0; depth < MAX_NODE_MODULES_ANCESTORS; depth += 1) {
    const manifestPath = path.join(directory, "package.json");
    try {
      const metadata = lstatSync(manifestPath);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw subjectUnsupported();
      }
      return directory;
    } catch (error) {
      if (error instanceof ManagedError) throw error;
      if (error?.code !== "ENOENT") throw subjectUnreadable();
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  return path.dirname(scriptPath);
}

function subjectModules(
  capturedFiles,
  script,
  interpreter,
  interpreterDigest,
) {
  const moduleFiles = capturedFiles.filter(
    (entry) =>
      entry === script ||
      NODE_MODULE_EXTENSIONS.has(path.extname(entry.sourcePath).toLowerCase()),
  );
  if (moduleFiles.length + 1 > MAX_SUBJECT_MODULES) {
    throw subjectUnbounded();
  }
  const modules = moduleFiles.map((entry) => ({
    identity: entry.digest,
    module_digest: entry.digest,
    path: entry.subjectPath,
  }));
  modules.push({
    identity: interpreter.identity,
    module_digest: interpreterDigest,
    path: "/reproit/subject/node/interpreter.json",
  });

  const debugArtifacts = [];
  const capturedBySource = new Map(
    capturedFiles.map((entry) => [entry.sourcePath, entry]),
  );
  const boundMaps = new Map();
  for (const entry of moduleFiles) {
    if (path.extname(entry.sourcePath).toLowerCase() === ".node") continue;
    debugArtifacts.push({
      artifact_digest: entry.digest,
      kind: "interpreted-source-identity",
      module_digest: entry.digest,
      path: entry.subjectPath,
    });
    const reference = sourceMapReference(entry);
    if (reference === null) continue;
    const mapSourcePath = path.resolve(path.dirname(entry.sourcePath), reference);
    const sourceMap = capturedBySource.get(mapSourcePath);
    if (sourceMap === undefined) throw subjectUnreadable();
    const existingModule = boundMaps.get(sourceMap.subjectPath);
    if (existingModule !== undefined && existingModule !== entry.digest) {
      throw subjectUnsupported();
    }
    if (existingModule === entry.digest) continue;
    sourceMap.kind = "debug-artifact";
    sourceMap.mediaType = "application/json";
    boundMaps.set(sourceMap.subjectPath, entry.digest);
    debugArtifacts.push({
      artifact_digest: sourceMap.digest,
      kind: "source-map",
      module_digest: entry.digest,
      path: sourceMap.subjectPath,
    });
  }
  if (debugArtifacts.length === 0 || debugArtifacts.length > MAX_SUBJECT_MODULES) {
    throw subjectUnbounded();
  }
  modules.sort((left, right) => compareText(left.path, right.path));
  debugArtifacts.sort((left, right) => compareText(left.path, right.path));
  return { debugArtifacts, modules };
}

// Bind each installed package identity to its captured package.json bytes.
function dependencyClosure(dependencyFiles) {
  const entries = [];
  for (const packageFile of dependencyFiles) {
    if (!isDependencyPackageManifest(packageFile.relativePath)) continue;
    if (packageFile.size > MAX_PACKAGE_MANIFEST_BYTES) {
      throw subjectUnbounded();
    }
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(packageFile.spoolPath, "utf8"));
    } catch {
      throw subjectUnreadable();
    }
    const { name, version } = manifest;
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      typeof version !== "string" ||
      version.length === 0
    ) {
      throw subjectUnreadable();
    }
    entries.push({
      manifest_digest: packageFile.digest,
      name,
      path: packageFile.subjectPath,
      version,
    });
    if (entries.length > MAX_DEPENDENCIES) {
      throw subjectUnbounded();
    }
  }
  entries.sort((left, right) => compareText(left.path, right.path));
  return {
    format: "reproit.node-dependency-closure.v1",
    packages: entries,
  };
}

function isDependencyPackageManifest(relativePath) {
  const parts = relativePath.split(path.sep);
  if (parts.at(-1) !== "package.json") return false;
  const nestedBoundary = parts.lastIndexOf("node_modules");
  const packageParts = parts.slice(nestedBoundary + 1);
  return (
    (packageParts.length === 2 && !packageParts[0].startsWith("@")) ||
    (packageParts.length === 3 && packageParts[0].startsWith("@"))
  );
}

function findNodeModules(startDirectory) {
  let directory = startDirectory;
  let dependencyRoot = null;
  for (let depth = 0; depth < MAX_NODE_MODULES_ANCESTORS; depth += 1) {
    const candidate = path.join(directory, "node_modules");
    try {
      const metadata = lstatSync(candidate);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        throw subjectUnsupported();
      }
      if (dependencyRoot !== null) throw subjectUnsupported();
      dependencyRoot = candidate;
    } catch (error) {
      if (error instanceof ManagedError) throw error;
      if (error?.code !== "ENOENT") throw subjectUnreadable();
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  return dependencyRoot;
}

function unicodeArguments(scriptSubjectPath) {
  validateNodeRuntimeArguments(process.execArgv, process.env.NODE_OPTIONS);
  const processArguments = [
    ...process.execArgv,
    scriptSubjectPath,
    ...process.argv.slice(2),
  ];
  if (
    processArguments.length > MAX_ARGUMENTS ||
    processArguments.some(
      (argument) => typeof argument !== "string" || argument.length > 4_096,
    )
  ) {
    throw subjectUnsupported();
  }
  return [...processArguments];
}

export function validateNodeRuntimeArguments(arguments_, nodeOptions) {
  if (typeof nodeOptions === "string" && nodeOptions.trim().length > 0) {
    throw subjectUnsupported();
  }
  const hostPathOptions = [
    "--build-snapshot",
    "--experimental-loader",
    "--icu-data-dir",
    "--import",
    "--loader",
    "--openssl-config",
    "--policy-integrity",
    "--require",
    "--snapshot-blob",
    "--test-reporter-destination",
    "--watch-path",
    "-r",
  ];
  for (const argument of arguments_) {
    if (typeof argument !== "string") throw subjectUnsupported();
    if (
      argument === "--inspect" ||
      argument.startsWith("--inspect=") ||
      argument === "--inspect-brk" ||
      argument.startsWith("--inspect-brk=") ||
      argument === "--inspect-wait" ||
      argument.startsWith("--inspect-wait=") ||
      hostPathOptions.some(
        (option) => argument === option || argument.startsWith(`${option}=`),
      )
    ) {
      throw subjectUnsupported();
    }
  }
}

function environmentNames() {
  const names = [...new Set(Object.keys(process.env))].sort(compareText);
  if (names.length > MAX_ENVIRONMENT_NAMES) {
    throw subjectUnbounded();
  }
  for (const name of names) {
    if (
      name.length === 0 ||
      name.length > 256 ||
      !/^[!-~]+$/u.test(name) ||
      name.includes("=")
    ) {
      throw subjectUnsupported();
    }
  }
  return names;
}

function architecture() {
  const capability = ARCHITECTURES[process.arch];
  if (capability === undefined) {
    throw unsupportedHost();
  }
  return capability;
}

function operatingSystem() {
  const capability = OPERATING_SYSTEMS[process.platform];
  if (capability === undefined) {
    throw unsupportedHost();
  }
  return capability;
}

// Mirror reproit-core SubjectClosureManifest::validate.
export function validateSubjectClosureManifest(value) {
  if (
    !sameKeys(value, [
      "architecture",
      "debug_artifacts",
      "files",
      "format",
      "launch",
      "modules",
      "objects",
      "operating_system",
      "runtime_family",
      "total_bytes",
    ])
  ) {
    throw schemaInvalid();
  }
  if (
    value.format !== "reproit.subject-closure.v1" ||
    !["dotnet", "go", "node", "python", "rust"].includes(
      value.runtime_family,
    ) ||
    !validCapability(value.architecture) ||
    !validCapability(value.operating_system)
  ) {
    throw schemaInvalid();
  }
  const objects = value.objects;
  const files = value.files;
  const modules = value.modules;
  const debugArtifacts = value.debug_artifacts;
  if (
    !Array.isArray(objects) ||
    objects.length < 1 ||
    objects.length > 32_767 ||
    !Array.isArray(files) ||
    files.length < 1 ||
    files.length > 32_767 ||
    !Array.isArray(modules) ||
    modules.length < 1 ||
    modules.length > 4_096 ||
    !Array.isArray(debugArtifacts) ||
    debugArtifacts.length < 1 ||
    debugArtifacts.length > 4_096
  ) {
    throw schemaInvalid();
  }
  validateLaunch(value.launch);
  const objectKinds = validateObjects(objects, value.total_bytes);
  const fileDigests = validateFiles(files, objectKinds);
  const moduleDigests = validateModules(modules, fileDigests, objectKinds);
  validateDebugArtifacts(
    debugArtifacts,
    fileDigests,
    objectKinds,
    moduleDigests,
  );
  const launch = value.launch;
  if (
    !files.some(
      (file) => file.path === launch.executable && file.executable === true,
    )
  ) {
    throw schemaInvalid();
  }
}

function validateLaunch(value) {
  if (
    !sameKeys(value, [
      "arguments",
      "environment_names",
      "executable",
      "working_directory",
    ])
  ) {
    throw schemaInvalid();
  }
  const launchArguments = value.arguments;
  const names = value.environment_names;
  if (
    !Array.isArray(launchArguments) ||
    launchArguments.length > MAX_ARGUMENTS ||
    launchArguments.some(
      (argument) => typeof argument !== "string" || argument.length > 4_096,
    ) ||
    !Array.isArray(names) ||
    names.length > MAX_ENVIRONMENT_NAMES ||
    names.some((name, index) => index > 0 && names[index - 1] >= name) ||
    names.some(
      (name) =>
        typeof name !== "string" ||
        name.length === 0 ||
        name.length > 256 ||
        name.includes("=") ||
        !/^[!-~]+$/u.test(name),
    ) ||
    !validSubjectPath(value.executable) ||
    !validSubjectPath(value.working_directory)
  ) {
    throw schemaInvalid();
  }
}

function validateObjects(objects, totalBytes) {
  const kinds = new Map();
  let total = 0;
  let previous = null;
  for (const entry of objects) {
    if (!sameKeys(entry, ["digest", "kind", "media_type", "size"])) {
      throw schemaInvalid();
    }
    const size = entry.size;
    const mediaType = entry.media_type;
    if (
      !Number.isSafeInteger(size) ||
      size < 0 ||
      size > MAX_SUBJECT_OBJECT_BYTES ||
      typeof mediaType !== "string" ||
      mediaType.length === 0 ||
      mediaType.length > 128 ||
      ![
        "application",
        "debug-artifact",
        "launch-data",
        "module-identity",
        "native-dependency",
        "runtime",
      ].includes(entry.kind)
    ) {
      throw schemaInvalid();
    }
    if (previous !== null && previous >= entry.digest) {
      throw schemaInvalid();
    }
    previous = entry.digest;
    total += size;
    kinds.set(entry.digest, entry.kind);
  }
  if (total !== totalBytes || total > MAX_SUBJECT_TOTAL_BYTES) {
    throw schemaInvalid();
  }
  return kinds;
}

function validateFiles(files, objectKinds) {
  const digests = new Map();
  let previous = null;
  for (const entry of files) {
    if (
      !sameKeys(entry, ["executable", "object_digest", "path"]) ||
      typeof entry.executable !== "boolean" ||
      !validSubjectPath(entry.path) ||
      !objectKinds.has(entry.object_digest)
    ) {
      throw schemaInvalid();
    }
    if (previous !== null && previous >= entry.path) {
      throw schemaInvalid();
    }
    previous = entry.path;
    digests.set(entry.path, entry.object_digest);
  }
  return digests;
}

function validateModules(modules, fileDigests, objectKinds) {
  const moduleDigests = new Set();
  let previous = null;
  for (const entry of modules) {
    if (
      !sameKeys(entry, ["identity", "module_digest", "path"]) ||
      typeof entry.identity !== "string" ||
      entry.identity.length === 0 ||
      entry.identity.length > 512 ||
      !validSubjectPath(entry.path) ||
      fileDigests.get(entry.path) !== entry.module_digest ||
      !objectKinds.has(entry.module_digest)
    ) {
      throw schemaInvalid();
    }
    if (previous !== null && previous >= entry.path) {
      throw schemaInvalid();
    }
    previous = entry.path;
    moduleDigests.add(entry.module_digest);
  }
  return moduleDigests;
}

function validateDebugArtifacts(
  debugArtifacts,
  fileDigests,
  objectKinds,
  moduleDigests,
) {
  let previous = null;
  for (const entry of debugArtifacts) {
    if (
      !sameKeys(entry, ["artifact_digest", "kind", "module_digest", "path"])
    ) {
      throw schemaInvalid();
    }
    const kind = entry.kind;
    const artifactKind = objectKinds.get(entry.artifact_digest);
    let validKind;
    if (kind === "interpreted-source-identity") {
      validKind = artifactKind !== undefined;
    } else if (
      kind === "dwarf" &&
      entry.artifact_digest === entry.module_digest
    ) {
      validKind = artifactKind !== undefined;
    } else if (["dwarf", "portable-pdb", "source-map"].includes(kind)) {
      validKind = artifactKind === "debug-artifact";
    } else {
      validKind = false;
    }
    if (
      !validSubjectPath(entry.path) ||
      fileDigests.get(entry.path) !== entry.artifact_digest ||
      !validKind ||
      !moduleDigests.has(entry.module_digest)
    ) {
      throw schemaInvalid();
    }
    if (previous !== null && previous >= entry.path) {
      throw schemaInvalid();
    }
    previous = entry.path;
  }
}

function validSubjectPath(subjectPath) {
  if (
    typeof subjectPath !== "string" ||
    !subjectPath.startsWith("/reproit/subject/")
  ) {
    return false;
  }
  const relative = subjectPath.slice("/reproit/subject/".length);
  return (
    relative.length > 0 &&
    subjectPath.length <= 4_096 &&
    !subjectPath.includes("\u0000") &&
    relative
      .split("/")
      .every((part) => part.length > 0 && part !== "." && part !== "..")
  );
}

// Build the deployment Subject descriptor bound to this manifest.
export function subjectBinding(manifest) {
  const launch = manifest.launch;
  const manifestDigest = canonicalDigest(manifest);
  return {
    architecture: manifest.architecture,
    arguments: [...launch.arguments],
    artifact_digest: manifestDigest,
    artifact_media_type: "application/vnd.reproit.subject-closure.v1+json",
    artifact_uri: `reproit-managed://${manifestDigest}`,
    environment_names: [...launch.environment_names],
    executable: launch.executable,
    format: "reproit.subject.v1",
    operating_system: manifest.operating_system,
    working_directory: launch.working_directory,
  };
}

function unsupportedHost() {
  return new ManagedError(
    "UNSUPPORTED",
    "This host cannot package a Backend v1 Node.js production subject.",
  );
}
