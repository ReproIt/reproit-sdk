// Bounded capture of the running Node.js executable and loaded native modules.

import path from "node:path";
import { realpathSync } from "node:fs";

import { ManagedError } from "./subject-protocol.js";
import {
  MAX_SUBJECT_FILES,
  compareText,
  digestName,
  freezeSubjectFile,
  subjectChanging,
  subjectPath,
  subjectUnbounded,
  subjectUnreadable,
  subjectUnsupported,
} from "./managed-subject-files.js";

const MAX_RUNTIME_MODULES = 4_096;

export function runningRuntimeEvidence() {
  const sharedObjectPaths = runtimeModuleReport();
  return {
    executablePath: process.execPath,
    sharedObjectPaths,
    verify() {
      const after = runtimeModuleReport();
      if (!sameRuntimeModuleReport(sharedObjectPaths, after)) {
        throw subjectChanging();
      }
    },
  };
}

function runtimeModuleReport() {
  let report;
  try {
    report = process.report?.getReport();
  } catch {
    throw subjectUnreadable();
  }
  if (!Array.isArray(report?.sharedObjects)) throw subjectUnsupported();
  return [...report.sharedObjects];
}

function sameRuntimeModuleReport(left, right) {
  const sortedLeft = [...new Set(left)].sort(compareText);
  const sortedRight = [...new Set(right)].sort(compareText);
  return (
    sortedLeft.length === sortedRight.length &&
    sortedLeft.every((entry, index) => entry === sortedRight[index])
  );
}

export function verifyRuntimeEvidence(evidence) {
  if (evidence.verify === undefined) return;
  if (typeof evidence.verify !== "function") throw subjectUnsupported();
  try {
    evidence.verify();
  } catch (error) {
    if (error instanceof ManagedError) throw error;
    throw subjectUnreadable();
  }
}

export function captureRuntimeClosure(
  evidence,
  subjectFiles,
  spool,
  state,
  fileMediaType,
) {
  if (
    evidence === null ||
    typeof evidence !== "object" ||
    typeof evidence.executablePath !== "string" ||
    !Array.isArray(evidence.sharedObjectPaths) ||
    evidence.sharedObjectPaths.length > MAX_RUNTIME_MODULES
  ) {
    throw subjectUnsupported();
  }
  const executablePath = exactRuntimePath(evidence.executablePath);
  const loadedPaths = loadedRuntimePaths(evidence, executablePath);
  const capturedSources = new Set(subjectFiles.map((entry) => entry.sourcePath));
  const uncapturedNativePaths = [...loadedPaths].filter(
    (modulePath) => modulePath !== executablePath && !capturedSources.has(modulePath),
  );
  proveNativeApplicationModules(subjectFiles, loadedPaths);

  const executable = captureRuntimeFile(executablePath, spool, state);
  describeRuntimeFile(executable, executablePath, "runtime", true, fileMediaType);
  executable.subjectPath = subjectPath(
    `/reproit/subject/runtime/${digestName(executable.digest)}`,
    path.basename(executablePath),
  );

  const native = uncapturedNativePaths.map((modulePath) => {
    const entry = captureRuntimeFile(modulePath, spool, state);
    describeRuntimeFile(
      entry,
      modulePath,
      "native-dependency",
      isRuntimeLoader(modulePath),
      fileMediaType,
    );
    entry.subjectPath = subjectPath(
      `/reproit/subject/native/${digestName(entry.digest)}`,
      path.basename(modulePath),
    );
    return entry;
  });
  if (process.platform === "linux" && !native.some((entry) => entry.executable)) {
    throw subjectUnsupported();
  }
  return { executable, files: [executable, ...native], native };
}

function loadedRuntimePaths(evidence, executablePath) {
  const loadedPaths = new Set([executablePath]);
  for (const reportedPath of evidence.sharedObjectPaths) {
    const resolved = resolveRuntimeModule(reportedPath);
    if (resolved !== null) loadedPaths.add(resolved);
  }
  return loadedPaths;
}

function describeRuntimeFile(
  entry,
  sourcePath,
  kind,
  executable,
  mediaType,
) {
  entry.executable = executable;
  entry.kind = kind;
  entry.mediaType = mediaType;
  entry.sourcePath = sourcePath;
}

function exactRuntimePath(filePath) {
  if (!path.isAbsolute(filePath)) throw subjectUnsupported();
  try {
    return realpathSync(filePath);
  } catch {
    throw subjectUnreadable();
  }
}

function resolveRuntimeModule(reportedPath) {
  if (typeof reportedPath !== "string" || reportedPath.length === 0) {
    throw subjectUnsupported();
  }
  if (!path.isAbsolute(reportedPath)) {
    if (process.platform === "linux" && reportedPath.startsWith("linux-vdso")) {
      return null;
    }
    throw subjectUnsupported();
  }
  if (
    process.platform === "darwin" &&
    (reportedPath.startsWith("/System/Library/") ||
      reportedPath.startsWith("/usr/lib/"))
  ) {
    return null;
  }
  return exactRuntimePath(reportedPath);
}

function captureRuntimeFile(filePath, spool, state) {
  state.entries += 1;
  if (state.entries > MAX_SUBJECT_FILES) throw subjectUnbounded();
  return freezeSubjectFile(filePath, spool, state);
}

function proveNativeApplicationModules(subjectFiles, loadedPaths) {
  for (const entry of subjectFiles) {
    if (path.extname(entry.sourcePath).toLowerCase() !== ".node") continue;
    if (!loadedPaths.has(entry.sourcePath)) throw subjectUnsupported();
  }
}

function isRuntimeLoader(filePath) {
  const name = path.basename(filePath);
  return name.startsWith("ld-linux-") || name.startsWith("ld-musl-");
}

export function interpreterIdentity(runtime) {
  const version = process.versions.node;
  return {
    executable_digest: runtime.executable.digest,
    executable_size: runtime.executable.size,
    format: "reproit.node-interpreter-identity.v1",
    identity: `node-${version}`,
    implementation: "node",
    native_dependency_digests: [
      ...new Set(runtime.native.map((entry) => entry.digest)),
    ].sort(compareText),
    version,
  };
}
