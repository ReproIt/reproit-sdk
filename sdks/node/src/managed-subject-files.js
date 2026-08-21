// Bounded file capture for the exact Node.js subject closure.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import path from "node:path";

import { ManagedError } from "./managed-protocol.js";

export const MAX_SUBJECT_OBJECT_BYTES = 274_878_824_448;
export const COPY_BUFFER_BYTES = 64 * 1024;
export const MAX_SUBJECT_FILES = 32_767;
const MAX_SUBJECT_TREE_DEPTH = 128;
const SOURCE_MAP_REFERENCE_BYTES = 8 * 1024;

// Freeze one bounded directory tree without following symbolic links. The
// application pass leaves node_modules for the separate dependency pass.
export function captureTree(root, spool, state, skipRootNodeModules) {
  const files = [];
  const directories = [];
  const pending = [{ depth: 0, directory: root, relativePath: "" }];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current.depth > MAX_SUBJECT_TREE_DEPTH) {
      throw subjectUnbounded();
    }
    let before;
    let entries;
    try {
      before = lstatSync(current.directory, { bigint: true });
      if (!before.isDirectory() || before.isSymbolicLink()) {
        throw subjectUnsupported();
      }
      entries = readdirSync(current.directory, { withFileTypes: true }).sort(
        (left, right) => compareText(left.name, right.name),
      );
    } catch (error) {
      if (error instanceof ManagedError) throw error;
      throw subjectUnreadable();
    }
    directories.push({ before, path: current.directory });
    const childDirectories = [];
    for (const entry of entries) {
      if (
        skipRootNodeModules &&
        current.relativePath === "" &&
        entry.name === "node_modules"
      ) {
        continue;
      }
      state.entries += 1;
      if (state.entries > MAX_SUBJECT_FILES) {
        throw subjectUnbounded();
      }
      const childPath = path.join(current.directory, entry.name);
      const relativePath =
        current.relativePath === ""
          ? entry.name
          : path.join(current.relativePath, entry.name);
      let metadata;
      try {
        metadata = lstatSync(childPath, { bigint: true });
      } catch {
        throw subjectUnreadable();
      }
      if (metadata.isSymbolicLink()) {
        throw subjectUnsupported();
      }
      if (metadata.isDirectory()) {
        childDirectories.push({
          depth: current.depth + 1,
          directory: childPath,
          relativePath,
        });
      } else if (metadata.isFile()) {
        files.push({
          ...freezeSubjectFile(childPath, spool, state),
          executable: (metadata.mode & 0o111n) !== 0n,
          relativePath,
          sourcePath: childPath,
        });
      } else {
        throw subjectUnsupported();
      }
    }
    for (let index = childDirectories.length - 1; index >= 0; index -= 1) {
      pending.push(childDirectories[index]);
    }
  }
  for (const directory of directories) {
    let after;
    try {
      after = lstatSync(directory.path, { bigint: true });
    } catch {
      throw subjectUnreadable();
    }
    if (!sameFileMetadata(directory.before, after) || !after.isDirectory()) {
      throw subjectChanging();
    }
  }
  return files.sort((left, right) =>
    compareText(left.relativePath, right.relativePath),
  );
}

export function freezeSubjectFile(sourcePath, spool, state) {
  let before;
  try {
    before = lstatSync(sourcePath, { bigint: true });
  } catch {
    throw subjectUnreadable();
  }
  if (!before.isFile() || before.isSymbolicLink()) {
    throw subjectUnsupported();
  }
  if (before.size > BigInt(MAX_SUBJECT_OBJECT_BYTES)) {
    throw subjectUnbounded();
  }
  const size = Number(before.size);
  state.logicalBytes += size;
  if (state.logicalBytes > MAX_SUBJECT_OBJECT_BYTES) {
    throw subjectUnbounded();
  }

  const temporaryPath = path.join(
    spool,
    `pending-${state.temporaryIndex.toString(16)}`,
  );
  state.temporaryIndex += 1;
  let input;
  let output;
  let total = 0;
  const hasher = createHash("sha256");
  try {
    input = openSync(sourcePath, "r");
    const opened = fstatSync(input, { bigint: true });
    if (!sameFileMetadata(before, opened) || !opened.isFile()) {
      throw subjectChanging();
    }
    output = openSync(temporaryPath, "wx", 0o600);
    const buffer = Buffer.alloc(COPY_BUFFER_BYTES);
    for (;;) {
      const read = readSync(input, buffer, 0, buffer.length, null);
      if (read === 0) break;
      total += read;
      if (total > size) throw subjectChanging();
      hasher.update(buffer.subarray(0, read));
      let written = 0;
      while (written < read) {
        written += writeSync(
          output,
          buffer,
          written,
          read - written,
          null,
        );
      }
    }
  } catch (error) {
    if (error instanceof ManagedError) throw error;
    throw subjectUnreadable();
  } finally {
    if (input !== undefined) closeSync(input);
    if (output !== undefined) closeSync(output);
  }
  let after;
  try {
    after = lstatSync(sourcePath, { bigint: true });
  } catch {
    throw subjectUnreadable();
  }
  if (total !== size || !sameFileMetadata(before, after)) {
    throw subjectChanging();
  }
  const digest = `sha256:${hasher.digest("hex")}`;
  const objectPath = path.join(spool, digestName(digest));
  try {
    const existing = state.packaged.get(digest);
    if (existing === undefined) {
      renameSync(temporaryPath, objectPath);
      state.packaged.set(digest, { digest, path: objectPath, size });
    } else {
      if (existing.size !== size) throw subjectUnreadable();
      unlinkSync(temporaryPath);
    }
  } catch (error) {
    if (existsSync(temporaryPath)) unlinkSync(temporaryPath);
    if (error instanceof ManagedError) throw error;
    throw subjectUnreadable();
  }
  return { digest, size, spoolPath: objectPath };
}

function sameFileMetadata(left, right) {
  return (
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ino === right.ino &&
    left.dev === right.dev
  );
}

export function subjectPath(prefix, relativePath) {
  const parts = relativePath.split(path.sep);
  if (
    parts.length === 0 ||
    parts.some(
      (part) =>
        part.length === 0 ||
        part === "." ||
        part === ".." ||
        part.includes("\u0000"),
    )
  ) {
    throw subjectUnsupported();
  }
  const value = `${prefix}/${parts.join("/")}`;
  if (value.length > 4_096) throw subjectUnbounded();
  return value;
}

export function sourceMapReference(module) {
  let descriptor;
  try {
    descriptor = openSync(module.spoolPath, "r");
  } catch {
    throw subjectUnreadable();
  }
  let carry = "";
  let reference = null;
  try {
    const buffer = Buffer.alloc(COPY_BUFFER_BYTES);
    for (;;) {
      const read = readSync(descriptor, buffer, 0, buffer.length, null);
      if (read === 0) break;
      const text = carry + buffer.subarray(0, read).toString("latin1");
      const expression =
        /(?:\/\/[#@]\s*sourceMappingURL=([^\s]+)|\/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*\/)/gu;
      for (const match of text.matchAll(expression)) {
        reference = match[1] ?? match[2];
      }
      carry = text.slice(-SOURCE_MAP_REFERENCE_BYTES);
    }
  } catch {
    throw subjectUnreadable();
  } finally {
    closeSync(descriptor);
  }
  if (reference === null || reference.startsWith("data:")) return null;
  if (
    reference.length > 4_096 ||
    !/^[!-~]+$/u.test(reference) ||
    reference.includes("?") ||
    reference.includes("#") ||
    reference.includes("\\") ||
    path.isAbsolute(reference)
  ) {
    throw subjectUnsupported();
  }
  let decoded;
  try {
    decoded = decodeURIComponent(reference);
  } catch {
    throw subjectUnsupported();
  }
  if (
    decoded.length === 0 ||
    decoded.includes("\u0000") ||
    decoded.includes("\\") ||
    path.isAbsolute(decoded)
  ) {
    throw subjectUnsupported();
  }
  return decoded;
}

export function digestName(digest) {
  return digest.replace("sha256:", "");
}

export function compareText(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

export function subjectUnreadable() {
  return new ManagedError(
    "INCOMPLETE_CANDIDATE",
    "The running Node.js subject is not completely readable.",
  );
}

export function subjectChanging() {
  return new ManagedError(
    "INCOMPLETE_CANDIDATE",
    "The running Node.js subject changed during local packaging.",
  );
}

export function subjectUnbounded() {
  return new ManagedError(
    "UPLOAD_LIMIT_EXCEEDED",
    "The running Node.js subject exceeds a Backend v1 bound.",
  );
}

export function subjectUnsupported() {
  return new ManagedError(
    "UNSUPPORTED",
    "The running Node.js subject has an unsupported file or launch identity.",
  );
}
