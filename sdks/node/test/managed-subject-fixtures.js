// Focused filesystem fixtures for Node.js subject-closure tests.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import * as fixtures from "./managed-fixtures.js";
import {
  FrozenManagedCaptureClosure,
  PreparedManagedCandidate,
} from "../src/managed-candidate.js";
import { canonicalDigest } from "../src/managed-protocol.js";

export function subjectFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-closure-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.mkdirSync(path.join(root, "src"), { recursive: true });
  fs.mkdirSync(path.join(root, "node_modules", "example"), {
    recursive: true,
  });
  fs.writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify({ name: "captured-app", type: "module", version: "1.0.0" }),
  );
  fs.writeFileSync(
    path.join(root, "src", "main.mjs"),
    'import "example";\n//# sourceMappingURL=main.mjs.map\n',
  );
  fs.writeFileSync(
    path.join(root, "src", "main.mjs.map"),
    JSON.stringify({ mappings: "AAAA", names: [], sources: ["main.ts"], version: 3 }),
  );
  fs.writeFileSync(path.join(root, "src", "settings.json"), '{"mode":"test"}\n');
  fs.writeFileSync(path.join(root, "src", "empty.txt"), "");
  fs.writeFileSync(
    path.join(root, "src", "empty-map.js"),
    "//# sourceMappingURL=empty-map.js.map\n",
  );
  fs.writeFileSync(path.join(root, "src", "empty-map.js.map"), "");
  fs.writeFileSync(
    path.join(root, "node_modules", "example", "empty-dependency.bin"),
    "",
  );
  fs.writeFileSync(
    path.join(root, "node_modules", "example", "package.json"),
    JSON.stringify({ main: "index.js", name: "example", version: "2.0.0" }),
  );
  fs.writeFileSync(
    path.join(root, "node_modules", "example", "index.js"),
    'export default 1;\n//# sourceMappingURL=index.js.map\n',
  );
  fs.writeFileSync(
    path.join(root, "node_modules", "example", "index.js.map"),
    JSON.stringify({ mappings: "AAAA", names: [], sources: ["index.ts"], version: 3 }),
  );
  return { entry: path.join(root, "src", "main.mjs"), root };
}

export function runtimeEvidence(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-runtime-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const executablePath = path.join(root, "node");
  const emptyLibraryPath = path.join(root, "libempty.so");
  fs.writeFileSync(executablePath, "node runtime fixture\n", { mode: 0o755 });
  fs.writeFileSync(emptyLibraryPath, "");
  const sharedObjectPaths = [emptyLibraryPath];
  if (process.platform === "linux") {
    const loaderPath = path.join(root, "ld-linux-fixture.so.1");
    fs.writeFileSync(loaderPath, "loader fixture\n", { mode: 0o755 });
    sharedObjectPaths.push(loaderPath);
  }
  return { executablePath, sharedObjectPaths };
}

export function preparedForSubject(subject) {
  const world = fixtures.emptyWorld();
  const deployment = fixtures.boundDeployment(subject);
  const candidate = fixtures.capturedCandidate(
    deployment,
    canonicalDigest(world),
  );
  return PreparedManagedCandidate.prepareComplete(
    candidate,
    subject,
    new FrozenManagedCaptureClosure({
      artifacts: [],
      completion: "return",
      world: structuredClone(world),
    }),
  );
}

export function packagedRuntime(subject) {
  const runtime = subject.manifest.objects.find(
    (entry) => entry.kind === "runtime",
  );
  if (runtime === undefined) {
    throw new Error("The subject fixture has no Node runtime object.");
  }
  const packaged = subject.objects.find(
    (entry) => entry.digest === runtime.digest,
  );
  if (packaged === undefined) {
    throw new Error("The subject fixture has no packaged Node runtime bytes.");
  }
  return packaged;
}
