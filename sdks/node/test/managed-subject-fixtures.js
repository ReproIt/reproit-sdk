import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function subjectFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-subject-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  fs.mkdirSync(path.join(root, "src"), { recursive: true });
  fs.mkdirSync(path.join(root, "node_modules", "example"), {
    recursive: true,
  });
  fs.writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify({ name: "captured-app", type: "module", version: "1.0.0" }),
  );
  const entry = path.join(root, "src", "main.mjs");
  fs.writeFileSync(entry, "export default 1;\n");
  fs.writeFileSync(
    path.join(root, "node_modules", "example", "package.json"),
    JSON.stringify({ name: "example", version: "1.0.0" }),
  );
  return { entry, root };
}

export function runtimeEvidence(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "reproit-node-runtime-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const executablePath = path.join(root, "node");
  const libraryPath = path.join(root, "libfixture.so");
  fs.writeFileSync(executablePath, "node runtime fixture\n", { mode: 0o755 });
  fs.writeFileSync(libraryPath, "");
  const sharedObjectPaths = [libraryPath];
  if (process.platform === "linux") {
    const loaderPath = path.join(root, "ld-linux-fixture.so.1");
    fs.writeFileSync(loaderPath, "loader fixture\n", { mode: 0o755 });
    sharedObjectPaths.push(loaderPath);
  }
  return { executablePath, sharedObjectPaths };
}
