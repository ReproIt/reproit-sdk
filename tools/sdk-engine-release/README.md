# SDK engine release builder

This tool builds one shared SDK engine on its matching native host. It runs one
Cargo release build. It then creates one digest-named bundle under
`target/sdk-engine-releases/`.

Run the tool on each native host:

```text
python3 tools/sdk-engine-release/release.py --target linux-arm64
python3 tools/sdk-engine-release/release.py --target linux-x86_64
python3 tools/sdk-engine-release/release.py --target macos-arm64
python3 tools/sdk-engine-release/release.py --target windows-x86_64
```

Use the approved internal transfer route to collect the four bundles. Do not
put credentials or host connection details in this repository.

To package a prebuilt Node loader, use `--node-loader` with a file named
`reproit-sdk-engine-loader.node`. The tool does not build the loader.

Each bundle contains `sdk-engine-artifacts.json`. The manifest contains only
the target, ABI contract digest, artifact basenames, roles, sizes, and content
digests. A loader must verify the selected artifact digest before it loads the
file.

The builder rejects a cross-target host, an unknown target, an unexpected
engine filename, an unexpected Node loader filename, an empty artifact, an
oversized artifact, or an existing bundle that does not match its digest.
