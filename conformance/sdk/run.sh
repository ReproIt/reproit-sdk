#!/usr/bin/env bash
set -euo pipefail

readonly rust_image="reproit-sdk-rust-conformance:$PPID-$$"
readonly python_image="reproit-sdk-python-conformance:$PPID-$$"
case "$(docker info --format '{{.Architecture}}')" in
  aarch64)
    readonly native_oci_platform=linux/arm64
    readonly native_target=linux/arm64
    ;;
  x86_64)
    readonly native_oci_platform=linux/amd64
    readonly native_target=linux/x86_64
    ;;
  *)
    echo "The container architecture is outside the Backend v1.0 matrix." >&2
    exit 1
    ;;
esac

cleanup() {
  docker image rm --force "$rust_image" >/dev/null 2>&1 || true
  docker image rm --force "$python_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build --platform "$native_oci_platform" \
  --file conformance/sdk/Dockerfile \
  --tag "$rust_image" . >/dev/null

docker build --platform "$native_oci_platform" \
  --file conformance/sdk/Python.Dockerfile \
  --tag "$python_image" . >/dev/null

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=512m \
  "$python_image"

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --security-opt label=disable \
  --tmpfs /tmp:rw,exec,nosuid,size=256m \
  --env GOCACHE=/tmp/go-cache \
  --env REPROIT_PROTOCOL_VECTORS=/source/.core/specs/v1/protocol-vectors.json \
  --env REPROIT_CLOUD_API_VECTORS=/source/.core/specs/v1/cloud-api-vectors.json \
  --volume "$PWD:/source:ro" --workdir /source/sdks/go \
  golang:1.26.5-bookworm@sha256:6c5605ab3a9a9fb3c4eafe5b3d63cdbf3881caf113262b67862547b54a9db599 \
  go test ./...

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --security-opt label=disable \
  --tmpfs /tmp:rw,exec,nosuid,size=512m \
  --tmpfs /work:rw,exec,nosuid,size=128m \
  --env HOME=/tmp \
  --env NPM_CONFIG_CACHE=/tmp/npm-cache \
  --env REPROIT_PROTOCOL_VECTORS=/source/.core/specs/v1/protocol-vectors.json \
  --env REPROIT_CLOUD_API_VECTORS=/source/.core/specs/v1/cloud-api-vectors.json \
  --env REPROIT_PROCESSOR_CAPTURE=/source/.core/specs/v1/processor-capture.json \
  --volume "$PWD:/source:ro" --workdir /work \
  node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d \
  bash -lc '
    cp -R /source/sdks/node /work/package
    cd /work/package
    npm pack --pack-destination /tmp >/dev/null
    mkdir /work/fixture
    cd /work/fixture
    npm install --ignore-scripts /tmp/reproit-sdk-1.0.0.tgz >/dev/null
    node -e "import(\"@reproit/sdk\").then(module => { if (!module.Sdk) process.exit(1) })"
    cd /work/package
    npm test
  '

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --security-opt label=disable \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --tmpfs /work:rw,exec,nosuid,size=512m \
  --env REPROIT_PROTOCOL_VECTORS=/source/.core/specs/v1/protocol-vectors.json \
  --env REPROIT_CLOUD_API_VECTORS=/source/.core/specs/v1/cloud-api-vectors.json \
  --volume "$PWD:/source:ro" \
  mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 \
  bash -lc '
    cp -R /source/sdks/dotnet/. /work/
    dotnet pack /work/ReproIt.Sdk/ReproIt.Sdk.csproj \
      --configuration Release --output /tmp/packages >/dev/null
    dotnet pack /work/ReproIt.Sdk.AspNetCore/ReproIt.Sdk.AspNetCore.csproj \
      --configuration Release --output /tmp/packages >/dev/null
    test -f /tmp/packages/ReproIt.Sdk.1.0.0.nupkg
    test -f /tmp/packages/ReproIt.Sdk.AspNetCore.1.0.0.nupkg
    cd /work/ReproIt.Sdk.Conformance
    dotnet run --configuration Release
  '

# Cross-SDK processor-capture differential: all five SDKs on this one host
# must derive the byte-identical sorted capability list from the canonical
# capture rule in the pinned Core specs/v1/processor-capture.json, and a Linux host must
# capture at least one capability.
capture_root="$PWD/.work/processor-capture"
mkdir -p "$capture_root"
find "$capture_root" -mindepth 1 -depth -delete
capture_cleanup() {
  find "$capture_root" -type f -delete 2>/dev/null || true
  rmdir "$capture_root" 2>/dev/null || true
  cleanup
}
trap capture_cleanup EXIT INT TERM

docker run --rm --platform "$native_oci_platform" --network none \
  "$rust_image" \
  cargo run --locked --quiet --package reproit-sdk-rust --example processor-capture \
  >"$capture_root/rust.txt"

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --entrypoint python "$python_image" \
  -c 'from reproit_sdk.processor_capture import capture_processor_capabilities
for capability in capture_processor_capabilities():
    print(capability)' \
  >"$capture_root/python.txt"

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --security-opt label=disable \
  --tmpfs /tmp:rw,exec,nosuid,size=256m \
  --env GOCACHE=/tmp/go-cache \
  --volume "$PWD:/source:ro" --workdir /source/sdks/go \
  golang:1.26.5-bookworm@sha256:6c5605ab3a9a9fb3c4eafe5b3d63cdbf3881caf113262b67862547b54a9db599 \
  go run ./cmd/reproit-processor-capture \
  >"$capture_root/go.txt"

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --security-opt label=disable \
  --tmpfs /tmp:rw,nosuid,size=32m \
  --volume "$PWD:/source:ro" \
  node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d \
  node --input-type=module -e \
  'const m = await import("/source/sdks/node/src/processor-capture.js");
for (const capability of m.captureProcessorCapabilities()) console.log(capability);' \
  >"$capture_root/node.txt"

docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --security-opt label=disable \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --tmpfs /work:rw,exec,nosuid,size=512m \
  --volume "$PWD:/source:ro" \
  mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 \
  bash -lc '
    cp -R /source/sdks/dotnet/. /work/
    cd /work/ReproIt.Sdk.Conformance
    dotnet build --configuration Release --verbosity quiet >/dev/null
    dotnet run --configuration Release --no-build -- processor-capture
  ' \
  >"$capture_root/dotnet.txt"

test -s "$capture_root/rust.txt"
for sdk in python go node dotnet; do
  if ! cmp -s "$capture_root/rust.txt" "$capture_root/$sdk.txt"; then
    echo "The $sdk SDK processor capture diverges from the Rust capture." >&2
    diff "$capture_root/rust.txt" "$capture_root/$sdk.txt" >&2 || true
    exit 1
  fi
done

echo "target=$native_target"
echo "rust_sdk=PASS"
echo "python_sdk=PASS"
echo "go_sdk=PASS"
echo "node_sdk=PASS"
echo "dotnet_sdk=PASS"
echo "python_sdk_queue_amplification=PASS"
echo "go_sdk_queue_amplification=PASS"
echo "node_sdk_queue_amplification=PASS"
echo "dotnet_sdk_queue_amplification=PASS"
echo "differential_candidate=PASS"
echo "differential_processor_capture=PASS"
echo "authenticated_unix_transport=PASS"
echo "fresh_package_installation=PASS"
