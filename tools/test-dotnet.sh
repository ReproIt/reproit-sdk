#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
cd "$repository_root"

if command -v dotnet >/dev/null 2>&1; then
  exec dotnet run --project sdks/dotnet/ReproIt.Sdk.Conformance
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "The .NET SDK check requires .NET 10 or Docker." >&2
  exit 1
fi

case "$(docker info --format '{{.Architecture}}')" in
  aarch64)
    readonly native_oci_platform=linux/arm64
    ;;
  x86_64)
    readonly native_oci_platform=linux/amd64
    ;;
  *)
    echo "The container architecture is outside the Backend v1.0 matrix." >&2
    exit 1
    ;;
esac

exec docker run --rm --platform "$native_oci_platform" --network none --read-only \
  --security-opt label=disable \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --tmpfs /work:rw,exec,nosuid,size=512m \
  --env DOTNET_CLI_HOME=/work/dotnet \
  --env REPROIT_PROTOCOL_VECTORS=/source/.core/specs/v1/protocol-vectors.json \
  --env REPROIT_CLOUD_API_VECTORS=/source/.core/specs/v1/cloud-api-vectors.json \
  --volume "$repository_root:/source:ro" \
  mcr.microsoft.com/dotnet/sdk:10.0@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0 \
  bash -lc '
    cp -R /source/sdks/dotnet/. /work/
    cd /work/ReproIt.Sdk.Conformance
    dotnet run --configuration Release
  '
