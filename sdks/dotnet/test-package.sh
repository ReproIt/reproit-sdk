#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd -- "$script_dir/../.." && pwd)"
normalizer="$script_dir/tools/normalize_nuget.py"
fixture="$script_dir/tests/package-consumer/ReproIt.ManagedConsumer.csproj"
dotnet_command="${DOTNET_COMMAND:-dotnet}"
package_framework="${REPROIT_DOTNET_PACKAGE_FRAMEWORK:-net10.0}"
msbuild_args=(
  --property:ContinuousIntegrationBuild=true
  --property:DebugType=embedded
)
if [[ -n "${REPROIT_DOTNET_COMPAT_VERSION:-}" ]]; then
  msbuild_args+=(
    --property:TargetFrameworkIdentifier=.NETCoreApp
    "--property:TargetFrameworkVersion=$REPROIT_DOTNET_COMPAT_VERSION"
  )
fi
package_a="$(mktemp -d)"
package_b="$(mktemp -d)"
package_cache="$(mktemp -d)"
empty_feed="$(mktemp -d)"
fixture_artifacts="$(mktemp -d)"

cleanup() {
  rm -rf -- "$package_a" "$package_b" "$package_cache" "$empty_feed" \
    "$fixture_artifacts"
}
trap cleanup EXIT

pack_set() {
  local destination="$1"
  local build_artifacts="$destination/build"
  local build_cache="$destination/cache"
  local build_path_map="$workspace=/source%2C$build_artifacts=/build"
  mkdir -- "$build_artifacts" "$build_cache"
  NUGET_PACKAGES="$build_cache" "$dotnet_command" restore \
    "$script_dir/ReproIt.Sdk/ReproIt.Sdk.csproj" \
    --force \
    --no-cache \
    --source "$empty_feed" \
    --artifacts-path "$build_artifacts" \
    "--property:PathMap=$build_path_map" \
    "${msbuild_args[@]}"
  NUGET_PACKAGES="$build_cache" SOURCE_DATE_EPOCH=315532800 "$dotnet_command" pack \
    "$script_dir/ReproIt.Sdk/ReproIt.Sdk.csproj" \
    --configuration Release \
    --no-restore \
    --artifacts-path "$build_artifacts" \
    --output "$destination" \
    "--property:PathMap=$build_path_map" \
    "${msbuild_args[@]}"
  rm -rf -- "$build_artifacts" "$build_cache"
  for package in "$destination"/*.nupkg; do
    python3 "$normalizer" "$package"
  done
}

pack_set "$package_a"
pack_set "$package_b"

for name in ReproIt.Sdk.1.0.0.nupkg; do
  if ! cmp --silent "$package_a/$name" "$package_b/$name"; then
    echo "The .NET package set is not deterministic." >&2
    exit 1
  fi
done

python3 - "$package_a" "$package_framework" <<'PY'
import hashlib
import sys
import zipfile
from pathlib import Path

package_dir = Path(sys.argv[1])
package_framework = sys.argv[2]
expected = {
    "ReproIt.Sdk.1.0.0.nupkg": {
        "README.md",
        f"lib/{package_framework}/ReproIt.Sdk.dll",
        f"lib/{package_framework}/ReproIt.Sdk.xml",
    },
}
for name, required in expected.items():
    package = package_dir / name
    with zipfile.ZipFile(package) as archive:
        missing = required.difference(archive.namelist())
    if missing:
        raise SystemExit(f"The .NET package is missing required files: {sorted(missing)}")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    print(f"{name}_sha256={digest}")
PY

NUGET_PACKAGES="$package_cache" "$dotnet_command" restore "$fixture" \
  --force \
  --no-cache \
  --property:RestoreSources="$package_a" \
  --property:PublishSingleFile=false \
  --property:UseAppHost=false \
  --artifacts-path "$fixture_artifacts" \
  "--property:PathMap=$workspace=/source%2C$fixture_artifacts=/build" \
  "${msbuild_args[@]}"
NUGET_PACKAGES="$package_cache" "$dotnet_command" build "$fixture" \
  --configuration Release \
  --no-restore \
  --property:PublishSingleFile=false \
  --property:UseAppHost=false \
  --artifacts-path "$fixture_artifacts" \
  "--property:PathMap=$workspace=/source%2C$fixture_artifacts=/build" \
  "${msbuild_args[@]}"

echo "dotnet_package=PASS"
