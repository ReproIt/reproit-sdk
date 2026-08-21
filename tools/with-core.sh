#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  echo "Usage: ./tools/with-core.sh COMMAND [ARGUMENT ...]" >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
readonly pin_path="$repository_root/core-pin.json"
readonly core_root="$repository_root/.core"

IFS=$'\t' read -r core_repository core_revision < <(
  python3 - "$pin_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    pin = json.load(source)
if pin.get("format") != "reproit.core-pin.v1":
    raise SystemExit("core-pin.json has an unsupported format")
print(f'{pin["repository"]}\t{pin["revision"]}')
PY
)
readonly core_repository core_revision

if [[ -e "$core_root" && ! -d "$core_root/.git" ]]; then
  echo "The .core path exists but is not a Repro It Core checkout." >&2
  exit 1
fi

if [[ ! -d "$core_root/.git" ]]; then
  git clone --filter=blob:none --no-checkout "$core_repository" "$core_root"
fi

if [[ "$(git -C "$core_root" remote get-url origin)" != "$core_repository" ]]; then
  echo "The .core checkout has the wrong origin." >&2
  exit 1
fi

git -C "$core_root" fetch --depth 1 origin "$core_revision"
git -C "$core_root" checkout --detach --force "$core_revision" >/dev/null

if [[ "$(git -C "$core_root" rev-parse HEAD)" != "$core_revision" ]]; then
  echo "The .core checkout does not match core-pin.json." >&2
  exit 1
fi

export REPROIT_PROTOCOL_VECTORS="$core_root/specs/v1/protocol-vectors.json"
export REPROIT_CLOUD_API_VECTORS="$core_root/specs/v1/cloud-api-vectors.json"
export REPROIT_PROCESSOR_CAPTURE="$core_root/specs/v1/processor-capture.json"

cd "$repository_root"
exec "$@"
