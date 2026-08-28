#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
cd "$repository_root"

exec ./tools/with-core.sh bash -c '
  set -euo pipefail
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --all-targets --locked
  uv run --project sdks/python --frozen pytest sdks/python/tests
  (cd sdks/go && go test ./... && go vet ./...)
  (cd sdks/node && npm test)
  ./tools/test-dotnet.sh
'
