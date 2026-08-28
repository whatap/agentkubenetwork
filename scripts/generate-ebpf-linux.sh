#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "generate-ebpf-linux.sh must run on Linux" >&2
  exit 1
fi

command -v clang >/dev/null
command -v go >/dev/null

go generate ./internal/collector
