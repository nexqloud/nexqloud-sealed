#!/usr/bin/env bash
# Print the gpu.DefaultPolicy() hash for the given NEXQLOUD_MODEL_ID.
#
# Usage:
#   NEXQLOUD_MODEL_ID=qwen-0.5b ./scripts/gpu-policy-hash.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

: "${NEXQLOUD_MODEL_ID:?set NEXQLOUD_MODEL_ID}"

exec go run ./scripts/gpu-policy-hash.go
