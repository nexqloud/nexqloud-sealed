#!/usr/bin/env bash
# Generate a model-attest issuer ed25519 seed + pubkey for
# MODEL_ATTEST_ISSUER_PRIVKEY / sealed-model-attest-issuers allowlist entries.
set -euo pipefail
cd "$(dirname "$0")/.."
go run ./scripts/gen-model-attest-issuer.go
