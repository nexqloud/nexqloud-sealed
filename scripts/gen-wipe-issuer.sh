#!/usr/bin/env bash
# Generate a wipe-issuer ed25519 seed + pubkey for WIPE_ISSUER_PRIVKEY /
# sealed-wipe-issuers allowlist entries.
set -euo pipefail
cd "$(dirname "$0")/.."
go run ./scripts/gen-wipe-issuer.go
