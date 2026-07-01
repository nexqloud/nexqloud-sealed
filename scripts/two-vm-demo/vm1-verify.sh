#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/vm1.env}"
load_env "$ENV_FILE"

REPO_ROOT="${REPO_ROOT:-$(default_repo_root)}"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-destruction-demo-vm1}"
TENANT_ID="${TENANT_ID:-acme}"

require_var VM1_IP

PROOF="${PROOF:-$RUN_DIR/last-proof.json}"
RECEIPTS="${RECEIPTS:-$RUN_DIR/receipts}"

if [[ ! -f "$PROOF" ]]; then
  die "Missing proof at $PROOF — run ./vm1-delete.sh first"
fi
if [[ ! -d "$RECEIPTS" ]] || [[ -z "$(find "$RECEIPTS" -maxdepth 1 -name '*.json' -print -quit 2>/dev/null)" ]]; then
  die "Missing receipts in $RECEIPTS — re-run ./vm1-delete.sh (after syncing latest scripts)"
fi

step "Verify federated deletion proof"
substep "proof=$PROOF"
substep "receipts=$RECEIPTS"
substep "registry=http://${VM1_IP}:7001"

NONCE=""
if [[ -f "$RUN_DIR/last-nonce" ]]; then
  NONCE="$(cat "$RUN_DIR/last-nonce")"
fi

ARGS=(
  -registry "http://${VM1_IP}:7001"
  -tenant "$TENANT_ID"
  -proof "$PROOF"
  -receipts "$RECEIPTS"
)
if [[ -n "$NONCE" ]]; then
  ARGS+=(-challenge "$NONCE")
fi

(cd "$REPO_ROOT" && go run ./cmd/sealed-verify-deletion/main.go "${ARGS[@]}")
