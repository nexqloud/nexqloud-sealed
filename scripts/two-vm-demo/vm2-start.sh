#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/vm2.env}"
load_env "$ENV_FILE"

REPO_ROOT="${REPO_ROOT:-$(default_repo_root)}"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-destruction-demo-vm2}"
TENANT_ID="${TENANT_ID:-acme}"

require_var VM1_IP
require_var VM2_IP
require_var SEED_HEX

export JWKS_URL="http://${VM1_IP}:7200/.well-known/jwks.json"
export REGISTRY_URL="http://${VM1_IP}:7001"

# Default coordinator pubkey from same fixed key as vm1.env.example
COORDINATOR_KEY_HEX="${COORDINATOR_KEY_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
COORDINATOR_PUB_HEX="${COORDINATOR_PUB_HEX:-$(coordinator_pubkey_hex "$COORDINATOR_KEY_HEX")}"

ensure_run_dir

step "VM2 destruction demo — start"
substep "REPO_ROOT=$REPO_ROOT"
substep "RUN_DIR=$RUN_DIR"
substep "VM1_IP=$VM1_IP  (registry, aggregator, IdP)"
substep "VM2_IP=$VM2_IP  (operator B listens here)"
substep "Coordinator pubkey: ${COORDINATOR_PUB_HEX:0:16}..."

step "Step 1/3 — Check registry reachable on VM1"
if ! wait_http "$REGISTRY_URL/records/${TENANT_ID}" 10; then
  die "Cannot reach $REGISTRY_URL — start VM1 (./vm1-start.sh) first"
fi
substep "Registry is reachable"

step "Step 2/3 — Bootstrap operator-b wrap (VM2 chip secret)"
WRAP_OK=false
if curl -fsS "$REGISTRY_URL/records/${TENANT_ID}" | grep -q operator-b; then
  substep "operator-b wrap already in registry — skipping bootstrap"
  WRAP_OK=true
fi
if [[ "$WRAP_OK" != true ]]; then
  substep "Posting operator-b wrap with shared seed ..."
  (
    cd "$REPO_ROOT"
    go run ./cmd/bootstrap/main.go \
      -registry "$REGISTRY_URL" \
      -operators operator-b \
      -seed-hex "$SEED_HEX"
  ) | tee "$RUN_DIR/logs/bootstrap.log"
fi
curl -fsS "$REGISTRY_URL/records/${TENANT_ID}" | (command -v jq >/dev/null && jq '.wraps | keys' || cat)

step "Step 3/3 — Operator B TEE (:7102)"
start_service operator-b go run ./cmd/operator-tee/main.go \
  -operator-id operator-b \
  -addr :7102 \
  -registry "$REGISTRY_URL" \
  -jwks "$JWKS_URL" \
  -coordinator-pub-hex "$COORDINATOR_PUB_HEX" \
  -state-dir "$RUN_DIR/state/operator-b"

step "VM2 operator B is up"
echo ""
echo "  Operator B:  http://${VM2_IP}:7102"
echo "  Health:      curl http://${VM2_IP}:7102/healthz"
echo ""
echo "  On VM1 run:  ./vm1-delete.sh"
echo ""
echo "  Stop VM2:    ./vm2-stop.sh"
echo "  Status:      ./vm2-status.sh"
echo "  Logs:        $RUN_DIR/logs/"
echo ""
