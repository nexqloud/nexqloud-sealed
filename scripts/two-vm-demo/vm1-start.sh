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
require_var VM2_IP
require_var COORDINATOR_KEY_HEX

export JWKS_URL="http://${VM1_IP}:7200/.well-known/jwks.json"
export AGGREGATOR_URL="http://${VM1_IP}:7004"
export REGISTRY_LOCAL="http://127.0.0.1:7001"
export COORDINATOR_PUB_HEX
COORDINATOR_PUB_HEX="$(coordinator_pubkey_hex "$COORDINATOR_KEY_HEX")"

ensure_run_dir

step "VM1 destruction demo — start"
substep "REPO_ROOT=$REPO_ROOT"
substep "RUN_DIR=$RUN_DIR"
substep "VM1_IP=$VM1_IP  VM2_IP=$VM2_IP"
substep "Coordinator pubkey: ${COORDINATOR_PUB_HEX:0:16}..."

ensure_demo_bin_dir
substep "DEMO_BIN_DIR=$DEMO_BIN_DIR"

step "Step 1/6 — Registry (:7001)"
start_service_or_die registry "$(build_demo_bin registry ./cmd/registry/main.go)"
for _ in $(seq 1 15); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$REGISTRY_LOCAL/records/${TENANT_ID}" || echo 000)"
  if [[ "$code" == "200" || "$code" == "404" ]]; then
    substep "Registry HTTP ready (status $code)"
    break
  fi
  sleep 1
done

step "Step 2/6 — Mock IdP (:7200)"
start_service_or_die mock-idp "$(build_demo_bin mock-idp ./cmd/mock-idp/main.go)" \
  -addr :7200 -tenant "$TENANT_ID" -key-file "$RUN_DIR/state/mock-idp.pem"
sleep 2
if ! refresh_customer_jwt "$VM1_IP" "$TENANT_ID" "$RUN_DIR" "$JWKS_URL"; then
  MOCK_LOG="$(log_file mock-idp)"
  CUSTOMER_JWT="$(grep '^CUSTOMER_JWT=' "$MOCK_LOG" | tail -1 | cut -d= -f2- || true)"
  if [[ -z "$CUSTOMER_JWT" ]]; then
    die "Could not read CUSTOMER_JWT from mock-idp /token or $MOCK_LOG"
  fi
  cat >"$RUN_DIR/credentials.env" <<EOF
JWKS_URL=$JWKS_URL
CUSTOMER_JWT=$CUSTOMER_JWT
TENANT_ID=$TENANT_ID
EOF
fi
substep "Saved customer JWT to $RUN_DIR/credentials.env"
substep "JWKS_URL=$JWKS_URL"

step "Step 3/6 — Bootstrap federation (operator-a)"
if curl -fsS "$REGISTRY_LOCAL/records/${TENANT_ID}" >/dev/null 2>&1; then
  substep "Registry record for $TENANT_ID already exists — skipping bootstrap"
else
  substep "Posting operator-a wrap to registry ..."
  BOOT_LOG="$RUN_DIR/logs/bootstrap.log"
  "$(build_demo_bin bootstrap ./cmd/bootstrap/main.go)" \
    -registry "$REGISTRY_LOCAL" \
    -operators operator-a 2>&1 | tee "$BOOT_LOG"
  SEED_LINE="$(grep 'seed-hex' "$BOOT_LOG" || true)"
  if [[ -n "$SEED_LINE" ]]; then
    SEED_HEX="$(echo "$SEED_LINE" | awk '{print $NF}')"
    echo "$SEED_HEX" >"$RUN_DIR/seed.hex"
    substep "Saved seed for VM2 → $RUN_DIR/seed.hex"
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────┐"
    echo "  │ Copy this seed to VM2 vm2.env as SEED_HEX before vm2-start:  │"
    echo "  │ $SEED_HEX"
    echo "  └─────────────────────────────────────────────────────────────┘"
    echo ""
  else
    substep "Bootstrap used existing seed (no new seed-hex printed)"
  fi
fi

step "Step 4/6 — Destruction aggregator (:7004)"
start_service_or_die aggregator "$(build_demo_bin destruction-aggregator ./cmd/destruction-aggregator/main.go)" -addr :7004

step "Step 5/6 — Destruction coordinator (:7003)"
OPERATORS="operator-a=http://${VM1_IP}:7101,operator-b=http://${VM2_IP}:7102"
substep "Operator dispatch map: $OPERATORS"
substep "Aggregator URL (reachable from VM2): $AGGREGATOR_URL"
start_service_or_die coordinator "$(build_demo_bin destruction-coordinator ./cmd/destruction-coordinator/main.go)" \
  -addr :7003 \
  -registry "$REGISTRY_LOCAL" \
  -aggregator "$AGGREGATOR_URL" \
  -jwks "$JWKS_URL" \
  -coordinator-key-hex "$COORDINATOR_KEY_HEX" \
  -operators "$OPERATORS"

step "Step 6/6 — Operator A TEE (:7101)"
start_service_or_die operator-a "$(build_demo_bin operator-tee ./cmd/operator-tee/main.go)" \
  -operator-id operator-a \
  -addr :7101 \
  -registry "$REGISTRY_LOCAL" \
  -jwks "$JWKS_URL" \
  -coordinator-pub-hex "$COORDINATOR_PUB_HEX" \
  -state-dir "$RUN_DIR/state/operator-a"

step "VM1 services are up"
echo ""
echo "  Registry:     http://${VM1_IP}:7001"
echo "  Mock IdP:     $JWKS_URL"
echo "  Coordinator:  http://${VM1_IP}:7003"
echo "  Aggregator:   $AGGREGATOR_URL"
echo "  Operator A:   http://${VM1_IP}:7101"
echo ""
echo "  Coordinator pubkey (for VM2): $COORDINATOR_PUB_HEX"
if [[ -f "$RUN_DIR/seed.hex" ]]; then
  echo "  Seed for VM2: $(cat "$RUN_DIR/seed.hex")"
fi
echo ""
echo "  Next on VM2:  ./vm2-start.sh"
echo "  Then on VM1:  ./vm1-delete.sh"
echo ""
echo "  Stop VM1:     ./vm1-stop.sh"
echo "  Status:       ./vm1-status.sh"
echo "  Logs:         $RUN_DIR/logs/"
echo ""
