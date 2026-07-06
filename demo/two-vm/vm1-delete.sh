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

if [[ ! -f "$RUN_DIR/credentials.env" ]]; then
  die "Missing $RUN_DIR/credentials.env — run ./vm1-start.sh first"
fi
# shellcheck disable=SC1090
source "$RUN_DIR/credentials.env"

export JWKS_URL="${JWKS_URL:-http://${VM1_IP}:7200/.well-known/jwks.json}"
if ! refresh_customer_jwt "$VM1_IP" "$TENANT_ID" "$RUN_DIR" "$JWKS_URL"; then
  substep "Could not refresh JWT from mock-idp /token — using $RUN_DIR/credentials.env"
  # shellcheck disable=SC1090
  source "$RUN_DIR/credentials.env"
fi

NONCE="$(openssl rand -hex 16)"
echo "$NONCE" >"$RUN_DIR/last-nonce"
CUSTOMER_SIG_B64="$(echo -n "$CUSTOMER_JWT" | base64 -w0 2>/dev/null || echo -n "$CUSTOMER_JWT" | base64)"

step "VM1 — trigger federated deletion"
substep "tenant=$TENANT_ID"
substep "fresh nonce=$NONCE (each delete needs a new nonce)"
substep "POST http://${VM1_IP}:7003/destructions"

RESP="$(post_coordinator_destruction "http://${VM1_IP}:7003/destructions" "$TENANT_ID" "$CUSTOMER_SIG_B64" "$NONCE")"

echo "$RESP" | (command -v jq >/dev/null && jq . || cat)

DESTRUCTION_ID="$(echo "$RESP" | (command -v jq >/dev/null && jq -r '.destruction_id' || python3 -c 'import json,sys; print(json.load(sys.stdin)["destruction_id"])' 2>/dev/null || true))"
if [[ -z "$DESTRUCTION_ID" || "$DESTRUCTION_ID" == "null" ]]; then
  die "Could not parse destruction_id from response"
fi
echo "$DESTRUCTION_ID" >"$RUN_DIR/last-destruction.id"

step "Waiting for quorum (up to 60s) ..."
AGG_URL="http://${VM1_IP}:7004"
for i in $(seq 1 30); do
  if curl -fsS "${AGG_URL}/destructions/${DESTRUCTION_ID}/proof" -o "$RUN_DIR/last-proof.json" 2>/dev/null; then
    substep "Proof ready → $RUN_DIR/last-proof.json"
    save_destruction_receipts "$AGG_URL" "$DESTRUCTION_ID" "$RUN_DIR/receipts"
    break
  fi
  sleep 2
done

step "Session status"
curl -fsS "http://${VM1_IP}:7003/destructions/${DESTRUCTION_ID}" | (command -v jq >/dev/null && jq . || cat)

if [[ -f "$RUN_DIR/last-proof.json" ]]; then
  step "Unified proof"
  cat "$RUN_DIR/last-proof.json" | (command -v jq >/dev/null && jq . || cat)
  echo ""
  substep "Verify with:  ./vm1-verify.sh"
  echo "  (or from repo root: go run ./cmd/sealed-verify-deletion/main.go ...)"
fi
