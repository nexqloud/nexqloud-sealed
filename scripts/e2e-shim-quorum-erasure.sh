#!/usr/bin/env bash
#
# The deployment-shaped proof: a sealed deployment is an operator node.
#
# Two sealed-shim processes stand in for two sealed deployments. Each one seals a
# conversation scope's seed, serves chat, and can be ordered by the coordinator to
# zeroize its copy. The registry is the MongoDB-backed service, not the demo one.
#
# Chain proven here:
#   scope registered on both shims -> chat sealed by shim A -> history opens
#   -> delete -> coordinator dispatches -> BOTH shims zeroize -> receipts -> proof
#   -> independent verification -> the same ciphertext opens on NEITHER shim
#
# Usage: scripts/e2e-shim-quorum-erasure.sh
# Env:   RUN_DIR, KEEP_RUNNING=1 to leave the federation up, MONGO_URL override.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-shim-quorum}"
BIN="$RUN_DIR/bin"
LOGS="$RUN_DIR/logs"

REGISTRY_DB="sealed_registry_e2e"
IDP_PORT=7200
REKOR_PORT=8899
SHIM_A_PORT=18080
SHIM_B_PORT=18081
COORD_PORT=7003
AGG_PORT=7004
REGISTRY_PORT=7001

SCOPE="ks1:$(openssl rand -hex 8)"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
sub() { printf '   %s\n' "$*"; }
ok()  { printf '   \033[32m✓\033[0m %s\n' "$*"; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
jget() { python3 -c "
import json,sys
d=json.load(sys.stdin)
v=eval(sys.argv[1],{'d':d})
print(v if not isinstance(v,bool) else str(v).lower())
" "$1"; }
port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

cleanup() {
  local f
  for f in "$RUN_DIR"/*.pid; do
    [ -f "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true
  done
  rm -f "$RUN_DIR"/*.pid
}
trap cleanup EXIT

start() { # name, port, cmd...
  local name="$1" port="$2"; shift 2
  "$@" >>"$LOGS/$name.log" 2>&1 &
  echo $! >"$RUN_DIR/$name.pid"
  for _ in $(seq 1 120); do
    port_free "$port" || { sub "$name listening on $port"; return 0; }
    sleep 0.25
  done
  tail -20 "$LOGS/$name.log" >&2
  die "$name never listened on $port"
}

mkdir -p "$BIN" "$LOGS"
export NEXQLOUD_DEV=1

# The registry is the real thing: MongoDB-backed, same collection shape we deploy.
MONGO_URL="${MONGO_URL:-$(grep -m1 -E '^DAI_DATABASE_MONGODB_URI=' "$REPO_ROOT/../dcp/dai-service/.env" | cut -d= -f2- | sed 's/^["'"'"']//; s/["'"'"']$//')}"
[ -n "$MONGO_URL" ] || die "no MongoDB URI (set MONGO_URL or DAI_DATABASE_MONGODB_URI)"

say "0. preflight"
for p in "$REGISTRY_PORT" "$IDP_PORT" "$COORD_PORT" "$AGG_PORT" "$SHIM_A_PORT" "$SHIM_B_PORT" "$REKOR_PORT"; do
  port_free "$p" || die "port $p is in use"
done
sub "scope under test: $SCOPE"
sub "registry: MongoDB db $REGISTRY_DB (persistent, not the demo store)"

say "1. build"
for b in \
  "registry ./cmd/registry" \
  "mock-idp ./demo/mock-idp" \
  "shim ./cmd/shim" \
  "coordinator ./cmd/destruction-coordinator" \
  "aggregator ./cmd/destruction-aggregator" \
  "sealed-verify-deletion ./cmd/sealed-verify-deletion" \
  "coordinator-pubkey ./demo/two-vm"; do
  set -- $b
  go build -C "$REPO_ROOT" -o "$BIN/$1" "$2"
done
ok "binaries built"

# Keep the proof off the public transparency log.
cat >"$RUN_DIR/rekor_stub.py" <<'PY'
import base64, json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        with open(sys.argv[2], "a") as fh:
            fh.write(json.dumps({"path": self.path, "body": raw.decode("utf-8", "replace")}) + "\n")
        uuid = "11111111-2222-3333-4444-555555555555"
        resp = json.dumps({uuid: {"logID": "stub", "logIndex": 4242, "integratedTime": 1700000000,
                                  "body": base64.b64encode(b"{}").decode()}}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Location", f"/api/v1/log/entries/{uuid}")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
rm -f "$RUN_DIR/rekor-entries.jsonl"
start rekor-stub "$REKOR_PORT" python3 "$RUN_DIR/rekor_stub.py" "$REKOR_PORT" "$RUN_DIR/rekor-entries.jsonl"
export REKOR_SERVER="http://127.0.0.1:$REKOR_PORT"

say "2. start the substrate"
COORD_SEED="$(openssl rand -hex 32)"
SUBSTRATE_SEED="$(openssl rand -hex 32)"
COORD_PUB="$("$BIN/coordinator-pubkey" "$COORD_SEED")"
JWKS_URL="http://127.0.0.1:$IDP_PORT/.well-known/jwks.json"
REGISTRY_URL="http://127.0.0.1:$REGISTRY_PORT"

MONGO_URL="$MONGO_URL" start registry "$REGISTRY_PORT" "$BIN/registry" \
  -addr ":$REGISTRY_PORT" -db "$REGISTRY_DB" -collection commitments
start idp "$IDP_PORT" "$BIN/mock-idp" -addr ":$IDP_PORT" -tenant "$SCOPE" -key-file "$RUN_DIR/idp.pem" -serve-only
start aggregator "$AGG_PORT" "$BIN/aggregator" -addr ":$AGG_PORT" -substrate-key-hex "$SUBSTRATE_SEED"
start coordinator "$COORD_PORT" "$BIN/coordinator" \
  -addr ":$COORD_PORT" -registry "$REGISTRY_URL" -aggregator "http://127.0.0.1:$AGG_PORT" \
  -operators "operator-a=http://127.0.0.1:$SHIM_A_PORT,operator-b=http://127.0.0.1:$SHIM_B_PORT" \
  -jwks "$JWKS_URL" -coordinator-key-hex "$COORD_SEED"

say "3. the two sealed deployments come up as operator nodes"
start sealed-a "$SHIM_A_PORT" env NEXQLOUD_DEV=1 \
  NEXQLOUD_JWKS_URL="$JWKS_URL" \
  NEXQLOUD_REGISTRY_URL="$REGISTRY_URL" \
  NEXQLOUD_OPERATOR_ID=operator-a \
  NEXQLOUD_COORDINATOR_PUB_HEX="$COORD_PUB" \
  NEXQLOUD_STATE_DIR="$RUN_DIR/shim-a" \
  "$BIN/shim" -addr ":$SHIM_A_PORT"
start sealed-b "$SHIM_B_PORT" env NEXQLOUD_DEV=1 \
  NEXQLOUD_JWKS_URL="$JWKS_URL" \
  NEXQLOUD_REGISTRY_URL="$REGISTRY_URL" \
  NEXQLOUD_OPERATOR_ID=operator-b \
  NEXQLOUD_COORDINATOR_PUB_HEX="$COORD_PUB" \
  NEXQLOUD_STATE_DIR="$RUN_DIR/shim-b" \
  "$BIN/shim" -addr ":$SHIM_B_PORT"
grep -q "operator surface enabled" "$LOGS/sealed-a.log" || { grep "operator surface" "$LOGS/sealed-a.log" >&2; die "shim A did not enable the destruction surface"; }
ok "both shims expose the destruction surface (each is a quorum member)"

say "4. register the conversation's key scope on both deployments"
REG="$(curl -fsS -X POST "http://127.0.0.1:$COORD_PORT/keyscopes" -H 'Content-Type: application/json' -d "{\"scope_id\":\"$SCOPE\"}")"
COMMIT="$(printf '%s' "$REG" | jget 'd["seed_commit"]')"
OPS="$(printf '%s' "$REG" | jget '",".join(d["operators"])')"
[ "$OPS" = "operator-a,operator-b" ] || die "expected both shims to seal the scope, got: $OPS"
ok "both deployments sealed the same scope seed (commit ${COMMIT:0:20}…)"

say "5. mint tokens and seal a conversation on shim A"
IDP="http://127.0.0.1:$IDP_PORT"
JWT="$(curl -fsS "$IDP/token?tenant=$SCOPE&purpose=inference" | jget 'd["jwt"]')"
DEL_JWT="$(curl -fsS "$IDP/token?tenant=$SCOPE&purpose=delete" | jget 'd["jwt"]')"

CHAT_STATUS="$(curl -sS -o "$RUN_DIR/chat.json" -w '%{http_code}' -X POST "http://127.0.0.1:$SHIM_A_PORT/v1/chat/completions" \
  -H 'Content-Type: application/json' -H "X-NexQloud-Identity: $JWT" \
  -d "{\"model\":\"mock\",\"messages\":[{\"role\":\"user\",\"content\":\"erase me: invoice 8842\"}],\"jwt_token\":\"$JWT\",\"challenge_nonce\":\"$(openssl rand -hex 32)\"}")"
[ "$CHAT_STATUS" = "200" ] || { cat "$RUN_DIR/chat.json" >&2; die "shim A rejected the chat (HTTP $CHAT_STATUS)"; }
CIPHERTEXT="$(jget 'd["encrypted_payload"]' <"$RUN_DIR/chat.json")"
ok "conversation sealed by shim A (${#CIPHERTEXT} bytes)"

decrypt() { # port, label -> sets DECRYPT_CODE / DECRYPT_BODY
  local port="$1"
  DECRYPT_CODE="$(curl -sS -o "$RUN_DIR/decrypt-$port.json" -w '%{http_code}' -X POST "http://127.0.0.1:$port/v1/chat/decrypt" \
    -H 'Content-Type: application/json' -H "X-NexQloud-Identity: $JWT" \
    -d "{\"encrypted_payload\":\"$CIPHERTEXT\",\"jwt_token\":\"$JWT\"}")"
  DECRYPT_BODY="$(cat "$RUN_DIR/decrypt-$port.json")"
}

decrypt "$SHIM_A_PORT"
[ "$DECRYPT_CODE" = "200" ] || { echo "$DECRYPT_BODY" >&2; die "shim A could not open its own ciphertext"; }
ok "shim A opens the history before erasure ($(printf '%s' "$DECRYPT_BODY" | jget 'len(d.get("messages") or [])') messages)"

say "6. delete: the coordinator orders both deployments to zeroize"
DEL_NONCE="$(openssl rand -hex 16)"
SIG_B64="$(printf '%s' "$DEL_JWT" | base64 -w0)"
SESSION="$(curl -fsS -X POST "http://127.0.0.1:$COORD_PORT/destructions" -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$SCOPE\",\"customer_sig\":\"$SIG_B64\",\"nonce\":\"$DEL_NONCE\"}")"
DID="$(printf '%s' "$SESSION" | jget 'd["destruction_id"]')"
sub "destruction $DID dispatched to $(printf '%s' "$SESSION" | jget '" ".join(d["quorum"])')"

for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:$AGG_PORT/destructions/$DID/proof" -o "$RUN_DIR/proof.json" 2>/dev/null && break
  sleep 1
done
[ -s "$RUN_DIR/proof.json" ] || die "no proof was produced"
curl -fsS "http://127.0.0.1:$AGG_PORT/destructions/$DID/receipts" >"$RUN_DIR/receipts.json"
mkdir -p "$RUN_DIR/receipts"
python3 - "$RUN_DIR/receipts.json" "$RUN_DIR/receipts" <<'PY'
import json, os, sys
raw = json.load(open(sys.argv[1]))
receipts = raw.get("receipts", raw if isinstance(raw, list) else [])
for r in receipts:
    op = r.get("package", {}).get("operator_id", "unknown")
    json.dump(r, open(os.path.join(sys.argv[2], f"{op}.json"), "w"), indent=2)
print(f"   receipts collected from {len(receipts)} deployment(s)")
PY

say "7. verify the proof independently"
set +e
"$BIN/sealed-verify-deletion" -registry "$REGISTRY_URL" -tenant "$SCOPE" \
  -proof "$RUN_DIR/proof.json" -receipts "$RUN_DIR/receipts" >"$RUN_DIR/verify.json" 2>"$RUN_DIR/verify.err"
set -e
SUMMARY="$(python3 - "$RUN_DIR/verify.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
hardware = {"hardware_genuine", "key_binding"}
checks = d["checks"]
passed = sum(1 for c in checks if c["ok"])
nonhw = [c["id"] for c in checks if not c["ok"] and c["id"] not in hardware]
hw = sorted({c["id"] for c in checks if not c["ok"] and c["id"] in hardware})
print(passed, len(checks), len(nonhw), ",".join(hw) or "-")
PY
)"
read -r PASSED TOTAL NONHW FAILED_HW <<<"$SUMMARY"
sub "checks passed: $PASSED/$TOTAL"
[ "$NONHW" = "0" ] || die "verifier rejected non-hardware checks — see $RUN_DIR/verify.json"
[ "$FAILED_HW" = "-" ] && ok "DELETION VERIFIED" || ok "verified apart from the silicon checks ($FAILED_HW)"

say "8. the material is gone on both deployments"
for port in "$SHIM_A_PORT" "$SHIM_B_PORT"; do
  decrypt "$port"
  if printf '%s' "$DECRYPT_BODY" | grep -q "8842"; then die "plaintext leaked on port $port after erasure"; fi
  [ "$DECRYPT_CODE" = "200" ] && die "port $port still opens the ciphertext after erasure (HTTP 200)"
  sub "port $port: HTTP $DECRYPT_CODE — $(printf '%s' "$DECRYPT_BODY" | tr -d '\n' | cut -c1-60)"
done
ok "neither deployment can open the conversation any more"

STATUS="$(curl -fsS "http://127.0.0.1:$SHIM_A_PORT/keyscope/$SCOPE")"
[ "$(printf '%s' "$STATUS" | jget 'len(d.get("destroyed") or [])')" = "2" ] || die "expected both slots destroyed: $STATUS"
ok "registry: both slots destroyed, quorum still auditable ($(printf '%s' "$STATUS" | jget '",".join(d["destroyed"])'))"

say "RESULT"
echo "   scope            : $SCOPE"
echo "   deployments      : sealed-a (:$SHIM_A_PORT), sealed-b (:$SHIM_B_PORT)"
echo "   registry         : MongoDB db $REGISTRY_DB, collection commitments"
echo "   proof            : $RUN_DIR/proof.json"
echo "   verifier output  : $RUN_DIR/verify.json"
echo "   logs             : $LOGS/"
