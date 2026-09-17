#!/usr/bin/env bash
#
# End-to-end proof of conversation-scoped federated cryptographic erasure.
#
# Runs a complete federation on localhost with the real binaries:
#   registry + customer IdP + operator A + operator B + coordinator + aggregator
#   + a sealed shim that seals a conversation under a per-conversation key scope.
#
# Then it erases that scope through the coordinator and proves three things:
#   1. the aggregated destruction proof verifies with sealed-verify-deletion
#   2. the registry no longer holds any operator's key material for the scope
#   3. the conversation's ciphertext can no longer be opened by the TEE
#
# Everything runs under NEXQLOUD_DEV=1 (dev chip secret, test attestation), so no
# SEV-SNP hardware is needed. The Rekor publish path is pointed at a local stub so
# no test proof is written to the public transparency log.
#
# Usage:  scripts/e2e-keyscope-erasure.sh
# Env:    RUN_DIR (default /tmp/nexqloud-keyscope-e2e), KEEP_RUNNING=1 to leave
#         the federation up for poking at.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-keyscope-e2e}"
BIN="$RUN_DIR/bin"
LOGS="$RUN_DIR/logs"

REGISTRY_URL="http://127.0.0.1:7001"
IDP_URL="http://127.0.0.1:7200"
JWKS_URL="$IDP_URL/.well-known/jwks.json"
REKOR_PORT=8899
SHIM_PORT=18080
OP_A_PORT=7101
OP_B_PORT=7102
COORD_PORT=7003
AGG_PORT=7004

SCOPE="ks1:$(openssl rand -hex 8)"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
sub() { printf '   %s\n' "$*"; }
ok()  { printf '   \033[32m✓\033[0m %s\n' "$*"; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Minimal JSON reader: jget '.field' or 'd["field"]' from stdin.
jget() { python3 -c "
import json,sys
d=json.load(sys.stdin)
v=eval(sys.argv[1],{'d':d})
print(v if not isinstance(v,bool) else str(v).lower())
" "$1"; }

cleanup() {
  local f
  for f in "$RUN_DIR"/*.pid; do
    [ -f "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true
  done
  rm -f "$RUN_DIR"/*.pid
}
if [ "${KEEP_RUNNING:-}" = "1" ]; then
  trap 'echo "(federation left running; RUN_DIR='"$RUN_DIR"')"' EXIT
else
  trap cleanup EXIT
fi

port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

wait_port() { # port, name, log
  local port="$1" name="$2" log="$3"
  for _ in $(seq 1 100); do
    if ! port_free "$port"; then return 0; fi
    sleep 0.3
  done
  tail -25 "$log" >&2 || true
  die "$name never listened on port $port"
}

start() { # name, port, cmd...
  local name="$1" port="$2"; shift 2
  "$@" >>"$LOGS/$name.log" 2>&1 &
  echo $! >"$RUN_DIR/$name.pid"
  wait_port "$port" "$name" "$LOGS/$name.log"
  sub "$name listening on $port"
}

say "0. preflight"
for p in 7001 7003 7004 "$OP_A_PORT" "$OP_B_PORT" 7200 "$SHIM_PORT" "$REKOR_PORT"; do
  port_free "$p" || die "port $p is already in use — stop that process first"
done
mkdir -p "$BIN" "$LOGS"
export NEXQLOUD_DEV=1
sub "dev mode on (no SNP hardware needed), scope = $SCOPE"

say "1. build the binaries"
for b in \
  "registry ./demo/registry" \
  "mock-idp ./demo/mock-idp" \
  "operator ./cmd/operator" \
  "coordinator ./cmd/destruction-coordinator" \
  "aggregator ./cmd/destruction-aggregator" \
  "shim ./cmd/shim" \
  "sealed-verify-deletion ./cmd/sealed-verify-deletion" \
  "coordinator-pubkey ./demo/two-vm"; do
  set -- $b
  go build -C "$REPO_ROOT" -o "$BIN/$1" "$2"
done
ok "8 binaries built"

# A local Rekor stand-in: keeps the proof off the public transparency log.
cat >"$RUN_DIR/rekor_stub.py" <<'PY'
import base64, json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        with open("/tmp/nexqloud-keyscope-e2e/rekor-entries.jsonl", "a") as fh:
            fh.write(json.dumps({"path": self.path, "body": raw.decode("utf-8", "replace")}) + "\n")
        uuid = "11111111-2222-3333-4444-555555555555"
        resp = json.dumps({uuid: {"logID": "stub", "logIndex": 4242,
                                  "integratedTime": 1700000000,
                                  "body": base64.b64encode(b"{}").decode()}}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Location", f"/api/v1/log/entries/{uuid}")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
rm -f "$RUN_DIR/rekor-entries.jsonl"
python3 "$RUN_DIR/rekor_stub.py" "$REKOR_PORT" >>"$LOGS/rekor-stub.log" 2>&1 &
echo $! >"$RUN_DIR/rekor-stub.pid"
wait_port "$REKOR_PORT" rekor-stub "$LOGS/rekor-stub.log"
export REKOR_SERVER="http://127.0.0.1:$REKOR_PORT"
sub "rekor stub on $REKOR_PORT (REKOR_SERVER=$REKOR_SERVER)"

say "2. start the federation"
COORD_SEED="$(openssl rand -hex 32)"
SUBSTRATE_SEED="$(openssl rand -hex 32)"
COORD_PUB="$("$BIN/coordinator-pubkey" "$COORD_SEED")"
sub "coordinator pubkey ${COORD_PUB:0:16}…"

start registry 7001 "$BIN/registry"
start idp 7200 "$BIN/mock-idp" -addr ":7200" -tenant "$SCOPE" -key-file "$RUN_DIR/idp.pem" -serve-only
start operator-a "$OP_A_PORT" "$BIN/operator" \
  -operator-id operator-a -addr ":$OP_A_PORT" -registry "$REGISTRY_URL" -jwks "$JWKS_URL" \
  -coordinator-pub-hex "$COORD_PUB" -state-dir "$RUN_DIR/op-a"
start operator-b "$OP_B_PORT" "$BIN/operator" \
  -operator-id operator-b -addr ":$OP_B_PORT" -registry "$REGISTRY_URL" -jwks "$JWKS_URL" \
  -coordinator-pub-hex "$COORD_PUB" -state-dir "$RUN_DIR/op-b"
start aggregator "$AGG_PORT" "$BIN/aggregator" -addr ":$AGG_PORT" -substrate-key-hex "$SUBSTRATE_SEED"
start coordinator "$COORD_PORT" "$BIN/coordinator" \
  -addr ":$COORD_PORT" -registry "$REGISTRY_URL" -aggregator "http://127.0.0.1:$AGG_PORT" \
  -operators "operator-a=http://127.0.0.1:$OP_A_PORT,operator-b=http://127.0.0.1:$OP_B_PORT" \
  -jwks "$JWKS_URL" -coordinator-key-hex "$COORD_SEED"

say "3. the conversation gets its own key scope, sealed on every operator"
REG="$(curl -fsS -X POST "http://127.0.0.1:$COORD_PORT/keyscopes" \
  -H 'Content-Type: application/json' -d "{\"scope_id\":\"$SCOPE\"}")"
COMMIT="$(printf '%s' "$REG" | jget 'd["seed_commit"]')"
OPS="$(printf '%s' "$REG" | jget '",".join(d["operators"])')"
[ "$OPS" = "operator-a,operator-b" ] || die "expected both operators to seal the scope, got: $OPS"
sub "coordinator registered the scope with: $OPS (commit ${COMMIT:0:22}...)"

# The registry record is shared, so either operator reports the whole scope: both
# slots must be live and none destroyed, or the erasure proof would be meaningless.
for op in operator-a operator-b; do
  case "$op" in
    operator-a) url="http://127.0.0.1:$OP_A_PORT/keyscope/$SCOPE" ;;
    operator-b) url="http://127.0.0.1:$OP_B_PORT/keyscope/$SCOPE" ;;
  esac
  SCOPE_STATUS="$(curl -fsS "$url")"
  [ "$(printf '%s' "$SCOPE_STATUS" | jget 'len(d.get("operators") or [])')" = "2" ] \
    || die "$op sees the wrong live slot count: $SCOPE_STATUS"
  [ "$(printf '%s' "$SCOPE_STATUS" | jget 'len(d.get("destroyed") or [])')" = "0" ] \
    || die "$op reports destroyed material before any erasure: $SCOPE_STATUS"
  [ "$(printf '%s' "$SCOPE_STATUS" | jget 'd["seed_commit"]')" = "$COMMIT" ] \
    || die "$op reports a different seed commit: $SCOPE_STATUS"
done
ok "both operators hold a sealed copy of the same seed (cross-operator continuity)"

say "4. mint the customer-authorized tokens for the scope"
# Two tokens, same tenant: the shim refuses a delete-purpose token for inference
# (identity.VerifyIdentity), and the mock IdP only drops the delete purpose for
# purpose=inference. The delete token authorizes the erasure itself.
JWT="$(curl -fsS "$IDP_URL/token?tenant=$SCOPE&purpose=inference" | jget 'd["jwt"]')"
DEL_JWT="$(curl -fsS "$IDP_URL/token?tenant=$SCOPE&purpose=delete" | jget 'd["jwt"]')"
ok "minted an inference token and a delete token for $SCOPE"

say "5. seal the conversation through the local TEE shim"
start shim "$SHIM_PORT" env \
  NEXQLOUD_DEV=1 \
  NEXQLOUD_JWKS_URL="$JWKS_URL" \
  NEXQLOUD_REGISTRY_URL="$REGISTRY_URL" \
  NEXQLOUD_OPERATOR_ID=operator-a \
  "$BIN/shim" -addr ":$SHIM_PORT"

NONCE_CTX="$(openssl rand -hex 32)"
CHAT_STATUS="$(curl -sS -o "$RUN_DIR/chat.json" -w '%{http_code}' -X POST "http://127.0.0.1:$SHIM_PORT/v1/chat/completions" \
  -H 'Content-Type: application/json' -H "X-NexQloud-Identity: $JWT" \
  -d "{\"model\":\"mock\",\"messages\":[{\"role\":\"user\",\"content\":\"delete me: ledger code 4417\"}],\"jwt_token\":\"$JWT\",\"challenge_nonce\":\"$NONCE_CTX\"}")"
if [ "$CHAT_STATUS" != "200" ]; then
  cat "$RUN_DIR/chat.json" >&2; echo >&2
  die "the shim rejected the sealed chat call (HTTP $CHAT_STATUS)"
fi
CIPHERTEXT="$(jget 'd["encrypted_payload"]' <"$RUN_DIR/chat.json")"
[ -n "$CIPHERTEXT" ] || die "shim returned no ciphertext"
sub "conversation sealed: ${#CIPHERTEXT} bytes of ciphertext"

say "6. before erasure: the TEE can open it"
BEFORE_STATUS="$(curl -sS -o "$RUN_DIR/before.json" -w '%{http_code}' -X POST "http://127.0.0.1:$SHIM_PORT/v1/chat/decrypt" \
  -H 'Content-Type: application/json' -H "X-NexQloud-Identity: $JWT" \
  -d "{\"encrypted_payload\":\"$CIPHERTEXT\",\"jwt_token\":\"$JWT\"}")"
if [ "$BEFORE_STATUS" != "200" ]; then
  cat "$RUN_DIR/before.json" >&2; echo >&2
  die "the TEE could not open its own ciphertext before erasure (HTTP $BEFORE_STATUS)"
fi
BEFORE_MSG="$(jget 'len(d.get("messages") or [])' <"$RUN_DIR/before.json")"
[ "$BEFORE_MSG" -ge 1 ] || die "expected the conversation to open before erasure"
ok "opened $BEFORE_MSG message(s) — ciphertext is live"

say "7. delete the conversation: federated erasure across the quorum"
DEL_NONCE="$(openssl rand -hex 16)"
SIG_B64="$(printf '%s' "$DEL_JWT" | base64 -w0)"
SESSION="$(curl -fsS -X POST "http://127.0.0.1:$COORD_PORT/destructions" \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$SCOPE\",\"customer_sig\":\"$SIG_B64\",\"nonce\":\"$DEL_NONCE\"}")"
DESTRUCTION_ID="$(printf '%s' "$SESSION" | jget 'd["destruction_id"]')"
sub "coordinator accepted destruction $DESTRUCTION_ID"
sub "quorum: $(printf '%s' "$SESSION" | jget '" ".join(d["quorum"])')"

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$AGG_PORT/destructions/$DESTRUCTION_ID/proof" -o "$RUN_DIR/proof.json" 2>/dev/null; then
    break
  fi
  sleep 1
done
[ -s "$RUN_DIR/proof.json" ] || die "aggregator never produced a proof"
curl -fsS "http://127.0.0.1:$AGG_PORT/destructions/$DESTRUCTION_ID/receipts" >"$RUN_DIR/receipts.json"
mkdir -p "$RUN_DIR/receipts"
python3 - "$RUN_DIR/receipts.json" "$RUN_DIR/receipts" <<'PY'
import json, os, sys
raw = json.load(open(sys.argv[1]))
receipts = raw.get("receipts", raw if isinstance(raw, list) else [])
for r in receipts:
    op = r.get("package", {}).get("operator_id", "unknown")
    json.dump(r, open(os.path.join(sys.argv[2], f"{op}.json"), "w"), indent=2)
print(f"   wrote {len(receipts)} receipt file(s)")
PY

say "8. independent verification of the destruction proof"
set +e
"$BIN/sealed-verify-deletion" -registry "$REGISTRY_URL" -tenant "$SCOPE" \
  -proof "$RUN_DIR/proof.json" -receipts "$RUN_DIR/receipts" \
  >"$RUN_DIR/verify.json" 2>"$RUN_DIR/verify.err"
VERIFY_RC=$?
set -e

SUMMARY="$(python3 - "$RUN_DIR/verify.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
hardware = {"hardware_genuine", "key_binding"}
checks = d["checks"]
passed = sum(1 for c in checks if c["ok"])
nonhw = sorted({c["id"] for c in checks if not c["ok"] and c["id"] not in hardware})
hw = sorted({c["id"] for c in checks if not c["ok"] and c["id"] in hardware})
print(passed, len(checks), len(nonhw), ",".join(hw) or "-", str(d.get("overall_ok")).lower())
PY
)"
read -r PASSED TOTAL NONHW_FAILED FAILED_HW OVERALL_OK <<<"$SUMMARY"
sub "checks passed: $PASSED/$TOTAL"

if [ "$NONHW_FAILED" != "0" ]; then
  python3 - "$RUN_DIR/verify.json" <<'PY' >&2
import json, sys
d = json.load(open(sys.argv[1]))
for c in d["checks"]:
    if not c["ok"]:
        print(f"   FAIL {c['id']} :: {c['detail']}")
PY
  cat "$RUN_DIR/verify.err" >&2
  die "sealed-verify-deletion rejected the proof"
fi

if [ "$FAILED_HW" != "-" ]; then
  ok "every check that does not need silicon passed"
  sub "dev mode: $FAILED_HW fail because this run has no AMD certificate chain (test attestation, no VCEK)"
  sub "the same proof verifies fully on a SEV-SNP operator — that is the verifier doing its job, not a bug"
else
  ok "DELETION VERIFIED (overall_ok=$OVERALL_OK)"
fi

say "9. the key material is really gone"
STATUS="$(curl -fsS "http://127.0.0.1:$OP_A_PORT/keyscope/$SCOPE")"
DESTROYED="$(printf '%s' "$STATUS" | jget '",".join(d.get("destroyed") or [])')"
REMAINING="$(printf '%s' "$STATUS" | jget 'len(d.get("operators") or [])')"
[ "$REMAINING" = "0" ] || die "operator slots still hold material: $STATUS"
ok "registry slots destroyed: $DESTROYED (none hold material)"

set +e
AFTER="$(curl -sS -o "$RUN_DIR/after.json" -w '%{http_code}' -X POST "http://127.0.0.1:$SHIM_PORT/v1/chat/decrypt" \
  -H 'Content-Type: application/json' -H "X-NexQloud-Identity: $JWT" \
  -d "{\"encrypted_payload\":\"$CIPHERTEXT\",\"jwt_token\":\"$JWT\"}")"
set -e
if [ "$AFTER" = "200" ]; then
  printf '%s\n' "$(cat "$RUN_DIR/after.json")" >&2
  die "the ciphertext still opens after erasure — this is not cryptographic erasure"
fi
if grep -q "4417" "$RUN_DIR/after.json" 2>/dev/null; then
  die "the plaintext leaked after erasure"
fi
ok "the TEE now refuses to open the same ciphertext (HTTP $AFTER)"
sed 's/^/   /' "$RUN_DIR/after.json" | head -3 || true

say "RESULT"
cat <<EOF
   conversation scope : $SCOPE
   destruction proof  : $RUN_DIR/proof.json   (verifier exit $VERIFY_RC, overall_ok=$OVERALL_OK)
   per-operator files : $RUN_DIR/receipts/
   verifier output    : $RUN_DIR/verify.json
   rekor entries      : $RUN_DIR/rekor-entries.jsonl (local stub, nothing public)
   logs               : $LOGS/
EOF
echo "   the conversation's ciphertext no longer opens: the scope's key material is gone on every operator,"
echo "   and the proof that records it is independently checkable (needs SEV-SNP for the hardware checks)."
[ "${KEEP_RUNNING:-}" = "1" ] && echo "   federation still running (KEEP_RUNNING=1)" || true
