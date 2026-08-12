#!/usr/bin/env bash
# Prove sealed-llama isolation flags and POST /slots/{id}?action=erase behavior.
#
# Usage (on nanoserver with sealed-llama up):
#   LLAMA_URL=http://127.0.0.1:8032 ./scripts/kv-isolation-check.sh
set -euo pipefail

LLAMA_URL="${LLAMA_URL:-http://127.0.0.1:8032}"
LLAMA_URL="${LLAMA_URL%/}"
CANARY="NXQ_CANARY_$(openssl rand -hex 8 2>/dev/null || echo deadbeef)"

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
need curl
need python3

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }

echo "==> health ${LLAMA_URL}/health"
curl -fsS "${LLAMA_URL}/health" >/dev/null || fail "llama health"

echo "==> GET /props (isolation flags)"
PROPS="$(curl -fsS "${LLAMA_URL}/props" || true)"
if [[ -z "${PROPS}" ]]; then
  fail "GET /props empty or unreachable (is --props / default props endpoint available?)"
fi

python3 - "${PROPS}" <<'PY' || exit 1
import json, sys
raw = sys.argv[1]
try:
    props = json.loads(raw)
except Exception as e:
    print(f"FAIL: props not JSON: {e}", file=sys.stderr)
    sys.exit(1)

# Shapes vary by llama.cpp version. Recent builds nest sampling under
# default_generation_settings.params and often omit cache_prompt entirely.
dgs = props.get("default_generation_settings") or {}
if not isinstance(dgs, dict):
    dgs = {}
params = dgs.get("params") if isinstance(dgs.get("params"), dict) else {}

cache_prompt = None
for src in (params, dgs, props):
    if "cache_prompt" in src:
        cache_prompt = src["cache_prompt"]
        break

total_slots = props.get("total_slots")
if total_slots is None:
    total_slots = props.get("n_slots") or dgs.get("n_slots")

errors = []
if total_slots is None:
    errors.append("total_slots missing from /props")
elif int(total_slots) != 1:
    errors.append(f"total_slots expected 1, got {total_slots!r}")

# cache_prompt is not exposed by every llama-server build's GET /props.
# When present it must be false; when absent, the canary probe below is the proof.
if cache_prompt is not None and cache_prompt is not False and cache_prompt != 0:
    errors.append(f"cache_prompt expected false, got {cache_prompt!r}")

if errors:
    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    print("props dump:", json.dumps(props, indent=2)[:2000], file=sys.stderr)
    sys.exit(1)

endpoint_slots = props.get("endpoint_slots")
print(f"cache_prompt={cache_prompt!r} total_slots={total_slots} endpoint_slots={endpoint_slots!r}")
if cache_prompt is None:
    print("WARN: /props does not expose cache_prompt; relying on canary probe", file=sys.stderr)
PY
ok "props assert total_slots=1 (cache_prompt when reported)"

echo "==> canary completion (request A)"
RESP_A="$(curl -fsS "${LLAMA_URL}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c "import json; print(json.dumps({
    'model': 'local',
    'messages': [
      {'role': 'system', 'content': 'You are a test assistant. Never invent secrets.'},
      {'role': 'user', 'content': 'Remember this secret token exactly: ${CANARY}. Reply with OK only.'}
    ],
    'max_tokens': 16,
    'temperature': 0
  }))")" )"

echo "==> overlapping-prefix completion (request B)"
RESP_B="$(curl -fsS "${LLAMA_URL}/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c "import json; print(json.dumps({
    'model': 'local',
    'messages': [
      {'role': 'system', 'content': 'You are a test assistant. Never invent secrets.'},
      {'role': 'user', 'content': 'What secret token did I ask you to remember? If none, say NONE.'}
    ],
    'max_tokens': 64,
    'temperature': 0
  }))")" )"

python3 - "${CANARY}" "${RESP_B}" <<'PY' || exit 1
import json, sys
canary, raw = sys.argv[1], sys.argv[2]
try:
    resp = json.loads(raw)
except Exception as e:
    print(f"FAIL: response B not JSON: {e}", file=sys.stderr)
    sys.exit(1)
content = ""
for ch in resp.get("choices") or []:
    msg = ch.get("message") or {}
    content += str(msg.get("content") or "")
    content += str(ch.get("text") or "")
if canary in content:
    print(f"FAIL: canary leaked into request B output: {content!r}", file=sys.stderr)
    sys.exit(1)
print(f"request B content (truncated): {content[:200]!r}")
PY
ok "canary did not leak into request B"

echo "==> POST /slots/0?action=erase"
ERASE_BODY="$(mktemp)"
ERASE_CODE="$(curl -sS -o "${ERASE_BODY}" -w '%{http_code}' \
  -X POST "${LLAMA_URL}/slots/0?action=erase" \
  -H 'Content-Length: 0' || true)"
if [[ "${ERASE_CODE}" != "200" ]]; then
  body="$(cat "${ERASE_BODY}" 2>/dev/null || true)"
  rm -f "${ERASE_BODY}"
  if [[ "${ERASE_CODE}" == "501" ]] && grep -q 'slot-save-path' <<<"${body}"; then
    fail "erase returned HTTP 501 (need --slot-save-path). Re-run scripts/start-sealed-sidecars.sh: ${body}"
  fi
  fail "erase returned HTTP ${ERASE_CODE}: ${body}"
fi
rm -f "${ERASE_BODY}"
ok "erase HTTP 200"

echo "==> GET /slots after erase"
SLOTS="$(curl -fsS "${LLAMA_URL}/slots" || true)"
python3 - "${SLOTS}" <<'PY' || exit 1
import json, sys
raw = sys.argv[1]
try:
    slots = json.loads(raw)
except Exception as e:
    print(f"FAIL: /slots not JSON: {e}", file=sys.stderr)
    sys.exit(1)
if not isinstance(slots, list):
    # some builds wrap under {"slots":[...]}
    if isinstance(slots, dict) and isinstance(slots.get("slots"), list):
        slots = slots["slots"]
    else:
        print(f"FAIL: unexpected /slots shape: {type(slots)}", file=sys.stderr)
        sys.exit(1)
for s in slots:
    if not isinstance(s, dict):
        continue
    prompt = s.get("prompt")
    if prompt in (None, "", [], {}):
        continue
    # Non-empty prompt after erase is a failure for isolation bookkeeping.
    if isinstance(prompt, str) and prompt.strip():
        print(f"FAIL: slot {s.get('id')} still has prompt after erase", file=sys.stderr)
        sys.exit(1)
    if isinstance(prompt, list) and len(prompt) > 0:
        print(f"FAIL: slot {s.get('id')} still has prompt tokens after erase", file=sys.stderr)
        sys.exit(1)
print(f"slots={len(slots)}")
PY
ok "slots empty after erase"

echo
echo "All KV isolation checks passed against ${LLAMA_URL}"
echo "Note: erase frees KV cells (bookkeeping); it does not memset tensor bytes."
echo "See docs/kv-isolation.md for residual risk."
