#!/usr/bin/env bash
# Start sealed host sidecars the reliable way (plain nerdctl run).
# Do not use nerdctl compose for these: GPUs are ignored and kata leaves ghosts.
#
# Usage (on nanoserver):
#   export WIPE_ISSUER_PRIVKEY=...
#   export MODEL_ATTEST_ISSUER_PRIVKEY=...
#   ./scripts/start-sealed-sidecars.sh
#
# Or with a .env next to the script / cwd:
#   WIPE_ISSUER_PRIVKEY=...
#   MODEL_ATTEST_ISSUER_PRIVKEY=...
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f ./.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source ./.env
  set +a
elif [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

: "${WIPE_ISSUER_PRIVKEY:?set WIPE_ISSUER_PRIVKEY}"
: "${MODEL_ATTEST_ISSUER_PRIVKEY:?set MODEL_ATTEST_ISSUER_PRIVKEY}"

MODEL_HOST_PATH="${MODEL_HOST_PATH:-/var/lib/nexqloud/models/qwen-0.5b.gguf}"
MODEL_ID="${MODEL_ID:-qwen-0.5b}"
LLAMA_HOST_PORT="${LLAMA_HOST_PORT:-8032}"
WIPE_IMAGE="${WIPE_IMAGE:-ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage}"
ATTEST_IMAGE="${ATTEST_IMAGE:-ghcr.io/nexqloud/nexqloud-sealed/sealed-model-attest:stage}"
LLAMA_IMAGE="${LLAMA_IMAGE:-ghcr.io/ggml-org/llama.cpp:server}"
SEALED_NET="${SEALED_NET:-sealed-net}"
LLAMA_URL="${LLAMA_URL:-http://sealed-llama:8080}"

if [[ ! -f "${MODEL_HOST_PATH}" ]]; then
  echo "missing model file: ${MODEL_HOST_PATH}" >&2
  echo "fetch it first, e.g.:" >&2
  echo "  curl -fL -o ${MODEL_HOST_PATH}.partial \\" >&2
  echo "    'https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf'" >&2
  echo "  mv ${MODEL_HOST_PATH}.partial ${MODEL_HOST_PATH}" >&2
  exit 1
fi

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
need nerdctl
need curl

wait_http() {
  local url="$1" name="$2" n=30
  for ((i = 1; i <= n; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "OK ${name}: ${url}"
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT waiting for ${name}: ${url}" >&2
  return 1
}

# Probe llama-server --help and append a flag only if the binary advertises it.
llama_help=""
LLAMA_EXTRA_FLAGS=()
add_llama_flag() {
  local flag="$1"
  shift
  if [[ -z "${llama_help}" ]]; then
    llama_help="$(nerdctl run --rm --entrypoint /bin/sh "${LLAMA_IMAGE}" -c 'llama-server --help 2>&1 || /app/llama-server --help 2>&1 || true' 2>/dev/null || true)"
    if [[ -z "${llama_help}" ]]; then
      llama_help="$(nerdctl run --rm "${LLAMA_IMAGE}" --help 2>&1 || true)"
    fi
  fi
  if grep -qE -- "${flag}([,[:space:]]|$)" <<<"${llama_help}"; then
    LLAMA_EXTRA_FLAGS+=("${flag}")
    if (($# > 0)); then
      LLAMA_EXTRA_FLAGS+=("$@")
    fi
  else
    echo "WARN: llama image lacks ${flag}; skipping" >&2
  fi
}

echo "==> ensuring network ${SEALED_NET}"
nerdctl network inspect "${SEALED_NET}" >/dev/null 2>&1 || nerdctl network create "${SEALED_NET}"

echo "==> stopping previous sidecars (if any)"
nerdctl rm -f sealed-wipe sealed-model-attest sealed-llama 2>/dev/null || true

echo "==> probing llama isolation flags"
add_llama_flag "-np" "1"
add_llama_flag "-sps" "0.0"
add_llama_flag "--no-cache-prompt"
add_llama_flag "-cram" "0"
add_llama_flag "--no-context-shift"
add_llama_flag "--slots"
# Required by this llama-server build to enable POST /slots/{id}?action=erase
# (save/restore are also unlocked). Keep the path container-local / ephemeral —
# do not bind-mount it to the host.
add_llama_flag "--slot-save-path" "/tmp/llama-slots"

echo "==> sealed-wipe (GPU; reaches llama via ${LLAMA_URL})"
nerdctl run -d --name sealed-wipe \
  --gpus all \
  --network "${SEALED_NET}" \
  --restart unless-stopped \
  -p 127.0.0.1:19001:19001 \
  -e WIPE_LISTEN=0.0.0.0:19001 \
  -e WIPE_MODE=cuda \
  -e WIPE_ISSUER_ID=nexqloud-wipe-worker \
  -e WIPE_ISSUER_PRIVKEY="${WIPE_ISSUER_PRIVKEY}" \
  -e LLAMA_URL="${LLAMA_URL}" \
  "${WIPE_IMAGE}"

echo "==> sealed-model-attest"
nerdctl run -d --name sealed-model-attest \
  --restart unless-stopped \
  -p 127.0.0.1:19002:19002 \
  -v "${MODEL_HOST_PATH}:/models/${MODEL_ID}.gguf:ro" \
  -e MODEL_PATH="/models/${MODEL_ID}.gguf" \
  -e MODEL_ATTEST_LISTEN=0.0.0.0:19002 \
  -e MODEL_ATTEST_ISSUER_ID=nexqloud-model-attest \
  -e NEXQLOUD_MODEL_ID="${MODEL_ID}" \
  -e MODEL_ATTEST_ISSUER_PRIVKEY="${MODEL_ATTEST_ISSUER_PRIVKEY}" \
  "${ATTEST_IMAGE}"

echo "==> sealed-llama (local GGUF; runc — kata cannot reliably bind-mount host files)"
echo "    isolation flags: ${LLAMA_EXTRA_FLAGS[*]:-(none detected)}"
# --slot-save-path must exist inside the container (llama returns 501 for erase
# without it; tmpfs keeps any save/restore off the host disk).
nerdctl run -d --name sealed-llama \
  --network "${SEALED_NET}" \
  --restart unless-stopped \
  --tmpfs /tmp/llama-slots:rw,mode=1777,size=64m \
  -v "${MODEL_HOST_PATH}:/models/${MODEL_ID}.gguf:ro" \
  -p "127.0.0.1:${LLAMA_HOST_PORT}:8080" \
  "${LLAMA_IMAGE}" \
  -m "/models/${MODEL_ID}.gguf" --host 0.0.0.0 --port 8080 \
  "${LLAMA_EXTRA_FLAGS[@]}"

echo "==> waiting for health"
wait_http "http://127.0.0.1:19001/health" "wipe"
wait_http "http://127.0.0.1:19002/health" "model-attest"
if ! wait_http "http://127.0.0.1:${LLAMA_HOST_PORT}/health" "llama"; then
  echo "==> sealed-llama failed health; recent logs:" >&2
  nerdctl logs --tail 80 sealed-llama 2>&1 || true
  nerdctl ps -a --filter name=sealed-llama || true
  exit 1
fi

DIGEST="$(nerdctl image inspect --format '{{index .RepoDigests 0}}' "${LLAMA_IMAGE}" 2>/dev/null || true)"

echo
nerdctl ps --filter name=sealed-
echo
echo "nanovirt guest URLs (injected automatically on sealed VM start):"
echo "  VLLM via tap-gw :19000 → host 127.0.0.1:${LLAMA_HOST_PORT}"
echo "  wipe via tap-gw :19001 → host 127.0.0.1:19001"
echo "  attest via tap-gw :19002 → host 127.0.0.1:19002"
echo
echo "llama image: ${LLAMA_IMAGE}"
if [[ -n "${DIGEST}" ]]; then
  echo "llama digest: ${DIGEST}"
  echo "Pin with: LLAMA_IMAGE=${DIGEST}"
fi
echo
echo "If nanovirt still probes llama on 8031, either use LLAMA_HOST_PORT=8031"
echo "or deploy nanovirt that prefers ${LLAMA_HOST_PORT}."
