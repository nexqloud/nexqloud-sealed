#!/usr/bin/env bash
# Start sealed host sidecars the reliable way (plain nerdctl run).
# Do not use nerdctl compose for these: GPUs are ignored and kata leaves ghosts.
#
# Usage (on nanoserver):
#   export WIPE_ISSUER_PRIVKEY=...
#   export MODEL_ATTEST_ISSUER_PRIVKEY=...
#   ./scripts/start-sealed-sidecars.sh
#
# Backend (pick one):
#   INFERENCE_BACKEND=llama   # default — local GGUF on :8032 + slot erase for wipe
#   INFERENCE_BACKEND=vllm    # HF weights on :8033; no /slots erase
#
#   ./scripts/start-sealed-sidecars.sh
#   INFERENCE_BACKEND=vllm ./scripts/start-sealed-sidecars.sh

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

INFERENCE_BACKEND="${INFERENCE_BACKEND:-llama}"
MODEL_HOST_PATH="${MODEL_HOST_PATH:-/var/lib/nexqloud/models/qwen-0.5b.gguf}"
MODEL_ID="${MODEL_ID:-qwen-0.5b}"
WIPE_IMAGE="${WIPE_IMAGE:-ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage}"
ATTEST_IMAGE="${ATTEST_IMAGE:-ghcr.io/nexqloud/nexqloud-sealed/sealed-model-attest:stage}"
LLAMA_IMAGE="${LLAMA_IMAGE:-ghcr.io/ggml-org/llama.cpp:server}"
VLLM_IMAGE="${VLLM_IMAGE:-vllm/vllm-openai:latest}"
VLLM_MODEL="${VLLM_MODEL:-Qwen/Qwen2.5-0.5B-Instruct}"
VLLM_MODEL_HOST_PATH="${VLLM_MODEL_HOST_PATH:-/var/lib/nexqloud/vllm-models/qwen-0.5b}"
VLLM_SERVED_NAME="${VLLM_SERVED_NAME:-${MODEL_ID}}"
VLLM_MAX_MODEL_LEN="${VLLM_MAX_MODEL_LEN:-4096}"
VLLM_GPU_MEM_UTIL="${VLLM_GPU_MEM_UTIL:-0.85}"
SEALED_NET="${SEALED_NET:-sealed-net}"

if [[ -n "${INFERENCE_HOST_PORT:-}" ]]; then
  :
elif [[ -n "${LLAMA_HOST_PORT:-}" ]]; then
  INFERENCE_HOST_PORT="${LLAMA_HOST_PORT}"
elif [[ "${INFERENCE_BACKEND}" == "vllm" ]]; then
  INFERENCE_HOST_PORT=8033
else
  INFERENCE_HOST_PORT=8032
fi

case "${INFERENCE_BACKEND}" in
  llama|vllm) ;;
  *)
    echo "INFERENCE_BACKEND must be llama or vllm (got ${INFERENCE_BACKEND})" >&2
    exit 1
    ;;
esac

if [[ ! -f "${MODEL_HOST_PATH}" ]]; then
  echo "missing GGUF for model-attest: ${MODEL_HOST_PATH}" >&2
  echo "fetch it first, e.g.:" >&2
  echo "  curl -fL -o ${MODEL_HOST_PATH}.partial \\" >&2
  echo "    'https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf'" >&2
  echo "  mv ${MODEL_HOST_PATH}.partial ${MODEL_HOST_PATH}" >&2
  exit 1
fi

if [[ "${INFERENCE_BACKEND}" == "vllm" && -n "${VLLM_MODEL_HOST_PATH}" && ! -d "${VLLM_MODEL_HOST_PATH}" ]]; then
  echo "missing local HF model dir: ${VLLM_MODEL_HOST_PATH}" >&2
  echo "download a snapshot first, e.g. huggingface-cli download Qwen/Qwen2.5-0.5B-Instruct --local-dir ${VLLM_MODEL_HOST_PATH}" >&2
  exit 1
fi

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
need nerdctl
need curl

wait_http() {
  local url="$1" name="$2" n="${3:-60}"
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

start_llama() {
  echo "==> probing llama isolation flags"
  add_llama_flag "-np" "1"
  add_llama_flag "-sps" "0.0"
  add_llama_flag "--no-cache-prompt"
  add_llama_flag "-cram" "0"
  add_llama_flag "--no-context-shift"
  add_llama_flag "--slots"
  add_llama_flag "--slot-save-path" "/tmp/llama-slots"

  echo "==> sealed-llama (local GGUF; runc — kata cannot reliably bind-mount host files)"
  echo "    isolation flags: ${LLAMA_EXTRA_FLAGS[*]:-(none detected)}"
  nerdctl run -d --name sealed-llama \
    --network "${SEALED_NET}" \
    --restart unless-stopped \
    --tmpfs /tmp/llama-slots:rw,mode=1777,size=64m \
    -v "${MODEL_HOST_PATH}:/models/${MODEL_ID}.gguf:ro" \
    -p "127.0.0.1:${INFERENCE_HOST_PORT}:8080" \
    "${LLAMA_IMAGE}" \
    -m "/models/${MODEL_ID}.gguf" --host 0.0.0.0 --port 8080 \
    "${LLAMA_EXTRA_FLAGS[@]}"
}

start_vllm() {
  echo "==> sealed-vllm (OpenAI-compatible; needs more RAM/VRAM than llama.cpp)"
  echo "    WARN: vLLM has no /slots erase API — wipe will skip KV erase (WIPE_KV_REQUIRED=0)."
  echo "    WARN: model-attest still hashes the GGUF at ${MODEL_HOST_PATH}; vLLM serves HF weights."
  echo "          Treat this as a perf experiment unless you align attest with HF bytes."

  local -a args=(
    run -d --name sealed-vllm
    --gpus all
    --network "${SEALED_NET}"
    --restart unless-stopped
    -p "127.0.0.1:${INFERENCE_HOST_PORT}:8000"
    -e HUGGING_FACE_HUB_TOKEN="${HUGGING_FACE_HUB_TOKEN:-}"
  )
  local model_arg="${VLLM_MODEL}"
  if [[ -n "${VLLM_MODEL_HOST_PATH}" ]]; then
    args+=(-v "${VLLM_MODEL_HOST_PATH}:/models:ro")
    model_arg="/models"
  fi
  args+=("${VLLM_IMAGE}")
  # vLLM 0.26+: model is a positional arg to `vllm serve` ( --model is deprecated).
  args+=(
    "${model_arg}"
    --served-model-name "${VLLM_SERVED_NAME}"
    --host 0.0.0.0
    --port 8000
    --max-model-len "${VLLM_MAX_MODEL_LEN}"
    --gpu-memory-utilization "${VLLM_GPU_MEM_UTIL}"
    --disable-log-requests
  )
  nerdctl "${args[@]}"
}

echo "==> ensuring network ${SEALED_NET}"
nerdctl network inspect "${SEALED_NET}" >/dev/null 2>&1 || nerdctl network create "${SEALED_NET}"

echo "==> stopping previous sidecars (if any)"
nerdctl rm -f sealed-wipe sealed-model-attest sealed-llama sealed-vllm 2>/dev/null || true

WIPE_KV_REQUIRED=1
WIPE_LLAMA_URL=""
case "${INFERENCE_BACKEND}" in
  llama)
    WIPE_LLAMA_URL="${LLAMA_URL:-http://sealed-llama:8080}"
    ;;
  vllm)
    WIPE_KV_REQUIRED=0
    WIPE_LLAMA_URL=""
    ;;
esac

echo "==> sealed-wipe (GPU; kv_required=${WIPE_KV_REQUIRED} llama_url=${WIPE_LLAMA_URL:-none})"
wipe_args=(
  run -d --name sealed-wipe
  --gpus all
  --network "${SEALED_NET}"
  --restart unless-stopped
  -p 127.0.0.1:19001:19001
  -e WIPE_LISTEN=0.0.0.0:19001
  -e WIPE_MODE=cuda
  -e WIPE_ISSUER_ID=nexqloud-wipe-worker
  -e WIPE_ISSUER_PRIVKEY="${WIPE_ISSUER_PRIVKEY}"
  -e WIPE_KV_REQUIRED="${WIPE_KV_REQUIRED}"
)
if [[ -n "${WIPE_LLAMA_URL}" ]]; then
  wipe_args+=(-e LLAMA_URL="${WIPE_LLAMA_URL}")
fi
wipe_args+=("${WIPE_IMAGE}")
nerdctl "${wipe_args[@]}"

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

case "${INFERENCE_BACKEND}" in
  llama) start_llama ;;
  vllm) start_vllm ;;
esac

echo "==> waiting for health"
wait_http "http://127.0.0.1:19001/health" "wipe" 30
wait_http "http://127.0.0.1:19002/health" "model-attest" 30
case "${INFERENCE_BACKEND}" in
  llama)
    if ! wait_http "http://127.0.0.1:${INFERENCE_HOST_PORT}/health" "llama" 60; then
      echo "==> sealed-llama failed health; recent logs:" >&2
      nerdctl logs --tail 80 sealed-llama 2>&1 || true
      nerdctl ps -a --filter name=sealed-llama || true
      exit 1
    fi
    DIGEST="$(nerdctl image inspect --format '{{index .RepoDigests 0}}' "${LLAMA_IMAGE}" 2>/dev/null || true)"
    ;;
  vllm)
    # vLLM exposes /v1/models (and /health on recent builds).
    if ! wait_http "http://127.0.0.1:${INFERENCE_HOST_PORT}/v1/models" "vllm" 180; then
      echo "==> sealed-vllm failed health; recent logs:" >&2
      nerdctl logs --tail 120 sealed-vllm 2>&1 || true
      nerdctl ps -a --filter name=sealed-vllm || true
      exit 1
    fi
    DIGEST="$(nerdctl image inspect --format '{{index .RepoDigests 0}}' "${VLLM_IMAGE}" 2>/dev/null || true)"
    ;;
esac

echo
nerdctl ps --filter name=sealed-
echo
echo "backend: ${INFERENCE_BACKEND}"
echo "nanovirt guest URLs (injected automatically on sealed VM start):"
echo "  VLLM via tap-gw :19000 → host 127.0.0.1:${INFERENCE_HOST_PORT}"
echo "  wipe via tap-gw :19001 → host 127.0.0.1:19001"
echo "  attest via tap-gw :19002 → host 127.0.0.1:19002"
echo
if [[ "${INFERENCE_BACKEND}" == "llama" ]]; then
  echo "llama image: ${LLAMA_IMAGE}"
  if [[ -n "${DIGEST}" ]]; then
    echo "llama digest: ${DIGEST}"
    echo "Pin with: LLAMA_IMAGE=${DIGEST}"
  fi
else
  echo "vllm image: ${VLLM_IMAGE}"
  echo "vllm model: ${VLLM_MODEL}"
  if [[ -n "${VLLM_MODEL_HOST_PATH}" ]]; then
    echo "vllm local mount: ${VLLM_MODEL_HOST_PATH} -> /models"
  fi
  if [[ -n "${DIGEST}" ]]; then
    echo "vllm digest: ${DIGEST}"
    echo "Pin with: VLLM_IMAGE=${DIGEST}"
  fi
fi
echo
echo "If nanovirt still probes inference on 8031, either use INFERENCE_HOST_PORT=8031"
echo "or deploy nanovirt that prefers ${INFERENCE_HOST_PORT}."
