#!/usr/bin/env bash
# Hash a single Hugging Face GGUF file for sealed Model Legit commitments.
#
# Default pin matches what sealed-llama serves today:
#   llama-server -hf Qwen/Qwen2.5-0.5B-Instruct-GGUF:Q4_K_M
#
# Pinned (do not silently follow "latest"):
#   repo:     Qwen/Qwen2.5-0.5B-Instruct-GGUF
#   revision: 9217f5db79a29953eb74d5343926648285ec7e67
#   file:     qwen2.5-0.5b-instruct-q4_k_m.gguf
#
# Usage:
#   ./scripts/hash-hf-gguf.sh
#   HF_REPO=... HF_REVISION=... HF_FILE=... OUT_DIR=./out/sealed-models ./scripts/hash-hf-gguf.sh
set -euo pipefail

HF_REPO="${HF_REPO:-Qwen/Qwen2.5-0.5B-Instruct-GGUF}"
HF_REVISION="${HF_REVISION:-9217f5db79a29953eb74d5343926648285ec7e67}"
HF_FILE="${HF_FILE:-qwen2.5-0.5b-instruct-q4_k_m.gguf}"
QUANT="${QUANT:-Q4_K_M}"
MODEL_ID="${MODEL_ID:-qwen-0.5b}"
OUT_DIR="${OUT_DIR:-$(pwd)/out/sealed-models/${MODEL_ID}}"
CACHE_DIR="${CACHE_DIR:-${HOME}/.cache/nexqloud-sealed/hf-gguf}"

mkdir -p "${OUT_DIR}" "${CACHE_DIR}"

URL="https://huggingface.co/${HF_REPO}/resolve/${HF_REVISION}/${HF_FILE}"
LOCAL="${CACHE_DIR}/${HF_REVISION}_${HF_FILE}"

if [[ ! -f "${LOCAL}" ]]; then
  echo "==> downloading ${HF_REPO}@${HF_REVISION}/${HF_FILE}" >&2
  echo "    ${URL}" >&2
  tmp="${LOCAL}.partial"
  curl -fL --retry 3 --retry-delay 2 -o "${tmp}" "${URL}"
  mv "${tmp}" "${LOCAL}"
else
  echo "==> using cached ${LOCAL}" >&2
fi

HEX=$(sha256sum "${LOCAL}" | awk '{print tolower($1)}')
COMMITMENT="sha256:${HEX}"

COMMIT_FILE="${OUT_DIR}/expected-model-commitment.txt"
META_FILE="${OUT_DIR}/model-meta.json"

printf '%s\n' "${COMMITMENT}" > "${COMMIT_FILE}"

python3 - "${META_FILE}" <<PY
import json, os, sys
meta = {
    "id": os.environ.get("MODEL_ID", "${MODEL_ID}"),
    "commitment": "${COMMITMENT}",
    "hf_repo": "${HF_REPO}",
    "revision": "${HF_REVISION}",
    "file": "${HF_FILE}",
    "quant": "${QUANT}",
    "bytes": $(wc -c < "${LOCAL}" | tr -d ' '),
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)
    f.write("\n")
PY

echo "${COMMITMENT}"
echo "==> wrote ${COMMIT_FILE}" >&2
echo "==> wrote ${META_FILE}" >&2
