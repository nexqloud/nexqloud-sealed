#!/usr/bin/env bash
# Hash a Hugging Face GGUF for sealed Model Legit and stage a local copy for R2.
#
# Usage (single model):
#   MODEL_ID=qwen-0.5b HF_REPO=... HF_REVISION=... HF_FILE=... QUANT=Q4_K_M \
#     OUT_DIR=./out/sealed-models/qwen-0.5b ./scripts/hash-hf-gguf.sh
#
# Catalog-driven CI uses scripts/hash-catalog-models.sh which loops catalog.yaml.
set -euo pipefail

HF_REPO="${HF_REPO:?HF_REPO required}"
HF_REVISION="${HF_REVISION:?HF_REVISION required}"
HF_FILE="${HF_FILE:?HF_FILE required}"
QUANT="${QUANT:-}"
MODEL_ID="${MODEL_ID:?MODEL_ID required}"
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
GGUF_OUT="${OUT_DIR}/model.gguf"

printf '%s\n' "${COMMITMENT}" > "${COMMIT_FILE}"
cp -f "${LOCAL}" "${GGUF_OUT}"

BYTES=$(wc -c < "${LOCAL}" | tr -d ' ')
export MODEL_ID HF_REPO HF_REVISION HF_FILE QUANT COMMITMENT BYTES
python3 - "${META_FILE}" <<'PY'
import json, os, sys
meta = {
    "id": os.environ["MODEL_ID"],
    "commitment": os.environ["COMMITMENT"],
    "hf_repo": os.environ["HF_REPO"],
    "revision": os.environ["HF_REVISION"],
    "file": os.environ["HF_FILE"],
    "quant": os.environ.get("QUANT", ""),
    "bytes": int(os.environ["BYTES"]),
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)
    f.write("\n")
PY

echo "${COMMITMENT}"
echo "==> wrote ${COMMIT_FILE}" >&2
echo "==> wrote ${META_FILE}" >&2
echo "==> wrote ${GGUF_OUT}" >&2
