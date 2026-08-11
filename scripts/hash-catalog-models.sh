#!/usr/bin/env bash
# Loop web/sealed-models/catalog.yaml and hash each GGUF into OUT_ROOT/<id>/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CATALOG="${CATALOG:-${ROOT}/web/sealed-models/catalog.yaml}"
OUT_ROOT="${OUT_ROOT:-${ROOT}/out/sealed-models}"
CACHE_DIR="${CACHE_DIR:-${HOME}/.cache/nexqloud-sealed/hf-gguf}"

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
need python3
need curl

python3 -c 'import yaml' 2>/dev/null || pip3 install --user pyyaml >/dev/null

mkdir -p "${OUT_ROOT}"

export CATALOG OUT_ROOT CACHE_DIR ROOT
python3 <<'PY' | while IFS=$'\t' read -r mid repo rev file quant; do
import os, sys, yaml
with open(os.environ["CATALOG"], encoding="utf-8") as f:
    data = yaml.safe_load(f) or {}
models = data.get("models") or []
if not models:
    sys.exit("catalog.yaml has no models")
for m in models:
    mid = (m.get("id") or "").strip()
    repo = (m.get("hf_repo") or "").strip()
    rev = (m.get("revision") or "").strip()
    file = (m.get("file") or "").strip()
    quant = (m.get("quant") or "").strip()
    if not mid or not repo or not rev or not file:
        sys.exit(f"incomplete catalog entry: {m!r}")
    print("\t".join([mid, repo, rev, file, quant]))
PY
  echo "==> hashing ${mid}" >&2
  MODEL_ID="${mid}" \
  HF_REPO="${repo}" \
  HF_REVISION="${rev}" \
  HF_FILE="${file}" \
  QUANT="${quant}" \
  OUT_DIR="${OUT_ROOT}/${mid}" \
  CACHE_DIR="${CACHE_DIR}" \
    "${ROOT}/scripts/hash-hf-gguf.sh"
done

echo "==> hashed catalog into ${OUT_ROOT}" >&2
