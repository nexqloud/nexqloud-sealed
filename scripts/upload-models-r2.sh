#!/usr/bin/env bash
# Publish sealed-models (GGUF blobs + meta + full allowlist) and model-attest
# issuer allowlists to Cloudflare R2 from a catalog hash output tree.
#
#   ENV_NAME=staging MODELS_ROOT=./out/sealed-models ./scripts/upload-models-r2.sh
#
# MODELS_ROOT must contain one subdirectory per catalog model with:
#   expected-model-commitment.txt, model-meta.json, model.gguf
set -euo pipefail

ENV_NAME="${ENV_NAME:?ENV_NAME required (staging|production)}"
MODELS_ROOT="${MODELS_ROOT:?MODELS_ROOT required (out/sealed-models)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

R2_ACCOUNT_ID="${R2_ACCOUNT_ID:-285ada7dda5a9110cc820302071df4f1}"
R2_BUCKET="${R2_BUCKET:-nexqloud-sealed-ai}"
R2_ENDPOINT="${R2_ENDPOINT:-https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com}"
if [[ -z "${R2_PUBLIC_BASE_URL:-}" ]]; then
  R2_PUBLIC_BASE_URL="https://pub-84b99924d959400aa97608c84bbd8000.r2.dev"
fi

: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID / R2 access key required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY / R2 secret required}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

need() { [[ -f "$1" ]] || { echo "missing $1" >&2; exit 1; }; }

put() {
  local src="$1" key="$2" ctype="${3:-application/octet-stream}"
  aws --endpoint-url "${R2_ENDPOINT}" s3 cp "${src}" "s3://${R2_BUCKET}/${key}" \
    --content-type "${ctype}" \
    --only-show-errors
  echo "  s3://${R2_BUCKET}/${key}"
}

PUBLIC_BASE="${R2_PUBLIC_BASE_URL%/}"
PREFIX="${ENV_NAME}/sealed-models"
ALLOWLIST_KEY="${PREFIX}/allowlist.json"
ALLOWLIST_LOCAL="${MODELS_ROOT}/allowlist.json"
RELEASE_JSON="${MODELS_ROOT}/release.json"

mapfile -t MODEL_DIRS < <(find "${MODELS_ROOT}" -mindepth 1 -maxdepth 1 -type d | sort)
if [[ ${#MODEL_DIRS[@]} -eq 0 ]]; then
  echo "no model dirs under ${MODELS_ROOT}" >&2
  exit 1
fi

ENTRIES_JSON='[]'
FIRST_ID=""
FIRST_COMMITMENT=""

for dir in "${MODEL_DIRS[@]}"; do
  need "${dir}/expected-model-commitment.txt"
  need "${dir}/model-meta.json"
  need "${dir}/model.gguf"

  MODEL_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${dir}/model-meta.json")
  COMMITMENT=$(tr -d '\n' < "${dir}/expected-model-commitment.txt")
  ENTRY_PREFIX="${PREFIX}/${MODEL_ID}"
  HEX="${COMMITMENT#sha256:}"

  echo "==> uploading ${ENV_NAME} sealed-models @ ${MODEL_ID}"
  put "${dir}/expected-model-commitment.txt" \
    "${ENTRY_PREFIX}/expected-model-commitment.txt" "text/plain; charset=utf-8"
  put "${dir}/model-meta.json" \
    "${ENTRY_PREFIX}/model-meta.json" "application/json"
  put "${dir}/model.gguf" \
    "${ENTRY_PREFIX}/model.gguf" "application/octet-stream"
  # Content-addressed alias for deploy-by-digest.
  put "${dir}/model.gguf" \
    "${ENV_NAME}/sealed-models/by-sha256/${HEX}.gguf" "application/octet-stream"

  ENV_NAME="${ENV_NAME}" MODEL_ID="${MODEL_ID}" PUBLIC_BASE="${PUBLIC_BASE}" \
  python3 - "${dir}/model-meta.json" "${dir}/release.json" <<'PY'
import json, os, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
env = os.environ["ENV_NAME"]
mid = os.environ["MODEL_ID"]
hex_part = meta["commitment"].removeprefix("sha256:")
release = {
    "schema": "nexqloud-sealed-models-release/1",
    "environment": env,
    "id": mid,
    "commitment": meta["commitment"],
    "hf_repo": meta.get("hf_repo", ""),
    "revision": meta.get("revision", ""),
    "file": meta.get("file", ""),
    "quant": meta.get("quant", ""),
    "objects": {
        "expected_model_commitment": f"{env}/sealed-models/{mid}/expected-model-commitment.txt",
        "model_meta": f"{env}/sealed-models/{mid}/model-meta.json",
        "model_gguf": f"{env}/sealed-models/{mid}/model.gguf",
        "model_gguf_by_sha256": f"{env}/sealed-models/by-sha256/{hex_part}.gguf",
    },
    "public_base_url": os.environ["PUBLIC_BASE"],
}
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump(release, f, indent=2)
    f.write("\n")
PY
  put "${dir}/release.json" "${ENTRY_PREFIX}/release.json" "application/json"

  ENTRIES_JSON=$(ENV_NAME="${ENV_NAME}" ENTRY_PREFIX="${ENTRY_PREFIX}" ENTRIES_JSON="${ENTRIES_JSON}" \
    python3 - "${dir}/model-meta.json" <<'PY'
import json, os, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
entries = json.loads(os.environ["ENTRIES_JSON"])
entry = {
    "id": meta["id"],
    "commitment": meta["commitment"],
    "hf_repo": meta.get("hf_repo", ""),
    "revision": meta.get("revision", ""),
    "file": meta.get("file", ""),
    "quant": meta.get("quant", ""),
    "expected_model_commitment": f"{os.environ['ENTRY_PREFIX']}/expected-model-commitment.txt",
    "model_meta": f"{os.environ['ENTRY_PREFIX']}/model-meta.json",
    "model_gguf": f"{os.environ['ENTRY_PREFIX']}/model.gguf",
}
entries.append(entry)
print(json.dumps(entries))
PY
  )

  if [[ -z "${FIRST_ID}" ]]; then
    FIRST_ID="${MODEL_ID}"
    FIRST_COMMITMENT="${COMMITMENT}"
    cp -f "${dir}/release.json" "${RELEASE_JSON}"
  fi

  # Sync committed Pages pins when present.
  PIN_DIR="${ROOT}/web/sealed-models/${ENV_NAME}/${MODEL_ID}"
  if [[ -d "${PIN_DIR}" ]]; then
    GOT="${COMMITMENT}"
    WANT=$(tr -d '\n' < "${PIN_DIR}/expected-model-commitment.txt" 2>/dev/null || true)
    if [[ -n "${WANT}" && "${GOT}" != "${WANT}" ]]; then
      echo "Hashed GGUF differs from committed Pages pin for ${MODEL_ID}." >&2
      echo "  hashed:    ${GOT}" >&2
      echo "  committed: ${WANT}" >&2
      echo "Update web/sealed-models/${ENV_NAME}/${MODEL_ID}/ after changing catalog.yaml" >&2
      exit 1
    fi
  fi
done

if [[ -n "${FIRST_ID}" ]]; then
  put "${RELEASE_JSON}" "${PREFIX}/latest/release.json" "application/json"
fi

ENV_NAME="${ENV_NAME}" ENTRIES_JSON="${ENTRIES_JSON}" ALLOWLIST_LOCAL="${ALLOWLIST_LOCAL}" \
python3 <<'PY'
import json, os, pathlib
entries = json.loads(os.environ["ENTRIES_JSON"])
data = {
    "schema": "nexqloud-sealed-models-allowlist/1",
    "environment": os.environ["ENV_NAME"],
    "entries": entries,
}
pathlib.Path(os.environ["ALLOWLIST_LOCAL"]).write_text(
    json.dumps(data, indent=2) + "\n", encoding="utf-8"
)
PY

put "${ALLOWLIST_LOCAL}" "${ALLOWLIST_KEY}" "application/json"

# Publish model-attest issuer allowlist from git.
ISSUERS_SRC="${ROOT}/web/sealed-model-attest-issuers/${ENV_NAME}/allowlist.json"
need "${ISSUERS_SRC}"
put "${ISSUERS_SRC}" "${ENV_NAME}/sealed-model-attest-issuers/allowlist.json" "application/json"

{
  echo "public_allowlist=${PUBLIC_BASE}/${ALLOWLIST_KEY}"
  echo "public_issuers=${PUBLIC_BASE}/${ENV_NAME}/sealed-model-attest-issuers/allowlist.json"
  echo "commitment=${FIRST_COMMITMENT}"
  echo "model_id=${FIRST_ID}"
  echo "models=${#MODEL_DIRS[@]}"
} | tee "${MODELS_ROOT}/r2-publish.txt"

echo "OK: published to s3://${R2_BUCKET}/${PREFIX}/ (${#MODEL_DIRS[@]} models)"
