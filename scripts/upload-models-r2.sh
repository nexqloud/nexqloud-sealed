#!/usr/bin/env bash
# Publish sealed-models allowlist + commitment blob to Cloudflare R2.
#
# Automated by .github/workflows/sealed-models.yml on push to stage/main
# (paths: web/sealed-models/**, this script, hash-hf-gguf.sh). Manual use:
#
#   ENV_NAME=staging MODEL_DIR=./out/sealed-models/qwen-0.5b ./scripts/upload-models-r2.sh
#
# Required:
#   ENV_NAME=staging|production
#   MODEL_DIR=./out/sealed-models/qwen-0.5b   # expected-model-commitment.txt + model-meta.json
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (R2)
#
# Optional:
#   R2_ACCOUNT_ID, R2_BUCKET, R2_PUBLIC_BASE_URL
set -euo pipefail

ENV_NAME="${ENV_NAME:?ENV_NAME required (staging|production)}"
MODEL_DIR="${MODEL_DIR:?MODEL_DIR required}"

need() { [[ -f "$1" ]] || { echo "missing $1" >&2; exit 1; }; }
need "${MODEL_DIR}/expected-model-commitment.txt"
need "${MODEL_DIR}/model-meta.json"

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

COMMITMENT=$(tr -d '\n' < "${MODEL_DIR}/expected-model-commitment.txt")
MODEL_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${MODEL_DIR}/model-meta.json")

PREFIX="${ENV_NAME}/sealed-models"
ENTRY_PREFIX="${PREFIX}/${MODEL_ID}"
ALLOWLIST_KEY="${PREFIX}/allowlist.json"
OUT="${MODEL_DIR}"
ALLOWLIST_LOCAL="${OUT}/allowlist.json"
ALLOWLIST_PREV="${OUT}/allowlist.prev.json"
RELEASE_JSON="${OUT}/release.json"

put() {
  local src="$1" key="$2" ctype="${3:-application/octet-stream}"
  aws --endpoint-url "${R2_ENDPOINT}" s3 cp "${src}" "s3://${R2_BUCKET}/${key}" \
    --content-type "${ctype}" \
    --only-show-errors
  echo "  s3://${R2_BUCKET}/${key}"
}

PUBLIC_BASE="${R2_PUBLIC_BASE_URL%/}"
export ENV_NAME PUBLIC_BASE MODEL_DIR

python3 - "${MODEL_DIR}/model-meta.json" "${RELEASE_JSON}" <<'PY'
import json, os, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
env = os.environ["ENV_NAME"]
mid = meta["id"]
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
    },
    "public_base_url": os.environ["PUBLIC_BASE"],
}
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump(release, f, indent=2)
    f.write("\n")
PY

echo "==> uploading ${ENV_NAME} sealed-models @ ${MODEL_ID}"
put "${MODEL_DIR}/expected-model-commitment.txt" \
  "${ENTRY_PREFIX}/expected-model-commitment.txt" "text/plain; charset=utf-8"
put "${MODEL_DIR}/model-meta.json" \
  "${ENTRY_PREFIX}/model-meta.json" "application/json"
put "${RELEASE_JSON}" "${ENTRY_PREFIX}/release.json" "application/json"
put "${RELEASE_JSON}" "${PREFIX}/latest/release.json" "application/json"

rm -f "${ALLOWLIST_PREV}"
aws --endpoint-url "${R2_ENDPOINT}" s3 cp "s3://${R2_BUCKET}/${ALLOWLIST_KEY}" "${ALLOWLIST_PREV}" \
  --only-show-errors 2>/dev/null || true

ENV_NAME="${ENV_NAME}" \
MODEL_DIR="${MODEL_DIR}" \
ENTRY_PREFIX="${ENTRY_PREFIX}" \
ALLOWLIST_PREV="${ALLOWLIST_PREV}" \
ALLOWLIST_LOCAL="${ALLOWLIST_LOCAL}" \
python3 - <<'PY'
import json, os, pathlib

meta = json.loads(pathlib.Path(os.environ["MODEL_DIR"], "model-meta.json").read_text(encoding="utf-8"))
prev_path = pathlib.Path(os.environ["ALLOWLIST_PREV"])
if prev_path.is_file():
    data = json.loads(prev_path.read_text(encoding="utf-8"))
else:
    data = {
        "schema": "nexqloud-sealed-models-allowlist/1",
        "environment": os.environ["ENV_NAME"],
        "entries": [],
    }

entry = {
    "id": meta["id"],
    "commitment": meta["commitment"],
    "hf_repo": meta.get("hf_repo", ""),
    "revision": meta.get("revision", ""),
    "file": meta.get("file", ""),
    "quant": meta.get("quant", ""),
    "expected_model_commitment": f"{os.environ['ENTRY_PREFIX']}/expected-model-commitment.txt",
    "model_meta": f"{os.environ['ENTRY_PREFIX']}/model-meta.json",
}

entries = data.get("entries") or []
replaced = False
for i, e in enumerate(entries):
    if (e.get("id") or "").strip() == entry["id"]:
        entries[i] = entry
        replaced = True
        break
if not replaced:
    entries.append(entry)

data["schema"] = "nexqloud-sealed-models-allowlist/1"
data["environment"] = os.environ["ENV_NAME"]
data["entries"] = entries
pathlib.Path(os.environ["ALLOWLIST_LOCAL"]).write_text(
    json.dumps(data, indent=2) + "\n", encoding="utf-8"
)
PY

put "${ALLOWLIST_LOCAL}" "${ALLOWLIST_KEY}" "application/json"

BASE="${PUBLIC_BASE}"
{
  echo "public_allowlist=${BASE}/${ALLOWLIST_KEY}"
  echo "public_commitment=${BASE}/${ENTRY_PREFIX}/expected-model-commitment.txt"
  echo "commitment=${COMMITMENT}"
  echo "model_id=${MODEL_ID}"
} | tee "${OUT}/r2-publish.txt"

echo "OK: published to s3://${R2_BUCKET}/${PREFIX}/"
