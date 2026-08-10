#!/usr/bin/env bash
# Publish GPU wipe allowlists (policies, issuers, workers) to R2.
#
#   ENV_NAME=staging ./scripts/upload-gpu-wipe-r2.sh
#
# Reads committed Pages copies under web/sealed-*/${ENV_NAME}/allowlist.json
set -euo pipefail

ENV_NAME="${ENV_NAME:?ENV_NAME required (staging|production)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

R2_ACCOUNT_ID="${R2_ACCOUNT_ID:-285ada7dda5a9110cc820302071df4f1}"
R2_BUCKET="${R2_BUCKET:-nexqloud-sealed-ai}"
R2_ENDPOINT="${R2_ENDPOINT:-https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID / R2 access key required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY / R2 secret required}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

put() {
  local src="$1" key="$2"
  aws --endpoint-url "${R2_ENDPOINT}" s3 cp "${src}" "s3://${R2_BUCKET}/${key}" \
    --content-type "application/json" \
    --only-show-errors
  echo "  s3://${R2_BUCKET}/${key}"
}

for kind in sealed-gpu-policies sealed-wipe-issuers sealed-wipe-workers; do
  src="${ROOT}/web/${kind}/${ENV_NAME}/allowlist.json"
  [[ -f "${src}" ]] || { echo "missing ${src}" >&2; exit 1; }
  put "${src}" "${ENV_NAME}/${kind}/allowlist.json"
done

echo "published GPU wipe allowlists for ${ENV_NAME}"
