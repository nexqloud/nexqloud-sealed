#!/usr/bin/env bash
# Build workers allowlist JSON from a wipe-worker binary commitment and publish to R2.
#
#   ENV_NAME=staging COMMITMENT=sha256:abcd… ./scripts/publish-wipe-workers-allowlist.sh
set -euo pipefail

ENV_NAME="${ENV_NAME:?ENV_NAME required (staging|production)}"
COMMITMENT="${COMMITMENT:?COMMITMENT required (sha256:…)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/web/sealed-wipe-workers/${ENV_NAME}/allowlist.json"

mkdir -p "$(dirname "${OUT}")"
python3 - "${OUT}" "${ENV_NAME}" "${COMMITMENT}" <<'PY'
import json, sys
path, env, commitment = sys.argv[1], sys.argv[2], sys.argv[3]
if not commitment.startswith("sha256:") or len(commitment) != len("sha256:") + 64:
    raise SystemExit(f"invalid commitment: {commitment!r}")
doc = {
    "schema": "nexqloud-sealed-wipe-workers-allowlist/1",
    "environment": env,
    "entries": [
        {
            "id": "wipe-worker",
            "commitment": commitment,
        }
    ],
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(path)
PY

if [[ "${PUBLISH_R2:-0}" == "1" ]]; then
  R2_ACCOUNT_ID="${R2_ACCOUNT_ID:-285ada7dda5a9110cc820302071df4f1}"
  R2_BUCKET="${R2_BUCKET:-nexqloud-sealed-ai}"
  R2_ENDPOINT="${R2_ENDPOINT:-https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com}"
  : "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID required}"
  : "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY required}"
  export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"
  aws --endpoint-url "${R2_ENDPOINT}" s3 cp "${OUT}" \
    "s3://${R2_BUCKET}/${ENV_NAME}/sealed-wipe-workers/allowlist.json" \
    --content-type "application/json" \
    --only-show-errors
  echo "published s3://${R2_BUCKET}/${ENV_NAME}/sealed-wipe-workers/allowlist.json"
fi
