#!/usr/bin/env bash
# Upload sealed-initrd publishables to Cloudflare R2 (S3-compatible).
# Layout (one public bucket, keyed by deploy environment):
#   <env>/sealed-initrd/<git_sha>/...
#   <env>/sealed-initrd/latest/...
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
OUT="${OUT:-${ROOT}/out/sealed-initrd}"
ENV_NAME="${ENV_NAME:?ENV_NAME required (staging|production)}"
GIT_SHA="${GIT_SHA:?GIT_SHA required}"
BUNDLE_TGZ="${BUNDLE_TGZ:?BUNDLE_TGZ required}"

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
need "${BUNDLE_TGZ}"
need "${OUT}/expected-measurement.txt"
need "${OUT}/expected-measurement.sigstore.json"
need "${OUT}/MANIFEST.txt"
need "${OUT}/MANIFEST.sigstore.json"

PREFIX="${ENV_NAME}/sealed-initrd"
SHA_PREFIX="${PREFIX}/${GIT_SHA}"
LATEST_PREFIX="${PREFIX}/latest"

put() {
  local src="$1" key="$2" ctype="${3:-application/octet-stream}"
  aws --endpoint-url "${R2_ENDPOINT}" s3 cp "${src}" "s3://${R2_BUCKET}/${key}" \
    --content-type "${ctype}" \
    --only-show-errors
  echo "  s3://${R2_BUCKET}/${key}"
}

rekor_index() {
  local bundle="$1"
  python3 - "$bundle" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
payload = (d.get("rekorBundle") or {}).get("Payload") or {}
idx = payload.get("logIndex")
print(idx if idx is not None else "")
PY
}

MEASUREMENT=$(tr -d '\n' < "${OUT}/expected-measurement.txt")
REKOR_MEAS=$(rekor_index "${OUT}/expected-measurement.sigstore.json")
REKOR_MANIFEST=$(rekor_index "${OUT}/MANIFEST.sigstore.json")
PUBLIC_BASE="${R2_PUBLIC_BASE_URL%/}"

RELEASE_JSON="${OUT}/release.json"
MEASUREMENT="${MEASUREMENT}" \
ENV_NAME="${ENV_NAME}" \
GIT_SHA="${GIT_SHA}" \
REKOR_MEAS="${REKOR_MEAS}" \
REKOR_MANIFEST="${REKOR_MANIFEST}" \
SHA_PREFIX="${SHA_PREFIX}" \
PUBLIC_BASE="${PUBLIC_BASE}" \
RELEASE_JSON="${RELEASE_JSON}" \
python3 - <<'PY'
import json, os

def idx(name):
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw.isdigit() else None

release = {
    "schema": "nexqloud-sealed-initrd-release/1",
    "environment": os.environ["ENV_NAME"],
    "git_sha": os.environ["GIT_SHA"],
    "measurement": os.environ["MEASUREMENT"],
    "rekor": {
        "expected_measurement_log_index": idx("REKOR_MEAS"),
        "manifest_log_index": idx("REKOR_MANIFEST"),
    },
    "objects": {
        "bundle": f"{os.environ['SHA_PREFIX']}/sealed-initrd-bundle.tgz",
        "expected_measurement": f"{os.environ['SHA_PREFIX']}/expected-measurement.txt",
        "expected_measurement_sigstore": f"{os.environ['SHA_PREFIX']}/expected-measurement.sigstore.json",
        "manifest": f"{os.environ['SHA_PREFIX']}/MANIFEST.txt",
        "manifest_sigstore": f"{os.environ['SHA_PREFIX']}/MANIFEST.sigstore.json",
    },
    "public_base_url": os.environ["PUBLIC_BASE"],
}
with open(os.environ["RELEASE_JSON"], "w", encoding="utf-8") as f:
    json.dump(release, f, indent=2)
    f.write("\n")
PY

echo "==> uploading ${ENV_NAME} sealed-initrd @ ${GIT_SHA}"
put "${BUNDLE_TGZ}" "${SHA_PREFIX}/sealed-initrd-bundle.tgz" "application/gzip"
put "${OUT}/expected-measurement.txt" "${SHA_PREFIX}/expected-measurement.txt" "text/plain; charset=utf-8"
put "${OUT}/expected-measurement.sigstore.json" "${SHA_PREFIX}/expected-measurement.sigstore.json" "application/json"
put "${OUT}/MANIFEST.txt" "${SHA_PREFIX}/MANIFEST.txt" "text/plain; charset=utf-8"
put "${OUT}/MANIFEST.sigstore.json" "${SHA_PREFIX}/MANIFEST.sigstore.json" "application/json"
put "${RELEASE_JSON}" "${SHA_PREFIX}/release.json" "application/json"

# Stable pointers for verifiers / humans
put "${BUNDLE_TGZ}" "${LATEST_PREFIX}/sealed-initrd-bundle.tgz" "application/gzip"
put "${OUT}/expected-measurement.txt" "${LATEST_PREFIX}/expected-measurement.txt" "text/plain; charset=utf-8"
put "${OUT}/expected-measurement.sigstore.json" "${LATEST_PREFIX}/expected-measurement.sigstore.json" "application/json"
put "${OUT}/MANIFEST.txt" "${LATEST_PREFIX}/MANIFEST.txt" "text/plain; charset=utf-8"
put "${OUT}/MANIFEST.sigstore.json" "${LATEST_PREFIX}/MANIFEST.sigstore.json" "application/json"
put "${RELEASE_JSON}" "${LATEST_PREFIX}/release.json" "application/json"

BASE="${R2_PUBLIC_BASE_URL%/}"
{
  echo "public_latest_measurement=${BASE}/${LATEST_PREFIX}/expected-measurement.txt"
  echo "public_latest_release=${BASE}/${LATEST_PREFIX}/release.json"
  echo "public_sha_bundle=${BASE}/${SHA_PREFIX}/sealed-initrd-bundle.tgz"
  echo "measurement=${MEASUREMENT}"
  if [[ -n "${REKOR_MEAS}" ]]; then
    echo "rekor_measurement=https://search.sigstore.dev/?logIndex=${REKOR_MEAS}"
  fi
} | tee "${OUT}/r2-publish.txt"

echo "OK: published to s3://${R2_BUCKET}/${PREFIX}/"
