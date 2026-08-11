#!/usr/bin/env bash
# Fetch a catalog model GGUF from R2 by id (or by sha256 digest).
#
#   ./scripts/fetch-sealed-model.sh staging qwen-0.5b /var/lib/nexqloud/models
#   ./scripts/fetch-sealed-model.sh staging sha256:74a4… /var/lib/nexqloud/models
set -euo pipefail

ENV_NAME="${1:?usage: $0 <staging|production> <model-id|sha256:hex> [dest-dir]}"
TARGET="${2:?model id or sha256:hex required}"
DEST="${3:-./models}"
R2_PUBLIC_BASE_URL="${R2_PUBLIC_BASE_URL:-https://pub-84b99924d959400aa97608c84bbd8000.r2.dev}"
BASE="${R2_PUBLIC_BASE_URL%/}"

mkdir -p "${DEST}"
OUT="${DEST}/model.gguf"

if [[ "${TARGET}" == sha256:* ]]; then
  HEX="${TARGET#sha256:}"
  HEX="${HEX,,}"
  URL="${BASE}/${ENV_NAME}/sealed-models/by-sha256/${HEX}.gguf"
  echo "==> fetching ${URL}" >&2
  curl -fL --retry 3 --retry-delay 2 -o "${OUT}.partial" "${URL}"
  mv "${OUT}.partial" "${OUT}"
  echo "${HEX}  ${OUT}" | sha256sum -c -
  echo "${OUT}"
  exit 0
fi

ALLOW_URL="${BASE}/${ENV_NAME}/sealed-models/allowlist.json"
echo "==> loading ${ALLOW_URL}" >&2
TMP=$(mktemp)
curl -fL -o "${TMP}" "${ALLOW_URL}"
HEX=$(python3 - "${TMP}" "${TARGET}" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
want = sys.argv[2].strip()
for e in data.get("entries") or []:
    if (e.get("id") or "").strip() == want:
        c = (e.get("commitment") or "").strip()
        if c.startswith("sha256:"):
            print(c[len("sha256:"):].lower())
            raise SystemExit(0)
        raise SystemExit(f"bad commitment for {want}: {c!r}")
raise SystemExit(f"model id {want!r} not in allowlist")
PY
)
rm -f "${TMP}"

URL="${BASE}/${ENV_NAME}/sealed-models/by-sha256/${HEX}.gguf"
# Prefer id path if by-sha256 missing (older publishes).
ALT="${BASE}/${ENV_NAME}/sealed-models/${TARGET}/model.gguf"
echo "==> fetching ${URL}" >&2
if ! curl -fL --retry 3 --retry-delay 2 -o "${OUT}.partial" "${URL}"; then
  echo "==> fallback ${ALT}" >&2
  curl -fL --retry 3 --retry-delay 2 -o "${OUT}.partial" "${ALT}"
fi
mv "${OUT}.partial" "${OUT}"
echo "${HEX}  ${OUT}" | sha256sum -c -
printf 'sha256:%s\n' "${HEX}" > "${DEST}/expected-model-commitment.txt"
echo "${OUT}"
