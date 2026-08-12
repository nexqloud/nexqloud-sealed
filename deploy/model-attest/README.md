# model-attest — hash on-disk GGUF and sign nonce-bound model commitments

Runs beside llama with the **same GGUF mount**. The shim calls
`POST /v1/attest-model` and embeds `model_commitment_cert` in the receipt.

Image: `ghcr.io/nexqloud/nexqloud-sealed/sealed-model-attest`

Required env:

```
MODEL_PATH=/models/model.gguf
MODEL_ATTEST_ISSUER_PRIVKEY=<32-byte hex seed>
MODEL_ATTEST_ISSUER_ID=nexqloud-model-attest
NEXQLOUD_MODEL_ID=qwen-0.5b   # optional, embedded in cert
```

## Fetch pinned GGUF (no Hugging Face at runtime)

Use the published allowlist commitment / content-addressed blob:

```bash
# From allowlist entry commitment sha256:<hex>
ENV_NAME=staging
HEX=74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db
R2=https://pub-84b99924d959400aa97608c84bbd8000.r2.dev

mkdir -p /var/lib/nexqloud/models
curl -fL -o /var/lib/nexqloud/models/model.gguf \
  "${R2}/${ENV_NAME}/sealed-models/by-sha256/${HEX}.gguf"
echo "${HEX}  /var/lib/nexqloud/models/model.gguf" | sha256sum -c -
```

Or: `./scripts/fetch-sealed-model.sh staging qwen-0.5b /var/lib/nexqloud/models`

## nerdctl (nanoserver)

```bash
# Prefer scripts/start-sealed-sidecars.sh — it creates sealed-net, isolation
# flags, and wires LLAMA_URL for the wipe worker. Manual equivalent:

nerdctl network create sealed-net 2>/dev/null || true

# 1) llama on the local file (no -hf); isolation flags disable KV reuse
nerdctl run -d --name sealed-llama \
  --network sealed-net \
  -p 127.0.0.1:8032:8080 \
  -v /var/lib/nexqloud/models:/models:ro \
  ghcr.io/ggml-org/llama.cpp:server \
  -m /models/qwen-0.5b.gguf --host 0.0.0.0 --port 8080 \
  -np 1 -sps 0.0 --no-cache-prompt -cram 0 --no-context-shift --slots \
  --slot-save-path /tmp/llama-slots

# 2) model-attest on the same volume
nerdctl pull ghcr.io/nexqloud/nexqloud-sealed/sealed-model-attest:stage

nerdctl run -d --name sealed-model-attest \
  -p 127.0.0.1:19002:19002 \
  -v /var/lib/nexqloud/models:/models:ro \
  -e MODEL_PATH=/models/qwen-0.5b.gguf \
  -e MODEL_ATTEST_LISTEN=0.0.0.0:19002 \
  -e MODEL_ATTEST_ISSUER_PRIVKEY='…' \
  -e MODEL_ATTEST_ISSUER_ID=nexqloud-model-attest \
  -e NEXQLOUD_MODEL_ID=qwen-0.5b \
  ghcr.io/nexqloud/nexqloud-sealed/sealed-model-attest:stage

curl -sS http://127.0.0.1:19002/health

# 3) shim points at attest (and llama as today)
#    NEXQLOUD_MODEL_ATTEST_URL=http://127.0.0.1:19002
#    Do not set NEXQLOUD_MODEL_COMMIT in production.
```

See [`docs/kv-isolation.md`](../../docs/kv-isolation.md) for why the llama
flags matter.
Generate issuer keys with `scripts/gen-model-attest-issuer.sh` and put the
pubkey in `web/sealed-model-attest-issuers/{env}/allowlist.json` (never commit
the private seed).
