# Wipe worker — real two-pass VRAM wipe (CUDA), adjacent to sealed-llama

Image: `ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe`

Default **`WIPE_MODE=cuda`**: marker-fill then zero free VRAM via libcudart.

**Worker commitment:** the process hashes its own binary (`sha256` of
`/usr/local/bin/wipe-worker`). CI (`wipe-worker-image.yml`) publishes that
exact value to R2 + `web/sealed-wipe-workers/{env}/allowlist.json`. Do **not**
set `WIPE_WORKER_COMMITMENT` in production.

Required env:

```
WIPE_ISSUER_PRIVKEY=<32-byte hex seed>
WIPE_ISSUER_ID=nexqloud-wipe-worker
```

## nerdctl (nanoserver — NVIDIA Container Toolkit)

```bash
nerdctl pull ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

nerdctl run -d --name sealed-wipe \
  --gpus all \
  -p 127.0.0.1:19001:19001 \
  -e WIPE_LISTEN=0.0.0.0:19001 \
  -e WIPE_MODE=cuda \
  -e WIPE_ISSUER_PRIVKEY='…' \
  -e WIPE_ISSUER_ID=nexqloud-wipe-worker \
  ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

curl -sS http://127.0.0.1:19001/health
```
