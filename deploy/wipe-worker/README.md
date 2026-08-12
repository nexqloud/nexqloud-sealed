# Wipe worker — real two-pass VRAM wipe (CUDA), adjacent to sealed-llama

Image: `ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe`

Default **`WIPE_MODE=cuda`**: marker-fill then zero free VRAM via libcudart.

When `LLAMA_URL` is set, each `/v1/zeroize` also erases llama-server KV slots
(`POST /slots/{id}?action=erase`) **before** the VRAM wipe, and the signed cert
includes `kv_cache_cleared` + `slots_erased`. See [`docs/kv-isolation.md`](../../docs/kv-isolation.md).

**Worker commitment:** the process hashes its own binary (`sha256` of
`/usr/local/bin/wipe-worker`). CI (`wipe-worker-image.yml`) publishes that
exact value to R2 + `web/sealed-wipe-workers/{env}/allowlist.json`. Do **not**
set `WIPE_WORKER_COMMITMENT` in production.

Required env:

```
WIPE_ISSUER_PRIVKEY=<32-byte hex seed>
WIPE_ISSUER_ID=nexqloud-wipe-worker
LLAMA_URL=http://sealed-llama:8080
```

Optional:

```
WIPE_KV_REQUIRED=0   # skip fail-closed when LLAMA_URL unset / erase fails (dev only)
```

`sealed-wipe` and `sealed-llama` must share a user-defined network (e.g.
`sealed-net`) so the wipe worker can reach llama by container DNS name.
`scripts/start-sealed-sidecars.sh` does this automatically.

## nerdctl (nanoserver — NVIDIA Container Toolkit)

```bash
nerdctl network create sealed-net 2>/dev/null || true
nerdctl pull ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

nerdctl run -d --name sealed-wipe \
  --gpus all \
  --network sealed-net \
  -p 127.0.0.1:19001:19001 \
  -e WIPE_LISTEN=0.0.0.0:19001 \
  -e WIPE_MODE=cuda \
  -e WIPE_ISSUER_PRIVKEY='…' \
  -e WIPE_ISSUER_ID=nexqloud-wipe-worker \
  -e LLAMA_URL=http://sealed-llama:8080 \
  ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

curl -sS http://127.0.0.1:19001/health
```
