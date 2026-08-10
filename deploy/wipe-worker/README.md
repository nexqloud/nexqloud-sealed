# Wipe worker — real two-pass VRAM wipe (CUDA), adjacent to sealed-llama

Image: `ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe` (`.github/workflows/wipe-worker-image.yml`)

Default mode is **`cuda`**: runs `vram_two_pass.py` against GPU 0 (marker fill, then zeroes
free VRAM via libcudart). `WIPE_MODE=host-buffer` is CI/unit-tests only.

Required env:

```
WIPE_ISSUER_PRIVKEY=<32-byte hex seed>
WIPE_WORKER_COMMITMENT=sha256:1111111111111111111111111111111111111111111111111111111111111111
WIPE_ISSUER_ID=nexqloud-wipe-worker
```

## nerdctl (nanoserver — needs NVIDIA Container Toolkit)

```bash
nerdctl pull ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

nerdctl run -d --name sealed-wipe \
  --gpus all \
  -p 127.0.0.1:19001:19001 \
  -e WIPE_LISTEN=0.0.0.0:19001 \
  -e WIPE_MODE=cuda \
  -e WIPE_ISSUER_PRIVKEY='…' \
  -e WIPE_WORKER_COMMITMENT='sha256:1111111111111111111111111111111111111111111111111111111111111111' \
  -e WIPE_ISSUER_ID=nexqloud-wipe-worker \
  ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

curl -sS http://127.0.0.1:19001/health
# smoke the wipe:
curl -sS -X POST http://127.0.0.1:19001/v1/zeroize \
  -H 'content-type: application/json' \
  -d '{"nonce":"aa","policy_hash":"sha256:00"}'
```

Nanovirt resolves `sealed-wipe` or `http://127.0.0.1:19001`.
