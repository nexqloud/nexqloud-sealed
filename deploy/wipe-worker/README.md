# Wipe worker (host, adjacent to sealed-llama)

Image: `ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe` (built by `.github/workflows/wipe-worker-image.yml`)

Listen: `:19001` (or `WIPE_LISTEN`)

Required env:

```
WIPE_ISSUER_PRIVKEY=<32-byte hex seed>
WIPE_WORKER_COMMITMENT=sha256:1111111111111111111111111111111111111111111111111111111111111111
WIPE_MODE=host-buffer   # use auto once CUDA/libcudart is available in the runtime
WIPE_ISSUER_ID=nexqloud-wipe-worker
```

Generate a keypair:

```bash
./scripts/gen-wipe-issuer.sh
```

Put `pubkey` in `web/sealed-wipe-issuers/{env}/allowlist.json`. Set `WIPE_ISSUER_PRIVKEY`
on the host only — never commit the seed.

`WIPE_WORKER_COMMITMENT` must appear in `web/sealed-wipe-workers/{env}/allowlist.json`.

## nerdctl (nanoserver)

```bash
nerdctl pull ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

nerdctl run -d --name sealed-wipe \
  -p 127.0.0.1:19001:19001 \
  -e WIPE_LISTEN=0.0.0.0:19001 \
  -e WIPE_MODE=host-buffer \
  -e WIPE_ISSUER_PRIVKEY='…' \
  -e WIPE_WORKER_COMMITMENT='sha256:1111111111111111111111111111111111111111111111111111111111111111' \
  -e WIPE_ISSUER_ID=nexqloud-wipe-worker \
  ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

curl -sS http://127.0.0.1:19001/health
```

Nanovirt resolves `sealed-wipe` or `http://127.0.0.1:19001` the same way it does `sealed-llama`.
