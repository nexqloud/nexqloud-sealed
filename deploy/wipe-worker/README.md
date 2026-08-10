# Wipe worker (host, adjacent to sealed-llama)

Listen: `:19001` (or `WIPE_LISTEN`)

Required env:

```
WIPE_ISSUER_PRIVKEY=<32-byte hex seed>
WIPE_WORKER_COMMITMENT=sha256:1111111111111111111111111111111111111111111111111111111111111111
WIPE_MODE=auto          # cuda via scripts/vram_two_pass.py; use host-buffer only for CI
WIPE_ISSUER_ID=nexqloud-wipe-worker
```

Generate a keypair:

```bash
./scripts/gen-wipe-issuer.sh
```

Put `pubkey` in `web/sealed-wipe-issuers/{env}/allowlist.json` (and publish via
`scripts/upload-gpu-wipe-r2.sh`). Set `WIPE_ISSUER_PRIVKEY` on the host only —
never commit the seed.

`WIPE_WORKER_COMMITMENT` must appear in `web/sealed-wipe-workers/{env}/allowlist.json`.

```bash
go build -o wipe-worker ./cmd/wipe-worker
WIPE_MODE=host-buffer WIPE_ISSUER_PRIVKEY=... WIPE_WORKER_COMMITMENT=sha256:1111... ./wipe-worker
```
