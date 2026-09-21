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

## GPU scope — the wipe covers exactly one device

The two-pass wipe runs against **CUDA device 0 only** (`cudaSetDevice(0)` in
`scripts/vram_two_pass.py`), and the signed cert's `gpu_id` is only the
`NEXQLOUD_GPU_ID` label (default `gpu-0`) — it does not select a device. On a
multi-GPU host:

- Pin the container to the single GPU you intend to wipe, and make the label name
  that GPU, so the cert says what it means.
- **Nothing else on the host may use the other GPUs.** If any other workload puts
  tenant data into a GPU this container cannot see, `/v1/zeroize` still succeeds and
  the receipt asserts a wipe — the claim would be false. A host that must use more
  than one GPU needs the wipe extended to cover every CUDA-visible device.

## nerdctl (nanoserver — NVIDIA Container Toolkit, via CDI)

Prefer **CDI with an explicit device** over `--gpus all`. On a cgroup-v2 host,
`--gpus all` goes through the legacy `nvidia-container-cli` hook, which can mount
`/dev/nvidia*` without adding those devices to the device-cgroup allowlist: the
container then lists the nodes but every `open()` fails, which surfaces as
`wipe failed: vram_two_pass: exit status 1: no CUDA device visible` and 500s every
receipt. Going through CDI puts the devices into the OCI spec, so the runtime grants
them itself.

```bash
nvidia-ctk cdi list        # names: nvidia.com/gpu=0 | 1 | <GPU-UUID> | all
nerdctl network create sealed-net 2>/dev/null || true
nerdctl pull ghcr.io/nexqloud/nexqloud-sealed/sealed-wipe:stage

nerdctl run -d --name sealed-wipe \
  --device nvidia.com/gpu=GPU-<uuid> \
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

Pin by **GPU UUID**, not index: CUDA's device index and the `/dev/nvidiaN` minor can
disagree (on the current TEE nanoserver, CUDA device 0 is `/dev/nvidia1`), so an
index is not a stable identifier across a reboot or a GPU addition.

Verify the devices actually landed (all read-only — no `nerdctl exec` needed):

```bash
nerdctl inspect sealed-wipe --format 'pid={{.State.Pid}}'
ls -l /proc/<pid>/root/dev/ | grep -i nvidia                             # nvidiaN + nvidiactl/uvm/modeset
ctr -n default containers info <container-id> | grep -c '"major": 195'   # expect > 0
```

