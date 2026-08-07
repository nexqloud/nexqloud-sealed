# sealed-shim container

Guest image for Kata SNP (`kata-qemu-snp`) and other SEV-SNP guests.

## Contents

| Path | Role |
|------|------|
| `Dockerfile` | Multi-stage build; bases pinned by digest; static `sealed-shim` + CA roots |
| `entrypoint.sh` | Mounts ConfigFS-TSM, creates `/dev/sev-guest`, `exec`s the shim as PID 1 |

## Runtime requirements

- `CAP_SYS_ADMIN` — ConfigFS mount
- `CAP_MKNOD` — `/dev/sev-guest` node (or `--privileged`)

```bash
make image-shim

nerdctl run -d --name sealed-shim \
  --runtime io.containerd.run.kata-qemu-snp.v2 \
  --annotation io.kubernetes.cri.image-name=docker.io/library/sealed-shim:local \
  --cap-add SYS_ADMIN --cap-add MKNOD \
  -p 8080:8080 \
  -e NEXQLOUD_JWKS_URL=... \
  -e VLLM_URL=... \
  sealed-shim:local
```

## Trust tiers (CI)

**Tier B (implemented):** `.github/workflows/shim-image.yml` builds and pushes
`ghcr.io/nexqloud/nexqloud-sealed/sealed-shim`, then keyless-cosign signs the OCI
digest into Rekor.

| Git ref | Environment | Floating tag | Immutable |
|---------|-------------|--------------|-----------|
| `stage` | staging | `:stage` | `:sha-<commit>` |
| `main` | production | `:latest` | `:sha-<commit>` |
| `v*` tags | production | `:latest` + semver | `:sha-<commit>` |

**Tier A (deferred):** Predict the AMD SEV-SNP launch measurement with
`sev-snp-measure` over golden `OVMF.fd` + guest `bzImage` + workload initrd, then
sign `expected-measurement.txt` to Rekor. Blocked until
`ghcr.io/nexqloud/sealed-base-os` (or equivalent pinned firmware/kernel assets)
exists.
