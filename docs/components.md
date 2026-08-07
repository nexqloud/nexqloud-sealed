# Component tiers

This document classifies every deployable binary and major package so demo scaffolding is easy to distinguish from production code.

## Layout

| Path | Role |
|------|------|
| `cmd/` | Production services and audit CLIs |
| `demo/` | Demo-only binaries and scripts (never ship to production) |
| `internal/derive/` | Invention 1 — federated per-tenant key derivation |
| `internal/receipt/` + `internal/inference/` | Invention 2 — attested inference receipts |
| `internal/erasure/` | Invention 3 — federated cryptographic erasure |
| `internal/enclave/`, `internal/identity/`, `internal/registry/` | Shared platform plumbing |
| `pkg/verify/` | Public verification library (native + WASM) |
| `web/` | Browser verifier UI |

## Production (`cmd/`)

| Binary | Invention | Tier | Purpose |
|--------|-----------|------|---------|
| `shim` | 2 | **prod** | Inference API + per-request sealed receipt (`deploy/shim` container image) |
| `operator` | 3 (+ derive later) | **prod** | TEE operator HTTP server (`/destruction`); run one instance per federation operator (`-operator-id`) |
| `destruction-coordinator` | 3 | **prod** | Customer delete JWT gate + dispatch to operators |
| `destruction-aggregator` | 3 | **prod** | Collect operator destruction receipts → unified proof |
| `verify` | 2 | **tooling** | CLI verifier for inference / derivation receipts |
| `sealed-verify-deletion` | 3 | **tooling** | CLI verifier for destruction proofs |

## Demo (`demo/`)

| Binary / script | Replaced in production by |
|-----------------|---------------------------|
| `demo/mock-idp` | Customer IdP JWKS |
| `demo/registry` + `demo/registry/memstore` | Persistent registry service |
| `demo/bootstrap` | Tenant onboarding API / ops workflow |
| `demo/two-vm/` | Internal staging / sales demos only |

## Shim container (Kata SNP)

`deploy/shim/` builds a guest image for `kata-qemu-snp` (or any SNP guest). See
[`deploy/shim/README.md`](../deploy/shim/README.md).

- entrypoint mounts ConfigFS-TSM and creates `/dev/sev-guest`, then `exec`s `/usr/local/bin/sealed-shim`
- runtime needs `CAP_SYS_ADMIN` + `CAP_MKNOD` (or `--privileged`) for that setup
- CI **Tier B:** push OCI image to GHCR and keyless-cosign the digest into Rekor
- CI **Tier A** (SNP launch measurement via `sev-snp-measure`) is deferred until golden guest firmware/kernel assets exist

```bash
make image-shim                          # sealed-shim:local
# or: docker build -t sealed-shim:local -f deploy/shim/Dockerfile .

nerdctl run -d --name sealed-shim \
  --runtime io.containerd.run.kata-qemu-snp.v2 \
  --annotation io.kubernetes.cri.image-name=docker.io/library/sealed-shim:local \
  --cap-add SYS_ADMIN --cap-add MKNOD \
  -p 8080:8080 \
  -e NEXQLOUD_JWKS_URL=... \
  -e VLLM_URL=... \
  sealed-shim:local
```

Image: `ghcr.io/nexqloud/nexqloud-sealed/sealed-shim` (workflow: `.github/workflows/shim-image.yml`).

| Branch / tag | Env | Pull |
|--------------|-----|------|
| `stage` | staging | `…/sealed-shim:stage` |
| `main` | production | `…/sealed-shim:latest` |
| `v*` | production | `…/sealed-shim:<semver>` |

## Dev mode

Set `NEXQLOUD_DEV=1` (or `shim --dev`) to allow mock inference, placeholder receipt fields, and test attestation fallbacks. **Production deployments must not set this.**

Demo scripts export `NEXQLOUD_DEV=1` automatically via `demo/two-vm/common.sh`.

## Operator model

Run **one** `operator` binary per federation member:

```bash
operator -operator-id operator-a -addr :7101 -state-dir /var/sealed/operator-a ...
operator -operator-id operator-b -addr :7102 -state-dir /var/sealed/operator-b ...
```

The destruction coordinator takes a dispatch map: `operator-a=http://host:7101,operator-b=http://host:7102`.

## Three inventions (quick reference)

1. **Federated per-tenant key derivation** — seed committed to registry, per-operator chip wraps, HKDF DEK (`internal/derive/`).
2. **Per-inference attested receipt** — SNP attestation + signed receipt per request (`cmd/shim`, `internal/receipt/`).
3. **Federated cryptographic erasure** — customer auth → all operators zeroize → aggregated proof (`internal/erasure/`, coordinator/aggregator/operator).
