# Sealed initrd workflow

Files in this directory belong to `.github/workflows/sealed-initrd.yml`.

| File | Role |
|------|------|
| `build.sh` | Build shim + `cmd/sealed-init`, pack initrd, fetch Kata SNP assets, `sev-snp-measure` |
| `run-vm.sh` | Boot the flat bundle on a SEV-SNP host (copied into the artifact) |
| `upload-r2.sh` | Publish signed bundle + measurement to public R2, per environment |

Guest PID1: `cmd/sealed-init`.

## Environments

Same mapping as `shim-image.yml`:

| Git ref | GitHub Environment | R2 prefix |
|---------|--------------------|-----------|
| `stage` | `staging` | `staging/sealed-initrd/` |
| `main` / `v*` | `production` | `production/sealed-initrd/` |

Bucket: `nexqloud-sealed-ai` (account `285ada7dda5a9110cc820302071df4f1`).

Published objects (also mirrored under `…/latest/`):

- `sealed-initrd-bundle.tgz`
- `expected-measurement.txt` (public gold measurement)
- `expected-measurement.sigstore.json` / `MANIFEST*.` (Rekor cosign bundles)
- `release.json` (sha + measurement + object keys)

## Secrets / vars

On GitHub Environments **staging** and **production** (or repo-level Actions secrets):

- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`

Optional Actions variable:

- `R2_PUBLIC_BASE_URL` — public HTTP base (r2.dev or custom domain).  
  Default: `https://285ada7dda5a9110cc820302071df4f1.r2.cloudflarestorage.com/nexqloud-sealed-ai`

## Local build

```bash
chmod +x .github/workflows/sealed-initrd/*.sh
GIT_SHA=$(git rev-parse HEAD) .github/workflows/sealed-initrd/build.sh
```

## Nanoserver (from R2)

```bash
# staging example
curl -fLO https://<public-base>/staging/sealed-initrd/latest/sealed-initrd-bundle.tgz
curl -fLO https://<public-base>/staging/sealed-initrd/latest/expected-measurement.txt
tar -xzf sealed-initrd-bundle.tgz
./run-vm.sh
# SEALED_MEASUREMENT must match expected-measurement.txt
```
