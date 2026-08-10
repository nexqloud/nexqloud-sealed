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
- `allowlist.json` (append-only index of measurements → proof object keys; Code Legit)

## Secrets / vars

On GitHub Environments **staging** and **production** (or repo-level Actions secrets):

- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`

Optional Actions variable:

- `R2_PUBLIC_BASE_URL` — public HTTP base. Default in workflow:
  `https://pub-84b99924d959400aa97608c84bbd8000.r2.dev`

## Local build

```bash
chmod +x .github/workflows/sealed-initrd/*.sh
GIT_SHA=$(git rev-parse HEAD) .github/workflows/sealed-initrd/build.sh
```

## Browser CORS

R2 public URLs do not send `Access-Control-Allow-Origin` by default. Apply once:

```bash
aws s3api put-bucket-cors \
  --bucket nexqloud-sealed-ai \
  --endpoint-url https://285ada7dda5a9110cc820302071df4f1.r2.cloudflarestorage.com \
  --cors-configuration file://.github/workflows/sealed-initrd/r2-cors.json
```

(Or paste the same JSON under R2 bucket → Settings → CORS.)

The public verifier also exposes same-origin proxies when Pages Functions are enabled
(`web/functions/`):

- `/api/initrd-release?env=staging` — latest `release.json`
- `/api/initrd-allowlist?env=staging` — append-only allowlist
- `/api/initrd-object?key=staging/sealed-initrd/<sha>/expected-measurement.sigstore.json`


```bash
curl -fLO https://pub-84b99924d959400aa97608c84bbd8000.r2.dev/staging/sealed-initrd/latest/sealed-initrd-bundle.tgz
curl -fLO https://pub-84b99924d959400aa97608c84bbd8000.r2.dev/staging/sealed-initrd/latest/expected-measurement.txt
mkdir -p ~/sealed-initrd && cd ~/sealed-initrd
tar -xzf ~/sealed-initrd-bundle.tgz
cat expected-measurement.txt
./run-vm.sh
```
