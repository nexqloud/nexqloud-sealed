# Sealed initrd workflow

Files in this directory belong to `.github/workflows/sealed-initrd.yml`.

| File | Role |
|------|------|
| `build.sh` | Build static shim + `cmd/sealed-init`, pack initrd, fetch Kata SNP assets, run `sev-snp-measure`, write MANIFEST |
| `run-vm.sh` | Boot the flat bundle on a SEV-SNP host (copied into the artifact) |

Guest PID1 source: `cmd/sealed-init`.

## Local

```bash
chmod +x .github/workflows/sealed-initrd/*.sh
GIT_SHA=$(git rev-parse HEAD) .github/workflows/sealed-initrd/build.sh
# outputs under out/sealed-initrd/
```

## Nanoserver check

```bash
tar -xzf sealed-initrd-bundle-*.tgz
cat expected-measurement.txt
./run-vm.sh
# serial SEALED_MEASUREMENT must match expected-measurement.txt
```
