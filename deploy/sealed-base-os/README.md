# sealed-base-os (exploratory)

CI workflow that pins **upstream Kata SNP boot files**, predicts the AMD
launch measurement with `sev-snp-measure`, and uploads a downloadable bundle.

This is **not** yet a NexQloud-owned base OS (no image-signature policy baked
into the initrd). It exists so we can validate the CI shape end-to-end.

## What the workflow produces

Artifact `sealed-base-os-<sha>.tgz` containing:

| File | Meaning |
|------|---------|
| `AMDSEV.fd` | SNP guest firmware from the Kata static release |
| `vmlinuz` | Guest kernel (`vmlinuz.container` target) |
| `initrd.img` | Confidential initrd from the same release (alternate profile) |
| `configuration-qemu-snp.toml` | Upstream SNP config snapshot |
| `kernel-cmdline.txt` | Cmdline used for measurement |
| `expected-measurement.txt` | Hex measurement for the kernel-only (stock config) profile |
| `expected-measurement-*.txt` | Per-profile measurements |
| `MANIFEST.txt` / `source.json` | Digests + provenance |

## How to run

1. Push this workflow to GitHub (or use **Actions → sealed-base-os → Run workflow**).
2. Download the artifact from the finished run.
3. Compare `expected-measurement.txt` to `enclave_measurement` in a live receipt
   from a host running the **same** Kata version / vCPU shape.

Mismatch is expected until host Kata version, cmdline, and `--vcpu-type`
exactly match what CI measured.

## Next steps (real Phase 2)

1. Replace upstream initrd with one that embeds an image-signature policy.
2. Install the bundle on nanoservers and point Kata SNP config at it.
3. Feed `expected-measurement.txt` into the verifier measurement catalog.
