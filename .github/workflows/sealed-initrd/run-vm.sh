#!/usr/bin/env bash
# Boot the sealed-initrd bundle (flat directory next to this script).
# Shipped inside the CI artifact for nanoserver validation.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU="${QEMU:-/opt/kata/bin/qemu-system-x86_64}"
APPEND="${APPEND:-$(tr -d '\n' < "${DIR}/kernel-cmdline.txt" 2>/dev/null || true)}"
APPEND="${APPEND:-console=ttyS0 earlyprintk=serial,ttyS0 noreplace-smp}"
VCPU_TYPE="${VCPU_TYPE:-EPYC-v4}"

for f in AMDSEV.fd vmlinuz sealed-initrd.img; do
  [[ -f "${DIR}/${f}" ]] || { echo "missing ${DIR}/${f}" >&2; exit 1; }
done

exec "${QEMU}" \
  -machine q35,accel=kvm,kernel_irqchip=split,confidential-guest-support=snp \
  -cpu "${VCPU_TYPE}",pmu=off \
  -smp 1,cores=1,threads=1 \
  -m 2048M \
  -object memory-backend-ram,id=mem0,size=2048M \
  -numa node,memdev=mem0 \
  -object sev-snp-guest,id=snp,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=196608 \
  -bios "${DIR}/AMDSEV.fd" \
  -kernel "${DIR}/vmlinuz" \
  -initrd "${DIR}/sealed-initrd.img" \
  -append "${APPEND}" \
  -nographic -nodefaults -serial stdio -vga none --no-reboot
