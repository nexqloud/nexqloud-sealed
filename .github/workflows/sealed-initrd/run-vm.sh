#!/usr/bin/env bash
# Boot the sealed-initrd bundle (flat directory next to this script).
# Shipped inside the CI artifact for nanoserver validation.
#
# Default: serial-only SNP boot (matches CI gold measurement).
#
# Network PoC (Kata QEMU has no -netdev user):
#   TAP_IF=tap-sealed0 ENV_FILE=./env.txt ./run-vm.sh
# env.txt must include NEXQLOUD_NET_IP / NEXQLOUD_NET_GW (and shim env).
# Do NOT put IP config on the kernel cmdline — that changes the measurement.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU="${QEMU:-/opt/kata/bin/qemu-system-x86_64}"
APPEND="${APPEND:-$(tr -d '\n' < "${DIR}/kernel-cmdline.txt" 2>/dev/null || true)}"
APPEND="${APPEND:-console=ttyS0 earlyprintk=serial,ttyS0 noreplace-smp}"
VCPU_TYPE="${VCPU_TYPE:-EPYC-v4}"
MEM_MB="${MEM_MB:-2048}"
TAP_IF="${TAP_IF:-}"
ENV_FILE="${ENV_FILE:-}"

for f in AMDSEV.fd vmlinuz sealed-initrd.img; do
  [[ -f "${DIR}/${f}" ]] || { echo "missing ${DIR}/${f}" >&2; exit 1; }
done

args=(
  -machine q35,accel=kvm,kernel_irqchip=split,confidential-guest-support=snp
  -cpu "${VCPU_TYPE}",pmu=off
  -smp 1,cores=1,threads=1
  -m "${MEM_MB}M"
  -object "memory-backend-ram,id=mem0,size=${MEM_MB}M"
  -numa node,memdev=mem0
  -object sev-snp-guest,id=snp,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=196608
  -bios "${DIR}/AMDSEV.fd"
  -kernel "${DIR}/vmlinuz"
  -initrd "${DIR}/sealed-initrd.img"
  -append "${APPEND}"
  -nographic -nodefaults -serial stdio -vga none --no-reboot
)

if [[ -n "${ENV_FILE}" ]]; then
  [[ -f "${ENV_FILE}" ]] || { echo "missing ENV_FILE=${ENV_FILE}" >&2; exit 1; }
  args+=(-fw_cfg "name=opt/nexqloud/env,file=${ENV_FILE}")
fi

if [[ -n "${TAP_IF}" ]]; then
  args+=(
    -netdev "tap,id=net0,ifname=${TAP_IF},script=no,downscript=no"
    -device virtio-net-pci,netdev=net0
  )
fi

if [[ -n "${QMP_SOCK:-}" ]]; then
  args+=(-qmp "unix:${QMP_SOCK},server,nowait")
fi

exec "${QEMU}" "${args[@]}"
