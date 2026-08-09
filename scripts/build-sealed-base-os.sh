#!/usr/bin/env bash
# Exploratory sealed-base-os builder.
#
# Downloads a pinned Kata Containers static release, extracts the SNP guest
# boot files referenced by configuration-qemu-snp.toml, runs sev-snp-measure,
# and writes a small bundle under out/sealed-base-os/.
#
# This does NOT yet bake a NexQloud image-signature policy into the initrd
# (Option B). It proves the CI shape: obtain boot files → measure → publish.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/out/sealed-base-os"
WORK="${ROOT}/out/kata-extract"
KATA_VERSION="${KATA_VERSION:-4.0.0}"
KATA_ARCH="${KATA_ARCH:-amd64}"
VCPUS="${VCPUS:-1}"
VCPU_TYPE="${VCPU_TYPE:-EPYC-Genoa}"
VMM_TYPE="${VMM_TYPE:-QEMU}"

KATA_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-static-${KATA_VERSION}-${KATA_ARCH}.tar.zst"
TARBALL="${WORK}/kata-static-${KATA_VERSION}-${KATA_ARCH}.tar.zst"

mkdir -p "${OUT}" "${WORK}"

echo "==> downloading Kata static ${KATA_VERSION} (${KATA_ARCH})"
if [[ ! -f "${TARBALL}" ]]; then
  curl -fL --retry 3 -o "${TARBALL}" "${KATA_URL}"
fi
ls -lh "${TARBALL}"

echo "==> extracting SNP boot assets (selective)"
# Stock SNP config uses a confidential disk image + direct kernel boot.
# Also keep the confidential initrd for an alternate measurement.
BASE_EXTRACT=(
  ./opt/kata/share/defaults/kata-containers/configuration-qemu-snp.toml
  ./opt/kata/share/ovmf/AMDSEV.fd
  ./opt/kata/share/kata-containers/vmlinuz.container
  ./opt/kata/share/kata-containers/kata-containers-initrd-confidential.img
  ./opt/kata/share/kata-containers/kata-ubuntu-noble-confidential.initrd
)
tar --zstd -xf "${TARBALL}" -C "${WORK}" "${BASE_EXTRACT[@]}"

KATA_ROOT="${WORK}/opt/kata"
CFG="${KATA_ROOT}/share/defaults/kata-containers/configuration-qemu-snp.toml"
KERNEL_LINK="${KATA_ROOT}/share/kata-containers/vmlinuz.container"
if [[ -L "${KERNEL_LINK}" ]]; then
  KERNEL_TARGET="$(readlink "${KERNEL_LINK}")"
  echo "==> resolving kernel symlink vmlinuz.container -> ${KERNEL_TARGET}"
  tar --zstd -xf "${TARBALL}" -C "${WORK}" \
    "./opt/kata/share/kata-containers/${KERNEL_TARGET}"
fi

toml_get() {
  local key="$1"
  # first non-comment assignment of key =
  awk -v k="$key" '
    $0 ~ /^[[:space:]]*#/ { next }
    $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
      sub(/^[^=]*=[[:space:]]*/, "", $0)
      gsub(/^"/, "", $0); gsub(/"$/, "", $0)
      print $0
      exit
    }
  ' "$CFG"
}

FIRMWARE_HOST="$(toml_get firmware)"
KERNEL_HOST="$(toml_get kernel)"
INITRD_HOST="$(toml_get initrd || true)"
IMAGE_HOST="$(toml_get image || true)"
KERNEL_PARAMS="$(toml_get kernel_params)"
DEFAULT_VCPUS="$(toml_get default_vcpus)"
KERNEL_VERITY="$(toml_get kernel_verity_params || true)"

# Map host paths from the config (/opt/kata/...) into the extract tree.
to_local() {
  local host_path="$1"
  echo "${WORK}${host_path}"
}

resolve_file() {
  local p="$1"
  if [[ -L "$p" ]]; then
    local dir target
    dir="$(dirname "$p")"
    target="$(readlink "$p")"
    if [[ "$target" != /* ]]; then
      p="${dir}/${target}"
    else
      p="$target"
    fi
  fi
  if [[ ! -f "$p" ]]; then
    echo "missing file: $p" >&2
    exit 1
  fi
  echo "$p"
}

FIRMWARE_SRC="$(resolve_file "$(to_local "${FIRMWARE_HOST}")")"
KERNEL_SRC="$(resolve_file "$(to_local "${KERNEL_HOST}")")"

# Stock SNP config uses image=, not initrd=. Prefer confidential initrd for
# the alternate measured profile that matches CoCo-style boots.
INITRD_SRC=""
if [[ -n "${INITRD_HOST}" ]]; then
  INITRD_SRC="$(resolve_file "$(to_local "${INITRD_HOST}")")"
elif [[ -f "${KATA_ROOT}/share/kata-containers/kata-ubuntu-noble-confidential.initrd" ]]; then
  INITRD_SRC="${KATA_ROOT}/share/kata-containers/kata-ubuntu-noble-confidential.initrd"
fi

if [[ -n "${DEFAULT_VCPUS}" ]]; then
  VCPUS="${DEFAULT_VCPUS}"
fi

# Kata may append dm-verity params at runtime for image-based confidential guests.
APPEND="${KERNEL_PARAMS}"
if [[ -n "${KERNEL_VERITY}" && -n "${IMAGE_HOST}" ]]; then
  APPEND="${KERNEL_PARAMS} dm-mod.create=\"verity,,,ro,0 ${KERNEL_VERITY}\" root=/dev/mapper/root rootflags=ro"
fi

cp -f "${CFG}" "${OUT}/configuration-qemu-snp.toml"
cp -f "${FIRMWARE_SRC}" "${OUT}/AMDSEV.fd"
cp -f "${KERNEL_SRC}" "${OUT}/vmlinuz"
if [[ -n "${INITRD_SRC}" ]]; then
  cp -f "${INITRD_SRC}" "${OUT}/initrd.img"
fi

printf '%s\n' "${APPEND}" > "${OUT}/kernel-cmdline.txt"

cat > "${OUT}/source.json" <<EOF
{
  "kata_version": "${KATA_VERSION}",
  "kata_url": "${KATA_URL}",
  "firmware_config_path": "${FIRMWARE_HOST}",
  "kernel_config_path": "${KERNEL_HOST}",
  "initrd_config_path": "${INITRD_HOST}",
  "image_config_path": "${IMAGE_HOST}",
  "kernel_params": "${KERNEL_PARAMS}",
  "kernel_verity_params": "${KERNEL_VERITY}",
  "default_vcpus": ${VCPUS},
  "measure_vcpus": ${VCPUS},
  "measure_vcpu_type": "${VCPU_TYPE}",
  "measure_vmm_type": "${VMM_TYPE}",
  "note": "Exploratory pin of upstream Kata SNP assets. Not yet a NexQloud-owned base OS with image-signature policy."
}
EOF

echo "==> installing sev-snp-measure"
python3 -m pip install --user -q 'sev-snp-measure==0.0.13'
export PATH="${HOME}/.local/bin:${PATH}"

measure() {
  local label="$1"
  shift
  local out_file="${OUT}/expected-measurement-${label}.txt"
  echo "==> sev-snp-measure (${label})"
  set -x
  sev-snp-measure \
    --mode snp \
    --vmm-type "${VMM_TYPE}" \
    --vcpus "${VCPUS}" \
    --vcpu-type "${VCPU_TYPE}" \
    --ovmf "${OUT}/AMDSEV.fd" \
    "$@" \
    --output-format hex \
    | tee "${out_file}"
  set +x
  # keep a stable name for the primary profile
  if [[ "${label}" == "kernel-only" ]]; then
    cp -f "${out_file}" "${OUT}/expected-measurement.txt"
  fi
}

# Profile A: matches stock SNP config shape (direct kernel boot, no initrd).
measure kernel-only --kernel "${OUT}/vmlinuz" --append "$(cat "${OUT}/kernel-cmdline.txt")"

# Profile B: confidential initrd present in the same Kata release (useful once
# we switch config from image= to initrd=).
if [[ -f "${OUT}/initrd.img" ]]; then
  measure with-initrd \
    --kernel "${OUT}/vmlinuz" \
    --initrd "${OUT}/initrd.img" \
    --append "$(cat "${OUT}/kernel-cmdline.txt")"
fi

{
  echo "kata_version=${KATA_VERSION}"
  echo "vcpu_type=${VCPU_TYPE}"
  echo "vcpus=${VCPUS}"
  echo "vmm_type=${VMM_TYPE}"
  echo "firmware_sha256=$(sha256sum "${OUT}/AMDSEV.fd" | awk '{print $1}')"
  echo "kernel_sha256=$(sha256sum "${OUT}/vmlinuz" | awk '{print $1}')"
  if [[ -f "${OUT}/initrd.img" ]]; then
    echo "initrd_sha256=$(sha256sum "${OUT}/initrd.img" | awk '{print $1}')"
  fi
  echo "measurement_kernel_only=$(tr -d '\n' < "${OUT}/expected-measurement-kernel-only.txt")"
  if [[ -f "${OUT}/expected-measurement-with-initrd.txt" ]]; then
    echo "measurement_with_initrd=$(tr -d '\n' < "${OUT}/expected-measurement-with-initrd.txt")"
  fi
} | tee "${OUT}/MANIFEST.txt"

echo "==> bundle ready at ${OUT}"
ls -lh "${OUT}"
