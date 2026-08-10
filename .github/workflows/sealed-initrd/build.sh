#!/usr/bin/env bash
# CI/local builder for the sealed-initrd boot bundle.
# Invoked by .github/workflows/sealed-initrd.yml (same directory).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
OUT="${OUT:-${ROOT}/out/sealed-initrd}"
STAGE="${OUT}/rootfs"
KATA_VERSION="${KATA_VERSION:-4.0.0}"
VCPU_TYPE="${VCPU_TYPE:-EPYC-v4}"
APPEND="${APPEND:-console=ttyS0 earlyprintk=serial,ttyS0 noreplace-smp}"
GIT_SHA="${GIT_SHA:-unknown}"

mkdir -p "${OUT}" "${STAGE}/etc/ssl/certs"
rm -rf "${STAGE:?}/"*
mkdir -p "${STAGE}/etc/ssl/certs"

echo "==> building static sealed-shim"
cd "${ROOT}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o "${STAGE}/sealed-shim" ./cmd/shim
chmod +x "${STAGE}/sealed-shim"

echo "==> building static /init (cmd/sealed-init)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o "${STAGE}/init" ./cmd/sealed-init
chmod +x "${STAGE}/init"

echo "==> embedding CA certificates"
if [[ -d /etc/ssl/certs ]]; then
  cp -a /etc/ssl/certs/. "${STAGE}/etc/ssl/certs/" || true
fi
if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  cp -f /etc/ssl/certs/ca-certificates.crt "${STAGE}/etc/ssl/certs/ca-certificates.crt"
elif [[ -f /etc/ssl/cert.pem ]]; then
  cp -f /etc/ssl/cert.pem "${STAGE}/etc/ssl/certs/ca-certificates.crt"
fi

echo "==> packing sealed-initrd.img"
(
  cd "${STAGE}"
  find . | cpio -o -H newc 2>/dev/null | gzip -9
) > "${OUT}/sealed-initrd.img"

echo "==> fetching Kata ${KATA_VERSION} SNP firmware + kernel"
WORK="${OUT}/kata"
mkdir -p "${WORK}"
URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-static-${KATA_VERSION}-amd64.tar.zst"
if [[ ! -f "${WORK}/kata.tar.zst" ]]; then
  curl -fL --retry 3 -o "${WORK}/kata.tar.zst" "${URL}"
fi
tar --zstd -xf "${WORK}/kata.tar.zst" -C "${WORK}" \
  ./opt/kata/share/ovmf/AMDSEV.fd \
  ./opt/kata/share/kata-containers/vmlinuz.container
TARGET=$(readlink "${WORK}/opt/kata/share/kata-containers/vmlinuz.container")
tar --zstd -xf "${WORK}/kata.tar.zst" -C "${WORK}" \
  "./opt/kata/share/kata-containers/${TARGET}"
cp -f "${WORK}/opt/kata/share/ovmf/AMDSEV.fd" "${OUT}/AMDSEV.fd"
cp -f "${WORK}/opt/kata/share/kata-containers/${TARGET}" "${OUT}/vmlinuz"

echo "==> predicting launch measurement"
if [[ ! -d "${OUT}/snp-venv" ]]; then
  python3 -m venv "${OUT}/snp-venv"
  "${OUT}/snp-venv/bin/pip" install -q 'sev-snp-measure==0.0.13'
fi
printf '%s\n' "${APPEND}" > "${OUT}/kernel-cmdline.txt"
"${OUT}/snp-venv/bin/sev-snp-measure" \
  --mode snp \
  --vmm-type QEMU \
  --vcpus 1 \
  --vcpu-type "${VCPU_TYPE}" \
  --ovmf "${OUT}/AMDSEV.fd" \
  --kernel "${OUT}/vmlinuz" \
  --initrd "${OUT}/sealed-initrd.img" \
  --append "${APPEND}" \
  --output-format hex \
  | tee "${OUT}/expected-measurement.txt"

SHIM_HASH=$(sha256sum "${STAGE}/sealed-shim" | awk '{print $1}')
{
  echo "schema=nexqloud-sealed-initrd/1"
  echo "git_sha=${GIT_SHA}"
  echo "kata_version=${KATA_VERSION}"
  echo "vcpu_type=${VCPU_TYPE}"
  echo "vcpus=1"
  echo "append=${APPEND}"
  echo "firmware_sha256=$(sha256sum "${OUT}/AMDSEV.fd" | awk '{print $1}')"
  echo "kernel_sha256=$(sha256sum "${OUT}/vmlinuz" | awk '{print $1}')"
  echo "initrd_sha256=$(sha256sum "${OUT}/sealed-initrd.img" | awk '{print $1}')"
  echo "sealed_shim_sha256=${SHIM_HASH}"
  echo "measurement=$(tr -d '\n' < "${OUT}/expected-measurement.txt")"
} | tee "${OUT}/MANIFEST.txt"

cp -f "${SCRIPT_DIR}/run-vm.sh" "${OUT}/run-vm.sh"
chmod +x "${OUT}/run-vm.sh"

ls -lh "${OUT}/sealed-initrd.img" "${OUT}/AMDSEV.fd" "${OUT}/vmlinuz" "${OUT}/expected-measurement.txt"
echo "OK: bundle staged in ${OUT}"
cat "${OUT}/MANIFEST.txt"
