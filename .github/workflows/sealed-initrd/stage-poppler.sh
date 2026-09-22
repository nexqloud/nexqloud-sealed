#!/usr/bin/env bash
# Stage poppler into the measured initrd rootfs.
#
# The shim executes the converter *inside the guest*: `ingest` draws the page
# renders with pdftoppm, `extract` reads the text layer with pdftotext
# (internal/render; both overridable through NEXQLOUD_PDFTOPPM / NEXQLOUD_PDFTOTEXT).
# The guest rootfs IS this initrd, so the binaries, their whole dynamic closure,
# fontconfig and at least one font have to travel inside it.
#
# Two failure modes this script exists to prevent:
#   - a binary without its libraries: pdftoppm aborts before it reads anything;
#   - libraries without fonts/fontconfig: poppler answers
#     "Fontconfig error: Cannot load default config file" and a page whose text is
#     not embedded rasterises blank.
#
# The script proves its own work: it renders a probe PDF that uses a non-embedded
# font (the case that needs fontconfig), reads the text back, and fails loudly if
# either step does not work. Probe artefacts are removed before the image is
# packed, so the initrd stays reproducible.
#
# Usage: stage-poppler.sh <rootfs-dir>
# The initrd builder calls this (ubuntu-latest). The same script runs unchanged
# in an ubuntu container to validate a rootfs before pushing.
set -euo pipefail

STAGE="${1:?usage: stage-poppler.sh <rootfs-dir>}"
STAGE="$(cd "${STAGE}" && pwd)"

LIBDIRS=()
MISSING=()
PROBE_FILES=()

die() { echo "stage-poppler: $*" >&2; exit 1; }
say() { echo "    $*" >&2; }

# Copy a file into the rootfs at its own absolute path, creating parents.
stage_file() {
  local src="$1"
  [[ -e "${src}" ]] || return 1
  install -D -m "$(stat -c '%a' "${src}")" "${src}" "${STAGE}${src}"
}

# Copy a whole directory, DEREFERENCING symlinks: Debian's /etc/fonts/conf.d is a
# tree of symlinks into /usr/share/fontconfig, and links copied as links would
# dangle inside the initrd.
stage_tree() {
  local src="$1"
  [[ -d "${src}" ]] || return 1
  install -d "${STAGE}${src}"
  cp -RL "${src}/." "${STAGE}${src}/"
}

remember_libdir() {
  local dir="$1" d
  for d in ${LIBDIRS[@]+"${LIBDIRS[@]}"}; do
    [[ "${d}" == "${dir}" ]] && return 0
  done
  LIBDIRS+=("${dir}")
}

# Every shared object a binary loads, plus its ELF interpreter.
stage_closure() {
  local bin="$1" line path
  while IFS= read -r line; do
    # ldd indents every line with a tab, and its interpreter line carries no "=>"
    line="${line#"${line%%[![:space:]]*}"}"
    case "${line}" in
      *" => "*)
        path="${line##* => }"
        path="${path%% *}"
        ;;
      *ld-linux*)
        path="${line%% *}"
        ;;
      *) continue ;;
    esac
    case "${path}" in
      ""|"not found"|linux-vdso*) continue ;;
    esac
    if [[ ! -f "${path}" ]]; then
      MISSING+=("${bin} -> ${path}")
      continue
    fi
    stage_file "${path}"
    remember_libdir "$(dirname "${path}")"
  done < <(ldd "${bin}")
}

BINARIES=(/usr/bin/pdftoppm /usr/bin/pdftotext)
for bin in "${BINARIES[@]}"; do
  [[ -x "${bin}" ]] || die "${bin} not found — install poppler-utils on the builder"
done

say "binaries + dynamic closure"
for bin in "${BINARIES[@]}"; do
  stage_file "${bin}"
  remember_libdir "$(dirname "${bin}")"
  stage_closure "${bin}"
done
[[ ${#MISSING[@]} -eq 0 ]] || die "unresolved libraries: ${MISSING[*]}"

say "fontconfig + fonts"
staged_fonts=0
for dir in /usr/share/fonts/truetype/dejavu /usr/share/fonts/truetype/liberation; do
  if [[ -d "${dir}" ]]; then
    stage_tree "${dir}"
    staged_fonts=1
  fi
done
[[ "${staged_fonts}" == "1" ]] || die "no usable font directory — install fonts-dejavu-core"
[[ -f /etc/fonts/fonts.conf ]] || die "/etc/fonts/fonts.conf missing — install fontconfig"
stage_tree /etc/fonts
# poppler's own tables (CMaps, name tables) where the package ships them
[[ -d /usr/share/poppler ]] && stage_tree /usr/share/poppler
# fontconfig writes a cache; the guest rootfs is ramfs, but the path must exist
install -d -m 0755 "${STAGE}/var/cache/fontconfig"

say "proving the rootfs runs poppler"
LOADER=""
for cand in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
  if [[ -f "${cand}" ]]; then
    LOADER="${cand}"
    break
  fi
done
[[ -n "${LOADER}" ]] || die "no ELF interpreter found on the builder"
stage_file "${LOADER}"
remember_libdir "$(dirname "${LOADER}")"

STAGED_LIBPATH=""
for dir in ${LIBDIRS[@]+"${LIBDIRS[@]}"}; do
  STAGED_LIBPATH="${STAGED_LIBPATH:+${STAGED_LIBPATH}:}${STAGE}${dir}"
done

# As root, chroot is the honest test: no host library can satisfy a missing one.
# Unprivileged, fall back to running the staged binary through the staged loader,
# which still proves the closure resolves entirely inside the rootfs.
if [[ "$(id -u)" == "0" ]]; then
  run_guest() { chroot "${STAGE}" "$@"; }
else
  run_guest() {
    local bin="$1"
    shift
    "${STAGE}${LOADER}" --library-path "${STAGED_LIBPATH}" "${STAGE}${bin}" "$@"
  }
fi
# always a host-visible path: the checks below read the rootfs from outside
guest_path() { printf '%s' "${STAGE}$1"; }

probe_dir="$(mktemp -d)"
trap 'rm -rf "${probe_dir}"' EXIT
install -d "${STAGE}/tmp"

# A one-page PDF that draws Helvetica WITHOUT embedding it: exactly the case that
# needs fontconfig and a real font file inside the rootfs.
python3 - "${STAGE}/tmp/probe.pdf" <<'PY'
import sys

text = b"BT /F1 24 Tf 20 100 Td (SEALEDPDF) Tj ET"
stream = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(text), text)
objs = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
    b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    stream,
]
out = bytearray(b"%PDF-1.4\n")
offsets = []
for i, body in enumerate(objs, start=1):
    offsets.append(len(out))
    out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
xref = len(out)
out += b"xref\n0 %d\n" % (len(objs) + 1)
out += b"0000000000 65535 f \n"
for off in offsets:
    out += b"%010d 00000 n \n" % off
out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
    len(objs) + 1,
    xref,
)
with open(sys.argv[1], "wb") as fh:
    fh.write(bytes(out))
PY
PROBE_FILES=(/tmp/probe.pdf)

if ! run_guest /usr/bin/pdftotext -layout /tmp/probe.pdf /tmp/probe.txt; then
  die "staged pdftotext failed to run"
fi
PROBE_FILES+=(/tmp/probe.txt)
grep -q SEALEDPDF "$(guest_path /tmp/probe.txt)" || die "staged pdftotext read no text layer"
say "pdftotext read the probe back"

if ! run_guest /usr/bin/pdftoppm -r 50 -png /tmp/probe.pdf /tmp/page 2>"${probe_dir}/render.err"; then
  cat "${probe_dir}/render.err" >&2
  die "staged pdftoppm failed to run"
fi
PROBE_FILES+=(/tmp/page-1.png)
page="$(guest_path /tmp/page-1.png)"
[[ -s "${page}" ]] || die "staged pdftoppm rendered no page"
[[ "$(head -c 8 "${page}" | od -An -tx1 | tr -d ' \n')" == "89504e470d0a1a0a" ]] \
  || die "page render is not a PNG"
if grep -qiE "fontconfig error|cannot load default config|no fonts" "${probe_dir}/render.err"; then
  cat "${probe_dir}/render.err" >&2
  die "fontconfig/fonts unusable inside the rootfs"
fi
say "pdftoppm rendered a page ($(stat -c '%s' "${page}") bytes, no fontconfig error)"

# The probe must not reach the measured image, and neither may a font cache the
# probe just wrote — that would make the same rootfs pack differently per run.
for f in "${PROBE_FILES[@]}"; do rm -f "${STAGE}${f}"; done
rm -rf "${STAGE}/var/cache/fontconfig"
install -d -m 0755 "${STAGE}/var/cache/fontconfig"

say "staged $(du -sh "${STAGE}" | cut -f1) of rootfs"
