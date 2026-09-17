#!/bin/sh
# Role dispatch for the erasure control plane image.
#
#   registry     the federated key-derivation registry  (MongoDB-backed)
#   coordinator  the destruction coordinator
#   aggregator   the destruction aggregator
#
# Everything after the role name is passed to the binary unchanged.
set -e

usage() {
  cat >&2 <<'EOF'
usage: <registry|coordinator|aggregator> [flags...]

  registry     --addr :7001 --mongo <uri> [--db sealed_registry] [--collection commitments]
  coordinator  --addr :7003 --registry <url> --aggregator <url> --operators id=url,... --jwks <url>
  aggregator   --addr :7004 [--substrate-key-hex <ed25519 seed>]
EOF
}

role="${1:-}"
[ -n "$role" ] || { usage; exit 2; }
shift

case "$role" in
  registry)    exec /usr/local/bin/sealed-registry "$@" ;;
  coordinator) exec /usr/local/bin/destruction-coordinator "$@" ;;
  aggregator)  exec /usr/local/bin/destruction-aggregator "$@" ;;
  -h|--help)   usage; exit 0 ;;
  *)           echo "unknown role: $role" >&2; usage; exit 2 ;;
esac
