#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/vm1.env}"
load_env "$ENV_FILE"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-destruction-demo-vm1}"

step "VM1 destruction demo — status"
for svc in registry mock-idp aggregator coordinator operator-a; do
  if is_running "$svc"; then
    echo "  RUNNING  $svc  pid $(cat "$(pid_file "$svc")")  log $(log_file "$svc")"
  else
    echo "  STOPPED  $svc"
  fi
done

if [[ -f "$RUN_DIR/credentials.env" ]]; then
  substep "credentials: $RUN_DIR/credentials.env"
fi
if [[ -f "$RUN_DIR/seed.hex" ]]; then
  substep "seed.hex: $(cat "$RUN_DIR/seed.hex")"
fi
if [[ -f "$RUN_DIR/last-destruction.id" ]]; then
  substep "last destruction_id: $(cat "$RUN_DIR/last-destruction.id")"
fi
