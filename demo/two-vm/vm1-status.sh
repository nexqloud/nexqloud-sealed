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
  port="$(service_port "$svc")"
  if is_running "$svc"; then
    pids="$(running_pids "$svc" | tr '\n' ' ' | sed 's/ $//')"
    echo "  RUNNING  $svc  pid(s) $pids  :${port}  log $(log_file "$svc")"
    # refresh pid file to real listener
    echo "$(running_pids "$svc" | head -1)" >"$(pid_file "$svc")"
  else
    echo "  STOPPED  $svc  :${port}"
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
