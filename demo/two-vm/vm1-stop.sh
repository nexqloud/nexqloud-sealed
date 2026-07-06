#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/vm1.env}"
load_env "$ENV_FILE"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-destruction-demo-vm1}"

step "VM1 destruction demo — stop"
for svc in operator-a coordinator aggregator mock-idp registry; do
  stop_service "$svc"
done
substep "All VM1 demo processes stopped (pid files removed from $RUN_DIR)"
substep "Logs and state kept in $RUN_DIR — delete manually to reset completely"
