#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/vm2.env}"
load_env "$ENV_FILE"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-destruction-demo-vm2}"

step "VM2 destruction demo — stop"
stop_service operator-b
substep "VM2 demo stopped (pid files removed from $RUN_DIR)"
