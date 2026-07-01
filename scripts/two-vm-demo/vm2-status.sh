#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/vm2.env}"
load_env "$ENV_FILE"
RUN_DIR="${RUN_DIR:-/tmp/nexqloud-destruction-demo-vm2}"

step "VM2 destruction demo — status"
if is_running operator-b; then
  echo "  RUNNING  operator-b  pid $(cat "$(pid_file operator-b)")  log $(log_file operator-b)"
else
  echo "  STOPPED  operator-b"
fi
