#!/usr/bin/env bash
set -euo pipefail

step() {
  echo ""
  echo "============================================================"
  echo "  $*"
  echo "============================================================"
}

substep() {
  echo "  -> $*"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

script_dir() {
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

default_repo_root() {
  local d
  d="$(script_dir)"
  cd "$d/../.." && pwd
}

load_env() {
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    substep "Loading $env_file"
    # shellcheck disable=SC1090
    source "$env_file"
  fi
}

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    die "Set $name in your env file or export it before running this script."
  fi
}

ensure_run_dir() {
  mkdir -p "$RUN_DIR/logs" "$RUN_DIR/state/operator-a"
}

pid_file() {
  echo "$RUN_DIR/$1.pid"
}

log_file() {
  echo "$RUN_DIR/logs/$1.log"
}

is_running() {
  local name="$1"
  local pf
  pf="$(pid_file "$name")"
  [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null
}

start_service() {
  local name="$1"
  shift
  local pf log pid
  pf="$(pid_file "$name")"
  log="$(log_file "$name")"

  if is_running "$name"; then
    substep "$name already running (pid $(cat "$pf"))"
    return 0
  fi

  substep "Starting $name ..."
  (
    cd "$REPO_ROOT"
    exec "$@"
  ) >>"$log" 2>&1 &
  pid=$!
  echo "$pid" >"$pf"
  sleep 1

  if kill -0 "$pid" 2>/dev/null; then
    substep "$name running — pid $pid"
    substep "log: $log"
  else
    substep "$name failed to start — last log lines:"
    tail -20 "$log" >&2 || true
    rm -f "$pf"
    return 1
  fi
}

stop_service() {
  local name="$1"
  local pf
  pf="$(pid_file "$name")"
  if [[ ! -f "$pf" ]]; then
    substep "$name: not running (no pid file)"
    return 0
  fi
  local pid
  pid="$(cat "$pf")"
  if kill -0 "$pid" 2>/dev/null; then
    substep "Stopping $name (pid $pid) ..."
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pf"
}

wait_http() {
  local url="$1"
  local tries="${2:-30}"
  local i
  for ((i = 1; i <= tries; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

coordinator_pubkey_hex() {
  local seed_hex="$1"
  (
    cd "$REPO_ROOT"
    go run ./scripts/two-vm-demo/coordinator_pubkey.go "$seed_hex"
  )
}
