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

default_demo_bin_dir() {
  echo "${HOME}/.cache/nexqloud-destruction-demo/bin"
}

ensure_run_dir() {
  mkdir -p "$RUN_DIR/logs" "$RUN_DIR/state/operator-a" "$RUN_DIR/state/operator-b"
}

ensure_demo_bin_dir() {
  DEMO_BIN_DIR="${DEMO_BIN_DIR:-$(default_demo_bin_dir)}"
  mkdir -p "$DEMO_BIN_DIR"
  local probe="$DEMO_BIN_DIR/.exec-probe"
  printf '#!/bin/sh\nexit 0\n' >"$probe"
  chmod +x "$probe"
  if ! "$probe" 2>/dev/null; then
    rm -f "$probe"
    die "Cannot execute binaries in DEMO_BIN_DIR=$DEMO_BIN_DIR — pick a directory on an exec-mounted filesystem (e.g. under \$HOME)."
  fi
  rm -f "$probe"
}

build_demo_bin() {
  local name="$1"
  local pkg_path="$2"
  ensure_demo_bin_dir
  local out="$DEMO_BIN_DIR/$name"
  if [[ ! -x "$out" ]]; then
    substep "Building $name → $out"
    if ! (cd "$REPO_ROOT" && go build -o "$out" "$pkg_path"); then
      die "go build failed for $name (package $pkg_path)"
    fi
  fi
  echo "$out"
}

start_service_or_die() {
  local name="$1"
  shift
  if ! start_service "$name" "$@"; then
    die "$name failed to start — see $(log_file "$name")"
  fi
}

# Return PIDs listening on a TCP port (Linux ss).
pids_on_port() {
  local port="$1"
  ss -ltnp 2>/dev/null | grep ":${port}" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}

service_port() {
  case "$1" in
    registry) echo 7001 ;;
    mock-idp) echo 7200 ;;
    aggregator) echo 7004 ;;
    coordinator) echo 7003 ;;
    operator-a) echo 7101 ;;
    operator-b) echo 7102 ;;
    *) echo "" ;;
  esac
}

running_pids() {
  local name="$1"
  local pf pid port p
  pf="$(pid_file "$name")"
  if [[ -f "$pf" ]]; then
    pid="$(cat "$pf")"
    if kill -0 "$pid" 2>/dev/null; then
      echo "$pid"
      return 0
    fi
  fi
  port="$(service_port "$name")"
  if [[ -n "$port" ]]; then
    for p in $(pids_on_port "$port"); do
      echo "$p"
    done
  fi
}

is_running() {
  local name="$1"
  [[ -n "$(running_pids "$name" | head -1)" ]]
}

start_service() {
  local name="$1"
  shift
  local pf log pid port
  pf="$(pid_file "$name")"
  log="$(log_file "$name")"

  if is_running "$name"; then
    pid="$(running_pids "$name" | head -1)"
    echo "$pid" >"$pf"
    substep "$name already running (pid $pid)"
    return 0
  fi

  substep "Starting $name ..."
  "$@" >>"$log" 2>&1 &
  pid=$!
  echo "$pid" >"$pf"
  sleep 1

  if kill -0 "$pid" 2>/dev/null; then
    substep "$name running — pid $pid"
    substep "log: $log"
    return 0
  fi

  # go run spawns a child; recover listener pid from port if configured
  port="$(service_port "$name")"
  if [[ -n "$port" ]]; then
    pid="$(pids_on_port "$port" | head -1)"
    if [[ -n "$pid" ]]; then
      echo "$pid" >"$pf"
      substep "$name running — pid $pid (tracked via :$port)"
      substep "log: $log"
      return 0
    fi
  fi

  substep "$name failed to start — last log lines:"
  tail -20 "$log" >&2 || true
  if grep -qi 'permission denied\|noexec\|text file busy' "$log" 2>/dev/null; then
    substep "Hint: binaries live in DEMO_BIN_DIR=${DEMO_BIN_DIR:-$(default_demo_bin_dir)} (not RUN_DIR). If this path is not executable, set DEMO_BIN_DIR in your env file." >&2
  fi
  rm -f "$pf"
  return 1
}

stop_service() {
  local name="$1"
  local pf port killed=0
  pf="$(pid_file "$name")"

  if [[ -f "$pf" ]]; then
    local pid
    pid="$(cat "$pf")"
    if kill -0 "$pid" 2>/dev/null; then
      substep "Stopping $name (pid $pid) ..."
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      killed=1
    fi
    rm -f "$pf"
  fi

  port="$(service_port "$name")"
  if [[ -n "$port" ]]; then
    local pid
    for pid in $(pids_on_port "$port"); do
      substep "Stopping $name orphan on :$port (pid $pid) ..."
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      killed=1
    done
  fi

  if [[ "$killed" -eq 0 ]]; then
    substep "$name: not running"
  fi
}

pid_file() {
  echo "$RUN_DIR/$1.pid"
}

log_file() {
  echo "$RUN_DIR/logs/$1.log"
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
