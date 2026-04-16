#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export BACKFLOW_CONFIG="${BACKFLOW_CONFIG:-config/backflow.toml}"
export RUST_LOG="${RUST_LOG:-info}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

port_is_listening() {
  local port="$1"

  if need_cmd ss; then
    ss -ltn "( sport = :$port )" | grep -q ":$port"
    return
  fi

  if need_cmd netstat; then
    netstat -ltn 2>/dev/null | grep -q "[.:]$port[[:space:]]"
    return
  fi

  return 1
}

config_uses_default_demo_origin() {
  [[ -f "$BACKFLOW_CONFIG" ]] || return 1
  grep -q '"127.0.0.1:9000"' "$BACKFLOW_CONFIG"
}

cleanup() {
  if [[ -n "${DEMO_ORIGIN_PID:-}" ]] && kill -0 "$DEMO_ORIGIN_PID" >/dev/null 2>&1; then
    kill "$DEMO_ORIGIN_PID" >/dev/null 2>&1 || true
    wait "$DEMO_ORIGIN_PID" 2>/dev/null || true
  fi
}

maybe_start_demo_origin() {
  if [[ "${BACKFLOW_AUTO_DEMO_ORIGIN:-1}" == "0" ]]; then
    return
  fi

  if ! config_uses_default_demo_origin; then
    return
  fi

  if port_is_listening 9000; then
    return
  fi

  if ! need_cmd python3; then
    echo "Backflow default config points at 127.0.0.1:9000, but python3 is not installed for the demo origin." >&2
    echo "Install python3 or edit $BACKFLOW_CONFIG so primary.peers points at your real application." >&2
    exit 1
  fi

  python3 "$ROOT_DIR/scripts/demo-origin.py" &
  DEMO_ORIGIN_PID="$!"
  trap cleanup EXIT INT TERM
  echo "Started Backflow demo origin on 127.0.0.1:9000 for first-run traffic."
}

maybe_start_demo_origin

exec ./target/release/backflow -c config/pingora.yaml
