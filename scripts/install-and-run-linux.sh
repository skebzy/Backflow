#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

find_run_helper() {
  if [[ -f "$ROOT_DIR/scripts/run-linux.sh" ]]; then
    printf '%s\n' "$ROOT_DIR/scripts/run-linux.sh"
    return
  fi

  local candidate
  for candidate in "$ROOT_DIR"/*; do
    [[ -d "$candidate" ]] || continue
    if [[ -f "$candidate/scripts/run-linux.sh" ]]; then
      printf '%s\n' "$candidate/scripts/run-linux.sh"
      return
    fi
  done

  return 1
}

bash "$ROOT_DIR/scripts/bootstrap-linux.sh"
RUN_HELPER="$(find_run_helper)"
exec bash "$RUN_HELPER"
