#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8080}"
HOST_HEADER="${BACKFLOW_SMOKE_HOST:-app.example.com}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_cmd curl; then
  echo "curl is required for smoke testing." >&2
  exit 1
fi

check_status() {
  local label="$1"
  local expected="$2"
  local url="$3"
  local actual
  actual="$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$url")"

  if [[ "$actual" != "$expected" ]]; then
    echo "FAIL: $label expected $expected got $actual" >&2
    exit 1
  fi

  echo "PASS: $label -> $actual"
}

echo "Smoke testing Backflow at $BASE_URL with Host: $HOST_HEADER"
check_status "health endpoint" "200" "$BASE_URL/healthz"
check_status "readiness endpoint" "200" "$BASE_URL/readyz"
check_status "basic request" "200" "$BASE_URL/"
check_status "secret probe blocked" "403" "$BASE_URL/.env"
check_status "traversal blocked" "403" "$BASE_URL/../../etc/passwd"
check_status "malicious query blocked" "403" "$BASE_URL/?id=1%20union%20select%20password"

echo "Smoke test complete."
