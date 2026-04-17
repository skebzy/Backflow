#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/init-config.sh <profile> [destination]

Profiles:
  single-origin
  app-and-api
  cloudflare-origin

Examples:
  bash scripts/init-config.sh single-origin
  bash scripts/init-config.sh cloudflare-origin config/backflow.toml

This copies a shipped Backflow profile into place without touching an existing
destination file unless BACKFLOW_FORCE_INIT=1 is set.
EOF
}

PROFILE="${1:-}"
DEST="${2:-config/backflow.toml}"

if [[ -z "$PROFILE" || "$PROFILE" == "-h" || "$PROFILE" == "--help" ]]; then
  usage
  exit 0
fi

SOURCE="config/profiles/${PROFILE}.toml"
if [[ ! -f "$SOURCE" ]]; then
  echo "Unknown Backflow profile: $PROFILE" >&2
  usage
  exit 1
fi

if [[ -f "$DEST" && "${BACKFLOW_FORCE_INIT:-0}" != "1" ]]; then
  echo "Refusing to overwrite existing $DEST" >&2
  echo "Set BACKFLOW_FORCE_INIT=1 if you want to replace it." >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"
cp "$SOURCE" "$DEST"

cat <<EOF
Wrote $DEST from $SOURCE

Next:
1. Edit allow_hosts, peers, and protected_paths for your real service.
2. If you are behind another proxy, set server.trusted_proxies before going live.
3. Run: bash scripts/run-linux.sh
EOF
