#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This bootstrap script is intended for Linux hosts."
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

load_rust_env() {
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
}

install_rust() {
  load_rust_env
  if need_cmd cargo && need_cmd rustc; then
    return
  fi

  if ! need_cmd curl; then
    echo "Rust is missing and curl is not installed. Install curl or rustup manually first."
    exit 1
  fi

  echo "Rust toolchain not found. Installing rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  load_rust_env
}

detect_cpu_cores() {
  if need_cmd nproc; then
    nproc
    return
  fi

  getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2
}

detect_mem_mb() {
  awk '/MemTotal:/ { printf "%d\n", $2 / 1024 }' /proc/meminfo 2>/dev/null || echo 2048
}

detect_ipv6_enabled() {
  if [[ -s /proc/net/if_inet6 ]]; then
    echo 1
  else
    echo 0
  fi
}

detect_fd_limit() {
  ulimit -n 2>/dev/null || echo 65535
}

pick_threads() {
  local cores="$1"
  local mem_mb="$2"
  local threads="$cores"

  if (( threads < 2 )); then
    threads=2
  fi

  if (( mem_mb < 2048 && threads > 2 )); then
    threads=2
  elif (( mem_mb < 4096 && threads > 4 )); then
    threads=4
  elif (( mem_mb < 8192 && threads > 6 )); then
    threads=6
  elif (( threads > 8 )); then
    threads=8
  fi

  echo "$threads"
}

pick_rate_limit() {
  local cores="$1"
  local mem_mb="$2"
  local base=$((120 * cores))

  if (( mem_mb < 2048 )); then
    base=$((base / 2))
  fi

  if (( base < 120 )); then
    base=120
  fi

  echo "$base"
}

pick_concurrency_cap() {
  local cores="$1"
  local cap=$((cores * 32))

  if (( cap < 24 )); then
    cap=24
  elif (( cap > 256 )); then
    cap=256
  fi

  echo "$cap"
}

prepare_layout() {
  mkdir -p logs scripts config deploy docs src
}

render_pingora_config() {
  local threads="$1"
  cat > config/pingora.yaml <<EOF
---
version: 1
threads: $threads
work_stealing: true
daemon: false
error_log: ./logs/backflow-error.log
upgrade_sock: ./logs/backflow-upgrade.sock
pid_file: ./logs/backflow.pid
EOF
}

render_backflow_config() {
  local rate_limit="$1"
  local concurrency_cap="$2"
  local ipv6_enabled="$3"

  if [[ -f config/backflow.toml ]]; then
    return
  fi

  cat > config/backflow.toml <<EOF
[server]
response_server_header = "Backflow"
trusted_proxies = []
client_ip_headers = ["CF-Connecting-IPv6", "CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For", "X-Real-IP"]
strict_proxy_headers = true

[[server.listeners]]
addr = "0.0.0.0:8080"
EOF

  if [[ "$ipv6_enabled" == "1" ]]; then
    cat >> config/backflow.toml <<'EOF'

[[server.listeners]]
addr = "[::]:8080"
EOF
  fi

  cat >> config/backflow.toml <<EOF

[primary]
name = "origin"
host_header = "origin.internal"
sni = "origin.internal"
use_tls = false
peers = [
  "127.0.0.1:9000",
]

[health_checks]
enabled = true
frequency_secs = 3

[filters]
default_action = "reject"
allow_ips = ["127.0.0.1", "::1"]
block_ips = []
allow_hosts = []
block_hosts = []
require_host_header = true
allow_methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
block_user_agents = ["masscan", "zgrab"]
block_header_names = ["x-original-url", "x-rewrite-url"]
trusted_user_agents = []
skip_rate_limit_paths = ["/healthz", "/readyz"]
strip_connection_headers = true
reject_underscored_headers = true
reject_multiple_host_headers = true
reject_conflicting_content_headers = true
reject_invalid_host_header = true
max_header_count = 96
max_header_bytes = 16384
max_path_length = 2048
max_query_length = 4096
max_content_length = 8388608
max_empty_headers = 8
max_repeated_path_chars = 24
max_suspicion_score = 5
empty_user_agent_score = 1
odd_method_score = 2
encoded_path_score = 2
header_spike_score = 2
query_spike_score = 2
empty_header_score = 1
blocked_ua_score = 3
repeated_path_score = 2
reject_status = 403
reject_body = "blocked by backflow"

[rate_limit]
enabled = true
requests_per_period = $rate_limit
burst = $((rate_limit * 2))
period_secs = 10
exceeded_action = "reject"
reject_status = 429
reject_body = "rate limit exceeded"

[adaptive]
enabled = true
max_concurrent_requests_per_ip = $concurrency_cap
concurrency_action = "reject"
strike_threshold = 6
ban_secs = 300
ban_action = "blackhole"

[backend]
inject_headers = {}
strip_inbound_internal_headers = [
  "X-Backflow-Client-IP",
  "X-Backflow-Decision",
  "X-Backflow-Pool",
  "X-Forwarded-For",
  "X-Forwarded-Host",
  "X-Forwarded-Proto",
  "Forwarded",
]
EOF

  echo "Created config/backflow.toml from detected host defaults."
}

write_runtime_helper() {
  cat > scripts/run-linux.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export BACKFLOW_CONFIG="${BACKFLOW_CONFIG:-config/backflow.toml}"
export RUST_LOG="${RUST_LOG:-info}"

exec ./target/release/backflow -- -c config/pingora.yaml
EOF
  chmod +x scripts/run-linux.sh
}

write_summary() {
  local cores="$1"
  local mem_mb="$2"
  local ipv6_enabled="$3"
  local fd_limit="$4"
  local threads="$5"
  local rate_limit="$6"
  local concurrency_cap="$7"

  cat > logs/bootstrap-summary.txt <<EOF
cpu_cores=$cores
memory_mb=$mem_mb
ipv6_enabled=$ipv6_enabled
fd_limit=$fd_limit
recommended_threads=$threads
recommended_requests_per_period=$rate_limit
recommended_concurrency_cap=$concurrency_cap
EOF
}

build_release() {
  echo "Building Backflow in release mode..."
  cargo build --release
}

print_next_steps() {
  local cores="$1"
  local mem_mb="$2"
  local ipv6_enabled="$3"
  local fd_limit="$4"
  local threads="$5"
  local rate_limit="$6"
  local concurrency_cap="$7"

  cat <<EOF

Backflow build complete.

Detected host profile:
- CPU cores: $cores
- Memory: ${mem_mb} MB
- IPv6 enabled: $ipv6_enabled
- Open file limit: $fd_limit
- Pingora worker threads selected: $threads
- Rate-limit baseline selected: $rate_limit requests per 10s
- Per-IP concurrency cap selected: $concurrency_cap

Next steps:
1. Edit config/backflow.toml for your real domains, upstream peers, and trusted proxy CIDRs.
2. Review deploy/backflow.sysctl.conf before applying it on the host.
3. Start the proxy with:
   bash scripts/run-linux.sh

Optional:
- Install the service template:
  sudo cp deploy/backflow.service /etc/systemd/system/backflow.service
  sudo systemctl daemon-reload
  sudo systemctl enable --now backflow
- Apply sysctl tuning:
  sudo cp deploy/backflow.sysctl.conf /etc/sysctl.d/99-backflow.conf
  sudo sysctl --system

Important:
- This tunes the initial setup to the VPS shape.
- It still does not make a small VPS immune to upstream bandwidth saturation.
EOF
}

main() {
  prepare_layout
  install_rust

  local cores mem_mb ipv6_enabled fd_limit threads rate_limit concurrency_cap
  cores="$(detect_cpu_cores)"
  mem_mb="$(detect_mem_mb)"
  ipv6_enabled="$(detect_ipv6_enabled)"
  fd_limit="$(detect_fd_limit)"
  threads="$(pick_threads "$cores" "$mem_mb")"
  rate_limit="$(pick_rate_limit "$cores" "$mem_mb")"
  concurrency_cap="$(pick_concurrency_cap "$cores")"

  render_pingora_config "$threads"
  render_backflow_config "$rate_limit" "$concurrency_cap" "$ipv6_enabled"
  write_runtime_helper
  write_summary "$cores" "$mem_mb" "$ipv6_enabled" "$fd_limit" "$threads" "$rate_limit" "$concurrency_cap"
  build_release
  print_next_steps "$cores" "$mem_mb" "$ipv6_enabled" "$fd_limit" "$threads" "$rate_limit" "$concurrency_cap"
}

main "$@"
