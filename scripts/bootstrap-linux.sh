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

need_any_cmd() {
  local cmd
  for cmd in "$@"; do
    if need_cmd "$cmd"; then
      return 0
    fi
  done
  return 1
}

has_rust_targets() {
  local dir="$1"
  [[ -f "$dir/src/main.rs" || -f "$dir/src/lib.rs" ]]
}

resolve_project_root() {
  if [[ -f "$ROOT_DIR/Cargo.toml" ]] && has_rust_targets "$ROOT_DIR"; then
    return
  fi

  local matches=()
  local candidate
  for candidate in "$ROOT_DIR"/*; do
    [[ -d "$candidate" ]] || continue
    if [[ -f "$candidate/Cargo.toml" ]] && has_rust_targets "$candidate"; then
      matches+=("$candidate")
    fi
  done

  if [[ "${#matches[@]}" -eq 1 ]]; then
    ROOT_DIR="${matches[0]}"
    cd "$ROOT_DIR"
    echo "Detected Backflow project files in nested directory: $ROOT_DIR"
    return
  fi

  echo "Backflow project files were not found in: $ROOT_DIR"
  echo "Expected Cargo.toml plus src/main.rs or src/lib.rs."
  echo "This usually means the VPS checkout is incomplete or you are running the script from the wrong clone."
  echo "Re-clone the repository, then rerun the script."
  exit 1
}

have_sudo() {
  need_cmd sudo && sudo -n true >/dev/null 2>&1
}

install_system_build_tools() {
  if need_cmd cc && need_cmd c++ && need_cmd make && need_cmd cmake && need_any_cmd pkg-config pkgconf && need_cmd perl; then
    return
  fi

  echo "Required native build tools are missing. Installing system build tools..."

  if [[ -f /etc/debian_version ]]; then
    if have_sudo; then
      sudo apt-get update
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        clang \
        cmake \
        perl \
        libssl-dev \
        ca-certificates
      return
    fi

    echo "Missing native build tools. Run:"
    echo "  sudo apt-get update && sudo apt-get install -y build-essential pkg-config clang cmake perl libssl-dev ca-certificates"
    exit 1
  fi

  if [[ -f /etc/redhat-release ]]; then
    if have_sudo; then
      if need_cmd dnf; then
        sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config clang cmake perl openssl-devel ca-certificates
      else
        sudo yum install -y gcc gcc-c++ make pkgconfig clang cmake perl openssl-devel ca-certificates
      fi
      return
    fi

    echo "Missing native build tools. Install gcc/g++/make/pkgconfig/clang/cmake/perl/openssl-devel with your package manager."
    exit 1
  fi

  if [[ -f /etc/alpine-release ]]; then
    if have_sudo; then
      sudo apk add --no-cache build-base pkgconf clang cmake perl openssl-dev ca-certificates
      return
    fi

    echo "Missing native build tools. Run:"
    echo "  sudo apk add --no-cache build-base pkgconf clang cmake perl openssl-dev ca-certificates"
    exit 1
  fi

  echo "Missing native build tools and unsupported distro auto-install path."
  echo "Install a C/C++ compiler toolchain plus cmake, pkg-config, perl, OpenSSL headers, and CA certificates, then rerun this script."
  exit 1
}

clean_cargo_state() {
  echo "Cleaning local Cargo build state..."
  rm -rf target
}

clean_cargo_registry_state() {
  echo "Cleaning Cargo registry cache and extracted sources..."
  rm -rf "$HOME/.cargo/registry/index" \
         "$HOME/.cargo/registry/cache" \
         "$HOME/.cargo/registry/src"
}

load_rust_env() {
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
}

rust_version_meets_minimum() {
  local current major minor
  current="$(rustc -V 2>/dev/null | awk '{print $2}')"
  major="${current%%.*}"
  minor="$(echo "$current" | cut -d. -f2)"

  if [[ -z "$major" || -z "$minor" ]]; then
    return 1
  fi

  if (( major > 1 )); then
    return 0
  fi

  (( minor >= 85 ))
}

install_rust() {
  load_rust_env
  if ! need_cmd curl; then
    echo "Rust is missing and curl is not installed. Install curl or rustup manually first."
    exit 1
  fi

  if ! need_cmd rustup; then
    echo "Rust toolchain not found. Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    load_rust_env
  fi

  rustup set profile minimal
  rustup set auto-self-update disable
  if ! need_cmd rustc || ! need_cmd cargo || ! rust_version_meets_minimum; then
    echo "Installing or updating the stable Rust toolchain..."
    rustup toolchain install stable --profile minimal --no-self-update
  else
    echo "Rust toolchain already satisfies the project minimum."
  fi
  rustup override set stable >/dev/null
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

pick_build_jobs() {
  local cores="$1"
  local mem_mb="$2"
  local jobs="$cores"

  if (( mem_mb < 2048 && jobs > 2 )); then
    jobs=2
  elif (( mem_mb < 4096 && jobs > 4 )); then
    jobs=4
  elif (( jobs > 8 )); then
    jobs=8
  fi

  if (( jobs < 1 )); then
    jobs=1
  fi

  echo "$jobs"
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
  mkdir -p logs scripts config deploy docs
}

write_demo_origin_helper() {
  cat > scripts/demo-origin.py <<'EOF'
#!/usr/bin/env python3
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoOriginHandler(BaseHTTPRequestHandler):
    server_version = "BackflowDemoOrigin/1.0"
    sys_version = ""

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/healthz", "/readyz"):
            payload = json.dumps({"ok": True, "service": "backflow-demo-origin"}).encode()
            self._write(200, payload, "application/json")
            return

        body = (
            "Backflow demo origin is running on 127.0.0.1:9000.\n"
            "Point primary.peers at your real application when you are ready.\n"
        ).encode()
        self._write(200, body, "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 9000), DemoOriginHandler)
    server.serve_forever()
EOF
  chmod +x scripts/demo-origin.py
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

[sinkhole]
enabled = false

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
  "X-Forwarded-Port",
  "X-Real-IP",
  "True-Client-IP",
  "CF-Connecting-IP",
  "CF-Connecting-IPv6",
  "Forwarded",
]
set_forwarded_port = true
EOF

  echo "Created config/backflow.toml from detected host defaults."
  echo "The default first run expects a localhost demo origin on 127.0.0.1:9000 until you point primary.peers at your real app."
}

write_runtime_helper() {
  cat > scripts/run-linux.sh <<'EOF'
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
  local build_jobs="$8"

  cat > logs/bootstrap-summary.txt <<EOF
cpu_cores=$cores
memory_mb=$mem_mb
ipv6_enabled=$ipv6_enabled
fd_limit=$fd_limit
recommended_threads=$threads
recommended_requests_per_period=$rate_limit
recommended_concurrency_cap=$concurrency_cap
recommended_build_jobs=$build_jobs
EOF
}

configure_cargo_environment() {
  local build_jobs="$1"

  export CARGO_BUILD_JOBS="$build_jobs"
  export CARGO_REGISTRIES_CRATES_IO_PROTOCOL="sparse"
  export CARGO_NET_GIT_FETCH_WITH_CLI="true"
}

build_release() {
  local build_jobs="$1"
  echo "Building Backflow in release mode..."
  configure_cargo_environment "$build_jobs"

  if cargo build --release --locked; then
    return
  fi

  echo "Initial build failed. Refreshing the stable toolchain and retrying before deeper cleanup..."
  rustup update stable
  rustup override set stable
  clean_cargo_state
  if cargo build --release --locked; then
    return
  fi

  echo "Retry still failed. Clearing stale Cargo registry state and trying again..."
  clean_cargo_registry_state
  if cargo build --release --locked; then
    return
  fi

  if [[ ! -f Cargo.lock ]]; then
    echo "Cargo.lock is missing, refreshing dependency resolution..."
    cargo update
    cargo build --release
    return
  fi

  echo "Build still failed after automated recovery."
  return 1
}

print_next_steps() {
  local cores="$1"
  local mem_mb="$2"
  local ipv6_enabled="$3"
  local fd_limit="$4"
  local threads="$5"
  local rate_limit="$6"
  local concurrency_cap="$7"
  local build_jobs="$8"

  cat <<EOF

Backflow build complete.

Detected host profile:
- CPU cores: $cores
- Memory: ${mem_mb} MB
- IPv6 enabled: $ipv6_enabled
- Open file limit: $fd_limit
- Pingora worker threads selected: $threads
- Cargo build jobs selected: $build_jobs
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
- The default first run auto-starts a tiny demo origin on 127.0.0.1:9000 when that port is unused.
- It still does not make a small VPS immune to upstream bandwidth saturation.
EOF
}

main() {
  resolve_project_root
  prepare_layout
  install_rust
  install_system_build_tools

  local cores mem_mb ipv6_enabled fd_limit threads rate_limit concurrency_cap build_jobs
  cores="$(detect_cpu_cores)"
  mem_mb="$(detect_mem_mb)"
  ipv6_enabled="$(detect_ipv6_enabled)"
  fd_limit="$(detect_fd_limit)"
  threads="$(pick_threads "$cores" "$mem_mb")"
  build_jobs="$(pick_build_jobs "$cores" "$mem_mb")"
  rate_limit="$(pick_rate_limit "$cores" "$mem_mb")"
  concurrency_cap="$(pick_concurrency_cap "$cores")"

  render_pingora_config "$threads"
  render_backflow_config "$rate_limit" "$concurrency_cap" "$ipv6_enabled"
  write_demo_origin_helper
  write_runtime_helper
  write_summary "$cores" "$mem_mb" "$ipv6_enabled" "$fd_limit" "$threads" "$rate_limit" "$concurrency_cap" "$build_jobs"
  build_release "$build_jobs"
  print_next_steps "$cores" "$mem_mb" "$ipv6_enabled" "$fd_limit" "$threads" "$rate_limit" "$concurrency_cap" "$build_jobs"
}

main "$@"
