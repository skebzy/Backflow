# Backflow

Backflow is a modular Rust HTTP reverse proxy built around [Cloudflare Pingora](https://github.com/cloudflare/pingora), with some hot-path defense logic implemented directly in plain Rust so the filtering behavior stays fast, explicit, and easy to extend.

## What this version does

- Uses Pingora as the HTTP/HTTPS reverse proxy engine.
- Routes traffic to a primary upstream pool.
- Supports multiple named upstream pools and routing rules by host and path.
- Supports an optional sinkhole upstream pool for suspicious traffic.
- Supports host allow/block rules, method allowlists, header and body sanity checks, anomaly scoring, and sanitized forwarding headers.
- Supports CIDR-based IPv4/IPv6 trust and block rules for proxies and client filtering.
- Supports per-IP token-bucket rate limiting.
- Supports temporary bans and concurrent request caps with a plain-Rust adaptive state table.
- Supports health checks for upstream pools.
- Supports optional TLS termination on the proxy listener.
- Supports backend-facing header injection/stripping so origins can trust proxy-added metadata.

## Design target

Backflow is aimed at being a hardened HTTP reverse proxy for Linux servers, especially smaller VPS deployments where you want something fast, controlled, and readable rather than a huge appliance. It still does not replace upstream network scrubbing, host firewalling, or kernel tuning.

Pingora is primarily an HTTP-focused framework, so this project stays honest about that scope and focuses on application-layer filtering done well.

## Project layout

```text
backflow/
|-- Cargo.toml
|-- config/
|   |-- backflow.example.toml
|   `-- pingora.yaml
|-- deploy/
|   |-- backflow.service
|   `-- backflow.sysctl.conf
|-- docs/
|   |-- DEPLOYMENT.md
|   `-- FILTERING.md
|-- scripts/
|   `-- bootstrap-linux.sh
`-- src/
    |-- app.rs
    |-- config.rs
    |-- filters.rs
    |-- lib.rs
    |-- main.rs
    |-- proxy.rs
    |-- rate_limit.rs
    |-- sinkhole.rs
    `-- state.rs
```

## Configuration

Backflow reads its own TOML config from `BACKFLOW_CONFIG`, or falls back to `config/backflow.toml`.

Copy the example first:

```powershell
Copy-Item config/backflow.example.toml config/backflow.toml
```

Pingora's own server/runtime config remains separate in `config/pingora.yaml` and is passed through Pingora's built-in CLI flags. This keeps process-level tuning separate from request-defense policy.

The example config also shows:

- named pools under `pools.*`
- routing rules under `[[routes]]`
- trusted proxy CIDRs plus real-client-IP header precedence for Cloudflare-style setups
- backend header injection and internal-header stripping for protected origins
- stricter backend header sanitization for common proxy/CDN client-IP headers

## One Command On Linux

After cloning the repo:

```bash
bash scripts/install-and-run-linux.sh
```

That command will:

- install Rust with `rustup` if it is missing
- install the system C build toolchain automatically on common Linux distros when it is missing
- reuse an already-suitable Rust toolchain instead of reinstalling it every time
- detect CPU cores, memory, IPv6 availability, and file-descriptor limits
- build Backflow in release mode
- retry builds in stages so it only does expensive Cargo cleanup when lighter recovery did not work
- use sparse Cargo registry access and VPS-sized parallel build jobs automatically
- generate `config/pingora.yaml` to match the detected VPS profile
- create `config/backflow.toml` with first-run defaults if it does not exist yet
- create `scripts/run-linux.sh`
- launch Backflow immediately

If the script reports that `Cargo.toml` exists but `src/main.rs` or `src/lib.rs` does not, the VPS checkout is incomplete or you are inside the wrong directory. Re-clone the repository and rerun the installer.

## Bootstrap Only

If you want to build first and launch later:

```bash
bash scripts/bootstrap-linux.sh
```

That script will:

- install Rust with `rustup` if it is missing
- install the system C build toolchain automatically on common Linux distros when it is missing
- reuse an already-suitable Rust toolchain instead of reinstalling it every time
- detect CPU cores, memory, IPv6 availability, and file-descriptor limits
- build Backflow in release mode
- retry builds in stages so it only does expensive Cargo cleanup when lighter recovery did not work
- use sparse Cargo registry access and VPS-sized parallel build jobs automatically
- generate `config/pingora.yaml` for the detected host
- create `config/backflow.toml` with first-run defaults if needed
- create `scripts/run-linux.sh` as a simple launch helper

The detected bootstrap summary is also written to `logs/bootstrap-summary.txt`.

## Running

Once Rust is installed:

```powershell
$env:BACKFLOW_CONFIG = "config/backflow.toml"
$env:RUST_LOG = "info"
cargo run -- -c config/pingora.yaml
```

## Install Rust on Windows

If you do not already have Rust:

1. Install `rustup` from [rustup.rs](https://rustup.rs/).
2. Open a new shell.
3. Confirm:

```powershell
rustc --version
cargo --version
```

## Notes about Pingora on Windows

Pingora's own documentation says Linux is the tier-1 environment and Windows support is still preliminary. Development on Windows can still be fine, but for production you should expect Linux to be the target environment.

## Additional docs

- `docs/DEPLOYMENT.md` explains the intended Linux deployment model.
- `docs/FILTERING.md` explains how filtering decisions are made.
