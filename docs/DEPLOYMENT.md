# Deployment Guide

Backflow is designed as an HTTP reverse proxy for Linux production environments. Pingora itself treats Linux as the primary deployment target, so that should also be your expectation for real traffic.

## Recommended layout on an 8 GB VPS

- Run Backflow directly on the edge host.
- Keep the origin service bound to localhost or a private network only.
- Put logs on disk with rotation.
- Terminate TLS at Backflow unless you intentionally want passthrough elsewhere.
- Start with a small thread count and increase only after measurement.
- Allow only trusted upstream anti-DDoS providers or partners to reach the origin whenever possible.

## Fast bootstrap

From a fresh clone on Linux:

```bash
bash scripts/install-and-run-linux.sh
```

If you want to prepare everything without starting the service yet:

```bash
bash scripts/bootstrap-linux.sh
```

The repository also includes:

- `deploy/backflow.service` for `systemd`
- `deploy/backflow.sysctl.conf` for host networking defaults

The bootstrap scripts automatically detect:

- CPU core count
- total memory
- IPv6 availability
- current file-descriptor limit

They then use that information to generate the initial `config/pingora.yaml` and first-run `config/backflow.toml` defaults.

On that first generated config, `scripts/run-linux.sh` will also auto-start a tiny localhost demo origin on `127.0.0.1:9000` when that port is unused. That keeps the default bootstrap path healthy until you replace `primary.peers` with your real application.

The bootstrap also installs the native build toolchain, including `cmake`, `pkg-config`, `perl`, OpenSSL development headers, and CA certificates when possible, reuses a suitable stable Rust toolchain when one is already present, and if the first build fails it retries in stages before doing heavier Cargo cache cleanup.

## Basic rollout steps

1. Install Rust with `rustup`, then build in release mode.
2. Copy `config/backflow.example.toml` to `config/backflow.toml`.
3. Restrict `allow_hosts` to the exact domains you serve.
4. Point `primary.peers` at your real origin addresses.
5. Either disable sinkhole mode or point `sinkhole.peers` at a cheap internal responder.
6. Run with `RUST_LOG=info` at first, then reduce verbosity if logs become noisy.

## System-level hardening that still matters

This project is only one layer. For an exposed VPS you should still tune:

- `ufw` or `nftables`
- connection tracking limits
- file descriptor limits
- socket backlog and TCP kernel settings
- origin binding so the app is not directly exposed
- log rotation
- process supervision with `systemd`
- upstream IP allowlisting so direct-to-origin bypass is blocked

## Operational truth

Application-layer filtering is good at rejecting malformed, abusive, and obviously automated HTTP traffic. It does not replace upstream bandwidth protection. If the link itself is saturated, your proxy code does not get a chance to be clever.
