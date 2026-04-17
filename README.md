# Backflow

Backflow is a small Rust reverse proxy for people who want to put a stricter HTTP edge in front of a private app, API, or self-hosted service without dragging in a giant control plane.

It is built on [Cloudflare Pingora](https://github.com/cloudflare/pingora), but the value of this project is not "Pingora in a different wrapper." The point is to ship a focused edge proxy that does a few things well:

- routes HTTP traffic to one or more private upstreams
- rejects a lot of noisy or hostile traffic early
- keeps backend-facing headers predictable
- stays readable enough that you can actually change the rules
- exposes built-in health and readiness endpoints
- propagates request IDs for tracing across the edge and origin
- supports maintenance windows and IP-protected path prefixes

This is a Linux-first project. Windows is fine for editing and experimenting, but if you are putting this on the internet, assume Linux is the real target.

## What It Is Good For

Backflow makes the most sense when you have a small number of services and you care more about edge hygiene than about having a full gateway platform.

Good fits:

- a single VPS running a private app on `127.0.0.1:9000`
- one public hostname for the app and another for the API
- a service behind Cloudflare or another upstream proxy where you still want strict origin-side request filtering
- an origin that keeps getting hammered by scanners, cheap bots, exploit probes, or junk traffic

Bad fits:

- L4 DDoS defense
- huge dynamic service discovery setups
- Kubernetes ingress replacement
- environments where you mainly want a polished UI and batteries-included certificate automation

## Why Use This Instead Of Something Else

### Backflow vs Nginx

Nginx is still the default answer for a reason. It is mature, fast, and everywhere.

Backflow is better when you want:

- a codebase built around request filtering as a first-class concern instead of a pile of location blocks
- clearer control over suspicious-request scoring, sinkholing, and adaptive bans
- a smaller project surface dedicated to "protect the origin and route traffic"

Nginx is better when you want:

- broad ecosystem support
- lots of battle-tested modules
- a tool your whole team already knows

### Backflow vs Caddy

Caddy is easier when TLS automation and quick setup matter most.

Backflow is better when you want a more opinionated hostile-edge proxy with stricter request validation and custom abuse logic.

### Backflow vs Traefik or Envoy

Traefik and Envoy are stronger choices when you need service discovery, richer gateway features, or bigger platform integration.

Backflow is better when you want a smaller box:

- static config
- predictable routing
- focused filtering
- no control-plane story to babysit

## Real Use Cases

### 1. Shield a private web app on one VPS

- Backflow listens on `:80` or `:443`
- your real app stays on `127.0.0.1:9000`
- Backflow filters junk requests before they hit the app

Start with: `config/profiles/single-origin.toml`

### 2. Split app and API traffic cleanly

- `app.example.com` goes to one upstream pool
- `api.example.com` or `/api/` goes to another
- you keep one small edge process instead of separate front doors

Start with: `config/profiles/app-and-api.toml`

### 3. Put a stricter origin behind Cloudflare

- trust only Cloudflare CIDRs
- extract the real client IP from forwarded headers
- keep scanner junk and malformed requests away from your origin app

The example config shows the trust and header model. The filtering model is explained in `docs/FILTERING.md`.

## Quick Start

On Linux:

```bash
bash scripts/install-and-run-linux.sh
```

That bootstrap path installs the toolchain if needed, builds Backflow, writes a runnable config when one does not exist, and starts the proxy. If the generated config still points at the default localhost origin, the helper script starts a tiny demo origin so you can verify the proxy path before wiring in your real app.

If you want to bootstrap without starting the process yet:

```bash
bash scripts/bootstrap-linux.sh
```

Then copy a profile or the example config:

```bash
cp config/profiles/single-origin.toml config/backflow.toml
```

Point `primary.peers` at your real service and run:

```bash
bash scripts/run-linux.sh
```

## Smoke Test

Once the proxy is running:

```bash
bash scripts/smoke-test.sh http://127.0.0.1:8080
```

That script checks that normal traffic passes and a few common hostile requests get blocked.

## Features That Matter In Practice

- Built-in `/healthz` and `/readyz` endpoints so you can plug Backflow into simple uptime checks and process supervision.
- Request ID propagation via `X-Request-ID` and `X-Correlation-ID` so backend logs can be tied back to edge traffic.
- Maintenance mode with allowlisted IPs and allowed path prefixes for controlled rollouts.
- Path-level protection rules for things like `/admin`, internal dashboards, or debug endpoints.
- Configurable response header hardening so you can strip noisy upstream headers and add sane browser-facing defaults.

## Repo Map

The structure is small on purpose.

- `config/`: runnable proxy configs and copy-paste starting points
- `config/profiles/`: practical starting configs for common deployments
- `scripts/`: bootstrap, run, and smoke-test helpers
- `deploy/`: systemd and sysctl files for a real Linux host
- `docs/`: operator docs, filtering notes, and deployment guidance
- `src/`: the actual proxy, routing, filtering, rate-limit, and adaptive-defense code

There is no big "platform" layer here because the project is meant to stay understandable. If you need a graph of ten subsystems to reason about the edge, this stops being the kind of tool Backflow is trying to be.

## Configuration

Backflow reads its policy config from `BACKFLOW_CONFIG` and defaults to `config/backflow.toml`.

Pingora runtime settings stay in `config/pingora.yaml`. That split is intentional:

- `backflow.toml` is about traffic policy and upstream behavior
- `pingora.yaml` is about process-level runtime tuning

If you are starting from scratch, use one of these:

- `config/profiles/single-origin.toml`
- `config/profiles/app-and-api.toml`
- `config/backflow.example.toml`

Useful config sections beyond filters:

- `[trace]`
- `[response]`
- `[maintenance]`
- `[internal_endpoints]`
- `[[protected_paths]]`

## Operational Notes

- This helps with abusive HTTP traffic, not link saturation.
- Keep the real origin bound to localhost or private addresses.
- Put it under `systemd` if it matters.
- Use upstream filtering too if you are exposed to serious traffic.

## Further Reading

- `docs/DEPLOYMENT.md`
- `docs/FILTERING.md`
- `docs/USE_CASES.md`
