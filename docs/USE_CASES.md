# Use Cases

## Best-Fit Deployment

Backflow is strongest as a small HTTP edge for a small number of services.

The most practical pattern is:

1. Bind the real app to `127.0.0.1` or a private subnet.
2. Put Backflow on the public port.
3. Let Backflow reject junk before the app sees it.
4. Keep the config static and boring.

Useful extras:

- keep `/healthz` and `/readyz` enabled for process checks
- protect `/admin` or similar routes with `[[protected_paths]]`
- use `[maintenance]` instead of changing upstreams by hand during planned work

## Pattern 1: One Public App, One Private Origin

Use this when:

- you have one app
- you want a stricter edge than a bare app server
- you want the origin hidden from direct public access

Use `config/profiles/single-origin.toml`.

## Pattern 2: App Plus API

Use this when:

- the browser app and API should go to different backends
- you want host-based or path-based routing
- you still want one front door

Use `config/profiles/app-and-api.toml`.

## Pattern 3: Origin Behind Cloudflare

Use this when:

- Cloudflare is already in front
- you still want the origin to reject malformed and obviously hostile traffic
- you want stricter forwarding-header handling before requests reach the app

In that model, Backflow is not your DDoS provider. It is your origin gatekeeper.

## When Not To Use It

Do not choose Backflow just because Pingora sounds fast.

Pick something else if:

- you want automatic TLS management first and foremost
- you need dynamic discovery and platform integrations
- you want a broadly standardized edge your team already knows
- you need an L4 or network-wide defense product
