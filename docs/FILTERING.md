# Filtering Model

Backflow applies multiple layers in order:

1. IP allowlist and blocklist
2. Host validation and method allowlist checks
3. Header count, header byte budget, blocked-header, and duplicate-host checks
4. URI, query, content length, traversal, and request-smuggling sanity checks
5. Signature blocking for common exploit probes and scanner paths
6. Blocking for suspicious path suffixes, high-risk backup/config file extensions, and dangerous query keys
7. Suspicion scoring for known-bad patterns and weaker attack signals
8. Per-IP token bucket rate limiting
9. Adaptive defense using temporary bans and concurrent request caps

## Decision modes

- `reject`: return an HTTP error response immediately
- `sinkhole`: either forward to a sinkhole upstream pool or return a local deceptive response with optional delay and jitter
- `blackhole`: tarpit for a configured delay and then close the client session without a normal response

## Proxy Compatibility

Backflow can be placed behind upstream anti-DDoS layers by trusting only their proxy CIDRs and then extracting the client IP from a configured header precedence list. This is intended for providers such as Cloudflare that forward the original client IP in dedicated headers.

## Why this mix

- Hard limits cheaply stop obviously bad requests.
- Protocol sanity rejects malformed transfer encodings, content-length abuse, traversal attempts, and malformed percent-encoding before they can reach an origin.
- Signature blocking catches common probes for leaked secrets, admin panels, CMS scanners, backup files, secret-bearing file extensions, and common query exploit strings such as SQLi, XSS, JNDI, and command-injection payloads.
- Suspicion scoring catches combinations of weaker signals.
- Rate limiting controls burst pressure.
- Adaptive state prevents the same IP from hammering the proxy forever without consequence.

## New practical controls

- `allow_path_prefixes` lets you declare the path surface your app actually serves.
- `block_path_suffixes` cheaply blocks fixed high-risk artifacts like `/.git/config` or `/backup.sql`.
- `block_file_extensions` rejects direct requests for backup, key, archive, and secret file types.
- `block_query_keys` shuts down obvious abuse patterns where attackers probe with `cmd`, `exec`, `token`, or `password` parameters.
- `require_user_agent` can be enabled for browser-heavy apps without forcing it on API deployments.
- `[sinkhole]` now supports `mode = "local"` for cheap deception without an extra upstream, plus tarpit delay/jitter and custom decoy headers/body.
- `[blackhole]` lets you delay connection teardown so abusive clients burn more time and expose less about your exact policy behavior.
