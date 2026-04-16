# Filtering Model

Backflow applies multiple layers in order:

1. IP allowlist and blocklist
2. Host validation and method allowlist checks
3. Header count, header byte budget, blocked-header, and duplicate-host checks
4. URI, query, content length, smuggling, and empty-header sanity checks
5. Suspicion scoring for known-bad patterns
6. Per-IP token bucket rate limiting
7. Adaptive defense using temporary bans and concurrent request caps

## Decision modes

- `reject`: return an HTTP error response immediately
- `sinkhole`: forward the request to the sinkhole upstream pool
- `blackhole`: close the client session without a normal response

## Proxy Compatibility

Backflow can be placed behind upstream anti-DDoS layers by trusting only their proxy CIDRs and then extracting the client IP from a configured header precedence list. This is intended for providers such as Cloudflare that forward the original client IP in dedicated headers.

## Why this mix

- Hard limits cheaply stop obviously bad requests.
- Suspicion scoring catches combinations of weaker signals.
- Rate limiting controls burst pressure.
- Adaptive state prevents the same IP from hammering the proxy forever without consequence.
