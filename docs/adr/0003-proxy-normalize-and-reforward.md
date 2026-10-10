# ADR 0003: Proxy built on net/http, normalize and re-forward

- Status: accepted
- Date: 2026-10-10

## Context

The proxy must forward exactly what the engine inspected. A raw TCP relay that
inspects bytes in flight would have to implement HTTP framing itself, and any
disagreement with the backend (smuggling, obs-fold, duplicate headers) becomes
a bypass. A WAF that is itself a new parser differential defeats the purpose.

## Decision

1. Use the standard library (`net/http`, `httputil.ReverseProxy`); no third-party
   dependencies in the proxy.
2. Parse once, inspect a snapshot, and forward a **freshly serialized** request:
   one `Content-Length`, no `Transfer-Encoding` or trailers, target sent verbatim.
3. Reject requests that cannot be forwarded unambiguously instead of repairing them.
4. Add a final `RoundTripper` guard that verifies the outbound request equals the
   inspected snapshot plus a fixed set of generated headers, failing with 502.
5. Default to monitor mode; block mode is explicit.

## Consequences

- Smuggling-style differentials toward the backend are removed by construction.
- Some unusual but legal requests (CONNECT, Upgrade, absolute-form) are refused.
- Go-level parse rejections happen before our handler and are not observable.
- Depending on the standard library means Go security releases matter: CI builds
  with current stable and `govulncheck` runs on it.
