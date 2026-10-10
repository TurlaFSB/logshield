# ADR 0005: TLS termination and HTTP/2 stance

- Status: accepted
- Date: 2026-10-11

## Context

Most real traffic arrives over TLS, and clients negotiate HTTP/2 by default. A
WAF that only sees plaintext HTTP/1.1 is not deployable on its own, but HTTP/2
adds new parser-differential surface (pseudo-headers, header splitting such as
`cookie`, `Host` versus `:authority`, trailers, downgrade smuggling).

## Decision

1. LogShield terminates TLS itself (TLS 1.2 minimum, 1.3 selectable) and serves
   HTTP/2 and HTTP/1.1 from the standard library. Certificates are reloaded from
   disk when their modification time changes; a broken rotation keeps the working
   certificate and logs an error. Mutual TLS to clients is out of scope.
2. HTTP/2 is always **terminated**, never relayed: the request is decoded by Go's
   HTTP/2 server, turned into the same `http.Request` as an HTTP/1.1 request, and
   goes through the same snapshot, inspection and re-serialization path. The
   upstream hop is HTTP/1.1. No HTTP/2 frame, header block or trailer is forwarded as such.
3. The h2 differentials are covered by raw-frame tests (`h2_test.go`) that send
   what Go's client refuses to: CRLF in values, `transfer-encoding`, mismatched
   `content-length`, a `Host` header that disagrees with `:authority`, odd `:path`
   forms, `CONNECT`, trailers, cookie crumbs, and interleaved streams.
4. The https upstream is verified; verification cannot be disabled. A private CA
   bundle and a server-name override are the only knobs.
5. `MaxConcurrentStreams` is capped at 100 per connection.

## Consequences

- Trailers (HTTP/1.1 or HTTP/2) are not forwarded, so a payload placed there never
  reaches the backend; applications that depend on trailers (gRPC) are not
  supported behind this proxy.
- Under TLS the listener cannot also be wrapped to count requests that Go's server
  refuses before our handler (the wrapper would hide the `*tls.Conn` that HTTP/2
  negotiation needs). Those requests are still refused and never forwarded.
  Plain-text deployments do observe them (`protocol-error`).
- Go's HTTP/2 server mitigations (rapid reset, frame limits) are inherited, so
  keeping the Go toolchain current matters; CI builds with current stable Go and
  runs `govulncheck`.
