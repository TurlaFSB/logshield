# Proxy

`logshield` is a reverse proxy: it buffers each request, asks the engine for a
verdict, and either forwards the request to one upstream or answers itself.
This page describes what it guarantees and, just as important, what it does not.

## Usage

```
logshield -upstream http://10.0.0.5:8080 -listen 127.0.0.1:8080 -mode block
```

| Flag | Default | Meaning |
|---|---|---|
| `-upstream` | required | Backend URL (`http` or `https`, no path). |
| `-listen` | `127.0.0.1:8080` | Listen address. Loopback by default on purpose. |
| `-mode` | `monitor` | `monitor` logs detections; `block` also rejects them. |
| `-block-suspicious` | off | In block mode, also reject `suspicious` verdicts. |
| `-on-error` | `closed` | Block mode only: what to do if inspection itself fails. |
| `-max-body` | 1 MiB | Largest body that is buffered and inspected. |
| `-skip-body-type` | none | Media type whose body is streamed uninspected (repeatable). |
| `-forwarded-for` | `replace` | `replace`, `append` or `off`. |
| `-rewrite-host` | off | Send the upstream's host instead of the client's. |
| `-admin-listen` | off | `/metrics`, `/healthz`, `/readyz` listener; see [observability](observability.md). |
| `-max-in-flight` | 1024 | Concurrency limit; excess requests get `503`. `-1` disables. |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `-config`, `-check-config`, `-disable-rule` | | File-based configuration, validation, rule tuning: see [configuration](configuration.md). |

**Monitor is the default** so a first deployment cannot break traffic. The
process says so at startup. Use `-mode block` once the logs look right.

Exit codes: `0` clean shutdown, `1` runtime failure, `2` usage or configuration error.

## Request lifecycle

1. **Reject what cannot be forwarded unambiguously**: `CONNECT` and `Upgrade`
   (501), non-origin-form targets, targets starting with `//`, and targets
   containing `#` (400).
2. **Buffer the body** up to `-max-body`. Oversize bodies: in block mode, 413;
   in monitor mode the prefix is inspected and the whole body is streamed.
3. **Snapshot** the request: method, target, `Host`, every header (including
   hop-by-hop ones and the `Transfer-Encoding` that Go's server hides), body.
4. **Inspect** with the engine (panics are recovered and treated as inspection errors).
5. **Decide** by mode and policy; on block, answer with a fixed body and a request ID.
6. **Forward** a normalized request built from the same snapshot.

## Why the proxy re-serializes requests

Most WAF bypasses are parser differentials: the WAF sees one request, the
backend another. Request smuggling (`Content-Length` vs `Transfer-Encoding`)
is the classic case. The proxy never relays the client's framing. It parses the
request once with Go's HTTP server, forwards a freshly serialized request with a
single `Content-Length`, drops `Transfer-Encoding` and trailers, and sends the
request target verbatim (so `%24%7B` stays as the client wrote it and is not
silently normalized between inspection and forwarding). See
[ADR 0003](adr/0003-proxy-normalize-and-reforward.md).

## The forwarded == inspected guard

The last hop before the network is a `RoundTripper` that checks the outbound
request against the snapshot that was inspected: method, destination, target,
`Host`, and body must match, and every header must be one the engine saw or one
the proxy generated (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`,
`X-Request-Id`). Anything else is a bug and produces a 502, not a forward. Tests
mutate requests at each stage to prove the guard trips.

## TLS and HTTP/2

With `-tls-cert` and `-tls-key` the proxy serves HTTPS (TLS 1.2+, `-tls-min-version
1.3` to require 1.3), negotiating HTTP/2 or HTTP/1.1. HTTP/2 is terminated, not
relayed: each stream becomes an ordinary request that is inspected, re-serialized
and sent to the upstream over HTTP/1.1, so `:authority`, `cookie` crumbs, trailers
and pseudo-headers cannot create a difference between what was inspected and what
the backend receives. Details and the tested cases are in
[ADR 0005](adr/0005-tls-termination-and-http2.md). Behavior worth knowing:

- Trailers are never forwarded (gRPC is not supported behind the proxy).
- `Transfer-Encoding`, CRLF in header values and a `Content-Length` that disagrees
  with the data are refused by the HTTP/2 layer before the handler.
- A `Host` header that differs from `:authority` is inspected like any other header.
- Under TLS, requests the HTTP server refuses before the handler are refused but
  not counted as `protocol-error` (see the ADR).

## Policies

- **Mode**: `monitor` never blocks. `block` rejects `malicious`.
- **`-block-suspicious`**: also rejects `suspicious` (for example a lookup that
  could be JNDI but resolves to something unknown). Off by default to protect
  availability; turn it on for hosts where false positives are cheaper than misses.
- **`-on-error`** applies only to *inspection failures* (a bug, a panic). Engine
  verdicts, including budget exhaustion, are never fail-open: a request that
  exhausts the decoder budget is `malicious` by design.

## Logging safety

Log lines can themselves be a Log4Shell vector when they reach a vulnerable
log pipeline. Every string the proxy logs passes through a handler that rewrites
`${` to `$%7B`; evidence from the engine is already defanged at source. The
query string is never logged, only the path and the query length. At most 8
detections are logged per request.

## Hardening

Server timeouts (header 10 s, read 30 s, idle 90 s), 64 KiB header limit,
environment proxy variables ignored for the upstream, response compression
disabled so bodies are relayed as-is, graceful shutdown on `SIGINT`/`SIGTERM`
(15 s).

## Tested against real servers

`make integration` runs the proxy in front of Node.js (llhttp), Python's
`http.server` (which does not understand chunked bodies, a useful differential),
and the JDK's HTTP server, and checks what each backend actually parsed:
verbatim targets, a request smuggled inside a body staying a body, chunked bodies
re-framed with exactly one `Content-Length`, pipelined requests staying separate,
headers unfolded, malformed requests never delivered, and blocked attacks never
reaching the backend (the backend's request counter proves it). CI runs it with
`REQUIRE_BACKENDS=1`. Differential testing against a *vulnerable Log4j* is done
in the lab; see [lab.md](lab.md).

## Known limitations

- Requests Go's server rejects as malformed (bad framing, invalid header bytes,
  oversize headers, unsupported versions) never reach the handler. They are safe
  (they are never forwarded) and are still observed: the binary wraps its listener
  with `Proxy.WrapListener`, which recognizes the server's own error responses and
  emits an event (`rejected`, reason `protocol-error`, with the status and client
  address) and a warning log line. This relies on the exact shape of those responses
  and is pinned by tests on every Go version CI covers. It works on plain-text
  connections only: with TLS they are still refused but not counted (ADR 0005).
- `TE: trailers` and similar end-to-end-looking headers are relayed by
  `httputil.ReverseProxy`; they are inspected like any other header.
- WebSocket and other `Upgrade` traffic is not supported.
- Throughput and latency are measured in [load-report.md](load-report.md); the p99 target is met on the lab host, not guaranteed on yours.
