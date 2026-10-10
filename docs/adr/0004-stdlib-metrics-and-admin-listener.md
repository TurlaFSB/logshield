# ADR 0004: Stdlib metrics on a separate admin listener

- Status: accepted
- Date: 2026-10-11

## Context

Operators need metrics, liveness and readiness. The usual route is
`prometheus/client_golang`, which brings a sizeable dependency tree into a
component whose job is to sit in front of a vulnerable host. LogShield uses only
the standard library today, which keeps supply-chain exposure and audit scope small.

## Decision

1. Implement the small subset of the Prometheus text exposition format that is
   needed (counters, one fixed-bucket histogram, two gauges) in `internal/telemetry`.
   It is covered by exact-output tests and can be swapped for the official client
   later without changing the `proxy.Observer` seam.
2. Serve `/metrics`, `/healthz` and `/readyz` on a **separate listener**
   (`-admin-listen`), disabled unless set, never on the proxy port. Nothing about
   the proxy's own state is reachable through the protected path.
3. Every label value comes from a closed set (action, decision, mode, rule ID,
   rejection reason, budget). No request data ever becomes a label.
4. Readiness fails first on shutdown (drain), then the proxy stops accepting.
   Overload is shed with `503` + `Retry-After` instead of queueing.

## Consequences

- No new module dependencies.
- We own the exposition format: histograms are cumulative with `+Inf`, labels
  are escaped, and output is sorted for stable diffs. Exemplars and native
  histograms are not supported.
- Anyone who can reach the admin port can read operational metrics, so it should
  bind to loopback or a management network.
