# ADR 0001: Implement LogShield in Go

- Status: accepted
- Date: 2026-10-10

## Context

LogShield is a security control placed inline on the request path. It processes
attacker-controlled input, must add little latency, and must be easy to deploy
on constrained or legacy network segments.

## Decision

Use Go.

## Rationale

- Go's standard `regexp` package guarantees linear-time matching, which removes
  catastrophic-backtracking denial of service from the engine by construction.
- `net/http/httputil` provides a mature reverse-proxy foundation.
- A static binary with no runtime dependency suits minimal, signed, distroless
  container images and OT environments.
- Built-in fuzzing and benchmarking (`go test -fuzz`, `-bench`) support the
  project's evidence-first approach.

## Consequences

- Contributors need Go 1.24 or newer.
- The lookup resolver is a hand-written parser, not a regular expression, because
  Log4j lookups nest.

## Alternatives considered

- **Python**: faster to prototype, but weaker latency and a heavier runtime for
  inline use.
- **Rust**: strong safety and performance, but a higher cost to iterate for a
  single-maintainer project.
