# ADR 0002: Engine design constraints

- Status: accepted
- Date: 2026-10-10

## Context

The inspection engine decodes and evaluates untrusted input. A WAF that can be
made to consume unbounded resources, or that fails open under pressure, defeats
its own purpose.

## Decision

The `internal/engine` package must be:

1. **Pure**: no I/O, clock, randomness, or global mutable state.
2. **Bounded**: decoding depth, expansion ratio, lookup nesting depth, and total
   work have hard limits.
3. **Fail-closed on budget exhaustion**: exceeding a limit returns a blocking
   verdict with a distinct rule identifier, not an error that callers might
   ignore.
4. **Linear-time**: no backtracking matching on attacker-controlled data.
5. **Deterministic**: identical input produces identical verdict and rule IDs.

Whether the proxy fails open or closed on *engine or upstream failure* is a
separate, explicit operator setting decided in Step 2. Budget exhaustion inside
the engine is always a block.

## Consequences

- Legitimate but pathological input (for example, extremely deep percent
  encoding) is blocked. This is a deliberate trade-off, documented in the threat
  model.
- Limits are configurable constants with documented defaults, and each has a
  test that exercises the boundary.
