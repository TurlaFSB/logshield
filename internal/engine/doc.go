// Package engine is the LogShield inspection engine.
//
// It decides whether a request carries a Log4Shell-class payload. The package
// is the security core of the project and is held to these design rules, which
// the linter enforces where it can (see the depguard rule in .golangci.yml):
//
//   - Pure: no network, filesystem, clock, randomness, logging, or global
//     state. Input in, verdict out.
//   - Bounded: every decoding, parsing and expansion loop has a hard budget.
//     Exceeding a budget is reported through Budget and must be treated as a
//     block (fail-closed), so the engine cannot be turned into a DoS vector.
//   - Linear-time: no backtracking regular expressions on attacker-controlled
//     input, and no unbounded recursion on attacker-controlled nesting.
//   - Deterministic: the same input always yields the same result.
//
// The pipeline has two stages today, with rules and verdicts to follow:
//
//   - Decode expands one untrusted string into every plausible decoded variant
//     (URL, double URL, escape, entity, overlong UTF-8, gzip, fullwidth).
//   - Resolve emulates Log4j's lookup substitution on one variant and reports
//     JNDI lookups however they are spelled.
//
// See docs/engine/decoder.md and docs/engine/resolver.md.
package engine
