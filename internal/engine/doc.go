// Package engine is the LogShield inspection engine.
//
// It decides whether a request carries a Log4Shell-class payload. The package
// is the security core of the project and is held to these design rules:
//
//   - Pure: no network, filesystem, clock, or global state. Input in, verdict out.
//   - Bounded: every decoding and expansion loop has a hard budget on depth and
//     output size. Exceeding a budget is itself a blocking verdict (fail-closed
//     inside the engine), so the engine cannot be turned into a DoS vector.
//   - Linear-time: no backtracking regular expressions on attacker-controlled
//     input.
//   - Deterministic: the same input always yields the same verdict and the same
//     rule identifiers.
//
// The pipeline is built up in stages: decoding and normalization, nested
// lookup resolution, then rule evaluation. See docs/ROADMAP.md.
package engine
