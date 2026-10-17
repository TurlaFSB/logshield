# Contributing

Thanks for your interest. LogShield is a security control, so the bar for
changes is deliberately high.

## Ground rules

- **Tests are required.** Engine changes need table-driven tests, and any bypass
  fix needs a regression entry in the bypass corpus (see
  [corpus/README.md](corpus/README.md)).
- **Payloads must be inert.** Test payloads may only reference reserved names
  (`example.com`, `*.invalid`, `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`). Never add a payload that calls a live host or ships a
  working exploit chain.
- **Keep the engine pure.** No I/O, no global mutable state, no unbounded loops.
- **No secrets** in code, tests, logs, or fixtures.

## Workflow

```sh
make check   # vet, lint, tests with race detector, coverage floor
make fuzz    # fuzz every target (FUZZTIME=30s by default; FUZZ_TARGETS=engine:FuzzInspect for one)
make bench   # benchmarks; mention results if you touch a hot path
make eval    # regenerate docs/eval/report.md after engine or corpus changes
make vuln    # govulncheck
make integration  # proxy in front of real Node, Python and JDK backends
```

Commits should be small and focused, with an imperative subject line
(`engine: bound decode depth`). Open a pull request against `main`; `main` is protected, so every change
merges through a pull request with green CI (squash merge, linear history).

## Reporting security issues

Use the process in [SECURITY.md](SECURITY.md), not a public issue.
