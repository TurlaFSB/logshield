# Contributing

Thanks for your interest. LogShield is a security control, so the bar for
changes is deliberately high.

## Ground rules

- **Tests are required.** Engine changes need table-driven tests, and any bypass
  fix needs a regression entry in the bypass corpus.
- **Payloads must be inert.** Test payloads may only reference reserved names
  (`example.com`, `*.invalid`, `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`). Never add a payload that calls a live host or ships a
  working exploit chain.
- **Keep the engine pure.** No I/O, no global mutable state, no unbounded loops.
- **No secrets** in code, tests, logs, or fixtures.

## Workflow

```sh
make check   # vet, lint, tests with race detector, coverage floor
make fuzz    # fuzz the engine (FUZZTIME=30s by default)
make bench   # benchmarks; mention results if you touch a hot path
make vuln    # govulncheck
```

Commits should be small and focused, with an imperative subject line
(`engine: bound decode depth`). Open a pull request against `main`; CI must be
green.

## Reporting security issues

Use the process in [SECURITY.md](SECURITY.md), not a public issue.
