# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will
follow [Semantic Versioning](https://semver.org/) from the first tagged release.

## [Unreleased]

## [0.1.0-rc.1] - 2026-10-17

First release candidate. Pin a verified release, run in monitor mode first, and read [docs/threat-model.md](docs/threat-model.md).

### Added
- OT/ICS guide (`docs/ot-ics.md`).
- Final threat model: trust boundaries, attacks on LogShield itself, what the evidence does and does not show, operator responsibilities.
- Prometheus alerting rules and Sigma rules over the JSON logs (`examples/prometheus`, `examples/sigma`), checked in CI by `scripts/check-sigma.py` (PyYAML only).
- `make lab-scripts`: smoke test of the lab control script with a fake JDK and the real proxy, run in CI.
- Release engineering: reproducible release archives (`scripts/build-release.sh`), a tag-triggered release workflow with keyless cosign signatures, build provenance attestations and SPDX SBOM, a distroless non-root container image, OpenSSF Scorecard, Dependabot for Docker, `docs/releasing.md` (versioning policy and verification) and `docs/deployment.md` with hardened systemd, Kubernetes and nginx examples.
- Docs-consistency tests (rules and configuration keys must be documented), version information from Go build metadata, `CITATION.cff`, `scripts/repo-settings.sh`, and CI for shell, Python and workflow files.
- Hardened profile (`examples/logshield.hardened.json`: block mode plus `block_suspicious`), tested to load, and the measured cost and benefit of the stricter policy.
- Lab for differential validation against real Log4j 2.14.1: canary with a hermetic JNDI hook, logging-only listener, `labrun`, a verifying bundle script (`lab/bundle.py`) and `docs/lab.md`.
- Reverse proxy (`internal/proxy`, `cmd/logshield`): monitor and block modes,
  request normalization with a forwarded-equals-inspected guard, rejection of
  ambiguous requests, fail-closed/fail-open inspection errors, defanged
  structured logs, hardened server timeouts, graceful shutdown. See `docs/proxy.md`.
- `engine.Config.Effective`.
- Load and latency harness (`make load`, `docs/load-report.md`) with a CI smoke test of the 5 ms added-p99 budget; upstream failure tests (refused, silent, garbage, hung, dying mid-response) with slot and goroutine leak checks.
- `-read-timeout`, `-client-write-timeout`, `-drain-delay` settings.
- TLS termination with HTTP/2 (`-tls-cert`, `-tls-key`, `-tls-min-version`), certificate hot-reload, and verified https upstreams with a private CA or server-name override. HTTP/2 differentials are covered by raw-frame tests (ADR 0005).
- Configuration from a strict JSON file, `LOGSHIELD_*` environment variables and flags (`-config`, `-check-config`, `-disable-rule`); unknown keys and variables are reported. See `docs/configuration.md`.
- Prometheus metrics, `/healthz` and `/readyz` on a separate admin listener (`-admin-listen`), stdlib only (ADR 0004); `-max-in-flight` overload shedding (`503` + `Retry-After`). See `docs/observability.md`.
- `Proxy.WrapListener`: requests refused by Go's HTTP server before the handler runs are now logged and observed (`protocol-error`).
- `make integration` and a CI job: the proxy in front of real Node.js, Python and JDK backends (smuggling, re-framing, pipelining, verbatim targets, blocked attacks never delivered).
- Proxy fuzz target `FuzzNothingMaliciousLeaves`; `CODE_OF_CONDUCT.md`, `SUPPORT.md`; README rewritten.

### Fixed
- Slow-read protection: a client that stops reading a response no longer holds an in-flight slot and its buffers indefinitely (`-client-write-timeout`, default 60 s per stalled write).
- Proxy guard no longer depends on body identity, which Go 1.26 changes by wrapping bodies; it now sends the inspected buffer itself.
- Bounded multi-layer decoder (`engine.Decode`): gzip, percent, `%uXXXX`,
  backslash escapes, HTML entities, overlong UTF-8, fullwidth folding, with
  fail-closed budgets.
- Log4j lookup resolver (`engine.Resolve`): name-first substitution, `:-`
  defaults, `lower`/`upper`/`date`, environment-dependent lookups, Java-faithful
  case folding, re-expansion of results and of the assembled output, JNDI and
  possible-JNDI findings with scheme, key, obfuscation and exfiltration signals.
- Request inspection (`engine.Inspect`): request model with method, target,
  query, headers (names and values, duplicates kept), cookies, form and raw
  bodies, and base64 unwrapping of Basic and Bearer (JWT) credentials.
- Rule catalogue (`engine.Rules`) with stable IDs mapped to CVE-2021-44228,
  45046 and 45105, three-tier decisions (clean, suspicious, malicious), mandatory
  fail-closed budget rules, and per-rule disabling.
- `engine.Defang` for log-safe evidence that never contains `${`.
- Multipart/form-data part inspection; NUL-strip (UTF-16/32), zlib and base64
  decode layers; EBCDIC-charset bodies; `Config.Validate`; JSON-friendly
  `Decision`/`Severity`; `Verdict.RuleIDs`.
- Corpora with provenance (`corpus/`): hand-curated bypass and benign sets,
  100,000 generated benign requests, a loader that rejects non-inert hosts, and
  an evaluation harness that enforces the targets and keeps
  `docs/eval/report.md` in sync (`make eval`).
- Property tests (obfuscation, encoding chains, embedding, monotonicity, defang
  round-trip, decode invariants), corpus-seeded mutation fuzzing, a weekly long
  fuzz workflow that uploads crashers, a latency guard, a benchmark baseline
  (`docs/performance.md`), and a benchmark smoke job in CI.
- Coverage ratchet: 97% total and 98% for the engine package.
- Fuzz targets, benchmarks, and an obfuscation test matrix.
- CI: lint, race tests with a coverage floor, cross-OS and cross-architecture
  builds, `go mod tidy` check, govulncheck, fuzz smoke, CodeQL, dependency review.
- `depguard` rule enforcing the engine purity constraint (ADR 0002).
- Early threat model.
