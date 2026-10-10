# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will
follow [Semantic Versioning](https://semver.org/) from the first tagged release.

## [Unreleased]

### Added
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
- Fuzz targets, benchmarks, and an obfuscation test matrix.
- CI: lint, race tests with a coverage floor, cross-OS and cross-architecture
  builds, `go mod tidy` check, govulncheck, fuzz smoke, CodeQL, dependency review.
- `depguard` rule enforcing the engine purity constraint (ADR 0002).
- Early threat model.
