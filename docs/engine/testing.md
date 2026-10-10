# How the engine is tested

The engine is a security boundary, so it is tested from several independent
angles. Each catches a different class of mistake.

| Layer | What it proves | Where |
|---|---|---|
| Table tests | Specific behaviors, edge cases and error paths of the decoder, resolver, rules and request model | `internal/engine/*_test.go` |
| Placement matrix | 11 payload styles in 16 request locations are all caught | `inspect_test.go` |
| Property tests | Invariants hold over thousands of generated inputs: any obfuscation of the lookup is caught, any chain of up to three encodings is caught, embedding in arbitrary text keeps detection, adding data never lowers a verdict, plain text never produces findings, `Defang` is safe and reversible, `Decode` is deterministic and bounded | `property_test.go` |
| Fuzzing | No panic, hang or unbounded work on arbitrary bytes; evidence never contains `${`; budget exhaustion is always malicious | `FuzzDecode`, `FuzzResolve`, `FuzzInspect`, and `FuzzMutatedCorpus` (seeded from every corpus request) |
| Corpora | Measured miss rate on 165 attack entries with provenance, and false-positive rate on 100,000+ benign requests | `corpus/`, [evaluation report](../eval/report.md) |
| Concurrency | `Inspect` is safe from many goroutines | `hardening_test.go` under `-race` |
| Latency guard | p99 stays inside the 5 ms budget | `internal/corpus/latency_test.go` |
| Static checks | Engine purity (no I/O, clock, randomness or `unsafe`), enforced by `depguard`; `govulncheck`; CodeQL | `.golangci.yml`, CI |

## Coverage floors

`make cover-check` fails below 97% total and 98% for `internal/engine`. These
only go up. Coverage shows what ran, not what is correct, which is why the
property tests and corpora exist alongside it.

## Fuzzing

- Every commit: a 20-second run of each target in CI.
- Weekly: `.github/workflows/fuzz.yml` runs each target for 10 minutes and uploads
  any crashing input as an artifact.
- A crash becomes a seed under `testdata/fuzz/` and a named regression test in the
  same change as its fix (for example `TestEvidenceIsAlwaysDefanged`, found by
  `FuzzInspect`).

## What found real bugs so far

Recorded so the process stays honest about what the testing is worth:

- `FuzzInspect`: lookup prefixes were logged without defanging.
- Corpus probing: UTF-16 bodies and `%00`-interleaved text were scored clean.
- Property tests: base64 of non-ASCII UTF-8 text was ignored.
- Matrix test: overlong-UTF-8 payloads in Basic and Bearer credentials were
  missed when binary-looking decoded data was discarded.
