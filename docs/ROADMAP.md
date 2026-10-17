# Roadmap

LogShield is built in small, reviewable steps. Each step ends with something
measurable.

## Targets

These started as goals and were then confirmed by measurement (details in the
[evaluation report](eval/report.md), [lab report](lab-report.md) and
[load report](load-report.md)).

| Metric | Target | Result at v0.1.0 |
|---|---|---|
| Missed payloads in in-scope bypass classes | 0 | 0 of 165 corpus entries; 107 of 107 real Log4j JNDI attempts flagged in the lab |
| False-positive rate on the benign corpus | < 0.1% | 0 of 100,111 (95% upper bound below 0.0038%) |
| p99 added latency | < 5 ms | 0.7 ms, one client |
| Coverage floors (total / engine) | 97% / 98% | 97.5% / 99.5% |

## Step 1: inspection engine

- [x] **1a. Foundation**: repo, MIT, SECURITY.md, Go module, CI skeleton (pinned actions, read-only tokens)
- [x] **1b. Decoder**: bounded multi-layer normalizer (URL, double URL, `\u` escapes, HTML entities, overlong UTF-8, gzip)
- [x] **1c. Lookup resolver**: emulate Log4j substitution for nested `lower`/`upper`/`::-`/`env:x:-d`/`sys`/`date`; flag unresolvable fragments that could form `jndi`
- [x] **1d. Rules and verdicts**: rule IDs mapped to CVEs (44228, 45046, 45105), protocol coverage, DNS-exfil lookups, request model (path, query, header names and values, cookies, body), definite / suspicious / clean tiers
- [x] **1e. Corpora and evaluation**: bypass corpus with provenance, benign corpus, reproducible eval report
- [x] **1f. Hardening**: fuzzing (including corpus-seeded mutation and a weekly long run), property tests, coverage floors (total 97%, engine 98%), benchmark baseline and latency guard

## Step 2: reverse proxy

- [x] **2a. Proxy core**: size and time limits, fail-open / fail-closed, `monitor` and `block` modes, log output that defangs `${`; forward exactly the bytes that were inspected and reject ambiguous requests (parser differentials: `Content-Length` vs `Transfer-Encoding`, duplicate headers, obs-fold, invalid characters), per the [threat model](threat-model.md)
- [x] **2b. Observability and operations**: Prometheus metrics (block rate, monitor-mode hits, latency histogram), config file, health check
- [x] **2c. Proxy tests**: integration tests, load test, latency benchmark

## Step 3: lab, validation, release

- [x] **3a. Lab design and tooling**: a Log4j 2.14.1 canary with a hermetic JNDI hook, a logging-only listener, the `labrun` differential runner, a verified host-side bundle, and [docs/lab.md](lab.md). The Windows target is dropped: the Ubuntu 14.04 VM has no Java, so the canary runs from a bundled JDK 8.
- [x] **3b. Lab runs**: direct-to-Log4j baseline vs through LogShield, balanced and hardened profiles (see [lab.md](lab.md)). The egress-filter comparison was dropped: the oracle never sends traffic, and egress control is outside LogShield's scope.
- [x] **3c. Differential validation**: label the corpus with ground truth from real vulnerable Log4j, compare against engine verdicts
- [x] **3d. Release engineering**: distroless non-root image, keyless signing, SBOM, build provenance, CodeQL, Scorecard, branch protection. v0.1.0 is released: signed, attested, reproducible archives and a signed image, verified end to end (see [releasing.md](releasing.md)). `main` accepts pull requests only.
- [x] **3e. Documentation**: threat model, limits, layered-defense argument, OT/ICS mapping, quickstart

## Step 4 (optional)

- [ ] **Control self-test canary**: send inert payloads through the proxy on a schedule and alert if any reaches the backend

## Step 5

- [ ] Technical write-up of methodology and results. Drafted as a four-part series (what and why, how it works, how it was tested, how to use it); the links go here once published.

## After 0.1

Candidates, roughly in order of value. None is promised.

- **Outside review.** The invitation is published ([challenge](challenge.md)); the first independent report is still to come. Every confirmed bypass becomes a corpus entry.
- **Wider validation.** Run the lab against more Log4j versions (such as 2.15 and 2.16) and more JDKs, and extend the differential to other logging paths.
- **Measurements still missing.** Memory under concurrent load and behaviour on production-shaped traffic ([performance](performance.md)).
- **Control self-test canary** (Step 4).
- **Container health check.** The distroless image has no shell, so a plain `docker run` has no built-in `HEALTHCHECK`; a small `-healthcheck` mode would close that gap.
- **SLSA Build Level 3**, by moving the release build into an isolated reusable workflow ([assurance](assurance.md)).
- **A second maintainer**, which also raises the Code-Review and OpenSSF scores.

## Done since 0.1.0

- `logshield check`, to explain the verdict for one payload without a proxy.
- A Grafana dashboard on the documented metrics, with a one-command demo.
- A public challenge page for independent testers ([challenge](challenge.md)).

## Working agreement

One sub-step at a time. Each is implemented, reported, and reviewed before the
next begins.
