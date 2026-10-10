# Roadmap

LogShield is built in small, reviewable steps. Each step ends with something
measurable.

## Targets

These are goals to be confirmed by measurement, not claims.

| Metric | Target |
|---|---|
| Missed payloads in in-scope bypass classes | 0 |
| False-positive rate on the benign corpus | < 0.1% |
| p99 added latency | < 5 ms |
| Engine line coverage floor | >= 90% |

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
- [ ] **2c. Proxy tests**: integration tests, load test, latency benchmark

## Step 3: lab, validation, release

- [ ] **3a. Lab design**: isolated host-only network with a client, the LogShield host, a Windows target running a Log4j 2.x test application, a legacy Linux neighbor (Metasploitable 3), a logging-only canary listener, and egress filtering
- [ ] **3b. Lab runs**: baseline, WAF off vs on, egress filter off vs on
- [ ] **3c. Differential validation**: label the corpus with ground truth from real vulnerable Log4j, compare against engine verdicts
- [ ] **3d. Release engineering**: distroless non-root image, keyless signing, SBOM, build provenance, CodeQL, Scorecard, branch protection
- [ ] **3e. Documentation**: threat model, limits, layered-defense argument, OT/ICS mapping, quickstart

## Step 4 (optional)

- [ ] **Control self-test canary**: send inert payloads through the proxy on a schedule and alert if any reaches the backend

## Step 5

- [ ] Short technical write-up of methodology and results

## Working agreement

One sub-step at a time. Each is implemented, reported, and reviewed before the
next begins.
