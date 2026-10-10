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

- [ ] **1a. Foundation**: repo, MIT, SECURITY.md, Go module, CI skeleton (pinned actions, read-only tokens)
- [ ] **1b. Decoder**: bounded multi-layer normalizer (URL, double URL, `\u` escapes, HTML entities, overlong UTF-8, gzip)
- [ ] **1c. Lookup resolver**: emulate Log4j substitution for nested `lower`/`upper`/`::-`/`env:x:-d`/`sys`/`date`; flag unresolvable fragments that could form `jndi`
- [ ] **1d. Rules and verdicts**: rule IDs mapped to CVEs (44228, 45046, 45105), protocol coverage, DNS-exfil lookups, request model (path, query, headers, body), definite / suspicious / clean tiers
- [ ] **1e. Corpora and evaluation**: bypass corpus with provenance, benign corpus, reproducible eval report
- [ ] **1f. Hardening**: fuzzing, property tests, coverage floor raised to 90%, benchmarks

## Step 2: reverse proxy

- [ ] **2a. Proxy core**: size and time limits, fail-open / fail-closed, `monitor` and `block` modes, log output that defangs `${`
- [ ] **2b. Observability**: Prometheus metrics (block rate, monitor-mode hits, latency histogram), config file, health check
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
