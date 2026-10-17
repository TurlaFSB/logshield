# Grafana dashboard

A ready-made Grafana dashboard for LogShield, built only on the metrics
documented in [docs/observability.md](../../docs/observability.md). A test fails
if the dashboard ever queries a metric LogShield does not expose.

It answers, top to bottom: is it working (requests, blocks, engine errors,
failed-open, p99 inspection time), what is happening to traffic (outcomes and
engine verdicts), what is it catching (detections per rule, exhausted budgets,
rejections, concurrency), and how fast it is (engine time and total request time,
with the project's 5 ms target drawn on the chart).

## See it in one command

The `demo/` directory runs LogShield, a plain nginx page behind it, Prometheus,
Grafana and a traffic generator that sends normal requests and attack-shaped
ones. Everything listens on `127.0.0.1` only; the attack payloads use reserved
`.invalid` hosts and the page behind LogShield is not vulnerable, so nothing is
at risk.

```sh
cd examples/grafana/demo
docker compose up
```

Open <http://127.0.0.1:3000>; the LogShield dashboard is the home page. LogShield
itself is on `127.0.0.1:18080` if you want to send it requests with `curl`. Give it
about a minute for the graphs to fill. Stop with `Ctrl+C`, then
`docker compose down`.

If a port is already in use on your machine (Docker reports "port is already
allocated"), pick others: `LOGSHIELD_PORT=28080 GRAFANA_PORT=3001 docker compose up`.

To try the monitor-mode workflow, set `LOGSHIELD_MODE: monitor` in
`demo/docker-compose.yml`: the "Would be blocked / s" panel then shows what block
mode would have stopped, which is the number to watch before you enforce.

## Use it with your own LogShield

1. Run LogShield with `-admin-listen` on an address Prometheus can reach (keep it
   off public interfaces) and scrape `/metrics` from it.
2. In Grafana: Dashboards, New, Import, upload `logshield-dashboard.json`, and
   choose your Prometheus data source.
3. Pick the Prometheus `job` that scrapes LogShield in the Job drop-down (it
   defaults to all jobs that expose `logshield_build_info`).

Panels draw `rate()` over Grafana's `$__rate_interval`, so the scrape interval
does not need to be set by hand. Pair it with the alert rules in
[`../prometheus/logshield.rules.yml`](../prometheus/logshield.rules.yml).

The dashboard needs Grafana 10 or newer. It was written against the metric
schema of LogShield 0.1.x; metric names are part of the public surface and
follow the stability rule in [docs/releasing.md](../../docs/releasing.md).
