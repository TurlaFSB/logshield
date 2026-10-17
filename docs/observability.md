# Observability and operations

## Admin endpoints

Enable with `-admin-listen 127.0.0.1:9090` (disabled by default; keep it off public
interfaces). They are served on a separate listener, never on the proxy port.

| Path | Meaning |
|---|---|
| `/healthz` | Liveness: 200 while the process runs, including while draining. |
| `/readyz` | Readiness: 200 when the upstream accepts a TCP connection (probed at most every 2 s) and the process is not shutting down; otherwise 503 with no detail. |
| `/metrics` | Prometheus text format 0.0.4. |

On `SIGTERM`, `/readyz` fails first; after `-drain-delay` (default none) the proxy
stops accepting and finishes in-flight requests (up to 15 s).

## Metrics

| Metric | Type | Labels | Use |
|---|---|---|---|
| `logshield_requests_total` | counter | `action`, `decision`, `mode` | Traffic and block rate. `action` is `forwarded`, `blocked`, `rejected` or `error`. |
| `logshield_monitor_would_block_total` | counter | `mode` | What block mode would have stopped; the number to watch before switching from monitor to block. |
| `logshield_rule_detections_total` | counter | `rule` | Detections per rule ID (`LSH-1001`...). |
| `logshield_rejections_total` | counter | `reason` | Requests rejected or failed, by stable reason (`protocol-error`, `overloaded`, `body-too-large`, `guard-violation`, ...). |
| `logshield_budget_exhausted_total` | counter | `budget` | Requests that hit an engine budget (treated as malicious). Spikes suggest a resource-exhaustion attempt. |
| `logshield_inspection_errors_total` | counter | | Engine failures (bugs). Should stay at 0. |
| `logshield_failed_open_total` | counter | | Requests forwarded uninspected under `-on-error open`. |
| `logshield_inspection_duration_seconds` | histogram | | Engine time per request. |
| `logshield_request_duration_seconds` | histogram | | Total time per request, including the upstream. |
| `logshield_requests_in_flight` | gauge | | Current concurrency. |
| `logshield_build_info` | gauge | `version` | Always 1. |

## Log events

Each request that is blocked, rejected, failed or flagged is one JSON line on
standard error (`slog` JSON handler). Clean requests are logged only at `debug`.
Every string is defanged, so a log line never contains a live `${`. The query
string is never logged, only its length. Field names are part of the public
surface versioned in [releasing.md](releasing.md).

`msg` is `request blocked`, `request rejected`, `request flagged` (a
suspicious or would-block request that was forwarded), `request failed`, or
`request` (debug).

| Field | Meaning |
|---|---|
| `id` | Request identifier, also sent upstream and in the response. |
| `mode` | `monitor` or `block`. |
| `action` | `forwarded`, `blocked`, `rejected` or `error`. |
| `status` | HTTP status sent to the client. |
| `decision` | Engine verdict: `clean`, `suspicious` or `malicious`. |
| `would_block` | True when monitor mode forwarded a request that block mode would have stopped. |
| `remote` | Client IP address. |
| `method`, `host`, `path` | Defanged and truncated request parts. |
| `query_bytes`, `body_bytes` | Sizes only; the content is not logged. |
| `duration_us`, `inspect_us` | Total time and engine time, in microseconds. |
| `reason` | Stable code for rejections and errors. |
| `body_truncated`, `body_skipped` | Only the first `-max-body` bytes were inspected, or the body type is on the skip list. |
| `failed_open` | Inspection failed and `-on-error open` forwarded the request anyway. |
| `budget` | The engine budget that was exhausted, if any. |
| `rules` | Rule IDs that fired, for example `["LSH-1001"]`. |
| `detections` | Up to 8 findings, each with `rule`, `severity`, `location`, `scheme`, `evidence` and `decoded_via` (the decoding layers that revealed it). |
| `detections_omitted` | How many further findings were not listed. |

Suggested alerts:

- `increase(logshield_inspection_errors_total[5m]) > 0` (a bug; report it).
- `increase(logshield_failed_open_total[5m]) > 0` (traffic bypassed inspection).
- `rate(logshield_rejections_total{reason="overloaded"}[5m]) > 0` (raise `-max-in-flight` or add capacity).
- `histogram_quantile(0.99, rate(logshield_inspection_duration_seconds_bucket[5m])) > 0.005` (the project's own latency target).

## Overload

`-max-in-flight` (default 1024, `-1` for no limit) bounds concurrently handled
requests. One more is answered `503` with `Retry-After: 1` immediately instead of
queueing, in both monitor and block mode. Because each request can buffer up to
`-max-body` bytes, the limit is also the memory bound (default worst case about
1 GiB). A client that stops reading is cut off after `-client-write-timeout` (60 s of stall), so
slow-read attacks cannot pin slots. Long-lived streams occupy a slot for as long as they last, so size the limit
for your connection mix.

## Ready-made alerting and detection content

- [examples/prometheus/logshield.rules.yml](../examples/prometheus/logshield.rules.yml): Prometheus alerting rules for the conditions above.
- [examples/sigma/](../examples/sigma/): [Sigma](https://sigmahq.io/) rules over LogShield's JSON log events (blocked attempts, attacks forwarded in monitor mode, fail-open events, budget exhaustion). Convert them for your SIEM with `sigma-cli`; the log source is `product: logshield`, and field names are the keys documented in the log event example in the README.
