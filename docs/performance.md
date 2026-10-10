# Performance

Targets: the engine adds well under the project's **p99 < 5 ms** end-to-end latency
budget (the proxy as a whole is measured in [End to end](#end-to-end-the-proxy)), and worst-case work is bounded by
the budgets in [decoder](engine/decoder.md) and [rules](engine/rules.md).

## End to end (the proxy)

`make load` sends the same benign workload straight to a fast upstream and through
the proxy and reports the difference ([load report](load-report.md)). On the 2-vCPU
cloud VM used for development, with one client the proxy adds **about 0.1 ms at p50
and 0.7 ms at p99** (4 to 10 times under the 5 ms budget), and every benign request is
forwarded. With 32 clients the machine is saturated by the load generator, the proxy
and the upstream together, so latency there is CPU queueing: the proxy sustains about
8,700 requests/s on two shared cores (the engine is about 40% of the proxy's CPU; the
rest is Go's HTTP server and client). Measure on production-class hardware before
sizing a deployment; the lab runs (Step 3b) repeat this on a dedicated host.

CI runs a short version (`load-smoke`) that fails if added p99 with one client
exceeds 5 ms, which catches order-of-magnitude regressions on noisy shared runners.

## Engine baseline

Measured with `make bench` (`go test -bench . -benchmem -count=3`, median of 3) on:
Go 1.24.7, linux/amd64, Intel Xeon @ 2.10 GHz, 2 vCPUs
(a small shared cloud VM; expect better on a developer laptop or server).

| Benchmark | Time per op | Bytes per op | Allocations per op |
|---|---|---|---|
| `Decode/typical-user-agent` | 0.2 µs | 48 | 1 |
| `Decode/typical-url` | 1.0 µs | 464 | 8 |
| `Decode/encoded-payload` | 0.5 µs | 176 | 4 |
| `Decode/double-encoded-payload` | 0.9 µs | 432 | 8 |
| `Decode/1MiB-plain` | 2.45 ms | 1,572,912 | 3 |
| `Decode/640KiB-percent-heavy` | 1.70 ms | 655,504 | 4 |
| `Inspect/browser-GET` | 8.2 µs | 5,040 | 46 |
| `Inspect/JSON-POST` | 4.0 µs | 2,632 | 36 |
| `Inspect/attack` | 10.0 µs | 7,288 | 93 |
| `Inspect/adversarial-400KiB-percent` | 3.09 ms | 1,418,384 | 19 |
| `Resolve/typical-header-no-lookup` | 0.0 µs | 0 | 0 |
| `Resolve/plain-exploit` | 0.6 µs | 448 | 9 |
| `Resolve/obfuscated-exploit` | 3.7 µs | 3,752 | 48 |
| `Resolve/deeply-nested` | 4.5 µs | 4,656 | 59 |
| `Resolve/template-heavy-64KiB` | 379.7 µs | 120,168 | 5003 |
| `Resolve/lookup-heavy-64KiB` | 273.0 µs | 338,000 | 4111 |

Reading the numbers:

- A typical browser request (about 12 fields) is inspected in roughly 8 µs, a
  JSON POST in about 4 µs, and an attack request in about 10 µs, so the engine's
  share of the 5 ms budget is around 0.2%.
- The adversarial cases are the ceiling: a 400 KiB body of nested percent
  escapes costs about 3 ms and is then blocked by the budgets (fail-closed), and
  a 1 MiB plain input is decoded in about 2.5 ms. Nothing in the engine is
  super-linear, and every loop is bounded by a `Limits` or `Config` field.
- `Resolve` on a header with no `${` takes about 40 ns and allocates nothing.

## Guards

- `TestLatencyBudget` (internal/corpus) measures `Inspect` over 5,000 generated
  requests and fails if p99 exceeds 5 ms. It is intentionally loose so shared CI
  runners and the race detector do not cause flakes.
- CI runs the benchmarks for one iteration on every change so they cannot rot.
- Compare before and after a change to a hot path with
  `go test ./internal/engine -bench . -count=10 > new.txt` and `benchstat old.txt new.txt`.

## Not yet measured

Memory under concurrent load, throughput and latency on production-class hardware
(Step 3b), and behavior on production-shaped traffic.
