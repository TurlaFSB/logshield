//go:build load

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TurlaFSB/logshield/internal/corpus"
)

// This file measures what the proxy costs. It compares the same workload sent
// straight to a fast upstream and through the proxy, so what remains is the
// proxy's contribution. Run with `make load`; set LOAD_REPORT=path to write the
// Markdown report, LOAD_DURATION and LOAD_WORKERS to change the scale.

// target is a prebuilt request.
type target struct {
	method, target string
	header         http.Header
	body           []byte
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func targetsFrom(t *testing.T, entries []corpus.Entry) []target {
	t.Helper()
	out := make([]target, 0, len(entries))
	for _, e := range entries {
		r, err := e.EngineRequest()
		if err != nil {
			t.Fatal(err)
		}
		h := http.Header{}
		for _, hd := range r.Headers {
			h.Add(hd.Name, hd.Value)
		}
		out = append(out, target{method: r.Method, target: r.Target, header: h, body: r.Body})
	}
	return out
}

// sendable reports whether Go's HTTP client will put the request on the wire:
// it refuses invalid methods and header bytes, which some corpus attacks use.
func sendable(r target) bool {
	token := func(s string) bool {
		if s == "" {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c <= ' ' || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
				return false
			}
		}
		return true
	}
	if !token(r.method) {
		return false
	}
	for k, vs := range r.header {
		if !token(k) {
			return false
		}
		for _, v := range vs {
			for i := 0; i < len(v); i++ {
				if v[i] < ' ' && v[i] != '\t' || v[i] == 0x7f {
					return false
				}
			}
		}
	}
	return true
}

type sample struct {
	d      time.Duration
	status int
}

type phase struct {
	name     string
	n        int
	errors   int
	rps      float64
	lat      []time.Duration // sorted
	statuses map[int]int
}

func (p phase) pct(q float64) time.Duration {
	if len(p.lat) == 0 {
		return 0
	}
	i := int(q * float64(len(p.lat)-1))
	return p.lat[i]
}

// drive sends the workload with the given concurrency for the duration.
func drive(t *testing.T, name, addr string, targets []target, workers int, d time.Duration) phase {
	t.Helper()
	tr := &http.Transport{MaxIdleConnsPerHost: workers, MaxConnsPerHost: workers, DisableCompression: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	var next atomic.Int64
	results := make([][]sample, workers)
	stop := time.Now().Add(d)
	warm := time.Now().Add(d / 10) // the first tenth warms connections and caches and is not counted
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for time.Now().Before(stop) {
				tg := targets[int(next.Add(1))%len(targets)]
				req := &http.Request{
					Method: tg.method, URL: &url.URL{Scheme: "http", Host: addr, Opaque: tg.target},
					Host: "app.example.com", Header: tg.header.Clone(), ContentLength: int64(len(tg.body)),
				}
				if len(tg.body) > 0 {
					req.Body = io.NopCloser(bytes.NewReader(tg.body))
				}
				t0 := time.Now()
				resp, err := client.Do(req.WithContext(context.Background()))
				status := -1
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					status = resp.StatusCode
				} else if os.Getenv("LOAD_DEBUG") != "" {
					fmt.Fprintln(os.Stderr, "client error:", err)
				}
				if t0.After(warm) {
					results[w] = append(results[w], sample{time.Since(t0), status})
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start) - d/10

	p := phase{name: name, statuses: map[int]int{}}
	for _, r := range results {
		for _, s := range r {
			p.n++
			p.lat = append(p.lat, s.d)
			p.statuses[s.status]++
		}
	}
	sort.Slice(p.lat, func(i, j int) bool { return p.lat[i] < p.lat[j] })
	p.rps = float64(p.n) / elapsed.Seconds()
	return p
}

func ms(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }

func cpuModel() string {
	b, _ := os.ReadFile("/proc/cpuinfo")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "model name") {
			if _, v, ok := strings.Cut(l, ":"); ok {
				return strings.TrimSpace(v)
			}
		}
	}
	return "unknown CPU"
}

func TestLatencyOverhead(t *testing.T) {
	dur := time.Duration(envInt("LOAD_DURATION", 8)) * time.Second
	loaded := envInt("LOAD_WORKERS", 32)
	budget := time.Duration(envInt("LOAD_P99_BUDGET_US", 5000)) * time.Microsecond

	benign := corpus.Generate(4000, 20211209)
	benignT := targetsFrom(t, benign)
	attacks, err := corpus.Load(os.DirFS("../../corpus"), "bypass")
	if err != nil {
		t.Fatal(err)
	}
	var malicious []corpus.Entry
	for _, e := range attacks {
		if e.Expect.Decision == "malicious" {
			malicious = append(malicious, e)
		}
	}
	var attackT []target
	for _, tg := range targetsFrom(t, malicious) {
		if sendable(tg) {
			attackT = append(attackT, tg)
		}
	}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1024))
	}))
	defer up.Close()
	upURL, _ := url.Parse(up.URL)

	upstreamTransport := DefaultTransport()
	p, err := New(Config{Upstream: upURL, Mode: ModeBlock, Logger: newTestLogger(io.Discard), Transport: upstreamTransport})
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer("", p, ServerConfig{}, nil)
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	proxyAddr, directAddr := ln.Addr().String(), upURL.Host

	baseline := runtime.NumGoroutine()
	one := func(name, addr string) phase { return drive(t, name, addr, benignT, 1, dur) }
	many := func(name, addr string) phase { return drive(t, name, addr, benignT, loaded, dur) }

	d1, p1 := one("direct", directAddr), one("proxy", proxyAddr)
	dN, pN := many("direct", directAddr), many("proxy", proxyAddr)
	blocked := drive(t, "blocked attacks", proxyAddr, attackT, loaded, dur/2)

	// Correctness under load: benign traffic is never blocked or failed, attacks always are.
	for _, ph := range []phase{p1, pN} {
		if ph.statuses[200] != ph.n {
			t.Errorf("%s: statuses %v, want all 200", ph.name, ph.statuses)
		}
	}
	for status, n := range blocked.statuses {
		if status != http.StatusForbidden && status != http.StatusBadRequest {
			t.Errorf("blocked attacks: %d responses with status %d", n, status)
		}
	}

	// The budget: the proxy's contribution at p99 with a single client.
	added99 := p1.pct(0.99) - d1.pct(0.99)
	if added99 > budget {
		t.Errorf("added p99 latency (1 client) = %s ms, budget %s ms", ms(added99), ms(budget))
	}

	// No leaks: every slot is back and goroutines settle once idle pooled
	// connections (which legitimately keep goroutines) are closed.
	upstreamTransport.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for (p.InFlight() != 0 || runtime.NumGoroutine() > baseline+20) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if p.InFlight() != 0 {
		t.Errorf("in flight after the run: %d", p.InFlight())
	}
	if g := runtime.NumGoroutine(); g > baseline+20 {
		t.Errorf("goroutines grew from %d to %d", baseline, g)
	}

	if path := os.Getenv("LOAD_REPORT"); path != "" {
		row := func(d, p phase, label string) string {
			return fmt.Sprintf("| %s | %d | %.0f | %s / %s | %s / %s | %s / %s | %s / %s |\n", label, p.n, p.rps,
				ms(d.pct(0.5)), ms(p.pct(0.5)), ms(d.pct(0.99)), ms(p.pct(0.99)), ms(d.pct(0.999)), ms(p.pct(0.999)),
				ms(d.lat[len(d.lat)-1]), ms(p.lat[len(p.lat)-1]))
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# Proxy load and latency report\n\nGenerated by `make load`. Do not edit by hand.\n\n")
		fmt.Fprintf(&b, "Environment: %s, %s, GOMAXPROCS=%d, load generator, proxy and upstream on the same machine over loopback. ", cpuModel(), runtime.Version(), runtime.GOMAXPROCS(0))
		fmt.Fprintf(&b, "Workload: %d generated benign requests (seed 20211209: GET and POST, JSON and form bodies, cookies, JWT-like tokens), keep-alive, %s per phase, upstream returns 1 KiB.\n\n", len(benignT), dur)
		fmt.Fprintf(&b, "## Added latency (direct → through the proxy)\n\nEach cell is `direct / proxy` in milliseconds.\n\n")
		fmt.Fprintf(&b, "| Scenario | Requests (proxy) | Requests/s (proxy) | p50 | p99 | p99.9 | max |\n|---|---|---|---|---|---|---|\n")
		b.WriteString(row(d1, p1, "1 client (no queueing)"))
		b.WriteString(row(dN, pN, fmt.Sprintf("%d clients (saturated)", loaded)))
		fmt.Fprintf(&b, "\n**Added p99, 1 client: %s ms** (budget %s ms). ", ms(added99), ms(budget))
		fmt.Fprintf(&b, "Added p50: %s ms. Added p99.9: %s ms.\n\n", ms(p1.pct(0.5)-d1.pct(0.5)), ms(p1.pct(0.999)-d1.pct(0.999)))
		fmt.Fprintf(&b, "With %d clients on a %d-CPU machine that also runs the load generator and the upstream, the CPUs are saturated, so those latencies measure queueing for CPU, not the proxy's per-request cost; the 1-client row is the one that isolates the proxy.\n\n", loaded, runtime.NumCPU())
		fmt.Fprintf(&b, "## Blocked path\n\n%d attack requests from the bypass corpus (%d distinct) at %d clients: every one answered 403 or 400, %.0f requests/s, p50 %s ms, p99 %s ms.\n\n", blocked.n, len(attackT), loaded, blocked.rps, ms(blocked.pct(0.5)), ms(blocked.pct(0.99)))
		fmt.Fprintf(&b, "## Checks during the run\n\n- Benign requests answered 200: %d of %d (1 client), %d of %d (%d clients).\n- In-flight requests after the run: %d. Goroutines settled to within 20 of the starting %d.\n", p1.statuses[200], p1.n, pN.statuses[200], pN.n, loaded, p.InFlight(), baseline)
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // a report meant to be committed and read
			t.Fatal(err)
		}
	}
	t.Logf("added p99 (1 client) %s ms; p50 %s ms; saturated rps direct %.0f proxy %.0f", ms(added99), ms(p1.pct(0.5)-d1.pct(0.5)), dN.rps, pN.rps)
}
