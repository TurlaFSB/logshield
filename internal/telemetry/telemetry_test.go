package telemetry

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
	"github.com/TurlaFSB/logshield/internal/proxy"
)

func render(t *testing.T, m *Metrics) string {
	t.Helper()
	var b strings.Builder
	if _, err := m.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestMetricsRenderExactly(t *testing.T) {
	m := New("v1")
	m.SetInFlight(func() int { return 3 })
	m.Observe(proxy.Event{Action: proxy.ActionBlocked, Decision: engine.DecisionMalicious, Mode: proxy.ModeBlock,
		Rules: []engine.RuleID{"LSH-1001"}, InspectDuration: 30 * time.Microsecond, Duration: 80 * time.Microsecond})
	m.Observe(proxy.Event{Action: proxy.ActionForwarded, Decision: engine.DecisionMalicious, Mode: proxy.ModeMonitor, WouldBlock: true,
		Rules: []engine.RuleID{"LSH-1001", "LSH-2002"}, InspectDuration: 30 * time.Microsecond, Duration: 2 * time.Millisecond})
	m.Observe(proxy.Event{Action: proxy.ActionRejected, Mode: proxy.ModeBlock, Reason: "protocol-error", Duration: time.Microsecond})
	m.Observe(proxy.Event{Action: proxy.ActionBlocked, Decision: engine.DecisionMalicious, Mode: proxy.ModeBlock, Exhausted: engine.BudgetDepth, Duration: time.Millisecond})
	m.Observe(proxy.Event{Action: proxy.ActionForwarded, Mode: proxy.ModeBlock, FailedOpen: true, Reason: "inspection-error", Duration: time.Millisecond})
	got := render(t, m)

	for _, want := range []string{
		`logshield_build_info{version="v1"} 1`,
		`logshield_requests_in_flight 3`,
		`logshield_requests_total{action="blocked",decision="malicious",mode="block"} 2`,
		`logshield_requests_total{action="forwarded",decision="malicious",mode="monitor"} 1`,
		`logshield_requests_total{action="rejected",decision="clean",mode="block"} 1`,
		`logshield_monitor_would_block_total{mode="monitor"} 1`,
		`logshield_rule_detections_total{rule="LSH-1001"} 2`,
		`logshield_rule_detections_total{rule="LSH-2002"} 1`,
		`logshield_rejections_total{reason="protocol-error"} 1`,
		`logshield_budget_exhausted_total{budget="depth"} 1`,
		`logshield_failed_open_total 1`,
		`logshield_inspection_errors_total 1`,
		`logshield_inspection_duration_seconds_bucket{le="5e-05"} 2`,
		`logshield_inspection_duration_seconds_bucket{le="+Inf"} 2`,
		`logshield_inspection_duration_seconds_count 2`,
		`logshield_request_duration_seconds_count 5`,
		"# TYPE logshield_request_duration_seconds histogram",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// A forwarded request's Reason is informational and must not count as a rejection.
	if strings.Contains(got, `reason="inspection-error"`) {
		t.Error("a fail-open forward was counted as a rejection")
	}
}

func TestHistogramIsCumulativeAndMonotonic(t *testing.T) {
	h := newHistogram("x", "h", []float64{1, 2, 3})
	for _, v := range []float64{0.5, 1, 1.5, 2.5, 100} {
		h.observe(v)
	}
	out := renderPart(h.write)
	for _, want := range []string{`x_bucket{le="1"} 2`, `x_bucket{le="2"} 3`, `x_bucket{le="3"} 4`, `x_bucket{le="+Inf"} 5`, "x_sum 105.5", "x_count 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestLabelEscapingAndNoLabelCounter(t *testing.T) {
	if got := formatLabels([]string{"a"}, []string{"x\"y\\z\nw"}); got != `{a="x\"y\\z\nw"}` {
		t.Errorf("escaped = %s", got)
	}
	if got := formatLabels(nil, nil); got != "" {
		t.Errorf("no labels = %q", got)
	}
	if got := formatLabels([]string{"a", "b"}, []string{"1"}); got != `{a="1",b=""}` {
		t.Errorf("short values = %s", got)
	}
	c := newCounterVec("n", "help")
	out := renderPart(c.write)
	if !strings.Contains(out, "\nn 0\n") {
		t.Errorf("an unlabeled counter must render 0: %q", out)
	}
}

func TestMetricsAreSafeForConcurrentUse(t *testing.T) {
	m := New("v")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				m.Observe(proxy.Event{Action: proxy.ActionForwarded, Duration: time.Millisecond, InspectDuration: time.Microsecond,
					Rules: []engine.RuleID{"LSH-1001"}})
				if j%100 == 0 {
					_ = render(t, m)
				}
			}
		}()
	}
	wg.Wait()
	if !strings.Contains(render(t, m), `logshield_rule_detections_total{rule="LSH-1001"} 4000`) {
		t.Error("lost updates")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteToReportsWriterErrors(t *testing.T) {
	// The write error surfaces on flush because output is buffered.
	if _, err := New("v").WriteTo(failWriter{}); err == nil {
		t.Error("expected an error")
	}
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
	return rec
}

func TestAdminEndpoints(t *testing.T) {
	a := NewAdmin(AdminConfig{Metrics: New("v")})
	h := a.Handler()
	if r := get(t, h, http.MethodGet, "/healthz"); r.Code != 200 || r.Body.String() != "ok\n" {
		t.Errorf("healthz: %d %q", r.Code, r.Body)
	}
	if r := get(t, h, http.MethodGet, "/readyz"); r.Code != 200 {
		t.Errorf("readyz: %d", r.Code)
	}
	r := get(t, h, http.MethodGet, "/metrics")
	if r.Code != 200 || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/plain; version=0.0.4") || !strings.Contains(r.Body.String(), "logshield_build_info") {
		t.Errorf("metrics: %d %v", r.Code, r.Header())
	}
	if r := get(t, h, http.MethodPost, "/metrics"); r.Code != http.StatusMethodNotAllowed || r.Header().Get("Allow") == "" {
		t.Errorf("POST: %d", r.Code)
	}
	if r := get(t, h, http.MethodGet, "/nope"); r.Code != http.StatusNotFound {
		t.Errorf("unknown path: %d", r.Code)
	}
	a.Drain()
	a.Drain() // idempotent
	if r := get(t, h, http.MethodGet, "/readyz"); r.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz while draining: %d", r.Code)
	}
	if r := get(t, h, http.MethodGet, "/healthz"); r.Code != 200 {
		t.Errorf("healthz must stay up while draining: %d", r.Code)
	}
}

func TestReadinessChecksTheUpstreamAndCaches(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	a := NewAdmin(AdminConfig{Metrics: New("v"), Upstream: addr, CacheFor: time.Hour})
	h := a.Handler()
	if r := get(t, h, http.MethodGet, "/readyz"); r.Code != 200 {
		t.Fatalf("upstream up: %d", r.Code)
	}
	_ = ln.Close()
	if r := get(t, h, http.MethodGet, "/readyz"); r.Code != 200 {
		t.Errorf("a cached result must be reused: %d", r.Code)
	}
	b := NewAdmin(AdminConfig{Metrics: New("v"), Upstream: addr, DialTimeout: 200 * time.Millisecond})
	r := get(t, b.Handler(), http.MethodGet, "/readyz")
	if r.Code != http.StatusServiceUnavailable || strings.Contains(r.Body.String(), "127.0.0.1") {
		t.Errorf("upstream down: %d %q (the address must not leak)", r.Code, r.Body)
	}
	if r2 := get(t, b.Handler(), http.MethodGet, "/readyz"); r2.Code != http.StatusServiceUnavailable {
		t.Errorf("second probe: %d", r2.Code)
	}
}

func TestAdminServerIsBounded(t *testing.T) {
	s := NewAdminServer("127.0.0.1:0", http.NotFoundHandler())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 {
		t.Errorf("unbounded admin server: %+v", s)
	}
}

func renderPart(write func(*printer)) string {
	var b strings.Builder
	p := &printer{w: bufio.NewWriter(&b)}
	write(p)
	_ = p.w.Flush()
	return b.String()
}
