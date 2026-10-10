package telemetry

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/TurlaFSB/logshield/internal/engine"
	"github.com/TurlaFSB/logshield/internal/proxy"
)

// counterVec is a counter with a fixed set of label names.
type counterVec struct {
	name, help string
	labels     []string
	mu         sync.RWMutex
	vals       map[string]*atomic.Uint64
}

func newCounterVec(name, help string, labels ...string) *counterVec {
	return &counterVec{name: name, help: help, labels: labels, vals: map[string]*atomic.Uint64{}}
}

func (c *counterVec) inc(values ...string) {
	key := strings.Join(values, "\xff")
	c.mu.RLock()
	v := c.vals[key]
	c.mu.RUnlock()
	if v == nil {
		c.mu.Lock()
		if v = c.vals[key]; v == nil {
			v = new(atomic.Uint64)
			c.vals[key] = v
		}
		c.mu.Unlock()
	}
	v.Add(1)
}

func (c *counterVec) write(w *printer) {
	w.f("# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	c.mu.RLock()
	keys := make([]string, 0, len(c.vals))
	for k := range c.vals {
		keys = append(keys, k)
	}
	c.mu.RUnlock()
	sort.Strings(keys)
	if len(keys) == 0 && len(c.labels) == 0 {
		w.f("%s 0\n", c.name)
	}
	for _, k := range keys {
		c.mu.RLock()
		n := c.vals[k].Load()
		c.mu.RUnlock()
		w.f("%s%s %d\n", c.name, formatLabels(c.labels, strings.Split(k, "\xff")), n)
	}
}

// histogram is a cumulative histogram with fixed buckets.
type histogram struct {
	name, help string
	bounds     []float64
	counts     []atomic.Uint64 // one per bound, plus +Inf
	sum        atomic.Uint64   // float64 bits
	count      atomic.Uint64
}

func newHistogram(name, help string, bounds []float64) *histogram {
	return &histogram{name: name, help: help, bounds: bounds, counts: make([]atomic.Uint64, len(bounds)+1)}
}

func (h *histogram) observe(v float64) {
	i := sort.SearchFloat64s(h.bounds, v) // first bound >= v
	h.counts[i].Add(1)
	h.count.Add(1)
	for {
		old := h.sum.Load()
		if h.sum.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			return
		}
	}
}

func (h *histogram) write(w *printer) {
	w.f("# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
	var cum uint64
	for i, b := range h.bounds {
		cum += h.counts[i].Load()
		w.f("%s_bucket{le=%q} %d\n", h.name, formatFloat(b), cum)
	}
	cum += h.counts[len(h.bounds)].Load()
	w.f("%s_bucket{le=\"+Inf\"} %d\n", h.name, cum)
	w.f("%s_sum %s\n%s_count %d\n", h.name, formatFloat(math.Float64frombits(h.sum.Load())), h.name, h.count.Load())
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func formatLabels(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		v := ""
		if i < len(values) {
			v = values[i]
		}
		b.WriteString(n + `="` + escapeLabel(v) + `"`)
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// latencyBuckets (seconds) resolve the engine's microsecond range up to the
// proxy's multi-second timeouts.
var latencyBuckets = []float64{
	0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// Metrics collects proxy events and renders them in Prometheus text format. It
// implements proxy.Observer and is safe for concurrent use.
type Metrics struct {
	version string

	requests     *counterVec
	wouldBlock   *counterVec
	detections   *counterVec
	rejections   *counterVec
	budgets      *counterVec
	failedOpen   *counterVec
	inspectErrs  *counterVec
	inspectTime  *histogram
	requestTime  *histogram
	inflightFunc atomic.Pointer[func() int]
}

// New returns an empty Metrics. version is exported as logshield_build_info.
func New(version string) *Metrics {
	return &Metrics{
		version:     version,
		requests:    newCounterVec("logshield_requests_total", "Requests handled, by outcome, engine decision and mode.", "action", "decision", "mode"),
		wouldBlock:  newCounterVec("logshield_monitor_would_block_total", "Requests monitor mode forwarded that block mode would have stopped.", "mode"),
		detections:  newCounterVec("logshield_rule_detections_total", "Rule detections, by rule ID.", "rule"),
		rejections:  newCounterVec("logshield_rejections_total", "Requests rejected or failed before or instead of a verdict, by reason.", "reason"),
		budgets:     newCounterVec("logshield_budget_exhausted_total", "Requests that exhausted an engine budget (always treated as malicious).", "budget"),
		failedOpen:  newCounterVec("logshield_failed_open_total", "Requests forwarded uninspected because inspection failed and the policy is fail-open."),
		inspectErrs: newCounterVec("logshield_inspection_errors_total", "Requests for which the engine itself failed (a bug, not an attack), whatever the policy then did."),
		inspectTime: newHistogram("logshield_inspection_duration_seconds",
			"Time the engine spent on a request.", latencyBuckets),
		requestTime: newHistogram("logshield_request_duration_seconds",
			"Total time from receiving a request to finishing its response.", latencyBuckets),
	}
}

// SetInFlight registers the function that reports the current in-flight request count.
func (m *Metrics) SetInFlight(f func() int) { m.inflightFunc.Store(&f) }

// Observe records one proxy event.
func (m *Metrics) Observe(e proxy.Event) {
	m.requests.inc(string(e.Action), e.Decision.String(), string(e.Mode))
	if e.WouldBlock && e.Action == proxy.ActionForwarded {
		m.wouldBlock.inc(string(e.Mode))
	}
	for _, id := range e.Rules {
		m.detections.inc(string(id))
	}
	if e.Reason != "" && e.Action != proxy.ActionForwarded {
		m.rejections.inc(e.Reason)
	}
	if e.Exhausted != engine.BudgetNone {
		m.budgets.inc(e.Exhausted.String())
	}
	if e.Reason == proxy.ReasonInspectionError {
		m.inspectErrs.inc()
	}
	if e.FailedOpen {
		m.failedOpen.inc()
	}
	if e.InspectDuration > 0 {
		m.inspectTime.observe(e.InspectDuration.Seconds())
	}
	m.requestTime.observe(e.Duration.Seconds())
}

// printer writes formatted text and remembers the first error.
type printer struct {
	w   *bufio.Writer
	n   int64
	err error
}

func (p *printer) f(format string, args ...any) {
	n, err := fmt.Fprintf(p.w, format, args...)
	p.n += int64(n)
	if err != nil && p.err == nil {
		p.err = err
	}
}

// WriteTo renders all metrics in Prometheus text exposition format 0.0.4.
func (m *Metrics) WriteTo(out io.Writer) (int64, error) {
	p := &printer{w: bufio.NewWriter(out)}
	p.f("# HELP logshield_build_info Build information.\n# TYPE logshield_build_info gauge\nlogshield_build_info{version=%q} 1\n", escapeLabel(m.version))
	inflight := 0
	if f := m.inflightFunc.Load(); f != nil {
		inflight = (*f)()
	}
	p.f("# HELP logshield_requests_in_flight Requests currently being handled.\n# TYPE logshield_requests_in_flight gauge\nlogshield_requests_in_flight %d\n", inflight)
	for _, c := range []*counterVec{m.requests, m.wouldBlock, m.detections, m.rejections, m.budgets, m.failedOpen, m.inspectErrs} {
		c.write(p)
	}
	m.inspectTime.write(p)
	m.requestTime.write(p)
	if err := p.w.Flush(); err != nil && p.err == nil {
		p.err = err
	}
	return p.n, p.err
}
