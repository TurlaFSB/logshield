package proxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// waitEvents polls until n events were recorded.
func (h *harness) waitEvents(n int) {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for h.eventCount() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.eventCount() < n {
		h.t.Fatalf("got %d events, want %d", h.eventCount(), n)
	}
}

// Requests that Go's server refuses must still be observed, and must never
// reach the upstream.
func TestServerRefusalsAreObserved(t *testing.T) {
	cases := []struct {
		name, raw string
		status    int
	}{
		{"invalid header name", "GET / HTTP/1.1\r\nHost: a\r\nBad Header: x\r\n\r\n", 400},
		{"bare newline in header", "GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n", 400},
		{"conflicting content-length", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", 400},
		{"unknown transfer-encoding", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501},
		{"oversize headers", "GET / HTTP/1.1\r\nHost: a\r\nX: " + strings.Repeat("a", 2<<20) + "\r\n\r\n", 431},
		{"unsupported version", "GET / HTTP/9.9\r\nHost: a\r\n\r\n", 505},
		{"missing host", "GET / HTTP/1.1\r\n\r\n", 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, nil)
			conn := dial(t, h.addr())
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte(c.raw))
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			h.waitEvents(1)
			ev := h.lastEvent()
			if ev.Action != ActionRejected || ev.Reason != reasonProtocolError || ev.Status != c.status || ev.Remote != "127.0.0.1" || ev.ID == "" {
				t.Errorf("event %+v, want protocol-error with status %d", ev, c.status)
			}
			if h.up.count() != 0 {
				t.Errorf("a refused request reached the upstream")
			}
			if !strings.Contains(h.logs.String(), `"reason":"protocol-error"`) {
				t.Errorf("no log line: %s", h.logs.String())
			}
		})
	}
}

// Responses the handler itself sends (even 400s) are not protocol errors.
func TestHandlerResponsesAreNotProtocolErrors(t *testing.T) {
	h := newHarness(t, nil)
	h.raw("GET /#frag HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n") // our own 400
	h.raw(rawGET("/"))
	for _, ev := range h.allEvents() {
		if ev.Reason == reasonProtocolError {
			t.Errorf("handler response misclassified: %+v", ev)
		}
	}
}

func TestGoErrorStatusRecognition(t *testing.T) {
	yes := "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
	if s, ok := goErrorStatus([]byte(yes)); !ok || s != 400 {
		t.Errorf("not recognized: %d %v", s, ok)
	}
	for _, no := range []string{
		"",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n",
		"HTTP/1.1 400 Bad Request\r\nCache-Control: no-store\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		"HTTP/1.1 4xx Bad\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n",
		"HTTP/1.1 400",
		"HTTP/1.1 400 Bad Request without line ending",
		"GET / HTTP/1.1\r\n\r\n",
	} {
		if _, ok := goErrorStatus([]byte(no)); ok {
			t.Errorf("misrecognized %q", no)
		}
	}
}

func TestProtocolErrorWithoutObserverOrAddress(t *testing.T) {
	p, err := New(Config{Upstream: mustURL("http://127.0.0.1:1")})
	if err != nil {
		t.Fatal(err)
	}
	p.protocolError(nil, 400)                                      // must not panic
	p.protocolError(&net.UnixAddr{Name: "sock", Net: "unix"}, 400) // address without a port
	p.cfg.Observer = ObserverFunc(func(Event) { panic("observer bug") })
	p.protocolError(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, 400)
}

func TestWrapListenerPassesAcceptErrors(t *testing.T) {
	p, _ := New(Config{Upstream: mustURL("http://127.0.0.1:1")})
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := p.WrapListener(ln)
	_ = w.Close()
	if _, err := w.Accept(); err == nil {
		t.Error("Accept on a closed listener succeeded")
	}
}
