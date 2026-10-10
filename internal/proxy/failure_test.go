package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"testing"
	"time"
)

// serveRaw runs a TCP "upstream" that handles each connection with fn.
func serveRaw(t *testing.T, fn func(net.Conn)) *url.URL {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				fn(c)
			}()
		}
	}()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}
}

// newFailureHarness points a harness at the given upstream.
func newFailureHarness(t *testing.T, up *url.URL, mutate func(*Config)) *harness {
	t.Helper()
	return newHarness(t, func(c *Config) {
		c.Upstream = up
		c.Mode = ModeBlock
		if mutate != nil {
			mutate(c)
		}
	})
}

func TestUpstreamFailureModes(t *testing.T) {
	closedPort := func() *url.URL {
		var lc net.ListenConfig
		ln, _ := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		u := &url.URL{Scheme: "http", Host: ln.Addr().String()}
		_ = ln.Close()
		return u
	}()
	cases := []struct {
		name       string
		up         *url.URL
		mutate     func(*Config)
		wantStatus int
		wantReason string
	}{
		{"connection refused", closedPort, nil, http.StatusBadGateway, reasonUpstream},
		{"closes without answering", serveRaw(t, func(c net.Conn) { _, _ = io.CopyN(io.Discard, c, 16) }), nil, http.StatusBadGateway, reasonUpstream},
		{"sends garbage", serveRaw(t, func(c net.Conn) {
			_, _ = io.CopyN(io.Discard, c, 16)
			_, _ = io.WriteString(c, "not http at all\r\n\r\n")
		}), nil, http.StatusBadGateway, reasonUpstream},
		{"never answers", serveRaw(t, func(net.Conn) { time.Sleep(3 * time.Second) }), func(c *Config) {
			tr := DefaultTransport()
			tr.ResponseHeaderTimeout = 200 * time.Millisecond
			c.Transport = tr
		}, http.StatusGatewayTimeout, reasonUpstreamSlow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFailureHarness(t, tc.up, tc.mutate)
			r := h.raw(rawGET("/x"))
			if r.Status != tc.wantStatus {
				t.Errorf("status %d, want %d", r.Status, tc.wantStatus)
			}
			if r.Body == "" || len(r.Body) > 100 {
				t.Errorf("the error body must be short and fixed: %q", r.Body)
			}
			h.waitEvents(1)
			if ev := h.lastEvent(); ev.Action != ActionError || ev.Reason != tc.wantReason {
				t.Errorf("event %+v", ev)
			}
			if h.proxy.InFlight() != 0 {
				t.Errorf("in flight: %d", h.proxy.InFlight())
			}
		})
	}
}

// An upstream that dies halfway through a response must not wedge the proxy.
func TestUpstreamDiesMidResponse(t *testing.T) {
	up := serveRaw(t, func(c net.Conn) {
		_, _ = io.CopyN(io.Discard, c, 16)
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\npartial")
	})
	h := newFailureHarness(t, up, nil)
	_ = h.rawAll(rawGET("/x"), 1) // the client sees a truncated body; what matters is the proxy's state
	deadline := time.Now().Add(3 * time.Second)
	for h.proxy.InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.proxy.InFlight() != 0 {
		t.Errorf("in flight: %d", h.proxy.InFlight())
	}
	// Many more truncated responses in a row: slots must keep coming back.
	for i := 0; i < 50; i++ {
		_ = h.rawAll(rawGET("/again"), 1)
	}
	deadline = time.Now().Add(3 * time.Second)
	for h.proxy.InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.proxy.InFlight() != 0 {
		t.Errorf("in flight after repeated truncations: %d", h.proxy.InFlight())
	}
}

// Repeated failures must not leak slots or goroutines.
func TestRepeatedUpstreamFailuresDoNotLeak(t *testing.T) {
	var lc net.ListenConfig
	ln, _ := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	dead := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	_ = ln.Close()
	h := newFailureHarness(t, dead, func(c *Config) { c.MaxInFlight = 4 })
	before := runtime.NumGoroutine()
	for i := 0; i < 300; i++ {
		if r := h.raw(rawGET("/x")); r.Status != http.StatusBadGateway {
			t.Fatalf("request %d: status %d (a leaked slot would turn this into 503)", i, r.Status)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for (h.proxy.InFlight() != 0 || runtime.NumGoroutine() > before+10) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if h.proxy.InFlight() != 0 || runtime.NumGoroutine() > before+10 {
		t.Errorf("in flight %d, goroutines %d -> %d", h.proxy.InFlight(), before, runtime.NumGoroutine())
	}
}
