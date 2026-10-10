package proxy

import (
	"net/http"
	"testing"
	"time"
)

func TestOverloadIsShedWithRetryAfter(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxInFlight = 1 })
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	h.up.handler = func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}
	first := make(chan reply, 1)
	go func() { first <- h.raw(rawGET("/slow")) }()
	<-started
	if got := h.proxy.InFlight(); got != 1 {
		t.Errorf("InFlight = %d, want 1", got)
	}

	r := h.raw(rawGET("/second"))
	if r.Status != http.StatusServiceUnavailable || r.Header.Get("Retry-After") != "1" {
		t.Fatalf("second request: %d %v", r.Status, r.Header)
	}
	if h.up.count() != 1 {
		t.Errorf("a shed request reached the upstream")
	}
	h.waitEvents(1)
	if ev := h.lastEvent(); ev.Action != ActionRejected || ev.Reason != reasonOverloaded || ev.Status != http.StatusServiceUnavailable {
		t.Errorf("event %+v", ev)
	}

	close(release)
	if r := <-first; r.Status != http.StatusNoContent {
		t.Errorf("first request: %d", r.Status)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.proxy.InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := h.proxy.InFlight(); got != 0 {
		t.Errorf("InFlight = %d after completion", got)
	}
	if r := h.raw(rawGET("/after")); r.Status != http.StatusNoContent {
		t.Errorf("after the slot was freed: %d", r.Status)
	}
}

func TestInFlightLimitCanBeDisabledAndValidated(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxInFlight = -1 })
	if h.proxy.slots != nil {
		t.Error("slots allocated although the limit is disabled")
	}
	if r := h.raw(rawGET("/")); r.Status != http.StatusOK {
		t.Errorf("status %d", r.Status)
	}
	if err := (Config{Upstream: mustURL("http://x:1"), MaxInFlight: -2}).Validate(); err == nil {
		t.Error("-2 accepted")
	}
	p, _ := New(Config{Upstream: mustURL("http://x:1")})
	if cap(p.slots) != defaultMaxInFlight {
		t.Errorf("default limit = %d", cap(p.slots))
	}
}
