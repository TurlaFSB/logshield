package proxy

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/TurlaFSB/logshield/internal/engine"
)

func TestCleanRequestIsForwardedVerbatim(t *testing.T) {
	h := newHarness(t, nil)
	target := "/a%2Fb/c?x=%7B&y=%24&z=a+b&empty="
	r := h.raw(rawGET(target, "User-Agent: curl/8.5.0", "Accept: */*", "X-Custom: value with  spaces", "Cookie: a=1; b=2"))
	if r.Status != 200 || r.Body != "ok" || r.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("response = %d %q %v", r.Status, r.Body, r.Header)
	}
	got := h.up.received()
	if len(got) != 1 {
		t.Fatalf("upstream saw %d requests", len(got))
	}
	s := got[0]
	if s.Method != http.MethodGet || s.RequestURI != target || s.Host != "app.example.com" {
		t.Errorf("method/target/host = %q %q %q", s.Method, s.RequestURI, s.Host)
	}
	for k, want := range map[string]string{"User-Agent": "curl/8.5.0", "Accept": "*/*", "X-Custom": "value with  spaces", "Cookie": "a=1; b=2"} {
		if s.Header.Get(k) != want {
			t.Errorf("header %s = %q, want %q", k, s.Header.Get(k), want)
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(s.Header.Get("X-Request-Id")) {
		t.Errorf("X-Request-Id = %q", s.Header.Get("X-Request-Id"))
	}
	if s.Header.Get("X-Forwarded-For") != "127.0.0.1" || s.Header.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("forwarded headers: %v", s.Header)
	}
	if ev := h.lastEvent(); ev.Action != ActionForwarded || ev.Decision != engine.DecisionClean || ev.Status != 200 {
		t.Errorf("event = %+v", ev)
	}
}

func TestBodyIsBufferedAndReframed(t *testing.T) {
	h := newHarness(t, nil)
	body := strings.Repeat("0123456789", 100)
	r := h.do("POST", "/submit", http.Header{"Content-Type": {"text/plain"}}, strings.NewReader(body))
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	s := h.up.received()[0]
	if string(s.Body) != body || s.ContentLength != int64(len(body)) || len(s.TE) != 0 {
		t.Errorf("body %d bytes, CL %d, TE %v", len(s.Body), s.ContentLength, s.TE)
	}
	if in := h.inspected(); len(in) != 1 || string(in[0].Body) != body {
		t.Errorf("engine did not see the whole body")
	}
}

func TestChunkedBodyIsDechunkedForwardedWithLength(t *testing.T) {
	h := newHarness(t, nil)
	r := h.raw("POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
		"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer-X: dropped\r\n\r\n")
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	s := h.up.received()[0]
	if string(s.Body) != "hello world" || s.ContentLength != 11 || len(s.TE) != 0 {
		t.Errorf("upstream saw body %q CL %d TE %v", s.Body, s.ContentLength, s.TE)
	}
	if s.Header.Get("Trailer-X") != "" || s.Header.Get("Trailer") != "" {
		t.Errorf("trailer leaked: %v", s.Header)
	}
}

func TestAttackInBodyOfChunkedRequestIsBlocked(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	chunk := attack
	r := h.raw("POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
		"1a\r\n" + chunk + "\r\n0\r\n\r\n")
	if r.Status != http.StatusForbidden || h.up.count() != 0 {
		t.Fatalf("status %d, upstream saw %d", r.Status, h.up.count())
	}
}

func TestBlockModeBlocksAndMonitorForwards(t *testing.T) {
	for _, mode := range []Mode{ModeBlock, ModeMonitor} {
		t.Run(string(mode), func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.Mode = mode })
			r := h.raw(rawGET("/", "User-Agent: "+attack))
			ev := h.lastEvent()
			if !ev.WouldBlock || ev.Decision != engine.DecisionMalicious || len(ev.Rules) == 0 {
				t.Errorf("event = %+v", ev)
			}
			if mode == ModeBlock {
				if r.Status != 403 || h.up.count() != 0 || ev.Action != ActionBlocked {
					t.Errorf("block: status %d, upstream %d, action %s", r.Status, h.up.count(), ev.Action)
				}
				if !strings.Contains(r.Body, "reference: "+ev.ID) || strings.Contains(r.Body, "jndi") {
					t.Errorf("block body = %q", r.Body)
				}
				if r.Header.Get("X-Request-Id") != ev.ID {
					t.Errorf("X-Request-Id %q", r.Header.Get("X-Request-Id"))
				}
			} else if r.Status != 200 || h.up.count() != 1 || ev.Action != ActionForwarded {
				t.Errorf("monitor: status %d, upstream %d, action %s", r.Status, h.up.count(), ev.Action)
			}
		})
	}
}

func TestMonitorIsTheDefault(t *testing.T) {
	h := newHarness(t, nil)
	if h.proxy.cfg.Mode != ModeMonitor {
		t.Fatalf("default mode = %q", h.proxy.cfg.Mode)
	}
	if r := h.raw(rawGET("/?q=" + attack)); r.Status != 200 {
		t.Errorf("status %d", r.Status)
	}
}

func TestBlockStatusAndStrictMode(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock; c.BlockStatus = 406 })
	if r := h.raw(rawGET("/", "User-Agent: "+attack)); r.Status != 406 {
		t.Errorf("block status %d", r.Status)
	}
	// Suspicious is forwarded by default and blocked in strict mode.
	suspicious := rawGET("/?q=${env:HOME}")
	if r := h.raw(suspicious); r.Status != 200 {
		t.Errorf("suspicious request: status %d", r.Status)
	}
	if ev := h.lastEvent(); ev.Decision != engine.DecisionSuspicious || ev.WouldBlock {
		t.Errorf("event %+v", ev)
	}
	s := newHarness(t, func(c *Config) { c.Mode = ModeBlock; c.BlockSuspicious = true })
	if r := s.raw(suspicious); r.Status != 403 || s.up.count() != 0 {
		t.Errorf("strict: status %d, upstream %d", r.Status, s.up.count())
	}
}

func TestHostHeaderIsInspected(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	// Go's server rejects some forbidden characters itself; either way the
	// request must not reach the upstream, and when it does reach the proxy the
	// Host value must have been inspected.
	for _, host := range []string{attack, "x.invalid:" + attack, "%24%7Bjndi:ldap://x.invalid/a%7D"} {
		before := h.up.count()
		r := h.raw("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
		if h.up.count() != before {
			t.Errorf("host %q reached the upstream (status %d)", host, r.Status)
		}
	}
	// A Host the proxy can see is part of the inspected request.
	h2 := newHarness(t, nil)
	h2.raw(rawGET("/"))
	in := h2.inspected()
	if len(in) != 1 || in[0].Headers[0].Name != "Host" || in[0].Headers[0].Value != "app.example.com" {
		t.Errorf("inspected headers: %+v", in[0].Headers)
	}
}

func TestSmuggledRequestIsInspectedOnItsOwn(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	// Conflicting framing: whatever the proxy decides the body is, the bytes that
	// follow it become a separate request on the connection and are inspected
	// like any other.
	payload := "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\n" +
		"GET /second HTTP/1.1\r\nHost: a\r\nUser-Agent: " + attack + "\r\n\r\n"
	h.rawAll(payload, 2)
	for _, s := range h.up.received() {
		for _, v := range s.Header {
			for _, x := range v {
				if strings.Contains(x, "jndi") {
					t.Fatalf("attack header reached the upstream: %+v", s)
				}
			}
		}
		if s.RequestURI == "/second" {
			t.Fatal("the second request carried an attack and was forwarded")
		}
	}
}

func TestFramingSentUpstreamIsUnambiguous(t *testing.T) {
	h := newHarness(t, nil)
	h.raw("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	for _, s := range h.up.received() {
		if len(s.TE) != 0 && s.ContentLength >= 0 {
			t.Errorf("upstream saw both Transfer-Encoding %v and Content-Length %d", s.TE, s.ContentLength)
		}
	}
}

func TestObsFoldAndBareLFAreNormalized(t *testing.T) {
	h := newHarness(t, nil)
	h.raw("GET / HTTP/1.1\nHost: a\nX-Fold: first\n second\nConnection: close\n\n")
	received := h.up.received()
	if len(received) == 1 {
		v := received[0].Header.Get("X-Fold")
		if strings.ContainsAny(v, "\r\n") {
			t.Errorf("folded value forwarded with a line break: %q", v)
		}
		// Whatever was forwarded was inspected.
		for _, hd := range h.inspected()[0].Headers {
			if hd.Name == "X-Fold" && hd.Value != v {
				t.Errorf("inspected %q but forwarded %q", hd.Value, v)
			}
		}
	}
}

func TestUnsupportedRequestFormsAreRejected(t *testing.T) {
	h := newHarness(t, nil)
	cases := map[string]struct {
		req    string
		status int
		reason string
	}{
		"connect":       {"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n", 501, reasonConnect},
		"upgrade":       {rawGET("/ws", "Upgrade: websocket", "Connection: Upgrade"), 501, reasonUpgrade},
		"absolute-form": {"GET http://other.example/x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", 400, reasonTarget},
		"double-slash":  {rawGET("//evil.example/x"), 400, reasonDoubleSlash},
		"fragment":      {rawGET("/a#frag"), 400, reasonFragment},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			before := h.eventCount()
			r := h.raw(tc.req)
			if r.Status != tc.status {
				t.Errorf("status %d, want %d", r.Status, tc.status)
			}
			if h.eventCount() == before {
				t.Fatal("no event")
			}
			if ev := h.lastEvent(); ev.Action != ActionRejected || ev.Reason != tc.reason {
				t.Errorf("event %+v", ev)
			}
		})
	}
	if h.up.count() != 0 {
		t.Errorf("rejected requests reached the upstream: %d", h.up.count())
	}
}

func TestOptionsAsteriskIsAnsweredByTheServerAndNeverForwarded(t *testing.T) {
	h := newHarness(t, nil)
	h.raw("OPTIONS * HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
	if h.up.count() != 0 {
		t.Error("OPTIONS * reached the upstream")
	}
}

func TestHopByHopHeadersAreNotForwarded(t *testing.T) {
	h := newHarness(t, nil)
	h.raw(rawGET("/", "Connection: keep-alive, X-Remove-Me", "X-Remove-Me: secret", "TE: trailers", "Proxy-Authorization: Basic eDp5", "Keep-Alive: timeout=5", "X-Keep: yes"))
	s := h.up.received()[0]
	// "TE: trailers" is the one hop-by-hop value the HTTP library relays (gRPC
	// needs it); it is inspected like every other header.
	for _, name := range []string{"X-Remove-Me", "Proxy-Authorization", "Keep-Alive"} {
		if s.Header.Get(name) != "" {
			t.Errorf("hop-by-hop header %s forwarded: %q", name, s.Header.Get(name))
		}
	}
	if s.Header.Get("X-Keep") != "yes" {
		t.Errorf("end-to-end header dropped")
	}
	// They were still inspected: a payload in a hop-by-hop header is an attack.
	found := false
	for _, hd := range h.inspected()[0].Headers {
		if hd.Name == "X-Remove-Me" {
			found = true
		}
	}
	if !found {
		t.Error("hop-by-hop headers were not inspected")
	}
}

func TestPayloadInHopByHopHeaderIsStillBlocked(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	r := h.raw(rawGET("/", "Connection: keep-alive, X-Remove-Me", "X-Remove-Me: "+attack))
	if r.Status != 403 {
		t.Errorf("status %d", r.Status)
	}
}

func TestForwardedForPolicies(t *testing.T) {
	tests := []struct {
		policy ForwardedFor
		want   string
		absent bool
	}{
		{ForwardedForReplace, "127.0.0.1", false},
		{ForwardedForAppend, "203.0.113.9, 127.0.0.1", false},
		{ForwardedForOff, "", true},
	}
	for _, tc := range tests {
		t.Run(string(tc.policy), func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.ForwardedFor = tc.policy })
			h.raw(rawGET("/", "X-Forwarded-For: 203.0.113.9", "X-Forwarded-Host: spoofed.example", "Forwarded: for=spoofed"))
			s := h.up.received()[0]
			got := s.Header.Get("X-Forwarded-For")
			if tc.absent {
				if _, ok := s.Header["X-Forwarded-For"]; ok {
					t.Errorf("X-Forwarded-For present: %q", got)
				}
			} else if got != tc.want {
				t.Errorf("X-Forwarded-For = %q, want %q", got, tc.want)
			}
			if s.Header.Get("X-Forwarded-Host") != "" || s.Header.Get("Forwarded") != "" {
				t.Errorf("client-supplied forwarding headers survived: %v", s.Header)
			}
		})
	}
}

func TestRewriteHost(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.RewriteHost = true })
	h.raw(rawGET("/"))
	s := h.up.received()[0]
	if s.Host != h.up.url(t).Host || s.Header.Get("X-Forwarded-Host") != "app.example.com" {
		t.Errorf("host %q, X-Forwarded-Host %q", s.Host, s.Header.Get("X-Forwarded-Host"))
	}
}

func TestExpectContinueIsHandled(t *testing.T) {
	h := newHarness(t, nil)
	r := h.do("POST", "/up", http.Header{"Expect": {"100-continue"}, "Content-Type": {"text/plain"}}, strings.NewReader("data"))
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	s := h.up.received()[0]
	if s.Header.Get("Expect") != "" || string(s.Body) != "data" {
		t.Errorf("Expect %q body %q", s.Header.Get("Expect"), s.Body)
	}
}

func TestUpstreamResponseIsRelayed(t *testing.T) {
	h := newHarness(t, nil)
	h.up.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "X-Secret-Hop")
		w.Header().Set("X-Secret-Hop", "x")
		w.Header().Set("X-End-To-End", "y")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}
	r := h.raw(rawGET("/"))
	if r.Status != 201 || r.Body != "created" || r.Header.Get("X-End-To-End") != "y" || len(r.Header.Values("Set-Cookie")) != 2 {
		t.Errorf("response %d %q %v", r.Status, r.Body, r.Header)
	}
	if r.Header.Get("X-Secret-Hop") != "" {
		t.Error("hop-by-hop response header relayed")
	}
}

func TestHEADAndEmptyBodies(t *testing.T) {
	h := newHarness(t, nil)
	if r := h.do("HEAD", "/h", nil, nil); r.Status != 200 || r.Body != "" {
		t.Errorf("HEAD: %d %q", r.Status, r.Body)
	}
	if r := h.do("POST", "/p", nil, bytes.NewReader(nil)); r.Status != 200 {
		t.Errorf("empty POST: %d", r.Status)
	}
	s := h.up.received()
	if len(s) != 2 || s[0].Method != http.MethodHead || len(s[1].Body) != 0 {
		t.Errorf("upstream saw %+v", s)
	}
}

func TestHTTP10WithoutHost(t *testing.T) {
	h := newHarness(t, nil)
	r := h.raw("GET / HTTP/1.0\r\n\r\n")
	if r.Status != 200 || h.up.count() != 1 {
		t.Errorf("status %d, upstream %d", r.Status, h.up.count())
	}
}
