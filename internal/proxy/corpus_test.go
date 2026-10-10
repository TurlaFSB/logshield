package proxy

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/TurlaFSB/logshield/internal/corpus"
	"github.com/TurlaFSB/logshield/internal/engine"
)

// rawFromEntry renders a corpus request as HTTP/1.1 bytes, so it goes through the
// real HTTP stack exactly as an attacker's client would send it.
func rawFromEntry(t *testing.T, e corpus.Entry) string {
	t.Helper()
	req, err := e.EngineRequest()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(req.Method + " " + req.Target + " HTTP/1.1\r\nHost: app.example.com\r\n")
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "Host") {
			continue
		}
		b.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	if len(req.Body) > 0 {
		b.WriteString("Content-Length: " + strconv.Itoa(len(req.Body)) + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.Write(req.Body)
	return b.String()
}

// Every attack in the corpus, sent over a real connection in block mode, must
// either be refused by the proxy or by Go's own parser, and never reach the
// upstream. Entries the engine only marks suspicious are forwarded.
func TestBypassCorpusThroughTheProxy(t *testing.T) {
	entries, err := corpus.Load(os.DirFS("../../corpus"), "bypass")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	for _, e := range entries {
		before := h.up.count()
		r := h.raw(rawFromEntry(t, e))
		reached := h.up.count() > before
		switch e.Expect.Decision {
		case "malicious":
			if reached || r.Status < 400 {
				t.Errorf("%s: malicious request got status %d and reached upstream=%v", e.ID, r.Status, reached)
			}
		case "suspicious":
			if !reached && r.Status != 400 {
				t.Errorf("%s: suspicious request not forwarded: status %d", e.ID, r.Status)
			}
		}
	}
}

// Every benign request is forwarded, and what the upstream receives is exactly
// what the engine inspected.
func TestBenignCorpusIsForwardedExactlyAsInspected(t *testing.T) {
	entries, err := corpus.Load(os.DirFS("../../corpus"), "benign")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	for _, e := range entries {
		before := h.up.count()
		r := h.raw(rawFromEntry(t, e))
		got := h.up.received()
		if h.up.count() != before+1 || r.Status != http.StatusOK {
			t.Errorf("%s: status %d, forwarded=%v", e.ID, r.Status, h.up.count() > before)
			continue
		}
		in := h.inspected()
		assertForwardedIsInspected(t, e.ID, in[len(in)-1], got[len(got)-1])
	}
}

// assertForwardedIsInspected is the central proxy invariant, checked from the
// outside: nothing the upstream received was absent from the inspected request.
func assertForwardedIsInspected(t *testing.T, id string, in engine.Request, up seen) {
	t.Helper()
	if up.Method != in.Method || up.RequestURI != in.Target {
		t.Errorf("%s: forwarded %s %s, inspected %s %s", id, up.Method, up.RequestURI, in.Method, in.Target)
	}
	if string(up.Body) != string(in.Body) {
		t.Errorf("%s: forwarded body differs from the inspected body (%d vs %d bytes)", id, len(up.Body), len(in.Body))
	}
	inspected := map[string]map[string]bool{}
	for _, h := range in.Headers {
		if inspected[http.CanonicalHeaderKey(h.Name)] == nil {
			inspected[http.CanonicalHeaderKey(h.Name)] = map[string]bool{}
		}
		inspected[http.CanonicalHeaderKey(h.Name)][h.Value] = true
	}
	for name, values := range up.Header {
		if generatedHeaders[name] || name == "Content-Length" || name == "Accept-Encoding" {
			continue
		}
		for _, v := range values {
			if !inspected[name][v] && (name != "User-Agent" || v != "") {
				t.Errorf("%s: upstream received %s: %q, which was not inspected", id, name, v)
			}
		}
	}
	if up.Host != "" && !inspected["Host"][up.Host] {
		t.Errorf("%s: upstream Host %q was not inspected", id, up.Host)
	}
}
