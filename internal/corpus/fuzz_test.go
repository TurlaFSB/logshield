package corpus

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// FuzzMutatedCorpus starts from every real corpus request and lets the fuzzer
// mutate it, which reaches inputs a generic fuzzer would need much longer to
// find (valid lookup syntax inside realistic requests, nested encodings, and
// so on). It checks safety invariants only: no panic, determinism, safe
// evidence, and the fail-closed budget rule.
func FuzzMutatedCorpus(f *testing.F) {
	for _, ds := range []string{"bypass", "benign"} {
		entries, err := Load(os.DirFS("../../corpus"), ds)
		if err != nil {
			f.Fatal(err)
		}
		for _, e := range entries {
			r, err := e.EngineRequest()
			if err != nil {
				f.Fatal(err)
			}
			hn, hv := "X-Fuzz", ""
			if len(r.Headers) > 0 {
				h := r.Headers[len(r.Headers)-1]
				hn, hv = h.Name, h.Value
			}
			ct := ""
			for _, h := range r.Headers {
				if strings.EqualFold(h.Name, "Content-Type") {
					ct = h.Value
				}
			}
			f.Add(r.Method, r.Target, hn, hv, ct, string(r.Body))
		}
	}

	cfg := engine.Config{MaxRequestBytes: 1 << 16, MaxWorkBytes: 4 << 20}
	f.Fuzz(func(t *testing.T, method, target, hn, hv, ct, body string) {
		r := engine.Request{
			Method:  method,
			Target:  target,
			Headers: []engine.Header{{Name: hn, Value: hv}, {Name: "Content-Type", Value: ct}},
			Body:    []byte(body),
		}
		a, b := engine.Inspect(r, cfg), engine.Inspect(r, cfg)
		if !reflect.DeepEqual(a, b) {
			t.Fatal("Inspect is not deterministic")
		}
		if !a.Complete() && a.Decision != engine.DecisionMalicious {
			t.Fatalf("budget exhausted (%v) but decision is %v", a.Exhausted, a.Decision)
		}
		for _, d := range a.Detections {
			for _, s := range append([]string{d.Evidence, d.Scheme}, d.KeyLookups...) {
				if strings.Contains(s, "${") {
					t.Fatalf("%s carries an active lookup: %q", d.Rule, s)
				}
			}
		}
	})
}
