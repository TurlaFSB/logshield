package corpus

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Outcome is the result of evaluating one entry.
type Outcome struct {
	Entry    Entry
	Verdict  engine.Verdict
	Pass     bool
	Reasons  []string // why it failed
	Rules    []engine.RuleID
	Decision string
}

// Evaluate runs every entry through the engine.
func Evaluate(entries []Entry, cfg engine.Config) []Outcome {
	out := make([]Outcome, 0, len(entries))
	for _, e := range entries {
		req, err := e.EngineRequest()
		o := Outcome{Entry: e}
		if err != nil {
			o.Reasons = append(o.Reasons, err.Error())
			out = append(out, o)
			continue
		}
		v := engine.Inspect(req, cfg)
		o.Verdict, o.Rules, o.Decision = v, v.RuleIDs(), v.Decision.String()
		if o.Decision != e.Expect.Decision {
			o.Reasons = append(o.Reasons, fmt.Sprintf("decision %s, want %s", o.Decision, e.Expect.Decision))
		}
		for _, id := range e.Expect.Rules {
			if !v.Has(engine.RuleID(id)) {
				o.Reasons = append(o.Reasons, "missing rule "+id)
			}
		}
		for _, id := range e.Expect.Forbid {
			if v.Has(engine.RuleID(id)) {
				o.Reasons = append(o.Reasons, "forbidden rule "+id)
			}
		}
		o.Pass = len(o.Reasons) == 0
		out = append(out, o)
	}
	return out
}

// Stats summarizes a set of outcomes for one dataset.
type Stats struct {
	Total      int
	Failed     int
	Malicious  int // decisions
	Suspicious int
	Clean      int
	// Misses counts entries expected malicious that were not blocked.
	Misses int
	// FalsePositives counts entries expected not-malicious that were blocked.
	FalsePositives int
}

// Summarize computes Stats.
func Summarize(outcomes []Outcome) Stats {
	var s Stats
	for _, o := range outcomes {
		s.Total++
		if !o.Pass {
			s.Failed++
		}
		switch o.Decision {
		case "malicious":
			s.Malicious++
		case "suspicious":
			s.Suspicious++
		case "clean":
			s.Clean++
		}
		if o.Entry.Expect.Decision == "malicious" && o.Decision != "malicious" {
			s.Misses++
		}
		if o.Entry.Expect.Decision != "malicious" && o.Decision == "malicious" {
			s.FalsePositives++
		}
	}
	return s
}

// WilsonUpper returns the upper bound of the 95% Wilson score interval for k
// events in n trials. With k = 0 it is the honest answer to "how sure are we
// the rate is below x": roughly 3.84/n.
func WilsonUpper(k, n int) float64 {
	if n == 0 {
		return 1
	}
	const z = 1.959964
	p := float64(k) / float64(n)
	nf := float64(n)
	denom := 1 + z*z/nf
	centre := p + z*z/(2*nf)
	margin := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf))
	return (centre + margin) / denom
}

// ByClass groups outcomes by class, in sorted class order.
func ByClass(outcomes []Outcome) (classes []string, groups map[string][]Outcome) {
	groups = make(map[string][]Outcome)
	for _, o := range outcomes {
		groups[o.Entry.Class] = append(groups[o.Entry.Class], o)
	}
	for c := range groups {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	return classes, groups
}

// Failures renders failed outcomes for test output.
func Failures(outcomes []Outcome) string {
	var b strings.Builder
	for _, o := range outcomes {
		if !o.Pass {
			fmt.Fprintf(&b, "%s [%s]: %s (rules %v)\n", o.Entry.ID, o.Entry.Class, strings.Join(o.Reasons, "; "), o.Rules)
		}
	}
	return b.String()
}

// SourceCounts counts entries per source type.
func SourceCounts(entries []Entry) map[string]int {
	m := make(map[string]int)
	for _, e := range entries {
		m[e.Source.Type]++
	}
	return m
}

// Classes lists the distinct classes of entries, sorted.
func Classes(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		if !slices.Contains(out, e.Class) {
			out = append(out, e.Class)
		}
	}
	sort.Strings(out)
	return out
}
