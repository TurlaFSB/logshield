package lab

import (
	"fmt"
	"sort"
	"strings"
)

// Summary aggregates a run.
type Summary struct {
	Total        int
	ByTruth      map[Truth]int
	ByProblem    map[string]int
	Triggered    int
	Caught       int // triggered and flagged malicious
	OverBlocked  int // not triggered, attack-class, flagged malicious
	ProxyBlocked int
	ProxyPassed  int
	ProxyRefused int
	// LookupPassed counts requests where Log4j resolved a non-JNDI lookup
	// (for example an environment variable) and the proxy let them through.
	// Informational: the default policy does not block suspicious requests.
	LookupPassed  int
	BenignTotal   int
	BenignBlocked int
}

// Summarize counts results.
func Summarize(rs []Result) Summary {
	s := Summary{Total: len(rs), ByTruth: map[Truth]int{}, ByProblem: map[string]int{}}
	for _, r := range rs {
		s.ByTruth[r.Truth]++
		for _, p := range r.Problems {
			s.ByProblem[p]++
		}
		benign := r.Dataset == "benign" || r.Dataset == "generated"
		if benign {
			s.BenignTotal++
			if r.Engine == "malicious" || r.Proxy == ProxyBlocked {
				s.BenignBlocked++
			}
		}
		if r.Truth == TruthTriggered {
			s.Triggered++
			if r.Engine == "malicious" {
				s.Caught++
			}
		} else if !benign && r.Engine == "malicious" {
			s.OverBlocked++
		}
		switch r.Proxy {
		case ProxyBlocked:
			s.ProxyBlocked++
		case ProxyPassed:
			s.ProxyPassed++
			if r.Truth == TruthLookupOnly {
				s.LookupPassed++
			}
		case ProxyRefused:
			s.ProxyRefused++
		}
	}
	return s
}

// Failed reports whether the run has any problem.
func (s Summary) Failed() bool { return len(s.ByProblem) > 0 }

// Markdown renders the report. Payload text appears only defanged.
func Markdown(rs []Result, s Summary, meta map[string]string) string {
	var b strings.Builder
	b.WriteString("# LogShield lab report\n\n")
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- **%s**: %s\n", k, meta[k])
	}
	b.WriteString("\n## Result\n\n")
	if s.Failed() {
		b.WriteString("**FAIL**\n\n")
	} else {
		b.WriteString("**PASS**\n\n")
	}
	fmt.Fprintf(&b, "| Measure | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| Entries run | %d |\n", s.Total)
	fmt.Fprintf(&b, "| Log4j attempted a JNDI lookup (ground truth) | %d |\n", s.Triggered)
	fmt.Fprintf(&b, "| ...of which the engine flagged malicious | %d |\n", s.Caught)
	fmt.Fprintf(&b, "| Log4j resolved another lookup only | %d |\n", s.ByTruth[TruthLookupOnly])
	fmt.Fprintf(&b, "| Log4j left the text unchanged | %d |\n", s.ByTruth[TruthInert])
	fmt.Fprintf(&b, "| No ground truth (indeterminate) | %d |\n", s.ByTruth[TruthUnknown])
	fmt.Fprintf(&b, "| Attack-class entries blocked although Log4j ignored them (over-blocks) | %d |\n", s.OverBlocked)
	fmt.Fprintf(&b, "| Benign entries run / blocked | %d / %d |\n", s.BenignTotal, s.BenignBlocked)
	fmt.Fprintf(&b, "| Proxy phase: blocked / passed / refused | %d / %d / %d |\n", s.ProxyBlocked, s.ProxyPassed, s.ProxyRefused)
	fmt.Fprintf(&b, "| Non-JNDI lookups Log4j resolved that the proxy let through (information, see docs/lab.md) | %d |\n", s.LookupPassed)
	for _, p := range []string{ProblemMiss, ProblemLeak, ProblemFalsePos, ProblemExpect, ProblemUnknown} {
		fmt.Fprintf(&b, "| **%s** | %d |\n", p, s.ByProblem[p])
	}

	var bad []Result
	for _, r := range rs {
		if len(r.Problems) > 0 {
			bad = append(bad, r)
		}
	}
	if len(bad) > 0 {
		b.WriteString("\n## Problems\n\n| ID | Dataset | Problems | Truth | Engine | Rules | Proxy | JNDI seen by Log4j | Error |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, r := range bad {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", r.ID, r.Dataset,
				strings.Join(r.Problems, ","), r.Truth, r.Engine, strings.Join(r.Rules, ","), r.Proxy,
				md(strings.Join(r.JNDI, " ; ")), md(r.Err))
		}
	}

	// Informational listings, so a reviewer sees the evidence and not only counts.
	var over, looks []Result
	for _, r := range rs {
		benign := r.Dataset == "benign" || r.Dataset == "generated"
		if !benign && r.Truth != TruthTriggered && r.Engine == "malicious" {
			over = append(over, r)
		}
		if r.Truth == TruthLookupOnly && r.Proxy == ProxyPassed {
			looks = append(looks, r)
		}
	}
	const capRows = 120
	if len(over) > 0 {
		b.WriteString("\n## Over-blocks (information)\n\nAttack-class entries the engine blocks although Log4j ignored them.\n\n| ID | Class | Truth | Rules | Proxy |\n|---|---|---|---|---|\n")
		for i, r := range over {
			if i == capRows {
				fmt.Fprintf(&b, "| ... %d more in results.json | | | | |\n", len(over)-capRows)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", r.ID, r.Class, r.Truth, strings.Join(r.Rules, ","), r.Proxy)
		}
	}
	if len(looks) > 0 {
		// Attack datasets first: they are the interesting ones.
		sort.SliceStable(looks, func(i, j int) bool {
			return (looks[i].Dataset == "bypass") && (looks[j].Dataset != "bypass")
		})
		b.WriteString("\n## Non-JNDI lookups Log4j resolved and the proxy forwarded (information)\n\n| ID | Dataset | Engine | Rules | What Log4j changed |\n|---|---|---|---|---|\n")
		for i, r := range looks {
			if i == capRows {
				fmt.Fprintf(&b, "| ... %d more in results.json | | | | |\n", len(looks)-capRows)
				break
			}
			var ch []string
			for _, c := range r.Changes {
				ch = append(ch, fmt.Sprintf("%s: `%s` to `%s`", c.Source, c.Raw, c.Rendered))
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", r.ID, r.Dataset, r.Engine, strings.Join(r.Rules, ","), md(strings.Join(ch, "; ")))
		}
	}
	return b.String()
}

func md(s string) string { return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s) }
