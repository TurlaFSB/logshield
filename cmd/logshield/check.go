package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Exit codes of "logshield check". They are separate from the usage (2) and
// runtime (1) errors so a script can tell "flagged" from "could not run".
const (
	checkExitClean      = 0
	checkExitSuspicious = 3
	checkExitMalicious  = 4
)

// maxCheckInput bounds what "check" reads from standard input.
const maxCheckInput = 1 << 20

// Places "check" can put the payload.
const (
	inHeader = "header"
	inQuery  = "query"
	inPath   = "path"
	inCookie = "cookie"
	inBody   = "body"
)

const checkUsage = `usage: logshield check [flags] PAYLOAD
       logshield check [flags] -      (read the payload from standard input)

Runs one payload through the same detection engine the proxy uses and explains
the verdict. It makes no network connection and never forwards anything.

Flags:
`

// runCheck implements "logshield check". It returns 0 (clean), 3 (suspicious),
// 4 (malicious), 1 (could not read the input) or 2 (usage error).
func runCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("logshield check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, checkUsage)
		fs.PrintDefaults()
	}
	var (
		in      = fs.String("in", inHeader, "where the payload sits in the request: header, query, path, cookie or body")
		name    = fs.String("name", "", "header, query or cookie name to use (default User-Agent, q, or s)")
		strict  = fs.Bool("block-suspicious", false, "report whether block mode would also block suspicious verdicts")
		asJSON  = fs.Bool("json", false, "print the result as JSON")
		disable listFlag
	)
	fs.Var(&disable, "disable-rule", "rule ID to switch off, as in the proxy (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "logshield check: expected exactly one PAYLOAD argument (or - for standard input)")
		fs.Usage()
		return 2
	}

	payload := fs.Arg(0)
	if payload == "-" {
		raw, err := io.ReadAll(io.LimitReader(stdin, maxCheckInput+1))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "logshield check: reading standard input: %v\n", err)
			return 1
		}
		if len(raw) > maxCheckInput {
			_, _ = fmt.Fprintf(stderr, "logshield check: input is larger than %d bytes\n", maxCheckInput)
			return 2
		}
		payload = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	}

	req, where, err := checkRequest(*in, *name, payload)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield check: %v\n", err)
		return 2
	}
	cfg := engine.Config{}
	for _, id := range disable {
		cfg.Disabled = append(cfg.Disabled, engine.RuleID(id))
	}
	if err := cfg.Validate(); err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield check: invalid configuration:\n%v\n", err)
		return 2
	}

	verdict := engine.Inspect(req, cfg)
	rep := newCheckReport(payload, where, verdict, *strict)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		rep.writeText(stdout)
	}
	switch verdict.Decision {
	case engine.DecisionMalicious:
		return checkExitMalicious
	case engine.DecisionSuspicious:
		return checkExitSuspicious
	default:
		return checkExitClean
	}
}

// checkRequest builds the request the payload would arrive in. The payload is
// placed exactly as given: percent-encode it yourself if a real client would.
func checkRequest(in, name, payload string) (engine.Request, string, error) {
	req := engine.Request{Method: "GET", Target: "/"}
	switch in {
	case inHeader:
		if name == "" {
			name = "User-Agent"
		}
		req.Headers = []engine.Header{{Name: name, Value: payload}}
		return req, "header " + name, nil
	case inCookie:
		if name == "" {
			name = "s"
		}
		req.Headers = []engine.Header{{Name: "Cookie", Value: name + "=" + payload}}
		return req, "cookie " + name, nil
	case inQuery:
		if name == "" {
			name = "q"
		}
		req.Target = "/?" + url.QueryEscape(name) + "=" + payload
		return req, "query parameter " + name, nil
	case inPath:
		req.Target = "/" + payload
		return req, "path", nil
	case inBody:
		req.Method = "POST"
		req.Headers = []engine.Header{{Name: "Content-Type", Value: "text/plain"}}
		req.Body = []byte(payload)
		return req, "body", nil
	default:
		return req, "", fmt.Errorf("unknown -in %q: use header, query, path, cookie or body", in)
	}
}

// checkDetection is one finding, in the JSON output and the text output.
type checkDetection struct {
	Rule     string   `json:"rule"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Location string   `json:"location"`
	Decoded  []string `json:"decoded_via,omitempty"`
	Scheme   string   `json:"scheme,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Leaks    []string `json:"key_lookups,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
}

// checkReport is the full result of one check.
type checkReport struct {
	Input           string           `json:"input"`
	Placed          string           `json:"placed_in"`
	Decision        string           `json:"decision"`
	WouldBlock      bool             `json:"would_block_in_block_mode"`
	Complete        bool             `json:"analysis_complete"`
	Exhausted       string           `json:"budget_exhausted,omitempty"`
	FieldsInspected int              `json:"fields_inspected"`
	Detections      []checkDetection `json:"detections"`
}

func newCheckReport(payload, where string, v engine.Verdict, strict bool) checkReport {
	rep := checkReport{
		// Defanged, so the report is safe to paste into a log or a terminal.
		Input:           engine.Defang(payload, 200),
		Placed:          where,
		Decision:        v.Decision.String(),
		WouldBlock:      v.Decision == engine.DecisionMalicious || (v.Decision == engine.DecisionSuspicious && strict),
		Complete:        v.Complete(),
		FieldsInspected: v.FieldsInspected,
		Detections:      []checkDetection{},
	}
	if !v.Complete() {
		rep.Exhausted = v.Exhausted.String()
	}
	info := map[engine.RuleID]engine.RuleInfo{}
	for _, r := range engine.Rules() {
		info[r.ID] = r
	}
	for _, d := range v.Detections {
		ri := info[d.Rule]
		cd := checkDetection{
			Rule: string(d.Rule), Name: ri.Name, Severity: d.Severity.String(),
			Location: d.Location.String(), Scheme: d.Scheme, Evidence: d.Evidence,
			Leaks: d.KeyLookups, CVEs: ri.CVEs,
		}
		for _, t := range d.Path {
			cd.Decoded = append(cd.Decoded, string(t))
		}
		rep.Detections = append(rep.Detections, cd)
	}
	return rep
}

func (r checkReport) writeText(w io.Writer) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("input:    %s\n", r.Input)
	p("          (defanged so it is safe to paste: dollar-brace becomes $%%7B and %% becomes %%25)\n")
	p("placed:   %s\n", r.Placed)
	p("verdict:  %s\n", strings.ToUpper(r.Decision))
	switch {
	case r.WouldBlock:
		p("          block mode would BLOCK this request (monitor mode records it only)\n")
	case r.Decision == "suspicious":
		p("          block mode would let it through and record it (add -block-suspicious to block)\n")
	case r.Decision == "clean":
		p("          nothing detected: block mode would forward it\n")
	}
	if !r.Complete {
		p("          analysis stopped at a resource limit (%s); the engine fails closed\n", r.Exhausted)
	}
	for _, d := range r.Detections {
		p("\n%s  %s  [%s]  at %s\n", d.Rule, d.Name, d.Severity, d.Location)
		if len(d.Decoded) > 0 {
			p("          revealed after decoding: %s\n", strings.Join(d.Decoded, " -> "))
		}
		if d.Scheme != "" {
			p("          JNDI scheme: %s\n", d.Scheme)
		}
		if d.Evidence != "" {
			p("          evidence: %s\n", d.Evidence)
		}
		if len(d.Leaks) > 0 {
			p("          would leak lookups: %s\n", strings.Join(d.Leaks, ", "))
		}
		if len(d.CVEs) > 0 {
			p("          %s\n", strings.Join(d.CVEs, ", "))
		}
	}
}
