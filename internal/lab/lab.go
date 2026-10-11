// Package lab drives the differential validation described in docs/lab.md.
//
// A "canary" runs real, vulnerable Log4j 2.14.1 and reports what Log4j did
// with every part of a request. The runner sends each corpus entry to the
// canary directly (ground truth), asks the engine for its decision, and,
// optionally, sends it through a LogShield instance in enforce mode. The three
// are then compared. Any entry that really triggered a JNDI lookup but was not
// flagged is a miss; any that got through the proxy is a leak.
//
// The package only builds and sends requests that are already in the corpora.
// Their payloads point at reserved names, and the canary runs with a JNDI hook
// that records lookups and refuses them, so nothing leaves the lab.
package lab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/TurlaFSB/logshield/internal/corpus"
	"github.com/TurlaFSB/logshield/internal/engine"
)

// Truth is what the vulnerable Log4j actually did.
type Truth string

// Truth values.
const (
	// TruthTriggered: Log4j attempted at least one JNDI lookup.
	TruthTriggered Truth = "triggered"
	// TruthLookupOnly: Log4j resolved some other lookup (for example ${java:version})
	// but attempted no JNDI lookup.
	TruthLookupOnly Truth = "lookup-only"
	// TruthInert: Log4j logged the text unchanged.
	TruthInert Truth = "inert"
	// TruthUnknown: the canary did not give a usable answer (rejected the
	// request, timed out). Never counted as a pass.
	TruthUnknown Truth = "indeterminate"
)

// Proxy outcomes.
const (
	ProxySkipped = "skipped"
	ProxyBlocked = "blocked"
	// ProxyRefused: an error status that is not the block status and carries no
	// canary reply. Either LogShield refused a malformed request, or the canary
	// answered with an error. No Log4j effect was observed.
	ProxyRefused = "refused"
	// ProxyPassed: the request was served by the canary.
	ProxyPassed = "passed"
	ProxyError  = "error"
)

// Problem kinds. Any of them fails the run.
const (
	ProblemMiss     = "MISS"            // really triggered, engine did not say malicious
	ProblemLeak     = "LEAK"            // really triggered, and the proxy let it reach Log4j
	ProblemFalsePos = "FALSE_POSITIVE"  // benign entry the engine or proxy blocked
	ProblemExpect   = "EXPECT_MISMATCH" // engine disagrees with the corpus expectation
	ProblemUnknown  = "INDETERMINATE"   // ground truth unavailable for an attack entry
)

// Item is what the canary reports for one logged value.
type Item struct {
	Source   string   `json:"source"`
	Raw      string   `json:"raw"`
	Rendered string   `json:"rendered"`
	Changed  bool     `json:"changed"`
	JNDI     []string `json:"jndi"`
	// Error is set by the canary when it could not observe Log4j for this value.
	Error string `json:"error,omitempty"`
}

// CanaryReply is the canary's JSON response.
type CanaryReply struct {
	Items []Item `json:"items"`
}

// Response is a parsed HTTP response.
type Response struct {
	Status int
	Body   []byte
	Canary *CanaryReply // nil if the body is not a canary reply
}

// BuildRaw serializes a corpus request exactly as written: the request target
// and header bytes are not normalised. A Content-Length is added only when the
// entry has a body and sets neither Content-Length nor Transfer-Encoding, and
// Connection: close is added unless the entry sets it.
func BuildRaw(r corpus.Request) ([]byte, error) {
	var body []byte
	switch {
	case r.Body != "" && r.BodyB64 != "":
		return nil, fmt.Errorf("body and body_b64 are mutually exclusive")
	case r.BodyB64 != "":
		e := corpus.Entry{Request: r}
		er, err := e.EngineRequest()
		if err != nil {
			return nil, err
		}
		body = er.Body
	default:
		body = []byte(r.Body)
	}
	var b bytes.Buffer
	method := r.Method
	if method == "" {
		method = "GET"
	}
	target := r.Target
	if target == "" {
		target = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, target)
	var hasCL, hasTE, hasConn, hasHost bool
	for _, h := range r.Headers {
		switch strings.ToLower(h[0]) {
		case "content-length":
			hasCL = true
		case "transfer-encoding":
			hasTE = true
		case "connection":
			hasConn = true
		case "host":
			hasHost = true
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	if !hasHost {
		b.WriteString("Host: lab.invalid\r\n")
	}
	if len(body) > 0 && !hasCL && !hasTE {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	if !hasConn {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes(), nil
}

// Send writes raw to addr (host:port) and reads one response.
func Send(ctx context.Context, addr string, raw []byte, timeout time.Duration) (Response, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, werr := conn.Write(raw); werr != nil {
		return Response{}, fmt.Errorf("write: %w", werr)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return Response{}, fmt.Errorf("read: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Response{}, fmt.Errorf("read body: %w", err)
	}
	out := Response{Status: resp.StatusCode, Body: body}
	var cr CanaryReply
	if resp.StatusCode == http.StatusOK && json.Unmarshal(body, &cr) == nil && cr.Items != nil {
		out.Canary = &cr
	}
	return out, nil
}

// TruthOf reads ground truth out of a canary reply.
func TruthOf(r Response, err error) (Truth, []string) {
	if err != nil || r.Canary == nil {
		return TruthUnknown, nil
	}
	var jndi []string
	changed := false
	for _, it := range r.Canary.Items {
		if it.Error != "" {
			return TruthUnknown, nil
		}
		jndi = append(jndi, it.JNDI...)
		changed = changed || it.Changed
	}
	switch {
	case len(jndi) > 0:
		return TruthTriggered, jndi
	case changed:
		return TruthLookupOnly, nil
	default:
		return TruthInert, nil
	}
}

// Change is one value Log4j rewrote, kept (defanged) so a reviewer can see
// what a lookup-only or triggering request actually did.
type Change struct {
	Source   string `json:"source"`
	Raw      string `json:"raw"`
	Rendered string `json:"rendered"`
}

const (
	maxChanges    = 4
	maxChangeText = 160
)

// ChangesOf lists up to maxChanges values that Log4j rewrote, defanged.
func ChangesOf(r Response) []Change {
	if r.Canary == nil {
		return nil
	}
	out := make([]Change, 0, maxChanges)
	for _, it := range r.Canary.Items {
		if !it.Changed || len(out) == maxChanges {
			continue
		}
		out = append(out, Change{
			Source:   it.Source,
			Raw:      engine.Defang(it.Raw, maxChangeText),
			Rendered: engine.Defang(it.Rendered, maxChangeText),
		})
	}
	return out
}

// Result is the comparison for one corpus entry.
type Result struct {
	ID      string   `json:"id"`
	Dataset string   `json:"dataset"`
	Class   string   `json:"class"`
	Expect  string   `json:"expect"`
	Engine  string   `json:"engine"`
	Rules   []string `json:"rules,omitempty"`
	Truth   Truth    `json:"truth"`
	// JNDI lists the lookups Log4j attempted, defanged.
	JNDI []string `json:"jndi,omitempty"`
	// Changes shows what Log4j rewrote (lookup-only and triggering requests).
	Changes []Change `json:"changes,omitempty"`
	Proxy   string   `json:"proxy"`
	// ProxyTruth is what Log4j did with the request after it passed through the
	// proxy (only set when it passed).
	ProxyTruth  Truth    `json:"proxy_truth,omitempty"`
	ProxyStatus int      `json:"proxy_status,omitempty"`
	Problems    []string `json:"problems,omitempty"`
	Err         string   `json:"error,omitempty"`
}

// Classify applies the lab's pass/fail rules to one entry. It is pure so the
// rules are testable without a lab.
//
//   - MISS: Log4j really attempted a JNDI lookup but the engine did not say malicious.
//   - LEAK: Log4j attempted a JNDI lookup on a request that came through the proxy.
//   - FALSE_POSITIVE: an entry the corpus expects to be clean was blocked.
//   - EXPECT_MISMATCH: the engine's decision differs from the corpus expectation.
//   - INDETERMINATE: no ground truth for an attack entry (so it proves nothing).
//
// An attack-class entry that Log4j ignored but the engine blocks is not a
// failure: the engine is intentionally conservative, and the report counts
// these as over-blocks.
func Classify(r Result, isBenignDataset bool) []string {
	var p []string
	if r.Truth == TruthTriggered && r.Engine != engine.DecisionMalicious.String() {
		p = append(p, ProblemMiss)
	}
	if r.Proxy == ProxyPassed && r.ProxyTruth == TruthTriggered {
		p = append(p, ProblemLeak)
	}
	if isBenignDataset && (r.Engine == engine.DecisionMalicious.String() || r.Proxy == ProxyBlocked) {
		p = append(p, ProblemFalsePos)
	}
	if r.Engine != r.Expect {
		p = append(p, ProblemExpect)
	}
	if !isBenignDataset && r.Truth == TruthUnknown {
		p = append(p, ProblemUnknown)
	}
	return p
}

// Options configures a run.
type Options struct {
	CanaryAddr string        // host:port of the canary (required)
	ProxyAddr  string        // host:port of LogShield in enforce mode; empty skips the proxy phase
	BlockCode  int           // status LogShield uses for blocks (default 403)
	Timeout    time.Duration // per request (default 10s)
	Engine     engine.Config
	// ReadyProbe is called once before the run to check the canary is up.
	ReadyProbe bool
}

// Run evaluates every entry. progress, if non-nil, is called after each one.
func Run(ctx context.Context, entries []corpus.Entry, o Options, progress func(done, total int)) ([]Result, error) {
	if o.CanaryAddr == "" {
		return nil, fmt.Errorf("canary address is required")
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.BlockCode == 0 {
		o.BlockCode = http.StatusForbidden
	}
	if o.ReadyProbe {
		probe := corpus.Request{Method: "GET", Target: "/lab-probe", Headers: [][2]string{{"Host", "lab.invalid"}, {"User-Agent", "labrun-probe"}}}
		raw, _ := BuildRaw(probe)
		resp, err := Send(ctx, o.CanaryAddr, raw, o.Timeout)
		if err != nil {
			return nil, fmt.Errorf("canary at %s: %w", o.CanaryAddr, err)
		}
		if resp.Canary == nil {
			return nil, fmt.Errorf("%s answered %d but is not a canary", o.CanaryAddr, resp.Status)
		}
	}
	results := make([]Result, 0, len(entries))
	for i, e := range entries {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		results = append(results, runOne(ctx, e, o))
		if progress != nil {
			progress(i+1, len(entries))
		}
	}
	return results, nil
}

func runOne(ctx context.Context, e corpus.Entry, o Options) Result {
	r := Result{ID: e.ID, Dataset: e.Dataset, Class: e.Class, Expect: e.Expect.Decision, Proxy: ProxySkipped}
	req, err := e.EngineRequest()
	if err != nil {
		r.Err = err.Error()
		r.Truth = TruthUnknown
		r.Problems = []string{ProblemUnknown}
		return r
	}
	v := engine.Inspect(req, o.Engine)
	r.Engine = v.Decision.String()
	for _, id := range v.RuleIDs() {
		r.Rules = append(r.Rules, string(id))
	}

	raw, err := BuildRaw(e.Request)
	if err != nil {
		r.Err = err.Error()
		r.Truth = TruthUnknown
	} else {
		resp, serr := Send(ctx, o.CanaryAddr, raw, o.Timeout)
		var jndi []string
		r.Truth, jndi = TruthOf(resp, serr)
		if serr != nil {
			r.Err = serr.Error()
		} else if r.Truth == TruthUnknown {
			r.Err = fmt.Sprintf("canary answered %d without a canary reply", resp.Status)
		}
		for _, j := range jndi {
			r.JNDI = append(r.JNDI, engine.Defang(j, 200))
		}
		if r.Truth == TruthLookupOnly || r.Truth == TruthTriggered {
			r.Changes = ChangesOf(resp)
		}
		if o.ProxyAddr != "" {
			presp, perr := Send(ctx, o.ProxyAddr, raw, o.Timeout)
			switch {
			case perr != nil:
				r.Proxy, r.Err = ProxyError, strings.TrimSpace(r.Err+" proxy: "+perr.Error())
			case presp.Status == o.BlockCode && presp.Canary == nil:
				r.Proxy, r.ProxyStatus = ProxyBlocked, presp.Status
			case presp.Canary == nil && presp.Status >= 400:
				r.Proxy, r.ProxyStatus = ProxyRefused, presp.Status
			default:
				r.Proxy, r.ProxyStatus = ProxyPassed, presp.Status
				// The reply shows what Log4j did with the request the proxy forwarded.
				r.ProxyTruth, _ = TruthOf(presp, nil)
			}
		}
	}
	r.Problems = Classify(r, e.Dataset == "benign" || e.Dataset == "generated")
	return r
}
