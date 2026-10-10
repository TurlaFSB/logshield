package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Proxy is an http.Handler that inspects and forwards requests. It is safe for
// concurrent use.
type Proxy struct {
	cfg Config
	log *slog.Logger
	rp  *httputil.ReverseProxy

	// slots bounds concurrent requests; nil when the limit is disabled.
	slots    chan struct{}
	inflight atomic.Int64

	// inspect is engine.Inspect; tests replace it to exercise error handling.
	inspect func(engine.Request, engine.Config) engine.Verdict
}

// New validates cfg and returns a Proxy.
func New(cfg Config) (*Proxy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	transport := cfg.Transport
	if transport == nil {
		transport = DefaultTransport()
	}

	p := &Proxy{cfg: cfg, log: newSafeLogger(logger), inspect: engine.Inspect}
	if cfg.MaxInFlight > 0 {
		p.slots = make(chan struct{}, cfg.MaxInFlight)
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:      p.rewrite,
		Transport:    guardTransport{next: transport},
		ErrorHandler: p.errorHandler,
		ErrorLog:     slog.NewLogLogger(p.log.Handler(), slog.LevelWarn),
	}
	return p, nil
}

// DefaultTransport returns the hardened transport used for the upstream: it
// ignores proxy environment variables, never adds compression, and bounds every
// phase of the connection.
func DefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   64,
		DisableCompression:    true,
	}
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // never fails: Go aborts the process if the system source is unavailable
	return hex.EncodeToString(b[:])
}

// statusRecorder remembers the status code sent to the client.
type statusRecorder struct {
	http.ResponseWriter
	status int
	// stall, if positive, is the longest a single write to the client may block.
	stall time.Duration
	rc    *http.ResponseController
}

// armWriteDeadline pushes the connection's write deadline out by stall. Writers
// that do not support deadlines (test recorders) are left alone.
func (s *statusRecorder) armWriteDeadline() {
	if s.stall > 0 {
		_ = s.rc.SetWriteDeadline(time.Now().Add(s.stall))
	}
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.armWriteDeadline()
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	s.armWriteDeadline()
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush and friends.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// InFlight reports how many requests are being handled right now.
func (p *Proxy) InFlight() int { return int(p.inflight.Load()) }

// acquire takes a slot without waiting; false means the proxy is at its limit.
func (p *Proxy) acquire() bool {
	if p.slots != nil {
		select {
		case p.slots <- struct{}{}:
		default:
			return false
		}
	}
	p.inflight.Add(1)
	return true
}

func (p *Proxy) release() {
	p.inflight.Add(-1)
	if p.slots != nil {
		<-p.slots
	}
}

// ServeHTTP inspects r and forwards, blocks or rejects it.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, rc: http.NewResponseController(w)}
	if p.cfg.ClientWriteTimeout > 0 {
		rec.stall = p.cfg.ClientWriteTimeout
	}
	ev := Event{ID: newID(), Mode: p.cfg.Mode}
	var (
		verdict engine.Verdict
		pl      *plan
	)
	defer func() {
		ev.Duration = time.Since(start)
		ev.Status = rec.status
		if pl != nil && pl.failure != "" {
			ev.Action, ev.Reason = ActionError, pl.failure
		}
		p.finish(r, ev, verdict)
	}()

	if !p.acquire() {
		// Shed load instead of queueing: queued requests hold memory and the
		// client is better served by an immediate, retryable answer.
		ev.Action, ev.Reason = ActionRejected, reasonOverloaded
		rec.Header().Set("Retry-After", "1")
		p.respond(rec, ev.ID, http.StatusServiceUnavailable, "Server busy")
		return
	}
	defer p.release()

	if status, reason := checkRequest(r); status != 0 {
		ev.Action, ev.Reason = ActionRejected, reason
		p.respond(rec, ev.ID, status, "Request not supported")
		return
	}

	body, err := readBody(r, p.cfg.MaxBodyBytes, p.cfg.SkipBodyTypes, p.cfg.Mode == ModeMonitor)
	switch {
	case err != nil:
		ev.Action, ev.Reason = ActionRejected, reasonBodyRead
		p.respond(rec, ev.ID, http.StatusBadRequest, "Bad request")
		return
	case body.tooLarge && !body.truncated && p.cfg.Mode == ModeBlock:
		ev.Action, ev.Reason = ActionRejected, reasonBodyTooLarge
		rec.Header().Set("Connection", "close")
		p.respond(rec, ev.ID, http.StatusRequestEntityTooLarge, "Request body too large")
		return
	}
	ev.BodyBytes, ev.BodyTruncated, ev.BodySkipped = len(body.data), body.truncated, body.skipped

	snap := newSnapshot(r, body.data)
	begin := time.Now()
	verdict, err = p.runEngine(snap.engineRequest())
	ev.InspectDuration = time.Since(begin)

	block, status := false, p.cfg.BlockStatus
	switch {
	case err != nil:
		ev.Reason = reasonInspection
		if p.cfg.Mode == ModeBlock {
			if p.cfg.OnError == FailClosed {
				block, status = true, http.StatusServiceUnavailable
			} else {
				ev.FailedOpen = true
			}
		}
		p.log.LogAttrs(r.Context(), slog.LevelError, "inspection failed", slog.String("id", ev.ID),
			slog.String("error", engine.Defang(err.Error(), 200)))
	default:
		ev.Decision, ev.Rules, ev.Exhausted = verdict.Decision, verdict.RuleIDs(), verdict.Exhausted
		ev.WouldBlock = verdict.Decision == engine.DecisionMalicious ||
			(verdict.Decision == engine.DecisionSuspicious && p.cfg.BlockSuspicious)
		block = ev.WouldBlock && p.cfg.Mode == ModeBlock
	}
	if block {
		ev.Action = ActionBlocked
		p.respond(rec, ev.ID, status, "Request blocked")
		return
	}

	pl = p.newPlan(ev.ID, snap, body)
	out := r.Clone(withPlan(r.Context(), pl))
	out.TransferEncoding, out.Trailer = nil, nil
	out.Header.Del("Expect") // the whole body is already in hand
	switch pl.kind {
	case bodyBuffered:
		out.Body, out.ContentLength = pl.body, int64(pl.bodyLen)
		if pl.bodyLen == 0 {
			out.Body = nil
		}
	case bodyStreamed:
		pl.stream = &streamedBody{Reader: io.MultiReader(bytes.NewReader(body.data), body.rest), Closer: r.Body}
		out.Body = pl.stream
	}
	ev.Action = ActionForwarded
	p.rp.ServeHTTP(rec, out)
}

// newPlan records what will be forwarded, for the guard.
func (p *Proxy) newPlan(id string, snap snapshot, body bodyResult) *plan {
	pl := &plan{id: id, snap: snap, allowed: snap.allowed(), upstream: p.cfg.Upstream, host: snap.host, bodyLen: len(body.data)}
	if p.cfg.RewriteHost {
		pl.host = p.cfg.Upstream.Host
	}
	switch {
	case body.rest != nil:
		pl.kind = bodyStreamed
	case len(body.data) > 0:
		pl.kind = bodyBuffered
		pl.body = &bufferedBody{r: bytes.NewReader(body.data)}
	default:
		pl.kind = bodyBuffered // empty body: nothing to forward
	}
	return pl
}

// runEngine calls the engine and turns a panic into an error: an inspection
// failure must be a policy decision, never a crashed connection.
func (p *Proxy) runEngine(req engine.Request) (v engine.Verdict, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("engine panic: %v", rec)
		}
	}()
	return p.inspect(req, p.cfg.Engine), nil
}

// rewrite builds the outbound request. The request target is sent verbatim,
// because the engine inspected it verbatim.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	in, out := pr.In, pr.Out
	target := in.RequestURI
	path, query, hasQuery := strings.Cut(target, "?")
	out.URL.Scheme, out.URL.Host = p.cfg.Upstream.Scheme, p.cfg.Upstream.Host
	out.URL.Path, out.URL.RawPath, out.URL.Opaque = "", "", path
	out.URL.RawQuery, out.URL.ForceQuery = query, hasQuery && query == ""
	if p.cfg.RewriteHost {
		out.Host = p.cfg.Upstream.Host
		out.Header.Set("X-Forwarded-Host", in.Host)
	} else {
		out.Host = in.Host
	}

	if pl := planFrom(in.Context()); pl != nil {
		out.Header.Set("X-Request-Id", pl.id)
	}
	if _, ok := in.Header["User-Agent"]; !ok {
		out.Header.Set("User-Agent", "") // suppress the HTTP client's default
	}
	if p.cfg.ForwardedFor != ForwardedForOff {
		setForwarded(in, out, p.cfg.ForwardedFor == ForwardedForAppend, p.cfg.RewriteHost)
	}
}

// setForwarded sets the standard forwarding headers. The client-supplied values
// were removed by ReverseProxy; in append mode the inspected chain is restored.
func setForwarded(in *http.Request, out *http.Request, appendChain, rewriteHost bool) {
	ip := remoteIP(in)
	if prior := in.Header.Values("X-Forwarded-For"); appendChain && len(prior) > 0 {
		ip = strings.Join(prior, ", ") + ", " + ip
	}
	out.Header.Set("X-Forwarded-For", ip)
	proto := "http"
	if in.TLS != nil {
		proto = "https"
	}
	out.Header.Set("X-Forwarded-Proto", proto)
	if rewriteHost {
		out.Header.Set("X-Forwarded-Host", in.Host)
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
