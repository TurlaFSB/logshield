package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// respond writes a short, fixed response. It never echoes request data.
func (p *Proxy) respond(w http.ResponseWriter, id string, status int, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Request-Id", id)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "%s\nreference: %s\n", msg, id)
}

// errorHandler handles failures after the request was cleared for forwarding.
func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	pl := planFrom(r.Context())
	status, reason := http.StatusBadGateway, reasonUpstream
	var netErr net.Error
	switch {
	case errors.Is(err, errGuard):
		reason = reasonGuard
		p.log.LogAttrs(r.Context(), slog.LevelError, "forwarding guard stopped a request", slog.String("error", engine.Defang(err.Error(), 300)))
	case errors.Is(err, context.Canceled):
		reason = reasonClientGone
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		status, reason = http.StatusGatewayTimeout, reasonUpstreamSlow
	}
	id := ""
	if pl != nil {
		pl.failure, id = reason, pl.id
	}
	p.respond(w, id, status, "Bad gateway")
}

type logDetection struct {
	Rule     engine.RuleID `json:"rule"`
	Severity string        `json:"severity"`
	Location string        `json:"location"`
	Scheme   string        `json:"scheme,omitempty"`
	Evidence string        `json:"evidence"`
	Path     []string      `json:"decoded_via,omitempty"`
}

const maxLoggedDetections = 8

// finish reports the outcome to the observer and the log.
func (p *Proxy) finish(r *http.Request, ev Event, v engine.Verdict) {
	if p.cfg.Observer != nil {
		func() {
			defer func() { _ = recover() }() // an observer must not take the request path down
			p.cfg.Observer.Observe(ev)
		}()
	}

	level := slog.LevelDebug
	msg := "request"
	switch {
	case ev.Action == ActionError || ev.Reason == reasonInspection:
		level, msg = slog.LevelError, "request failed"
	case ev.Action == ActionBlocked:
		level, msg = slog.LevelWarn, "request blocked"
	case ev.Action == ActionRejected:
		level, msg = slog.LevelWarn, "request rejected"
	case ev.WouldBlock:
		level, msg = slog.LevelWarn, "request flagged"
	case ev.Decision == engine.DecisionSuspicious:
		level, msg = slog.LevelInfo, "request flagged"
	}
	if !p.log.Enabled(r.Context(), level) {
		return
	}

	path, query, _ := strings.Cut(r.RequestURI, "?")
	attrs := []slog.Attr{
		slog.String("id", ev.ID),
		slog.String("mode", string(ev.Mode)),
		slog.String("action", string(ev.Action)),
		slog.Int("status", ev.Status),
		slog.String("decision", ev.Decision.String()),
		slog.Bool("would_block", ev.WouldBlock),
		slog.String("remote", remoteIP(r)),
		slog.String("method", engine.Defang(r.Method, 16)),
		slog.String("host", engine.Defang(r.Host, 100)),
		// The query string is not logged: it often carries credentials. Detection
		// evidence shows the offending part.
		slog.String("path", engine.Defang(path, 160)),
		slog.Int("query_bytes", len(query)),
		slog.Int("body_bytes", ev.BodyBytes),
		slog.Int64("duration_us", ev.Duration.Microseconds()),
		slog.Int64("inspect_us", ev.InspectDuration.Microseconds()),
	}
	if ev.Reason != "" {
		attrs = append(attrs, slog.String("reason", ev.Reason))
	}
	if ev.BodyTruncated {
		attrs = append(attrs, slog.Bool("body_truncated", true))
	}
	if ev.BodySkipped {
		attrs = append(attrs, slog.Bool("body_skipped", true))
	}
	if ev.FailedOpen {
		attrs = append(attrs, slog.Bool("failed_open", true))
	}
	if ev.Exhausted != engine.BudgetNone {
		attrs = append(attrs, slog.String("budget", ev.Exhausted.String()))
	}
	if len(ev.Rules) > 0 {
		rules := make([]string, len(ev.Rules))
		for i, id := range ev.Rules {
			rules[i] = string(id)
		}
		attrs = append(attrs, slog.Any("rules", rules))
	}
	if n := len(v.Detections); n > 0 {
		shown := min(n, maxLoggedDetections)
		ds := make([]logDetection, shown)
		for i, d := range v.Detections[:shown] {
			ld := logDetection{
				Rule: d.Rule, Severity: d.Severity.String(),
				// Location names come from the request (cookie, query and form
				// names), so they are defanged like everything else. Evidence and
				// scheme were defanged by the engine.
				Location: engine.Defang(d.Location.String(), 120),
				Scheme:   d.Scheme, Evidence: d.Evidence,
			}
			for _, t := range d.Path {
				ld.Path = append(ld.Path, string(t))
			}
			ds[i] = ld
		}
		attrs = append(attrs, slog.Any("detections", ds))
		if n > shown {
			attrs = append(attrs, slog.Int("detections_omitted", n-shown))
		}
	}
	p.log.LogAttrs(r.Context(), level, msg, attrs...)
}
