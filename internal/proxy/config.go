// Package proxy is the LogShield reverse proxy. It receives HTTP requests,
// asks the inspection engine for a verdict on exactly the bytes it is about to
// forward, and then forwards, blocks, or only records the request.
//
// The proxy never forwards anything it did not inspect: it buffers the request,
// inspects a snapshot of it, and a guard at the last hop before the wire checks
// that the outbound request matches the snapshot (see guard.go).
package proxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Mode selects what the proxy does with a request the engine flags.
type Mode string

const (
	// ModeMonitor forwards every request and records what it would have blocked.
	// It is the default, so that a first deployment cannot cause an outage.
	ModeMonitor Mode = "monitor"
	// ModeBlock rejects requests with a malicious verdict.
	ModeBlock Mode = "block"
)

// FailPolicy selects what happens when the proxy itself cannot reach a verdict:
// an internal error in inspection. It never applies to a request the engine
// analyzed and judged malicious, including one that exhausted a budget.
type FailPolicy string

const (
	// FailClosed rejects the request (block mode only).
	FailClosed FailPolicy = "closed"
	// FailOpen forwards the request uninspected.
	FailOpen FailPolicy = "open"
)

// ForwardedFor selects how X-Forwarded-For is produced.
type ForwardedFor string

const (
	// ForwardedForReplace discards any client-supplied value and sends only the
	// address the proxy saw. Use it when clients connect to the proxy directly.
	ForwardedForReplace ForwardedFor = "replace"
	// ForwardedForAppend keeps the (inspected) client-supplied chain and appends
	// the address the proxy saw. Use it behind a trusted load balancer.
	ForwardedForAppend ForwardedFor = "append"
	// ForwardedForOff sends no X-Forwarded-For.
	ForwardedForOff ForwardedFor = "off"
)

// Config configures a Proxy. Only Upstream is required.
type Config struct {
	// Upstream is the protected server, as scheme://host[:port] with no path.
	Upstream *url.URL
	// Mode defaults to ModeMonitor.
	Mode Mode
	// BlockSuspicious also blocks suspicious verdicts in block mode (strict).
	BlockSuspicious bool
	// OnError defaults to FailClosed.
	OnError FailPolicy
	// Engine configures inspection.
	Engine engine.Config

	// MaxBodyBytes bounds the request body that is buffered and inspected.
	// Default 1 MiB. In block mode a larger body is rejected with 413. In monitor
	// mode the first MaxBodyBytes are inspected and the request is forwarded whole.
	MaxBodyBytes int64
	// SkipBodyTypes lists media types (exact, or a prefix ending in "/", such as
	// "image/") whose bodies are streamed without inspection. Empty by default:
	// every body is inspected. Use it for large binary uploads.
	SkipBodyTypes []string

	// MaxInFlight bounds concurrently handled requests; one more is answered with
	// 503 and Retry-After instead of queueing. Each in-flight request may hold up
	// to MaxBodyBytes in memory, so this is also the memory bound. Long-lived
	// streams (server-sent events) occupy a slot for their whole life. Default
	// 1024; -1 disables the limit.
	MaxInFlight int

	// ClientWriteTimeout bounds how long a single write to the client may stall.
	// It is refreshed on every write, so long downloads and streams are fine, but
	// a client that stops reading (slow-read attack) is cut off instead of holding
	// an in-flight slot and its buffers forever. Default 60s; negative disables.
	ClientWriteTimeout time.Duration

	// BlockStatus is the status sent for blocked requests. Default 403.
	BlockStatus int
	// ForwardedFor defaults to ForwardedForReplace.
	ForwardedFor ForwardedFor
	// RewriteHost sends the upstream's own host in the Host header. By default
	// the client's Host header is preserved.
	RewriteHost bool

	// Transport carries requests to the upstream. The default is hardened (no
	// environment proxies, no compression, bounded timeouts).
	Transport http.RoundTripper
	// Logger receives security events. Everything written through it is
	// neutralized so that a request cannot inject a Log4j lookup into the proxy's
	// own logs. The default writes JSON to standard error.
	Logger *slog.Logger
	// Observer, if set, is called once per request with its outcome.
	Observer Observer
}

const defaultClientWriteTimeout = 60 * time.Second

// defaultMaxInFlight bounds memory to roughly this many default-size bodies.
const defaultMaxInFlight = 1024

const defaultMaxBody = 1 << 20

// Validate checks the configuration and reports every problem found.
func (c Config) Validate() error {
	var errs []error
	if c.Upstream == nil {
		errs = append(errs, errors.New("upstream is required"))
	} else {
		u := c.Upstream
		if u.Scheme != "http" && u.Scheme != "https" {
			errs = append(errs, fmt.Errorf("upstream scheme must be http or https, got %q", u.Scheme))
		}
		if u.Host == "" || u.Hostname() == "" {
			errs = append(errs, errors.New("upstream needs a host"))
		}
		if u.User != nil {
			errs = append(errs, errors.New("upstream must not contain credentials"))
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			errs = append(errs, errors.New("upstream must be scheme://host[:port] only: the proxy forwards request targets verbatim"))
		}
	}
	switch c.Mode {
	case "", ModeMonitor, ModeBlock:
	default:
		errs = append(errs, fmt.Errorf("unknown mode %q (want monitor or block)", c.Mode))
	}
	switch c.OnError {
	case "", FailClosed, FailOpen:
	default:
		errs = append(errs, fmt.Errorf("unknown on-error policy %q (want closed or open)", c.OnError))
	}
	switch c.ForwardedFor {
	case "", ForwardedForReplace, ForwardedForAppend, ForwardedForOff:
	default:
		errs = append(errs, fmt.Errorf("unknown forwarded-for policy %q (want replace, append or off)", c.ForwardedFor))
	}
	if c.MaxInFlight < -1 {
		errs = append(errs, fmt.Errorf("max in-flight must be positive, or -1 for no limit, got %d", c.MaxInFlight))
	}
	if c.MaxBodyBytes < 0 {
		errs = append(errs, errors.New("max body bytes must not be negative"))
	}
	if c.BlockStatus != 0 && (c.BlockStatus < 400 || c.BlockStatus > 599) {
		errs = append(errs, fmt.Errorf("block status %d must be 4xx or 5xx", c.BlockStatus))
	}
	for _, t := range c.SkipBodyTypes {
		if t == "" || strings.ContainsAny(t, " ;,") || strings.ToLower(t) != t {
			errs = append(errs, fmt.Errorf("skip body type %q must be a lower-case media type or prefix such as \"image/\"", t))
		}
	}
	if err := c.Engine.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("engine: %w", err))
	}
	if limit := int64(c.Engine.Effective().MaxRequestBytes); c.MaxBodyBytes > limit {
		errs = append(errs, fmt.Errorf("max body bytes (%d) exceeds the engine's request limit (%d): every large request would be rejected as a budget violation",
			c.MaxBodyBytes, limit))
	}
	return errors.Join(errs...)
}

func (c Config) withDefaults() Config {
	if c.Mode == "" {
		c.Mode = ModeMonitor
	}
	if c.OnError == "" {
		c.OnError = FailClosed
	}
	if c.ForwardedFor == "" {
		c.ForwardedFor = ForwardedForReplace
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaultMaxBody
	}
	if c.ClientWriteTimeout == 0 {
		c.ClientWriteTimeout = defaultClientWriteTimeout
	}
	if c.MaxInFlight == 0 {
		c.MaxInFlight = defaultMaxInFlight
	}
	if c.BlockStatus == 0 {
		c.BlockStatus = http.StatusForbidden
	}
	return c
}
