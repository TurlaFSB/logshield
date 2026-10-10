package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// errGuard marks a violation of the "forward exactly what was inspected"
// invariant. It indicates a bug (or an unexpected change in the HTTP library),
// never attacker input, and it always stops the request.
var errGuard = errors.New("outbound request differs from the inspected request")

type bodyKind int

const (
	bodyBuffered bodyKind = iota // the inspected buffer (possibly empty), forwarded with its length
	bodyStreamed                 // inspected prefix plus an uninspected remainder, or a skipped type
)

// bufferedBody is the only body type the guard accepts for an inspected body.
type bufferedBody struct{ r io.Reader }

func (b *bufferedBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (*bufferedBody) Close() error                 { return nil }

// streamedBody marks a body that is forwarded without being fully inspected.
type streamedBody struct {
	io.Reader
	io.Closer
}

// plan is what the proxy decided to forward for one request. It travels in the
// request context so the guard can check the final outbound request against it.
type plan struct {
	id       string
	snap     snapshot
	allowed  map[string]map[string]struct{}
	upstream *url.URL
	host     string // expected outbound Host
	kind     bodyKind
	body     *bufferedBody
	bodyLen  int

	// failure is set by the error handler for logging and metrics.
	failure string
}

type planKey struct{}

func withPlan(ctx context.Context, p *plan) context.Context {
	return context.WithValue(ctx, planKey{}, p)
}

func planFrom(ctx context.Context) *plan {
	p, _ := ctx.Value(planKey{}).(*plan)
	return p
}

// generatedHeaders are set by the proxy itself, from values it controls.
var generatedHeaders = map[string]bool{
	"X-Forwarded-For":   true,
	"X-Forwarded-Proto": true,
	"X-Forwarded-Host":  true,
	"X-Request-Id":      true,
}

// verify checks the outbound request against the plan.
func (p *plan) verify(req *http.Request) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errGuard, fmt.Sprintf(format, args...))
	}
	if req.Method != p.snap.method {
		return bad("method")
	}
	if req.URL == nil || req.URL.Scheme != p.upstream.Scheme || req.URL.Host != p.upstream.Host {
		return bad("destination")
	}
	if got := req.URL.RequestURI(); got != p.snap.target {
		return bad("request target %q, inspected %q", got, p.snap.target)
	}
	if req.Host != p.host {
		return bad("host %q, expected %q", req.Host, p.host)
	}
	if len(req.TransferEncoding) > 0 || len(req.Trailer) > 0 {
		return bad("framing")
	}
	for name, values := range req.Header {
		if generatedHeaders[name] {
			continue
		}
		set := p.allowed[name]
		for _, v := range values {
			if _, ok := set[v]; ok {
				continue
			}
			if v == "" && name == "User-Agent" { // suppresses the HTTP client's default
				continue
			}
			if name == "Content-Length" && p.kind == bodyBuffered && v == strconv.Itoa(p.bodyLen) {
				continue
			}
			return bad("header %s was not inspected", name)
		}
	}
	switch p.kind {
	case bodyBuffered:
		if p.bodyLen == 0 {
			if req.Body != nil && req.Body != http.NoBody {
				return bad("unexpected body")
			}
			break
		}
		// The HTTP library may wrap the body (Go 1.26 does), so identity cannot be
		// checked here; RoundTrip replaces whatever arrives with the inspected buffer.
		if req.Body == nil || req.Body == http.NoBody || req.ContentLength != int64(p.bodyLen) {
			return bad("body length differs from the inspected buffer")
		}
	case bodyStreamed:
		if _, ok := req.Body.(*streamedBody); !ok && req.Body != nil && req.Body != http.NoBody {
			return bad("body is not the expected stream")
		}
	}
	return nil
}

// guardTransport is the last hop before the wire.
type guardTransport struct{ next http.RoundTripper }

func (g guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pl := planFrom(req.Context())
	if pl == nil {
		return nil, bodyClose(req, fmt.Errorf("%w: no plan", errGuard))
	}
	if err := pl.verify(req); err != nil {
		return nil, bodyClose(req, err)
	}
	if pl.kind == bodyBuffered && pl.bodyLen > 0 {
		// Send the inspected bytes themselves, whatever wrapper the library added.
		orig := req.Body
		req = req.WithContext(req.Context())
		req.Body = pl.body
		_ = orig.Close()
	}
	return g.next.RoundTrip(req)
}

// bodyClose closes the request body, as RoundTrip must even on failure.
func bodyClose(req *http.Request, err error) error {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return err
}
