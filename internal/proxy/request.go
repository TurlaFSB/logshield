package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Reasons for requests the proxy refuses to forward. They are stable codes used
// in logs and metrics.
const (
	reasonConnect       = "connect-not-supported"
	reasonUpgrade       = "upgrade-not-supported"
	reasonTarget        = "target-not-origin-form"
	reasonDoubleSlash   = "target-starts-with-double-slash"
	reasonFragment      = "target-contains-fragment"
	reasonBodyTooLarge  = "body-too-large"
	reasonBodyRead      = "body-read-failed"
	reasonInspection    = "inspection-error"
	reasonUpstream      = "upstream-unreachable"
	reasonUpstreamSlow  = "upstream-timeout"
	reasonGuard         = "guard-violation"
	reasonClientGone    = "client-canceled"
	reasonBodySkipped   = "body-skipped"
	reasonBodyTruncated = "body-truncated"
)

// checkRequest rejects requests that cannot be forwarded faithfully. The proxy
// re-serializes every request it forwards, so most framing ambiguity (obs-fold,
// bare LF, conflicting Content-Length and Transfer-Encoding, chunk extensions)
// never reaches the upstream, and Go's server already refuses the malformed
// ones. What remains are request forms the proxy has no safe way to relay.
func checkRequest(r *http.Request) (status int, reason string) {
	switch {
	case r.Method == http.MethodConnect:
		return http.StatusNotImplemented, reasonConnect
	case len(r.Header.Values("Upgrade")) > 0:
		return http.StatusNotImplemented, reasonUpgrade
	}
	target := r.RequestURI
	switch {
	case target == "" || target[0] != '/':
		// absolute-form, authority-form, and "*" would be rewritten by the HTTP
		// client on the way out, so what was inspected would not be what is sent.
		return http.StatusBadRequest, reasonTarget
	case strings.HasPrefix(target, "//"):
		// The HTTP client treats a leading "//" as a network-path reference.
		return http.StatusBadRequest, reasonDoubleSlash
	case strings.IndexByte(target, '#') >= 0:
		return http.StatusBadRequest, reasonFragment
	}
	return 0, ""
}

// mediaType returns the lower-cased media type of Content-Type, or "".
func mediaType(h http.Header) string {
	mt, _, _ := strings.Cut(h.Get("Content-Type"), ";")
	return strings.ToLower(strings.TrimSpace(mt))
}

// skipBody reports whether the body's media type is on the skip list.
func skipBody(h http.Header, types []string) bool {
	if len(types) == 0 {
		return false
	}
	mt := mediaType(h)
	for _, t := range types {
		if mt == t || (strings.HasSuffix(t, "/") && strings.HasPrefix(mt, t)) {
			return true
		}
	}
	return false
}

// bodyResult is what readBody found.
type bodyResult struct {
	data      []byte    // the bytes handed to the engine
	rest      io.Reader // bytes after data that are forwarded but not inspected
	skipped   bool      // body type is on the skip list: data is empty, rest is the whole body
	truncated bool      // only a prefix is inspected (monitor mode)
	tooLarge  bool      // larger than the limit; the caller decides what to do
}

var errBodyRead = errors.New("reading request body")

// readBody buffers up to limit bytes of the request body. In block mode the
// caller rejects a too-large body; in monitor mode the prefix is inspected and
// the whole body is forwarded.
func readBody(r *http.Request, limit int64, types []string, streamLarge bool) (bodyResult, error) {
	var res bodyResult
	if r.Body == nil || r.Body == http.NoBody {
		return res, nil
	}
	if skipBody(r.Header, types) {
		res.skipped, res.rest = true, r.Body
		return res, nil
	}
	if r.ContentLength > limit {
		res.tooLarge = true
		if !streamLarge {
			return res, nil
		}
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return res, errors.Join(errBodyRead, err)
	}
	if int64(len(buf)) > limit {
		res.tooLarge = true
		if !streamLarge {
			return res, nil
		}
		res.truncated = true
		res.data = buf[:limit]
		res.rest = io.MultiReader(bytes.NewReader(buf[limit:]), r.Body)
		return res, nil
	}
	res.data = buf
	return res, nil
}

// snapshot is the request exactly as the proxy inspects it. The same values are
// used to verify the outbound request.
type snapshot struct {
	method  string
	target  string
	host    string
	headers []engine.Header
	body    []byte
}

// newSnapshot copies everything the backend could log from r. Go's server moves
// the Host and Transfer-Encoding headers out of r.Header, so they are put back:
// a payload in either must not escape inspection. Header names are sorted so
// verdicts are reproducible.
func newSnapshot(r *http.Request, body []byte) snapshot {
	s := snapshot{method: r.Method, target: r.RequestURI, host: r.Host, body: body}
	if r.Host != "" {
		s.headers = append(s.headers, engine.Header{Name: "Host", Value: r.Host})
	}
	if len(r.TransferEncoding) > 0 {
		s.headers = append(s.headers, engine.Header{Name: "Transfer-Encoding", Value: strings.Join(r.TransferEncoding, ", ")})
	}
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range r.Header[name] {
			s.headers = append(s.headers, engine.Header{Name: name, Value: v})
		}
	}
	return s
}

func (s snapshot) engineRequest() engine.Request {
	return engine.Request{Method: s.method, Target: s.target, Headers: s.headers, Body: s.body}
}

// allowed returns the set of header values the snapshot covers, by name.
func (s snapshot) allowed() map[string]map[string]struct{} {
	m := make(map[string]map[string]struct{}, len(s.headers))
	for _, h := range s.headers {
		set := m[h.Name]
		if set == nil {
			set = make(map[string]struct{}, 1)
			m[h.Name] = set
		}
		set[h.Value] = struct{}{}
	}
	return m
}
