package engine

import (
	"encoding/base64"
	"strings"
)

// Header is one HTTP header exactly as received. Order and duplicates are
// preserved, because a backend may log any of them.
type Header struct {
	Name  string
	Value string
}

// Request is the part of an HTTP request the engine inspects. The proxy fills
// it with the bytes it will forward, so that the engine inspects what the
// backend will see (see docs/threat-model.md).
type Request struct {
	Method  string
	Target  string // request-target as received: path and query
	Headers []Header
	Body    []byte // already de-chunked and size-limited by the caller
}

// Parts of a request that can carry a payload. They appear in Location.Part.
const (
	PartMethod        = "method"
	PartTarget        = "target"
	PartQueryName     = "query-name"
	PartQueryValue    = "query-value"
	PartHeaderName    = "header-name"
	PartHeaderValue   = "header-value"
	PartHeaderDecoded = "header-value-decoded"
	PartCookieName    = "cookie-name"
	PartCookieValue   = "cookie-value"
	PartBody          = "body"
	PartBodyCharset   = "body-charset-decoded"
	PartFormName      = "form-name"
	PartFormValue     = "form-value"

	PartMultipartName     = "multipart-name"
	PartMultipartFilename = "multipart-filename"
	PartMultipartHeader   = "multipart-header"
	PartMultipartValue    = "multipart-value"
)

// Location says where in the request a detection was made.
type Location struct {
	Part string
	// Name is the header, cookie, query or form field name, when there is one.
	Name string
}

// String returns "part" or "part:name".
func (l Location) String() string {
	if l.Name == "" {
		return l.Part
	}
	return l.Part + ":" + l.Name
}

// field is one string to run through the decode and resolve pipeline.
type field struct {
	loc  Location
	text string
}

// extractFields flattens a request into the strings to inspect. Whole values
// are always inspected, and their components as well (query pairs, cookies,
// form pairs, credentials), because a payload may only form inside one
// component and may only make sense across several.
func extractFields(req Request, cfg Config) ([]field, Budget) {
	size := len(req.Method) + len(req.Target) + len(req.Body)
	for _, h := range req.Headers {
		size += len(h.Name) + len(h.Value)
	}
	if size > cfg.MaxRequestBytes {
		return nil, BudgetRequestBytes
	}

	var out []field
	over := false
	add := func(part, name, text string) {
		if over {
			return
		}
		if len(out) >= cfg.MaxFields {
			over = true
			return
		}
		out = append(out, field{loc: Location{Part: part, Name: name}, text: text})
	}

	add(PartMethod, "", req.Method)
	add(PartTarget, "", req.Target)

	if _, query, ok := strings.Cut(req.Target, "?"); ok {
		forEachPair(query, "&", func(name, value string) {
			add(PartQueryName, "", name)
			add(PartQueryValue, name, value)
		})
	}

	for _, h := range req.Headers {
		add(PartHeaderName, "", h.Name)
		add(PartHeaderValue, h.Name, h.Value)

		switch {
		case strings.EqualFold(h.Name, "Cookie"):
			forEachPair(h.Value, ";", func(name, value string) {
				name = strings.TrimSpace(name)
				add(PartCookieName, "", name)
				add(PartCookieValue, name, strings.TrimSpace(value))
			})
		case strings.EqualFold(h.Name, "Authorization"):
			for _, d := range decodeCredentials(h.Value) {
				add(PartHeaderDecoded, h.Name, d)
			}
		}
	}

	if len(req.Body) > 0 {
		body := string(req.Body)
		add(PartBody, "", body)
		if ebcdicLabel(charsetParam(req.Headers)) {
			add(PartBodyCharset, "", ebcdicToASCII(body))
		}
		switch mediaType(req.Headers) {
		case "application/x-www-form-urlencoded":
			forEachPair(body, "&", func(name, value string) {
				add(PartFormName, "", name)
				add(PartFormValue, name, value)
			})
		case "multipart/form-data":
			if boundary := boundaryParam(req.Headers); boundary != "" {
				forEachPart(body, boundary, func(p mpPart) {
					add(PartMultipartName, "", p.name)
					add(PartMultipartFilename, p.name, p.filename)
					for _, h := range p.headers {
						add(PartMultipartHeader, h.Name, h.Value)
					}
					add(PartMultipartValue, p.name, p.value)
				})
			}
		}
	}

	if over {
		return nil, BudgetFields
	}
	return out, BudgetNone
}

// forEachPair calls fn for each "name=value" pair in s separated by sep. A pair
// without '=' is reported as a name with an empty value.
func forEachPair(s, sep string, fn func(name, value string)) {
	for s != "" {
		var pair string
		pair, s, _ = strings.Cut(s, sep)
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		fn(name, value)
	}
}

// mediaType returns the lower-cased media type of Content-Type, without
// parameters, or "".
func mediaType(headers []Header) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			mt, _, _ := strings.Cut(h.Value, ";")
			return strings.ToLower(strings.TrimSpace(mt))
		}
	}
	return ""
}

// decodeCredentials unwraps values that applications routinely decode and then
// log: the user name in HTTP Basic credentials, and the segments of a Bearer
// JWT. A failed login that logs the offered user name is a classic Log4Shell
// sink, and the payload is invisible until the base64 layer is removed.
func decodeCredentials(value string) []string {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(value), " ")
	if !ok {
		return nil
	}
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(scheme) {
	case "basic":
		if b, ok := decodeBase64(rest); ok {
			return []string{b}
		}
	case "bearer":
		var out []string
		segments := strings.Split(rest, ".")
		if len(segments) > 2 {
			segments = segments[:2] // header and payload; the signature is binary
		}
		for _, seg := range segments {
			if b, ok := decodeBase64(seg); ok {
				out = append(out, b)
			}
		}
		return out
	}
	return nil
}

// decodeBase64 accepts standard and URL-safe alphabets, with or without padding.
// It only reports text: a result containing control bytes (an opaque token, a
// signature) is not something an application would log, so it is ignored.
// Invalid UTF-8 is kept, since overlong encodings are an evasion technique.
func decodeBase64(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			if isText(b) {
				return string(b), true
			}
			return "", false
		}
	}
	return "", false
}

// isText reports whether b has no control bytes other than tab, carriage return
// and line feed.
func isText(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' || c == 0x7f {
			return false
		}
	}
	return true
}

// boundaryParam returns the multipart boundary from Content-Type, or "".
func boundaryParam(headers []Header) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			return headerParam(h.Value, "boundary")
		}
	}
	return ""
}

// headerParam returns the value of a ;-separated parameter such as
// name="x" in a header value, matching the parameter name case-insensitively.
// Quotes are removed; escapes inside quotes are not interpreted, which keeps
// the raw text available for inspection.
func headerParam(value, param string) string {
	_, rest, _ := strings.Cut(value, ";")
	for rest != "" {
		var item string
		item, rest, _ = strings.Cut(rest, ";")
		k, v, ok := strings.Cut(item, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), param) {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		return v
	}
	return ""
}

// mpPart is one multipart/form-data part.
type mpPart struct {
	name, filename string
	headers        []Header
	value          string
}

// forEachPart splits a multipart body leniently and in linear time. Backends
// differ in how strictly they parse multipart, so this accepts both CRLF and
// bare LF and does not insist on a closing boundary. The whole body is
// inspected as well, so a part this parser misses is still covered.
func forEachPart(body, boundary string, fn func(mpPart)) {
	delim := "--" + boundary
	chunks := strings.Split(body, delim)
	for i, chunk := range chunks {
		if i == 0 || strings.HasPrefix(chunk, "--") {
			continue // preamble and the closing delimiter
		}
		chunk = strings.TrimPrefix(chunk, "\r\n")
		chunk = strings.TrimPrefix(chunk, "\n")
		head, value, ok := cutHeaderBlock(chunk)
		if !ok {
			continue
		}
		var p mpPart
		p.value = strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r")
		for _, line := range strings.Split(head, "\n") {
			line = strings.TrimSuffix(line, "\r")
			name, val, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			name, val = strings.TrimSpace(name), strings.TrimSpace(val)
			p.headers = append(p.headers, Header{Name: name, Value: val})
			if strings.EqualFold(name, "Content-Disposition") {
				p.name = headerParam(val, "name")
				p.filename = headerParam(val, "filename")
			}
		}
		fn(p)
	}
}

// cutHeaderBlock splits a part at its first blank line.
func cutHeaderBlock(s string) (head, value string, ok bool) {
	i := strings.Index(s, "\r\n\r\n")
	j := strings.Index(s, "\n\n")
	switch {
	case i >= 0 && (j < 0 || i < j):
		return s[:i], s[i+4:], true
	case j >= 0:
		return s[:j], s[j+2:], true
	}
	return "", "", false
}
