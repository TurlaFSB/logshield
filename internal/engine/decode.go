package engine

import (
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"html"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// Transform names one decoding step. Names appear in Stage.Path so a verdict
// can explain exactly which layers were peeled to reveal a payload.
type Transform string

// The decoding steps the engine models. Each mirrors a decoding that a real
// web stack, framework, or logging pipeline commonly applies to untrusted
// input before it reaches Log4j.
const (
	TransformGzip      Transform = "gzip"
	TransformPercent   Transform = "percent"
	TransformPercentU  Transform = "percent-u"
	TransformBackslash Transform = "backslash-escape"
	TransformHTML      Transform = "html-entity"
	TransformOverlong  Transform = "overlong-utf8"
	TransformFullwidth Transform = "fullwidth"
	TransformNUL       Transform = "nul-strip"
	TransformZlib      Transform = "zlib"
	TransformBase64    Transform = "base64"
)

// Budget identifies which resource limit stopped decoding. The zero value means
// no limit was hit.
type Budget int

// Budget values. Any value other than BudgetNone means decoding was cut short
// and callers MUST treat the input as hostile (fail-closed).
const (
	BudgetNone         Budget = iota // decoding completed within all limits
	BudgetInputSize                  // raw input larger than MaxInputBytes
	BudgetDepth                      // still decodable after MaxDepth chained transforms
	BudgetStages                     // more than MaxStages distinct decoded variants
	BudgetStageBytes                 // one decoded variant larger than MaxStageBytes
	BudgetTotalBytes                 // all variants together larger than MaxTotalBytes
	BudgetNesting                    // lookups nested deeper than MaxNesting
	BudgetLookups                    // more than MaxLookups lookups to evaluate
	BudgetValueBytes                 // a lookup name or value larger than MaxValueBytes
	BudgetFields                     // a request with more than MaxFields inspectable fields
	BudgetRequestBytes               // a request larger than MaxRequestBytes
	BudgetWork                       // more than MaxWorkBytes of decoded text across the request
)

// String returns a stable, log-safe identifier for the budget.
func (b Budget) String() string {
	switch b {
	case BudgetNone:
		return "none"
	case BudgetInputSize:
		return "input-size"
	case BudgetDepth:
		return "depth"
	case BudgetStages:
		return "stages"
	case BudgetStageBytes:
		return "stage-bytes"
	case BudgetTotalBytes:
		return "total-bytes"
	case BudgetNesting:
		return "nesting"
	case BudgetLookups:
		return "lookups"
	case BudgetValueBytes:
		return "value-bytes"
	case BudgetFields:
		return "fields"
	case BudgetRequestBytes:
		return "request-bytes"
	case BudgetWork:
		return "work"
	default:
		return "unknown"
	}
}

// Limits bounds the work Decode may do. A zero or negative field selects the
// default for that field, so the zero Limits value is safe and bounded.
type Limits struct {
	// MaxInputBytes is the largest raw input Decode will process.
	MaxInputBytes int
	// MaxDepth is the longest chain of transforms applied to reach one variant.
	MaxDepth int
	// MaxStages is the maximum number of distinct variants, including the original.
	MaxStages int
	// MaxStageBytes is the largest single decoded variant, which also caps gzip
	// expansion.
	MaxStageBytes int
	// MaxTotalBytes caps the combined size of all variants.
	MaxTotalBytes int
	// MaxNesting is the deepest allowed nesting of "${" lookups (Resolve).
	MaxNesting int
	// MaxLookups caps the lookups Resolve may evaluate in one text, counting
	// re-expansion of lookup results. Plain "${word}" placeholders do not count.
	MaxLookups int
	// MaxValueBytes caps any single lookup name or computed value (Resolve).
	MaxValueBytes int
}

// DefaultLimits returns the default budgets. They are generous for real traffic
// (HTTP header and URL decoding rarely exceeds three layers) and small enough
// that a single request cannot exhaust memory.
func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes: 1 << 20,
		MaxDepth:      6,
		MaxStages:     32,
		MaxStageBytes: 2 << 20,
		MaxTotalBytes: 8 << 20,
		MaxNesting:    16,
		MaxLookups:    2048,
		MaxValueBytes: 32 << 10,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxInputBytes <= 0 {
		l.MaxInputBytes = d.MaxInputBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxStages <= 0 {
		l.MaxStages = d.MaxStages
	}
	if l.MaxStageBytes <= 0 {
		l.MaxStageBytes = d.MaxStageBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.MaxNesting <= 0 {
		l.MaxNesting = d.MaxNesting
	}
	if l.MaxLookups <= 0 {
		l.MaxLookups = d.MaxLookups
	}
	if l.MaxValueBytes <= 0 {
		l.MaxValueBytes = d.MaxValueBytes
	}
	return l
}

// Stage is one decoded variant of the input.
type Stage struct {
	// Text is the variant. It may contain arbitrary bytes, including invalid UTF-8,
	// because that is exactly what a hostile client can send.
	Text string
	// Path lists the transforms applied, in order, to the original input to
	// produce Text. It is empty for the original.
	Path []Transform
}

// Result is the outcome of Decode.
type Result struct {
	// Stages holds every distinct variant, original first, in deterministic
	// breadth-first order. Rules must inspect all of them: the application that
	// eventually logs the value may apply any subset of these decodings.
	Stages []Stage
	// Exhausted reports which budget stopped decoding, or BudgetNone.
	Exhausted Budget
}

// Complete reports whether decoding finished within every budget. When it is
// false the Stages are only a partial view and the request must be blocked.
func (r Result) Complete() bool { return r.Exhausted == BudgetNone }

// transform is one decoding step. It returns the decoded text and whether
// anything changed. over is true only when a hard output limit was exceeded.
type transform struct {
	name Transform
	fn   func(s string, lim Limits) (out string, changed, over bool)
}

// transforms is applied in this fixed order, which keeps Decode deterministic.
var transforms = []transform{
	{TransformGzip, gunzip},
	{TransformPercent, percentDecode},
	{TransformPercentU, percentUDecode},
	{TransformBackslash, backslashDecode},
	{TransformHTML, htmlDecode},
	{TransformOverlong, overlongDecode},
	{TransformFullwidth, fullwidthFold},
	{TransformNUL, nulStrip},
	{TransformZlib, unzlib},
	{TransformBase64, base64Decode},
}

// Decode expands input into every plausible decoded variant.
//
// It performs a breadth-first search over chains of transforms, de-duplicating
// by text, so a payload hidden behind any combination or repetition of the
// supported encodings appears as one of the Stages. The search is bounded by
// lim; if any bound is hit, Result.Exhausted says which, and the caller must
// block the request.
func Decode(input string, lim Limits) Result {
	lim = lim.withDefaults()
	res := Result{Stages: []Stage{{Text: input}}}

	if len(input) > lim.MaxInputBytes {
		res.Exhausted = BudgetInputSize
		return res
	}

	seen := map[string]struct{}{input: {}}
	total := len(input)

	// res.Stages grows while we iterate; indexing by position gives a queue.
	for i := 0; i < len(res.Stages); i++ {
		cur := res.Stages[i]
		for _, t := range transforms {
			out, changed, over := t.fn(cur.Text, lim)
			if over {
				res.Exhausted = BudgetStageBytes
				return res
			}
			if !changed {
				continue
			}
			if _, dup := seen[out]; dup {
				continue
			}
			switch {
			case len(cur.Path) >= lim.MaxDepth:
				res.Exhausted = BudgetDepth
				return res
			case len(out) > lim.MaxStageBytes:
				res.Exhausted = BudgetStageBytes
				return res
			case len(res.Stages) >= lim.MaxStages:
				res.Exhausted = BudgetStages
				return res
			case total+len(out) > lim.MaxTotalBytes:
				res.Exhausted = BudgetTotalBytes
				return res
			}
			seen[out] = struct{}{}
			total += len(out)
			path := append(slices.Clone(cur.Path), t.name)
			res.Stages = append(res.Stages, Stage{Text: out, Path: path})
		}
	}
	return res
}

// nulStrip removes NUL bytes. It reveals text sent in UTF-16 or UTF-32 (raw, or
// percent-encoded as %00), which the receiving stack decodes into the same
// characters as its ASCII form but which a byte-oriented filter never sees.
func nulStrip(s string, _ Limits) (string, bool, bool) {
	if !strings.Contains(s, "\x00") {
		return s, false, false
	}
	return strings.ReplaceAll(s, "\x00", ""), true, false
}

// unhex converts one hexadecimal digit.
func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hexByte parses the two hex digits at s[i:i+2].
func hexByte(s string, i int) (byte, bool) {
	if i+2 > len(s) {
		return 0, false
	}
	hi, ok1 := unhex(s[i])
	lo, ok2 := unhex(s[i+1])
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi<<4 | lo, true
}

// hexRune4 parses the four hex digits at s[i:i+4].
func hexRune4(s string, i int) (rune, bool) {
	hi, ok1 := hexByte(s, i)
	lo, ok2 := hexByte(s, i+2)
	if !ok1 || !ok2 {
		return 0, false
	}
	return rune(hi)<<8 | rune(lo), true
}

func isHighSurrogate(r rune) bool { return 0xD800 <= r && r <= 0xDBFF }
func isLowSurrogate(r rune) bool  { return 0xDC00 <= r && r <= 0xDFFF }

// gunzip inflates gzip data, capped at lim.MaxStageBytes. Truncated streams
// keep whatever was recovered, since a partial body can still carry a payload.
func gunzip(s string, lim Limits) (string, bool, bool) {
	if len(s) < 2 || s[0] != 0x1f || s[1] != 0x8b {
		return s, false, false
	}
	zr, err := gzip.NewReader(strings.NewReader(s))
	if err != nil {
		return s, false, false
	}
	defer func() { _ = zr.Close() }()

	data, err := io.ReadAll(io.LimitReader(zr, int64(lim.MaxStageBytes)+1))
	if len(data) > lim.MaxStageBytes {
		return s, false, true
	}
	if err != nil && len(data) == 0 {
		return s, false, false
	}
	return string(data), true, false
}

// unzlib inflates zlib-wrapped data (Content-Encoding: deflate as most clients
// and servers implement it).
func unzlib(s string, lim Limits) (string, bool, bool) {
	if len(s) < 2 || s[0]&0x0f != 8 || (int(s[0])<<8|int(s[1]))%31 != 0 {
		return s, false, false
	}
	zr, err := zlib.NewReader(strings.NewReader(s))
	if err != nil {
		return s, false, false
	}
	defer func() { _ = zr.Close() }()

	data, err := io.ReadAll(io.LimitReader(zr, int64(lim.MaxStageBytes)+1))
	if len(data) > lim.MaxStageBytes {
		return s, false, true
	}
	if err != nil && len(data) == 0 {
		return s, false, false
	}
	return string(data), true, false
}

// minBase64 is the shortest value treated as base64 text: the encoding of
// "${jndi:" is 12 characters.
const minBase64 = 12

// base64Decode decodes a value that is entirely base64 (standard or URL-safe
// alphabet, padded or not) into text. Applications routinely decode
// base64 cookies, parameters and tokens before logging them. Binary results are
// ignored, which discards almost every random token.
func base64Decode(s string, _ Limits) (string, bool, bool) {
	if len(s) < minBase64 {
		return s, false, false
	}
	for i := 0; i < len(s); i++ {
		if !isBase64Byte(s[i]) {
			return s, false, false
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if hasCompressionMagic(string(b)) {
			return string(b), true, false // gunzip or unzlib continues the chain
		}
		if !utf8.Valid(b) {
			return s, false, false
		}
		for _, c := range b {
			if c < 0x20 && c != '\t' && c != '\r' && c != '\n' || c == 0x7f {
				return s, false, false
			}
		}
		return string(b), true, false
	}
	return s, false, false
}

// hasCompressionMagic reports whether s starts like a gzip or zlib stream.
func hasCompressionMagic(s string) bool {
	if len(s) < 2 {
		return false
	}
	return s[0] == 0x1f && s[1] == 0x8b || s[0]&0x0f == 8 && (int(s[0])<<8|int(s[1]))%31 == 0
}

func isBase64Byte(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return c == '+' || c == '/' || c == '-' || c == '_' || c == '='
}

// percentDecode decodes %XX sequences. Malformed sequences are left as-is.
// Output bytes are not required to be valid UTF-8.
func percentDecode(s string, _ Limits) (string, bool, bool) {
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return s, false, false
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	changed := false
	for i < len(s) {
		if s[i] == '%' {
			if v, ok := hexByte(s, i+1); ok {
				b.WriteByte(v)
				i += 3
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), changed, false
}

// percentUDecode decodes the non-standard %uXXXX form that some servers accept.
func percentUDecode(s string, _ Limits) (string, bool, bool) {
	if !strings.Contains(s, "%u") && !strings.Contains(s, "%U") {
		return s, false, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '%' && i+1 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if r, ok := hexRune4(s, i+2); ok && !isHighSurrogate(r) && !isLowSurrogate(r) {
				b.WriteRune(r)
				i += 6
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), changed, false
}

// backslashDecode decodes \uXXXX (with surrogate pairs) and \xHH escapes as used
// by JSON, JavaScript, Java, and Python. A \x escape at or above 0x80 yields the
// raw byte, so a following overlong-UTF-8 step can still see it.
func backslashDecode(s string, _ Limits) (string, bool, bool) {
	if strings.IndexByte(s, '\\') < 0 {
		return s, false, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'u':
				if r, n, ok := parseUnicodeEscape(s, i); ok {
					b.WriteRune(r)
					i += n
					changed = true
					continue
				}
			case 'x':
				if v, ok := hexByte(s, i+2); ok {
					b.WriteByte(v)
					i += 4
					changed = true
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), changed, false
}

// parseUnicodeEscape parses \uXXXX at s[i:], joining a surrogate pair into one
// rune. It returns the rune and the number of bytes consumed. A lone surrogate
// is not an escape worth decoding and reports ok=false.
func parseUnicodeEscape(s string, i int) (rune, int, bool) {
	r, ok := hexRune4(s, i+2)
	if !ok {
		return 0, 0, false
	}
	switch {
	case isLowSurrogate(r):
		return 0, 0, false
	case isHighSurrogate(r):
		if i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
			if lo, ok := hexRune4(s, i+8); ok && isLowSurrogate(lo) {
				return 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00), 12, true
			}
		}
		return 0, 0, false
	}
	return r, 6, true
}

// htmlDecode resolves HTML character references such as &#36; and &dollar;.
func htmlDecode(s string, _ Limits) (string, bool, bool) {
	if strings.IndexByte(s, '&') < 0 {
		return s, false, false
	}
	out := html.UnescapeString(s)
	return out, out != s, false
}

// overlongDecode collapses overlong UTF-8 encodings (for example C0 A4 for '$').
// Strict decoders reject these; lenient ones, including some legacy servers and
// Java's modified UTF-8, accept them.
func overlongDecode(s string, _ Limits) (string, bool, bool) {
	if !hasLeadByte(s) {
		return s, false, false
	}
	isCont := func(c byte) bool { return c&0xC0 == 0x80 }
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case (c == 0xC0 || c == 0xC1) && i+1 < len(s) && isCont(s[i+1]):
			b.WriteRune(rune(c&0x1F)<<6 | rune(s[i+1]&0x3F))
			i += 2
			changed = true
		case c == 0xE0 && i+2 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9F && isCont(s[i+2]):
			b.WriteRune(rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F))
			i += 3
			changed = true
		case c == 0xF0 && i+3 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x8F && isCont(s[i+2]) && isCont(s[i+3]):
			b.WriteRune(rune(s[i+1]&0x3F)<<12 | rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F))
			i += 4
			changed = true
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), changed, false
}

// hasLeadByte is a cheap pre-check for bytes that can start an overlong form.
func hasLeadByte(s string) bool {
	return strings.IndexByte(s, 0xC0) >= 0 ||
		strings.IndexByte(s, 0xC1) >= 0 ||
		strings.IndexByte(s, 0xE0) >= 0 ||
		strings.IndexByte(s, 0xF0) >= 0
}

// fullwidthFold maps fullwidth ASCII (U+FF01..U+FF5E) and the small-form dollar
// and brace variants to plain ASCII. Log4j itself does not do this, but an
// application that applies Unicode compatibility normalization (NFKC) before
// logging does. Invalid bytes are copied through untouched.
func fullwidthFold(s string, _ Limits) (string, bool, bool) {
	if strings.IndexByte(s, 0xEF) < 0 {
		return s, false, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteByte(s[i])
		case 0xFF01 <= r && r <= 0xFF5E:
			b.WriteByte(byte(r - 0xFF01 + 0x21))
			changed = true
		case r == 0xFE69: // SMALL DOLLAR SIGN
			b.WriteByte('$')
			changed = true
		case r == 0xFE5B: // SMALL LEFT CURLY BRACKET
			b.WriteByte('{')
			changed = true
		case r == 0xFE5C: // SMALL RIGHT CURLY BRACKET
			b.WriteByte('}')
			changed = true
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String(), changed, false
}
