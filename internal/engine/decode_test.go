package engine

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// findStage returns the stage with exactly this text.
func findStage(res Result, text string) (Stage, bool) {
	for _, s := range res.Stages {
		if s.Text == text {
			return s, true
		}
	}
	return Stage{}, false
}

func gzipString(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.String()
}

func TestDecodeReveals(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string      // text of the stage that must exist
		path  []Transform // exact path to that stage
	}{
		{"percent", "%24%7Bjndi", "${jndi", []Transform{TransformPercent}},
		{"percent lowercase hex", "%24%7bjndi", "${jndi", []Transform{TransformPercent}},
		{"double percent", "%2524%257Bjndi", "${jndi", []Transform{TransformPercent, TransformPercent}},
		{"triple percent", "%252524%25257Bjndi", "${jndi", []Transform{TransformPercent, TransformPercent, TransformPercent}},
		{"percent-u", "%u0024%u007bjndi", "${jndi", []Transform{TransformPercentU}},
		{"percent-U uppercase marker", "%U0024%U007Bjndi", "${jndi", []Transform{TransformPercentU}},
		{"json unicode escape", `\u0024\u007bjndi`, "${jndi", []Transform{TransformBackslash}},
		{"hex escape", `\x24\x7bjndi`, "${jndi", []Transform{TransformBackslash}},
		{"surrogate pair", `\ud83d\ude00`, "\U0001F600", []Transform{TransformBackslash}},
		{"numeric entity", "&#36;&#123;jndi", "${jndi", []Transform{TransformHTML}},
		{"hex entity", "&#x24;&#x7b;jndi", "${jndi", []Transform{TransformHTML}},
		{"named entity", "&dollar;&lbrace;jndi", "${jndi", []Transform{TransformHTML}},
		{"overlong 2-byte", "\xc0\xa4\xc1\xbbjndi", "${jndi", []Transform{TransformOverlong}},
		{"overlong 3-byte", "\xe0\x80\xa4jndi", "$jndi", []Transform{TransformOverlong}},
		{"overlong 4-byte", "\xf0\x80\x80\xa4jndi", "$jndi", []Transform{TransformOverlong}},
		{"overlong NUL (modified UTF-8)", "a\xc0\x80b", "a\x00b", []Transform{TransformOverlong}},
		{"fullwidth", "\uff04\uff5bjndi", "${jndi", []Transform{TransformFullwidth}},
		{"small form variants", "\ufe69\ufe5bjndi\ufe5c", "${jndi}", []Transform{TransformFullwidth}},
		{"percent then entity", "%26%2336%3B{jndi", "${jndi", []Transform{TransformPercent, TransformHTML}},
		{"percent then backslash", "%5Cu0024{jndi", "${jndi", []Transform{TransformPercent, TransformBackslash}},
		{"percent yields overlong then collapsed", "%c0%a4%c1%bbjndi", "${jndi", []Transform{TransformPercent, TransformOverlong}},
		{"hex escape yields overlong", `\xc0\xa4`, "$", []Transform{TransformBackslash, TransformOverlong}},
		{"percent preserves invalid UTF-8", "%ff", "\xff", []Transform{TransformPercent}},
		{"gzip", gzipString(t, "${jndi"), "${jndi", []Transform{TransformGzip}},
		{"gzip then percent", gzipString(t, "%24%7Bjndi"), "${jndi", []Transform{TransformGzip, TransformPercent}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Decode(tc.input, Limits{})
			if res.Exhausted != BudgetNone {
				t.Fatalf("Exhausted = %v, want none", res.Exhausted)
			}
			st, ok := findStage(res, tc.want)
			if !ok {
				t.Fatalf("no stage with text %q; stages: %q", tc.want, stageTexts(res))
			}
			if !reflect.DeepEqual(st.Path, tc.path) {
				t.Errorf("path = %v, want %v", st.Path, tc.path)
			}
		})
	}
}

func stageTexts(res Result) []string {
	out := make([]string, len(res.Stages))
	for i, s := range res.Stages {
		out[i] = s.Text
	}
	return out
}

func TestDecodeLeavesBenignInputAlone(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"plain text", "hello world"},
		{"plain url", "/api/v1/items?id=42&sort=asc"},
		{"valid utf-8 two-byte", "caf\u00e9"},
		{"valid utf-8 three-byte", "\u20ac100"},
		{"valid utf-8 four-byte", "\U0001F600"},
		{"dangling percent", "100%"},
		{"percent with one digit", "%4"},
		{"percent with non-hex", "%zz"},
		{"percent-u too short", "%u00"},
		{"percent-u lone high surrogate", "%ud83d"},
		{"percent-u lone low surrogate", "%ude00"},
		{"backslash at end", `path\`},
		{"short unicode escape", `\u00`},
		{"non-hex unicode escape", `\uzzzz`},
		{"short hex escape", `\x2`},
		{"lone high surrogate escape", `\ud83d`},
		{"high surrogate followed by non-escape", `\ud83dabcdefgh`},
		{"high surrogate followed by non-low", `\ud83dA`},
		{"lone low surrogate escape", `\ude00`},
		{"ampersand without entity", "a & b"},
		{"truncated overlong lead", "x\xc0"},
		{"lead not followed by continuation", "\xc0A"},
		{"3-byte lead with non-overlong second byte", "\xe0\xa0\x80"},
		{"4-byte lead with non-overlong second byte", "\xf0\x90\x80\x80"},
		{"fullwidth lead with invalid tail", "\xef\xbc"},
		{"non-fullwidth EF character", "\xef\xbb\xbf"},
		{"gzip magic but corrupt", "\x1f\x8bnot-really-gzip"},
		{"single byte", "a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Decode(tc.input, Limits{})
			if res.Exhausted != BudgetNone {
				t.Fatalf("Exhausted = %v, want none", res.Exhausted)
			}
			if len(res.Stages) != 1 {
				t.Fatalf("got %d stages %q, want exactly the original", len(res.Stages), stageTexts(res))
			}
			if res.Stages[0].Text != tc.input || len(res.Stages[0].Path) != 0 {
				t.Errorf("stage 0 = %+v, want the untouched original", res.Stages[0])
			}
		})
	}
}

func TestDecodeOriginalIsAlwaysFirst(t *testing.T) {
	in := "%24%7Bjndi"
	res := Decode(in, Limits{})
	if res.Stages[0].Text != in || len(res.Stages[0].Path) != 0 {
		t.Fatalf("stage 0 = %+v, want original with empty path", res.Stages[0])
	}
}

func TestDecodeDeterministic(t *testing.T) {
	in := "%2526%2336%253B%257Bjndi&dollar;\\u0024"
	a, b := Decode(in, Limits{}), Decode(in, Limits{})
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("Decode is not deterministic:\n%+v\n%+v", a, b)
	}
}

func TestDecodeKeepsEveryIntermediateStage(t *testing.T) {
	// An application may stop decoding at any layer, so every layer is a stage.
	res := Decode("%2524%257Bjndi", Limits{})
	for _, want := range []string{"%2524%257Bjndi", "%24%7Bjndi", "${jndi"} {
		if _, ok := findStage(res, want); !ok {
			t.Errorf("missing intermediate stage %q; have %q", want, stageTexts(res))
		}
	}
}

// encodeLevels returns "$" percent-encoded n layers deep ("%24" is one layer).
func encodeLevels(n int) string {
	s := "%24"
	for i := 1; i < n; i++ {
		s = strings.ReplaceAll(s, "%", "%25")
	}
	return s
}

func TestDecodeDepthBoundary(t *testing.T) {
	lim := Limits{MaxDepth: 6}

	atLimit := Decode(encodeLevels(6), lim)
	if atLimit.Exhausted != BudgetNone {
		t.Fatalf("6 layers with MaxDepth 6: Exhausted = %v, want none", atLimit.Exhausted)
	}
	if _, ok := findStage(atLimit, "$"); !ok {
		t.Errorf("6 layers should fully decode to \"$\"; stages %q", stageTexts(atLimit))
	}

	over := Decode(encodeLevels(7), lim)
	if over.Exhausted != BudgetDepth {
		t.Fatalf("7 layers with MaxDepth 6: Exhausted = %v, want depth", over.Exhausted)
	}
}

func TestDecodeStageBudget(t *testing.T) {
	// Percent and entity decoding each produce a distinct child, and their
	// combination is a fourth variant: original, "$&#36;", "%24$", "$$".
	in := "%24&#36;"
	if res := Decode(in, Limits{MaxStages: 4}); res.Exhausted != BudgetNone || len(res.Stages) != 4 {
		t.Fatalf("MaxStages 4: Exhausted = %v, stages = %q", res.Exhausted, stageTexts(res))
	}
	if res := Decode(in, Limits{MaxStages: 3}); res.Exhausted != BudgetStages {
		t.Fatalf("MaxStages 3: Exhausted = %v, want stages", res.Exhausted)
	}
}

func TestDecodeInputSizeBudget(t *testing.T) {
	res := Decode("123456789", Limits{MaxInputBytes: 8})
	if res.Exhausted != BudgetInputSize {
		t.Fatalf("Exhausted = %v, want input-size", res.Exhausted)
	}
	if len(res.Stages) != 1 {
		t.Errorf("oversized input must not be decoded; got %d stages", len(res.Stages))
	}
	if res := Decode("12345678", Limits{MaxInputBytes: 8}); res.Exhausted != BudgetNone {
		t.Errorf("input exactly at the limit: Exhausted = %v, want none", res.Exhausted)
	}
}

func TestDecodeTotalBytesBudget(t *testing.T) {
	in := "%24%24%24" // 9 bytes, decodes to 3
	if res := Decode(in, Limits{MaxTotalBytes: 12}); res.Exhausted != BudgetNone {
		t.Fatalf("MaxTotalBytes 12: Exhausted = %v, want none", res.Exhausted)
	}
	if res := Decode(in, Limits{MaxTotalBytes: 11}); res.Exhausted != BudgetTotalBytes {
		t.Fatalf("MaxTotalBytes 11: Exhausted = %v, want total-bytes", res.Exhausted)
	}
}

func TestDecodeStageBytesBudget(t *testing.T) {
	// A variant larger than MaxStageBytes. Entities can grow slightly, so use
	// gzip, which is the realistic amplifier.
	body := strings.Repeat("A", 1024)
	in := gzipString(t, body)
	if res := Decode(in, Limits{MaxStageBytes: 1024}); res.Exhausted != BudgetNone {
		t.Fatalf("variant exactly at MaxStageBytes: Exhausted = %v, want none", res.Exhausted)
	}
	if res := Decode(in, Limits{MaxStageBytes: 1023}); res.Exhausted != BudgetStageBytes {
		t.Fatalf("variant one byte over: Exhausted = %v, want stage-bytes", res.Exhausted)
	}
}

func TestDecodeStageBytesBudgetOnGrowth(t *testing.T) {
	// The size cap applies to every produced variant, not just gzip output.
	in := "%e2%82%ac%e2%82%ac" // decodes to two euro signs: 6 bytes from 18
	res := Decode(in, Limits{MaxStageBytes: 5})
	if res.Exhausted != BudgetStageBytes {
		t.Fatalf("Exhausted = %v, want stage-bytes", res.Exhausted)
	}
}

func TestDecodeGzipBomb(t *testing.T) {
	// 16 MiB of zeros compresses to a few KiB; it must be refused, not inflated.
	in := gzipString(t, strings.Repeat("\x00", 16<<20))
	if len(in) > 64<<10 {
		t.Fatalf("test setup: bomb compressed to %d bytes, expected a small input", len(in))
	}
	res := Decode(in, Limits{})
	if res.Exhausted != BudgetStageBytes {
		t.Fatalf("Exhausted = %v, want stage-bytes", res.Exhausted)
	}
	for _, s := range res.Stages {
		if len(s.Text) > DefaultLimits().MaxStageBytes {
			t.Errorf("a stage of %d bytes escaped the cap", len(s.Text))
		}
	}
}

func TestDecodeTruncatedGzipKeepsRecoveredData(t *testing.T) {
	full := gzipString(t, strings.Repeat("${jndi:", 200))
	truncated := full[:len(full)-12]
	res := Decode(truncated, Limits{})
	if res.Exhausted != BudgetNone {
		t.Fatalf("Exhausted = %v, want none", res.Exhausted)
	}
	if len(res.Stages) < 2 || !strings.Contains(res.Stages[1].Text, "${jndi:") {
		t.Errorf("expected recovered partial data in stage 1; stages %d", len(res.Stages))
	}
}

func TestDecodeGzipHeaderOnlyIsIgnored(t *testing.T) {
	// A valid gzip header with no recoverable data is not a decodable layer.
	in := gzipString(t, "x")[:10]
	res := Decode(in, Limits{})
	if res.Exhausted != BudgetNone {
		t.Fatalf("Exhausted = %v, want none", res.Exhausted)
	}
	for _, st := range res.Stages {
		if len(st.Path) > 0 && st.Path[0] == TransformGzip {
			t.Errorf("gzip header alone produced a gzip stage: %q", st.Text)
		}
	}
}

func TestDecodeGzipEmptyBody(t *testing.T) {
	in := gzipString(t, "")
	res := Decode(in, Limits{})
	if res.Exhausted != BudgetNone {
		t.Fatalf("Exhausted = %v, want none", res.Exhausted)
	}
	if _, ok := findStage(res, ""); !ok {
		t.Errorf("an empty gzip body should decode to an empty stage; stages %q", stageTexts(res))
	}
}

func TestResultComplete(t *testing.T) {
	if !Decode("plain", Limits{}).Complete() {
		t.Error("an in-budget decode must be Complete")
	}
	if Decode("123456789", Limits{MaxInputBytes: 8}).Complete() {
		t.Error("an exhausted decode must not be Complete")
	}
}

func TestLimitsDefaults(t *testing.T) {
	d := DefaultLimits()
	if got := (Limits{}).withDefaults(); got != d {
		t.Errorf("zero Limits = %+v, want defaults %+v", got, d)
	}
	if got := (Limits{MaxDepth: -3, MaxStages: -1}).withDefaults(); got != d {
		t.Errorf("negative Limits = %+v, want defaults %+v", got, d)
	}
	custom := Limits{
		MaxInputBytes: 1, MaxDepth: 2, MaxStages: 3, MaxStageBytes: 4, MaxTotalBytes: 5,
		MaxNesting: 6, MaxLookups: 7, MaxValueBytes: 8,
	}
	if got := custom.withDefaults(); got != custom {
		t.Errorf("explicit Limits changed: %+v, want %+v", got, custom)
	}
}

func TestBudgetString(t *testing.T) {
	tests := map[Budget]string{
		BudgetNone:         "none",
		BudgetInputSize:    "input-size",
		BudgetDepth:        "depth",
		BudgetStages:       "stages",
		BudgetStageBytes:   "stage-bytes",
		BudgetTotalBytes:   "total-bytes",
		BudgetNesting:      "nesting",
		BudgetLookups:      "lookups",
		BudgetValueBytes:   "value-bytes",
		BudgetFields:       "fields",
		BudgetRequestBytes: "request-bytes",
		BudgetWork:         "work",
		Budget(99):         "unknown",
	}
	for b, want := range tests {
		if got := b.String(); got != want {
			t.Errorf("Budget(%d).String() = %q, want %q", int(b), got, want)
		}
	}
}

func FuzzDecode(f *testing.F) {
	seeds := []string{
		"", "${jndi:ldap://x.invalid/a}", "%24%7Bjndi", "%2524%257Bjndi",
		`\u0024\u007bjndi`, "&#36;&#123;", "\xc0\xa4\xc1\xbb", "\uff04\uff5b",
		"%u0024", "%", "\\", "&", "\x1f\x8b", "%c0%a4", `\ud83d\ude00`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Small limits keep each fuzz iteration fast and exercise the budget paths.
	lim := Limits{MaxInputBytes: 4096, MaxDepth: 4, MaxStages: 16, MaxStageBytes: 8192, MaxTotalBytes: 32768}

	f.Fuzz(func(t *testing.T, in string) {
		res := Decode(in, lim)

		if len(res.Stages) == 0 || res.Stages[0].Text != in || len(res.Stages[0].Path) != 0 {
			t.Fatalf("stage 0 must be the untouched original")
		}
		if len(res.Stages) > lim.MaxStages {
			t.Fatalf("%d stages exceeds MaxStages %d", len(res.Stages), lim.MaxStages)
		}
		seen := make(map[string]bool, len(res.Stages))
		total := 0
		for i, s := range res.Stages {
			if seen[s.Text] {
				t.Fatalf("duplicate stage %q", s.Text)
			}
			seen[s.Text] = true
			total += len(s.Text)
			if i > 0 && len(s.Text) > lim.MaxStageBytes {
				t.Fatalf("stage %d is %d bytes, over MaxStageBytes", i, len(s.Text))
			}
			if len(s.Path) > lim.MaxDepth {
				t.Fatalf("stage %d path length %d exceeds MaxDepth", i, len(s.Path))
			}
			if (i == 0) != (len(s.Path) == 0) {
				t.Fatalf("only the original may have an empty path (stage %d)", i)
			}
		}
		if len(in) <= lim.MaxInputBytes && total > lim.MaxTotalBytes {
			t.Fatalf("total %d bytes exceeds MaxTotalBytes", total)
		}
		if len(in) > lim.MaxInputBytes && res.Exhausted != BudgetInputSize {
			t.Fatalf("oversized input must report input-size, got %v", res.Exhausted)
		}
		// Determinism.
		if again := Decode(in, lim); !reflect.DeepEqual(res, again) {
			t.Fatalf("non-deterministic result for %q", in)
		}
		// Folding fullwidth characters must never corrupt otherwise valid text.
		if utf8.ValidString(in) {
			for _, s := range res.Stages {
				if len(s.Path) == 1 && s.Path[0] == TransformFullwidth && !utf8.ValidString(s.Text) {
					t.Fatalf("fullwidth fold produced invalid UTF-8 from valid input %q", in)
				}
			}
		}
	})
}

func TestDecodeNULStrip(t *testing.T) {
	// UTF-16LE text, and the same text percent-encoded: both reveal the payload
	// once NUL bytes are removed.
	utf16 := "$\x00{\x00j\x00n\x00d\x00i\x00"
	for _, in := range []string{utf16, "%24%00%7B%00jndi"} {
		res := Decode(in, Limits{})
		found := false
		for _, st := range res.Stages {
			if strings.HasPrefix(st.Text, "${jndi") && st.Path[len(st.Path)-1] == TransformNUL {
				found = true
			}
		}
		if !found {
			t.Errorf("Decode(%q) did not reveal ${jndi via nul-strip: %q", in, res.Stages)
		}
	}
	if res := Decode("plain", Limits{}); len(res.Stages) != 1 {
		t.Errorf("text without NUL gained stages: %d", len(res.Stages))
	}
}

func zlibString(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func hasStage(res Result, text string, last Transform) bool {
	for _, st := range res.Stages {
		if st.Text == text && len(st.Path) > 0 && st.Path[len(st.Path)-1] == last {
			return true
		}
	}
	return false
}

func TestDecodeZlib(t *testing.T) {
	res := Decode(zlibString(t, "${jndi:x}"), Limits{})
	if !hasStage(res, "${jndi:x}", TransformZlib) {
		t.Errorf("zlib not decoded: %q", res.Stages)
	}
	// Not zlib: wrong method nibble, bad check bits, truncated, empty stream.
	for _, in := range []string{"\x79\x9c....", "\x78\x9d....", "\x78\x9c", "x", ""} {
		if r := Decode(in, Limits{}); len(r.Stages) != 1 {
			t.Errorf("Decode(%q) produced %d stages", in, len(r.Stages))
		}
	}
	// Valid header, garbage stream: nothing recovered.
	if r := Decode("\x78\x9c\xff\xff\xff\xff", Limits{}); len(r.Stages) != 1 {
		t.Errorf("garbage zlib stream produced %d stages", len(r.Stages))
	}
	// Truncated stream keeps the recovered prefix, like gzip.
	z := zlibString(t, strings.Repeat("${jndi:x} ", 200))
	found := false
	for _, st := range Decode(z[:len(z)-8], Limits{}).Stages {
		if len(st.Path) > 0 && st.Path[0] == TransformZlib && strings.Contains(st.Text, "${jndi:x}") {
			found = true
		}
	}
	if !found {
		t.Error("truncated zlib prefix lost")
	}
}

func TestDecodeZlibBomb(t *testing.T) {
	z := zlibString(t, strings.Repeat("A", 3<<20))
	if res := Decode(z, Limits{}); res.Exhausted != BudgetStageBytes {
		t.Errorf("Exhausted = %v, want stage-bytes", res.Exhausted)
	}
}

func TestDecodeBase64(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte("${jndi:ldap://x.invalid/a}"))
	raw := base64.RawURLEncoding.EncodeToString([]byte("${jndi:ldap://x.invalid/a}?>>"))
	for _, in := range []string{std, raw, strings.TrimRight(std, "=")} {
		res := Decode(in, Limits{})
		found := false
		for _, st := range res.Stages {
			if strings.HasPrefix(st.Text, "${jndi:ldap") && st.Path[len(st.Path)-1] == TransformBase64 {
				found = true
			}
		}
		if !found {
			t.Errorf("base64 %q not decoded: %q", in, res.Stages)
		}
	}
	// Ignored: too short, not base64, binary result, control bytes, non-ASCII.
	binary := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	high := base64.StdEncoding.EncodeToString([]byte("caf\xe9 caf\xe9 caf\xe9")) // Latin-1, not UTF-8
	del := base64.StdEncoding.EncodeToString([]byte("aaaaaaaa\x7f"))
	for _, in := range []string{"aGk=", "abc def ghi jkl", "internationalization", binary, high, del, "AAAA AAAA AAAA", strings.Repeat("A", 12) + "!"} {
		if r := Decode(in, Limits{}); len(r.Stages) != 1 {
			t.Errorf("Decode(%q) produced %d stages: %q", in, len(r.Stages), r.Stages)
		}
	}
}

func TestDecodeBase64ThenCompression(t *testing.T) {
	for name, packed := range map[string]string{"gzip": gzipString(t, "${jndi:x}"), "zlib": zlibString(t, "${jndi:x}")} {
		in := base64.StdEncoding.EncodeToString([]byte(packed))
		res := Decode(in, Limits{})
		found := false
		for _, st := range res.Stages {
			if st.Text == "${jndi:x}" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s inside base64 not unpacked: %d stages", name, len(res.Stages))
		}
	}
}

func TestDecodeBase64KeepsNonASCIIText(t *testing.T) {
	in := base64.StdEncoding.EncodeToString([]byte("caf\u00e9 \u6f22\u5b57 \U0001F600 ok"))
	if res := Decode(in, Limits{}); !hasStage(res, "caf\u00e9 \u6f22\u5b57 \U0001F600 ok", TransformBase64) {
		t.Errorf("UTF-8 base64 text not decoded: %q", res.Stages)
	}
}
