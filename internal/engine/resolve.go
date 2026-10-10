package engine

import "strings"

// Resolve emulates the part of Log4j's lookup substitution (StrSubstitutor and
// Interpolator) that decides whether a string triggers a JNDI lookup.
//
// Log4j substitutes the inside of "${...}" first, innermost out, and only then
// splits the result at the first ":-" (default value) and the first ':' (lookup
// prefix, matched case-insensitively). Resolve reproduces that order, so
// obfuscations such as ${${lower:j}ndi:...}, ${${::-j}ndi:...},
// ${${env:X:-j}ndi:...} and ${${date:'j'}ndi:...} collapse to "jndi" and are
// reported, instead of being missed by a plain-text match.
//
// Text that depends on the environment (${env:...}, ${sys:...}, ${ctx:...} and
// similar) cannot be known statically. It is carried as an unknown marker; a
// prefix that could be "jndi" depending on that unknown is reported as
// FindingPossibleJNDI rather than ignored.
//
// Resolve is deliberately conservative where Log4j is not:
//   - the "$${" escape is not honored (the inner lookup is analyzed anyway);
//   - an unterminated "${" is analyzed as if it were closed at the end of the
//     text, because the application may append a "}" before logging;
//   - values returned by lookups are re-scanned for further "${", as Log4j does;
//   - the assembled output is re-scanned once, so a "${" formed by two adjacent
//     lookup values (for example ${::-$}${::-{}jndi:...}) is not missed if a
//     later substitution pass runs over the result.

// unknownRune stands for text that cannot be determined statically. U+FFFF is a
// Unicode noncharacter, and any real occurrence in the input is replaced first.
const (
	unknownRune = rune(0xFFFF)
	unknownMark = string(unknownRune)
)

// FindingKind classifies a Finding.
type FindingKind int

// Finding kinds.
const (
	// FindingJNDI is a lookup whose prefix resolves to exactly "jndi".
	FindingJNDI FindingKind = iota + 1
	// FindingPossibleJNDI is a lookup whose prefix would be "jndi" for some value
	// of an environment-dependent unknown.
	FindingPossibleJNDI
)

// String returns a stable identifier.
func (k FindingKind) String() string {
	switch k {
	case FindingJNDI:
		return "jndi"
	case FindingPossibleJNDI:
		return "possible-jndi"
	default:
		return "unknown"
	}
}

// Finding is one JNDI-class lookup found by Resolve.
type Finding struct {
	Kind FindingKind
	// Offset is the byte offset of the lookup's "${" in the analyzed text, or in
	// the lookup-generated text when Expanded is true.
	Offset int
	// Expanded is true when the lookup was found inside text produced by another
	// lookup (Log4j re-scans lookup results), so Offset is relative to that text.
	Expanded bool
	// Depth is how many lookups enclose this one (0 for top level). A nonzero
	// depth after re-expansion means the payload was built by another lookup.
	Depth int
	// Scheme is the lower-cased URL scheme of the lookup key ("ldap", "rmi", ...),
	// or "" if the key has none. Unknown characters appear as '?'.
	Scheme string
	// Key is the resolved key after the "jndi:" prefix, truncated to 256 bytes.
	// It is attacker-controlled: defang it before logging.
	Key string
	// Obfuscated is true when a nested lookup contributed to the prefix, i.e. the
	// text did not simply say "jndi:".
	Obfuscated bool
	// KeyLookups lists environment-dependent lookups ("env", "sys", "java", ...)
	// nested inside the key. Their presence signals data exfiltration over the
	// lookup channel.
	KeyLookups []string
	// Unterminated is true if the lookup had no closing brace in the text.
	Unterminated bool
}

// Lookup summarizes one evaluated lookup, whether or not it is dangerous. Plain
// placeholders such as ${name} (no ':' and no nesting) are counted in
// Resolution.Total but not listed.
type Lookup struct {
	Offset int
	// Expanded is true when the lookup was found in lookup-generated text.
	Expanded bool
	Depth    int
	// Prefix is the lower-cased lookup prefix, "" when there is none. Unknown
	// characters appear as '?'.
	Prefix string
	// Known is false when the prefix contains environment-dependent text.
	Known bool
	// Obfuscated is true when a nested lookup contributed to the prefix.
	Obfuscated   bool
	HasDefault   bool
	Unterminated bool
}

// Resolution is the outcome of Resolve.
type Resolution struct {
	// Total counts every "${...}" construct parsed, including plain placeholders.
	Total int
	// MaxNesting is the deepest nesting of lookups observed while parsing.
	MaxNesting int
	// Lookups lists the evaluated, non-trivial lookups in evaluation order.
	Lookups []Lookup
	// Findings lists JNDI-class lookups in evaluation order.
	Findings []Finding
	// Exhausted reports which budget stopped resolution, or BudgetNone. When it
	// is set the caller must block.
	Exhausted Budget
}

// Complete reports whether resolution finished within every budget.
func (r Resolution) Complete() bool { return r.Exhausted == BudgetNone }

// envLike lists the lookups whose result comes from the host environment or
// request context, so it cannot be known statically.
var envLike = map[string]bool{
	"env": true, "sys": true, "java": true, "ctx": true, "main": true,
	"bundle": true, "map": true, "sd": true, "event": true, "marker": true,
	"log4j": true, "web": true, "docker": true, "kubernetes": true,
	"spring": true, "jvmrunargs": true,
}

// IsLookupPrefix reports whether prefix (already lower-cased) names a lookup that
// Log4j 2.x evaluates. Prefixes outside this set are left unresolved by Log4j.
func IsLookupPrefix(prefix string) bool {
	switch prefix {
	case "jndi", "lower", "upper", "date":
		return true
	}
	return envLike[prefix]
}

const maxReportedKey = 256

// Resolve analyzes text for Log4j lookups. See the package notes above.
func Resolve(text string, lim Limits) Resolution {
	lim = lim.withDefaults()
	var res Resolution
	if !strings.Contains(text, "${") {
		return res
	}
	if strings.Contains(text, unknownMark) {
		text = strings.ReplaceAll(text, unknownMark, string(rune(0xFFFD)))
	}

	root, total, maxNest, b := parseLookups(text, lim, false)
	res.Total, res.MaxNesting = total, maxNest
	if b != BudgetNone {
		res.Exhausted = b
		return res
	}

	r := &resolver{lim: lim, res: &res}
	assemble := false
	for _, p := range root.parts {
		if p.lookup != nil {
			assemble = true
			break
		}
	}
	assembled := r.evalParts(root, 0, assemble, lim.MaxStageBytes, BudgetStageBytes)
	if assemble && r.exhausted == BudgetNone && assembled != text && strings.Contains(assembled, "${") {
		// One extra pass over the assembled output. Findings and lookups from it
		// are marked Expanded.
		r.expandText(assembled, 0)
	}
	res.Exhausted = r.exhausted
	return res
}

// part is either a literal span of the source or a nested lookup.
type part struct {
	start, end int
	lookup     *lookupNode
}

type lookupNode struct {
	src          string
	offset       int
	parts        []part
	unterminated bool
	expanded     bool
}

func (n *lookupNode) literal(p part) string { return n.src[p.start:p.end] }

type openFrame struct {
	offset   int
	litStart int
	parts    []part
}

// parseLookups builds the lookup tree iteratively (no recursion on attacker
// nesting). Plain placeholders are folded back into literal text so that
// memory is proportional to the number of interesting lookups, which is capped.
func parseLookups(src string, lim Limits, expanded bool) (root *lookupNode, total, maxNest int, b Budget) {
	stack := []openFrame{{offset: -1}}
	nonTrivial := 0

	addLiteral := func(f *openFrame, start, end int) {
		if end <= start {
			return
		}
		if n := len(f.parts); n > 0 && f.parts[n-1].lookup == nil && f.parts[n-1].end == start {
			f.parts[n-1].end = end
			return
		}
		f.parts = append(f.parts, part{start: start, end: end})
	}

	// closeTop finishes the innermost open lookup. at is the index of its '}',
	// or len(src) when it is unterminated.
	closeTop := func(at int, terminated bool) Budget {
		top := &stack[len(stack)-1]
		addLiteral(top, top.litStart, at)
		f := *top
		stack = stack[:len(stack)-1]
		parent := &stack[len(stack)-1]
		total++

		spanEnd := len(src)
		if terminated {
			spanEnd = at + 1
		}
		parent.litStart = spanEnd

		trivial := len(f.parts) == 0
		if len(f.parts) == 1 && f.parts[0].lookup == nil {
			trivial = !strings.Contains(src[f.parts[0].start:f.parts[0].end], ":")
		}
		if trivial {
			addLiteral(parent, f.offset, spanEnd)
			return BudgetNone
		}
		nonTrivial++
		if nonTrivial > lim.MaxLookups {
			return BudgetLookups
		}
		node := &lookupNode{src: src, offset: f.offset, parts: f.parts, unterminated: !terminated, expanded: expanded}
		parent.parts = append(parent.parts, part{lookup: node})
		return BudgetNone
	}

	for i := 0; i < len(src); {
		j := strings.IndexAny(src[i:], "$}")
		if j < 0 {
			break
		}
		i += j
		switch {
		case src[i] == '$' && i+1 < len(src) && src[i+1] == '{':
			top := &stack[len(stack)-1]
			addLiteral(top, top.litStart, i)
			stack = append(stack, openFrame{offset: i, litStart: i + 2})
			if nest := len(stack) - 1; nest > maxNest {
				maxNest = nest
			}
			if len(stack)-1 > lim.MaxNesting {
				return nil, total, maxNest, BudgetNesting
			}
			i += 2
		case src[i] == '}' && len(stack) > 1:
			if b := closeTop(i, true); b != BudgetNone {
				return nil, total, maxNest, b
			}
			i++
		default:
			i++
		}
	}

	for len(stack) > 1 {
		if b := closeTop(len(src), false); b != BudgetNone {
			return nil, total, maxNest, b
		}
	}
	addLiteral(&stack[0], stack[0].litStart, len(src))
	return &lookupNode{src: src, offset: -1, parts: stack[0].parts, expanded: expanded}, total, maxNest, BudgetNone
}

type resolver struct {
	lim       Limits
	res       *Resolution
	evals     int
	exhausted Budget
}

func (r *resolver) exhaust(b Budget) {
	if r.exhausted == BudgetNone {
		r.exhausted = b
	}
}

type evalResult struct {
	val    string
	prefix string
	// sources names the environment-dependent lookups in this subtree.
	sources []string
}

// evalParts evaluates a node's content. When build is false only the lookups
// are evaluated and no string is assembled. When build is true, assembling more
// than limit bytes exhausts the over budget.
func (r *resolver) evalParts(n *lookupNode, depth int, build bool, limit int, over Budget) string {
	var sb strings.Builder
	for _, p := range n.parts {
		if r.exhausted != BudgetNone {
			return ""
		}
		if p.lookup == nil {
			if build {
				sb.WriteString(n.literal(p))
			}
		} else {
			v := r.evalNode(p.lookup, depth)
			if build {
				sb.WriteString(v.val)
			}
		}
		if build && sb.Len() > limit {
			r.exhaust(over)
			return ""
		}
	}
	return sb.String()
}

// expandText re-scans a lookup result for further "${", as Log4j does.
func (r *resolver) expandText(s string, depth int) string {
	root, _, _, b := parseLookups(s, r.lim, true)
	if b != BudgetNone {
		r.exhaust(b)
		return ""
	}
	return r.evalParts(root, depth, true, r.lim.MaxValueBytes, BudgetValueBytes)
}

func (r *resolver) evalNode(n *lookupNode, depth int) evalResult {
	if r.exhausted != BudgetNone {
		return evalResult{}
	}
	r.evals++
	if r.evals > r.lim.MaxLookups {
		r.exhaust(BudgetLookups)
		return evalResult{}
	}
	if depth > r.lim.MaxNesting {
		r.exhaust(BudgetNesting)
		return evalResult{}
	}

	// Step 1: substitute nested lookups to obtain the full name.
	var name strings.Builder
	colonSeen, obfuscated := false, false
	var allSources, keySources []string
	for _, p := range n.parts {
		if p.lookup == nil {
			lit := n.literal(p)
			if strings.IndexByte(lit, ':') >= 0 {
				colonSeen = true
			}
			name.WriteString(lit)
		} else {
			c := r.evalNode(p.lookup, depth+1)
			if r.exhausted != BudgetNone {
				return evalResult{}
			}
			if !colonSeen {
				obfuscated = true
			} else {
				keySources = addSources(keySources, c.sources)
			}
			allSources = addSources(allSources, c.sources)
			name.WriteString(c.val)
		}
		if name.Len() > r.lim.MaxValueBytes {
			r.exhaust(BudgetValueBytes)
			return evalResult{}
		}
	}

	// Step 2: split off the default value at the first ":-", then the prefix at
	// the first ':'.
	nameStr := name.String()
	varName, def, hasDef := nameStr, "", false
	if i := strings.Index(nameStr, ":-"); i >= 0 {
		varName, def, hasDef = nameStr[:i], nameStr[i+2:], true
	}
	prefix, key, hasPrefix := "", varName, false
	if i := strings.IndexByte(varName, ':'); i >= 0 {
		prefix, key, hasPrefix = varName[:i], varName[i+1:], true
	}
	lp := ""
	if hasPrefix {
		lp = javaLower(prefix)
	}
	known := !strings.Contains(lp, unknownMark)

	r.res.Lookups = append(r.res.Lookups, Lookup{
		Offset:       n.offset,
		Expanded:     n.expanded,
		Depth:        depth,
		Prefix:       display(lp),
		Known:        known,
		Obfuscated:   obfuscated,
		HasDefault:   hasDef,
		Unterminated: n.unterminated,
	})

	// Step 3: resolve through the handler for the prefix.
	var val string
	expand := true
	ownSource := ""
	unresolved := func() {
		if hasDef {
			val = def
			return
		}
		val, expand = "${"+nameStr+"}", false
	}

	switch {
	case lp == "jndi":
		r.addFinding(FindingJNDI, n, depth, key, obfuscated, keySources)
		val = unknownMark
	case lp == "lower":
		val = javaLower(key)
	case lp == "upper":
		val = javaUpper(key)
	case lp == "date":
		if v, ok := datePattern(key); ok {
			val = v
		} else {
			unresolved()
		}
	case envLike[lp]:
		ownSource = lp
		if hasDef {
			val = def
		} else {
			val = unknownMark
		}
	case !known && couldBeJNDI(lp):
		r.addFinding(FindingPossibleJNDI, n, depth, key, obfuscated, keySources)
		val = unknownMark
	default:
		unresolved()
	}

	if len(val) > r.lim.MaxValueBytes {
		r.exhaust(BudgetValueBytes)
		return evalResult{}
	}

	// Log4j re-scans the replacement text for further variables.
	if expand && val != unknownMark && strings.Contains(val, "${") {
		val = r.expandText(val, depth+1)
		if r.exhausted != BudgetNone {
			return evalResult{}
		}
	}

	sources := allSources
	if ownSource != "" {
		sources = addSources(sources, []string{ownSource})
	}
	return evalResult{val: val, prefix: lp, sources: sources}
}

func (r *resolver) addFinding(kind FindingKind, n *lookupNode, depth int, key string, obfuscated bool, keySources []string) {
	f := Finding{
		Kind:         kind,
		Offset:       n.offset,
		Expanded:     n.expanded,
		Depth:        depth,
		Obfuscated:   obfuscated,
		KeyLookups:   keySources,
		Unterminated: n.unterminated,
	}
	if i := strings.IndexByte(key, ':'); i >= 0 && validScheme(key[:i]) {
		f.Scheme = display(strings.ToLower(key[:i]))
	}
	f.Key = display(truncate(key, maxReportedKey))
	r.res.Findings = append(r.res.Findings, f)
}

// display makes unknown markers readable.
func display(s string) string { return strings.ReplaceAll(s, unknownMark, "?") }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func validScheme(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '+', c == '-', c == '.', c == unknownRune:
		default:
			return false
		}
	}
	return true
}

const maxSources = 16

// addSources merges names into dst, de-duplicated and capped.
func addSources(dst, names []string) []string {
	for _, n := range names {
		if len(dst) >= maxSources {
			return dst
		}
		dup := false
		for _, d := range dst {
			if d == n {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, n)
		}
	}
	return dst
}

// couldBeJNDI reports whether a lower-cased prefix containing unknown markers
// equals "jndi" for some replacement of the markers. It is false for a prefix
// with no unknown marker (an exact "jndi" is handled separately), and at least
// two literal characters are required so that a prefix made only of unknowns
// does not match everything.
func couldBeJNDI(p string) bool {
	const target = "jndi"
	if !strings.Contains(p, unknownMark) {
		return false
	}
	literals := 0
	cur := [len(target) + 1]bool{true}
	for _, c := range p {
		var next [len(target) + 1]bool
		if c == unknownRune {
			for j := range cur {
				if cur[j] {
					for k := j; k <= len(target); k++ {
						next[k] = true
					}
				}
			}
		} else {
			literals++
			for j := 0; j < len(target); j++ {
				if cur[j] && rune(target[j]) == c {
					next[j+1] = true
				}
			}
		}
		cur = next
	}
	return cur[len(target)] && literals >= 2
}

// dateLetters are the unquoted pattern letters Java's SimpleDateFormat accepts.
const dateLetters = "GyYMLwWDdFEuaHkKhmsSzZX"

// datePattern evaluates a ${date:...} pattern. Quoted text is literal, so
// ${date:'j'} yields "j". Unquoted pattern letters yield unknown text. An
// unquoted letter that is not a valid pattern letter, or an unterminated quote,
// makes Java throw, so the lookup is unresolved (ok=false).
func datePattern(p string) (string, bool) {
	if p == "" {
		return unknownMark, true
	}
	rs := []rune(p)
	var b strings.Builder
	inQuote, lastUnknown := false, false
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\'':
			if i+1 < len(rs) && rs[i+1] == '\'' {
				b.WriteByte('\'')
				i++
			} else {
				inQuote = !inQuote
			}
			lastUnknown = false
		case inQuote:
			b.WriteRune(c)
			lastUnknown = false
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			if !strings.ContainsRune(dateLetters, c) {
				return "", false
			}
			if !lastUnknown {
				b.WriteRune(unknownRune)
			}
			lastUnknown = true
		default:
			b.WriteRune(c)
			lastUnknown = false
		}
	}
	if inQuote {
		return "", false
	}
	return b.String(), true
}
