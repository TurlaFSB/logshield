package engine

import (
	"slices"
	"strconv"
	"strings"
)

// Decision is the engine's overall judgement of a request.
type Decision int

// Decisions, in increasing order of severity.
const (
	// DecisionClean means nothing was detected.
	DecisionClean Decision = iota
	// DecisionSuspicious means only suspicious detections were made.
	DecisionSuspicious
	// DecisionMalicious means at least one malicious detection was made, or the
	// engine could not finish analyzing the request within its budgets.
	DecisionMalicious
)

// String returns a stable identifier.
func (d Decision) String() string {
	switch d {
	case DecisionClean:
		return "clean"
	case DecisionSuspicious:
		return "suspicious"
	case DecisionMalicious:
		return "malicious"
	default:
		return "unknown"
	}
}

// Config tunes Inspect. The zero value is safe and bounded.
type Config struct {
	// Limits bounds decoding and lookup resolution for each field.
	Limits Limits
	// MaxFields caps how many fields one request may expand into. Default 1024.
	MaxFields int
	// MaxRequestBytes caps the raw size of the request. Default 4 MiB.
	MaxRequestBytes int
	// MaxWorkBytes caps the total size of decoded text processed across the
	// request, which bounds worst-case CPU. Default 32 MiB.
	MaxWorkBytes int
	// NestingSuspicious is the lookup nesting depth at which RuleLookupDepth
	// fires. Default 4.
	NestingSuspicious int
	// Disabled lists rules to switch off, for tuning false positives. Mandatory
	// (budget) rules ignore this.
	Disabled []RuleID
}

func (c Config) withDefaults() Config {
	c.Limits = c.Limits.withDefaults()
	if c.MaxFields <= 0 {
		c.MaxFields = 1024
	}
	if c.MaxRequestBytes <= 0 {
		c.MaxRequestBytes = 4 << 20
	}
	if c.MaxWorkBytes <= 0 {
		c.MaxWorkBytes = 32 << 20
	}
	if c.NestingSuspicious <= 0 {
		c.NestingSuspicious = 4
	}
	return c
}

// maxEvidence bounds the evidence kept per detection.
const maxEvidence = 96

// Detection is one finding in one place in the request.
type Detection struct {
	Rule     RuleID
	Severity Severity
	Location Location
	// Path lists the decoding steps that revealed the payload; empty when it was
	// present as sent.
	Path []Transform
	// Scheme is the JNDI URL scheme, when there is one.
	Scheme string
	// Evidence is a short, defanged excerpt. It is safe to log.
	Evidence string
	// KeyLookups lists environment-dependent lookups nested in a JNDI key.
	KeyLookups []string
}

// Verdict is the result of Inspect.
type Verdict struct {
	Decision   Decision
	Detections []Detection
	// Exhausted is the first resource budget hit anywhere, or BudgetNone. If it
	// is set, Decision is DecisionMalicious.
	Exhausted Budget
	// FieldsInspected counts the fields analyzed.
	FieldsInspected int
}

// Complete reports whether the request was analyzed within every budget.
func (v Verdict) Complete() bool { return v.Exhausted == BudgetNone }

// Has reports whether any detection was made by rule.
func (v Verdict) Has(rule RuleID) bool {
	for _, d := range v.Detections {
		if d.Rule == rule {
			return true
		}
	}
	return false
}

// Inspect analyzes a request for Log4Shell-class payloads.
//
// Every field is decoded into all its plausible variants, and each variant is
// run through the lookup resolver. The result is deterministic, bounded by cfg,
// and fail-closed: a request that cannot be analyzed within budget is malicious.
func Inspect(req Request, cfg Config) Verdict {
	cfg = cfg.withDefaults()
	in := &inspector{cfg: cfg, seen: make(map[string]struct{})}

	fields, b := extractFields(req, cfg)
	if b != BudgetNone {
		in.budget(RuleRequestBudget, Location{Part: "request"}, b)
		return in.finish()
	}

	work := 0
	for _, f := range fields {
		in.v.FieldsInspected++

		dec := Decode(f.text, cfg.Limits)
		if !dec.Complete() {
			in.budget(RuleDecodeBudget, f.loc, dec.Exhausted)
		}
		for _, st := range dec.Stages {
			work += len(st.Text)
			if work > cfg.MaxWorkBytes {
				in.budget(RuleRequestBudget, f.loc, BudgetWork)
				return in.finish()
			}
			res := Resolve(st.Text, cfg.Limits)
			if !res.Complete() {
				in.budget(RuleResolveBudget, f.loc, res.Exhausted)
			}
			in.evaluate(f.loc, st.Path, res)
		}
	}
	return in.finish()
}

type inspector struct {
	cfg  Config
	v    Verdict
	seen map[string]struct{}
}

// add records a detection unless its rule is disabled or it duplicates one
// already recorded for the same place and evidence. Stages are visited shortest
// decoding path first, so the first copy is the most direct one.
func (in *inspector) add(d Detection) {
	info, ok := ruleInfo(d.Rule)
	if !ok {
		return
	}
	if !info.Mandatory && slices.Contains(in.cfg.Disabled, d.Rule) {
		return
	}
	d.Severity = info.Severity
	key := string(d.Rule) + "|" + d.Location.String() + "|" + d.Evidence
	if _, dup := in.seen[key]; dup {
		return
	}
	in.seen[key] = struct{}{}
	in.v.Detections = append(in.v.Detections, d)
}

func (in *inspector) budget(rule RuleID, loc Location, b Budget) {
	if in.v.Exhausted == BudgetNone {
		in.v.Exhausted = b
	}
	in.add(Detection{Rule: rule, Location: loc, Evidence: b.String()})
}

func (in *inspector) finish() Verdict {
	in.v.Decision = DecisionClean
	for _, d := range in.v.Detections {
		switch d.Severity {
		case SeverityMalicious:
			in.v.Decision = DecisionMalicious
		case SeveritySuspicious:
			if in.v.Decision < DecisionSuspicious {
				in.v.Decision = DecisionSuspicious
			}
		}
	}
	return in.v
}

// evaluate turns one resolution into detections.
func (in *inspector) evaluate(loc Location, path []Transform, res Resolution) {
	path = slices.Clone(path)

	if res.MaxNesting >= in.cfg.NestingSuspicious {
		in.add(Detection{
			Rule: RuleLookupDepth, Location: loc, Path: path,
			Evidence: "depth=" + strconv.Itoa(res.MaxNesting),
		})
	}

	for _, f := range res.Findings {
		d := Detection{
			Location: loc, Path: path, Scheme: f.Scheme,
			Evidence:   Defang(f.Key, maxEvidence),
			KeyLookups: f.KeyLookups,
		}
		switch f.Kind {
		case FindingJNDI:
			d.Rule = RuleJNDI
			if f.Obfuscated || f.Expanded || f.Depth > 0 || len(path) > 0 || loc.Part == PartHeaderDecoded {
				d.Rule = RuleJNDIEvasive
			}
			in.add(d)

			if len(f.KeyLookups) > 0 {
				x := d
				x.Rule = RuleJNDIExfil
				in.add(x)
			}
			if hostBypass(f.Key) {
				x := d
				x.Rule = RuleJNDIHostBypass
				in.add(x)
			}
		case FindingPossibleJNDI:
			d.Rule = RuleJNDIPossible
			in.add(d)
		}
	}

	for _, l := range res.Lookups {
		if l.Prefix == "jndi" {
			continue // reported through Findings
		}
		if l.Known && IsLookupPrefix(l.Prefix) {
			in.add(Detection{Rule: RuleLookupSyntax, Location: loc, Path: path, Evidence: l.Prefix})
		}
		if l.Obfuscated {
			in.add(Detection{Rule: RuleLookupObfuscated, Location: loc, Path: path, Evidence: l.Prefix})
		}
	}
}

// hostBypass reports whether the JNDI key's authority uses '#' or '@', the
// tricks used against the host allow-list added in Log4j 2.15.0 (CVE-2021-45046).
func hostBypass(key string) bool {
	_, rest, ok := strings.Cut(key, "://")
	if !ok {
		return false
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	return strings.ContainsAny(rest, "#@")
}
