// Package corpus loads and evaluates the LogShield test corpora.
//
// The corpora are JSON Lines files under corpus/. Each line is one Entry: a
// request, the verdict the engine must reach, and where the case came from.
// Bypass entries are attacks (or near-attacks) that must be caught; benign
// entries are legitimate traffic, including look-alikes, that must not be
// blocked. Together they give the project's measured miss and false-positive
// rates (see docs/eval/report.md).
//
// All payloads are inert: they may only point at reserved names.
package corpus

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Source types, from most to least independent.
const (
	// SourcePublic is a payload quoted from a public source, with hosts replaced
	// by reserved names.
	SourcePublic = "public-sample"
	// SourceDerived is constructed to exercise a technique that a public source
	// documents, without being quoted from it.
	SourceDerived = "derived"
	// SourceProject is written by this project: regression cases and look-alikes.
	SourceProject = "project"
)

// Source records the provenance of an entry.
type Source struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
	URL  string `json:"url,omitempty"`
}

// Request is a serialized engine.Request.
type Request struct {
	Method  string      `json:"method"`
	Target  string      `json:"target"`
	Headers [][2]string `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
	// BodyB64 carries bodies that are not valid text. Mutually exclusive with Body.
	BodyB64 string `json:"body_b64,omitempty"`
}

// Expect is the verdict an entry requires.
type Expect struct {
	Decision string `json:"decision"`
	// Rules must all have fired.
	Rules []string `json:"rules,omitempty"`
	// Forbid must not have fired.
	Forbid []string `json:"forbid,omitempty"`
}

// Entry is one corpus case.
type Entry struct {
	ID      string   `json:"id"`
	Class   string   `json:"class"`
	Source  Source   `json:"source"`
	CVEs    []string `json:"cves,omitempty"`
	Request Request  `json:"request"`
	Expect  Expect   `json:"expect"`
	Note    string   `json:"note,omitempty"`

	// Set by Load.
	Dataset string `json:"-"`
}

// EngineRequest converts the entry's request for the engine.
func (e Entry) EngineRequest() (engine.Request, error) {
	r := engine.Request{Method: e.Request.Method, Target: e.Request.Target}
	for _, h := range e.Request.Headers {
		r.Headers = append(r.Headers, engine.Header{Name: h[0], Value: h[1]})
	}
	switch {
	case e.Request.Body != "" && e.Request.BodyB64 != "":
		return r, fmt.Errorf("body and body_b64 are mutually exclusive")
	case e.Request.BodyB64 != "":
		b, err := base64.StdEncoding.DecodeString(e.Request.BodyB64)
		if err != nil {
			return r, fmt.Errorf("body_b64: %w", err)
		}
		r.Body = b
	default:
		r.Body = []byte(e.Request.Body)
	}
	return r, nil
}

// Load reads every *.jsonl file in dir (non-recursively). The dataset name of
// each entry is the directory's base name. It validates the corpus and returns
// an error describing every problem found.
func Load(fsys fs.FS, dir string) ([]Entry, error) {
	files, err := fs.Glob(fsys, path.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.jsonl files in %s", dir)
	}
	slices.Sort(files)

	var (
		entries []Entry
		problem []string
	)
	for _, name := range files {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
		for n := 1; sc.Scan(); n++ {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var e Entry
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&e); err != nil {
				problem = append(problem, fmt.Sprintf("%s:%d: %v", name, n, err))
				continue
			}
			e.Dataset = path.Base(dir)
			entries = append(entries, e)
		}
		if err := sc.Err(); err != nil {
			problem = append(problem, fmt.Sprintf("%s: %v", name, err))
		}
	}
	problem = append(problem, Validate(entries)...)
	if len(problem) > 0 {
		return entries, fmt.Errorf("corpus %s has %d problem(s):\n  %s", dir, len(problem), strings.Join(problem, "\n  "))
	}
	return entries, nil
}

var (
	idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	// urlHost finds scheme://host in raw text, for the inertness check.
	urlHost = regexp.MustCompile(`(?i)[a-z][a-z0-9+.\-]*://([^/\s:?#\\}$%]*)`)
)

// Validate checks entries for structure, provenance and inertness.
func Validate(entries []Entry) []string {
	var out []string
	ids := make(map[string]bool, len(entries))
	known := make(map[string]bool)
	for _, r := range engine.Rules() {
		known[string(r.ID)] = true
	}
	for _, e := range entries {
		bad := func(format string, args ...any) {
			out = append(out, fmt.Sprintf("%s: %s", e.ID, fmt.Sprintf(format, args...)))
		}
		switch {
		case !idPattern.MatchString(e.ID):
			bad("id must be lower-case words joined by '-'")
		case ids[e.ID]:
			bad("duplicate id")
		}
		ids[e.ID] = true
		if e.Class == "" {
			bad("missing class")
		}
		switch e.Source.Type {
		case SourcePublic:
			if e.Source.Ref == "" || !strings.HasPrefix(e.Source.URL, "https://") {
				bad("public-sample needs ref and an https url")
			}
		case SourceDerived:
			if e.Source.Ref == "" {
				bad("derived needs ref naming the technique and its documentation")
			}
		case SourceProject:
		default:
			bad("unknown source type %q", e.Source.Type)
		}
		switch e.Expect.Decision {
		case "clean", "suspicious", "malicious":
		default:
			bad("unknown expected decision %q", e.Expect.Decision)
		}
		for _, id := range append(slices.Clone(e.Expect.Rules), e.Expect.Forbid...) {
			if !known[id] {
				bad("unknown rule %q", id)
			}
		}
		r, err := e.EngineRequest()
		if err != nil {
			bad("%v", err)
			continue
		}
		if e.Request.Method == "" || e.Request.Target == "" {
			bad("request needs method and target")
		}
		for _, text := range rawTexts(r) {
			for _, m := range urlHost.FindAllStringSubmatch(text, -1) {
				if h := m[1]; h != "" && !inertHost(h) {
					bad("non-reserved host %q (payloads must be inert)", h)
				}
			}
		}
	}
	return out
}

func rawTexts(r engine.Request) []string {
	out := []string{r.Target, string(r.Body)}
	for _, h := range r.Headers {
		out = append(out, h.Name, h.Value)
	}
	return out
}

// inertHost reports whether h is a reserved name (RFC 2606, 6761, 5737) or a
// loopback address.
func inertHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.IndexByte(h, '#'); i >= 0 {
		h = h[:i]
	}
	for _, suffix := range []string{".invalid", ".example", ".test", ".localhost", "example.com", "example.net", "example.org"} {
		if h == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(h, suffix) {
			return true
		}
	}
	for _, prefix := range []string{"192.0.2.", "198.51.100.", "203.0.113.", "127."} {
		if strings.HasPrefix(h, prefix) {
			return true
		}
	}
	return h == "localhost" || h == "::1" || h == "[::1]"
}
