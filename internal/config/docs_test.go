package config

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// readDoc reads a documentation file relative to the repository root.
func readDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("../../" + rel)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEveryConfigKeyIsDocumented fails when a JSON key is added to Settings
// without being described in docs/configuration.md.
func TestEveryConfigKeyIsDocumented(t *testing.T) {
	doc := readDoc(t, "docs/configuration.md")
	typ := reflect.TypeOf(Settings{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		if !strings.Contains(doc, "`"+tag+"`") {
			t.Errorf("config key %q is not documented in docs/configuration.md", tag)
		}
	}
}

// TestEveryRuleIsDocumented fails when a rule is added to the catalogue
// without a row in docs/engine/rules.md, and when the doc lists a rule the
// engine does not have.
func TestEveryRuleIsDocumented(t *testing.T) {
	doc := readDoc(t, "docs/engine/rules.md")
	have := map[string]bool{}
	for _, r := range engine.Rules() {
		id := string(r.ID)
		have[id] = true
		if !strings.Contains(doc, "| "+id+" | "+r.Name+" |") {
			t.Errorf("rule %s (%s) missing from docs/engine/rules.md", id, r.Name)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| LSH-") {
			id := strings.TrimSpace(strings.Split(line, "|")[1])
			if !have[id] {
				t.Errorf("docs/engine/rules.md lists %s, which the engine does not have", id)
			}
		}
	}
}

var (
	mdLink    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	mdHeading = regexp.MustCompile(`(?m)^#{1,6}\s+(.+?)\s*$`)
	slugDrop  = regexp.MustCompile(`[^\p{L}\p{N} _-]`)
)

// slug approximates GitHub's heading anchors: lower case, punctuation removed,
// spaces become hyphens.
func slug(h string) string {
	h = strings.ReplaceAll(h, "`", "")
	h = slugDrop.ReplaceAllString(strings.ToLower(strings.TrimSpace(h)), "")
	return strings.ReplaceAll(h, " ", "-")
}

// TestMarkdownLinksResolve fails on a relative link, or heading anchor, in any
// Markdown file that points at nothing.
func TestMarkdownLinksResolve(t *testing.T) {
	root := "../.."
	anchors := map[string]map[string]bool{}
	headings := func(path string) map[string]bool {
		if a, ok := anchors[path]; ok {
			return a
		}
		a := map[string]bool{}
		if b, err := os.ReadFile(path); err == nil {
			for _, m := range mdHeading.FindAllStringSubmatch(string(b), -1) {
				a[slug(m[1])] = true
			}
		}
		anchors[path] = a
		return a
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Links inside fenced code blocks are examples, not links.
		var text strings.Builder
		fenced := false
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				fenced = !fenced
				continue
			}
			if !fenced {
				text.WriteString(line + "\n")
			}
		}
		for _, m := range mdLink.FindAllStringSubmatch(text.String(), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			file, frag, _ := strings.Cut(target, "#")
			dest := path
			if file != "" {
				dest = filepath.Join(filepath.Dir(path), file)
				if _, err := os.Stat(dest); err != nil {
					t.Errorf("%s: link %q: target does not exist", path, target)
					continue
				}
			}
			if frag != "" && strings.HasSuffix(dest, ".md") && !headings(dest)[frag] {
				t.Errorf("%s: link %q: no heading %q in %s", path, target, frag, dest)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
