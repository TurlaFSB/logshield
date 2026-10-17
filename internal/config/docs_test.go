package config

import (
	"os"
	"reflect"
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
