package proxy

import (
	"os"
	"regexp"
	"testing"
)

// TestLogFieldsAreDocumented keeps the log-event table in docs/observability.md
// complete. Log field names are part of the public surface protected by the
// version number (docs/releasing.md), and SIEM rules depend on them, so a new or
// renamed field must be documented in the same change.
func TestLogFieldsAreDocumented(t *testing.T) {
	src, err := os.ReadFile("respond.go")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../docs/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	for _, m := range regexp.MustCompile(`slog\.\w+\("([a-z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		fields[m[1]] = true
	}
	for _, m := range regexp.MustCompile("json:\"([a-z_]+)").FindAllStringSubmatch(string(src), -1) {
		fields[m[1]] = true
	}
	if len(fields) < 20 {
		t.Fatalf("found only %d log fields in respond.go; the scan is broken", len(fields))
	}
	for f := range fields {
		if !regexp.MustCompile("`" + f + "`").Match(doc) {
			t.Errorf("log field %q is not documented in docs/observability.md", f)
		}
	}
}
