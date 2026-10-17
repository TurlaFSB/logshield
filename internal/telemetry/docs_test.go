package telemetry

import (
	"bytes"
	"os"
	"regexp"
	"testing"
)

// TestMetricsMatchDocumentation keeps the metrics table in
// docs/observability.md equal to what /metrics really exposes. Metric names and
// types are part of the public surface protected by the version number (see
// docs/releasing.md), so adding, renaming or retyping one must be a deliberate,
// documented change.
func TestMetricsMatchDocumentation(t *testing.T) {
	var out bytes.Buffer
	if _, err := New("test").WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	exposed := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (logshield_\w+) (\w+)$`).FindAllStringSubmatch(out.String(), -1) {
		exposed[m[1]] = m[2]
	}
	if len(exposed) == 0 {
		t.Fatal("no metrics found in the exposition output")
	}

	raw, err := os.ReadFile("../../docs/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]string{}
	for _, m := range regexp.MustCompile("(?m)^\\| `(logshield_\\w+)` \\| (\\w+) \\|").FindAllStringSubmatch(string(raw), -1) {
		documented[m[1]] = m[2]
	}

	for name, typ := range exposed {
		got, ok := documented[name]
		switch {
		case !ok:
			t.Errorf("metric %s is exposed but not documented in docs/observability.md", name)
		case got != typ:
			t.Errorf("metric %s is a %s but documented as a %s", name, typ, got)
		}
	}
	for name := range documented {
		if _, ok := exposed[name]; !ok {
			t.Errorf("metric %s is documented but not exposed", name)
		}
	}
}
