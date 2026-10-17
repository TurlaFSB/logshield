package telemetry

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
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

// TestGrafanaDashboardUsesRealMetrics keeps the example dashboard in step with
// the metrics. A renamed or removed metric would otherwise leave an empty panel
// that nobody notices until an incident.
func TestGrafanaDashboardUsesRealMetrics(t *testing.T) {
	raw, err := os.ReadFile("../../examples/grafana/logshield-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var dash struct {
		Title  string `json:"title"`
		UID    string `json:"uid"`
		Panels []struct {
			ID      int    `json:"id"`
			Type    string `json:"type"`
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	if dash.Title == "" || dash.UID == "" || len(dash.Panels) == 0 {
		t.Fatalf("dashboard lacks a title, uid or panels: %+v", dash)
	}

	var out bytes.Buffer
	if _, err := New("test").WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	exposed := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (logshield_\w+) `).FindAllStringSubmatch(out.String(), -1) {
		exposed[m[1]] = true
	}

	ids := map[int]bool{}
	used := map[string]bool{}
	for _, p := range dash.Panels {
		if ids[p.ID] {
			t.Errorf("panel id %d is used twice", p.ID)
		}
		ids[p.ID] = true
		for _, tg := range p.Targets {
			for _, name := range regexp.MustCompile(`logshield_\w+`).FindAllString(tg.Expr, -1) {
				base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
				used[base] = true
				if !exposed[base] {
					t.Errorf("panel %q queries %s, which /metrics does not expose", p.Title, name)
				}
			}
		}
	}
	if len(used) == 0 {
		t.Fatal("the dashboard queries no LogShield metrics")
	}
}
