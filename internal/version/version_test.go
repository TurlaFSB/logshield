package version

import (
	"strings"
	"testing"
)

func TestStringDefaults(t *testing.T) {
	got := String()
	want := "logshield dev (commit none, built unknown)"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestStringReflectsOverrides(t *testing.T) {
	oldV, oldC, oldD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = oldV, oldC, oldD })

	Version, Commit, Date = "v1.2.3", "abc1234", "2026-10-10T00:00:00Z"
	got := String()
	for _, part := range []string{"v1.2.3", "abc1234", "2026-10-10T00:00:00Z"} {
		if !strings.Contains(got, part) {
			t.Errorf("String() = %q, missing %q", got, part)
		}
	}
}
