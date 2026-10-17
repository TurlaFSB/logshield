package version

import (
	"runtime/debug"
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

func TestFillFromBuildInfo(t *testing.T) {
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.4.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"},
			{Key: "vcs.time", Value: "2026-10-17T00:00:00Z"},
		},
	}
	v, c, d := fill("dev", "none", "unknown", bi)
	if v != "v1.4.0" || c != "0123456789ab" || d != "2026-10-17T00:00:00Z" {
		t.Fatalf("fill = %q %q %q", v, c, d)
	}
	// Explicit ldflags values win over build information.
	v, c, d = fill("v9", "abc", "today", bi)
	if v != "v9" || c != "abc" || d != "today" {
		t.Fatalf("ldflags overridden: %q %q %q", v, c, d)
	}
	// A (devel) module version and a nil BuildInfo leave the defaults alone.
	bi.Main.Version = "(devel)"
	if v, _, _ := fill("dev", "none", "unknown", bi); v != "dev" {
		t.Fatalf("(devel) leaked: %q", v)
	}
	if v, c, d := fill("dev", "none", "unknown", nil); v != "dev" || c != "none" || d != "unknown" {
		t.Fatal("nil BuildInfo changed defaults")
	}
}
