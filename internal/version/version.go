// Package version carries build metadata injected at link time, with a
// fallback to the module and VCS information the Go toolchain embeds.
package version

import (
	"fmt"
	"runtime/debug"
)

// These are overridden via -ldflags "-X" at build time (see the Makefile and
// the release workflow). The defaults identify an untagged local build; Info
// fills them from the embedded build information when they were not set.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// fill replaces unset defaults using build information. It is separate from
// String so tests can feed it synthetic data.
func fill(v, c, d string, bi *debug.BuildInfo) (string, string, string) {
	if bi == nil {
		return v, c, d
	}
	if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		v = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if c == "none" && s.Value != "" {
				c = s.Value
				if len(c) > 12 {
					c = c[:12]
				}
			}
		case "vcs.time":
			if d == "unknown" && s.Value != "" {
				d = s.Value
			}
		}
	}
	return v, c, d
}

// String returns a single-line, human-readable build description.
func String() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	v, c, d := fill(Version, Commit, Date, bi)
	return fmt.Sprintf("logshield %s (commit %s, built %s)", v, c, d)
}
