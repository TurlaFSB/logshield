// Package version carries build metadata injected at link time.
package version

import "fmt"

// These are overridden via -ldflags "-X" at build time (see the Makefile and
// the release workflow). The defaults identify an untagged local build.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a single-line, human-readable build description.
func String() string {
	return fmt.Sprintf("logshield %s (commit %s, built %s)", Version, Commit, Date)
}
