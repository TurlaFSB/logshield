// Command logshield is a virtual-patch reverse proxy for Log4Shell-class
// attacks. The proxy itself lands in Step 2; this entry point currently only
// reports build information.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/TurlaFSB/logshield/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is separated from main so it can be tested without exiting the process.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("logshield", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.String())
		return 0
	}

	_, _ = fmt.Fprintln(stderr, "logshield: the proxy is not implemented yet (pre-alpha); see docs/ROADMAP.md")
	return 1
}
