// Command labrun runs the LogShield lab: it sends the corpora to a canary that
// runs real vulnerable Log4j, compares what Log4j did with what the engine
// decides (and, optionally, with what a LogShield proxy lets through), and
// writes a report. See docs/lab.md.
//
// It sends attack payloads. Run it only against a canary on an isolated lab
// network, with the canary's JNDI hook on.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/TurlaFSB/logshield/internal/corpus"
	"github.com/TurlaFSB/logshield/internal/engine"
	"github.com/TurlaFSB/logshield/internal/lab"
	"github.com/TurlaFSB/logshield/internal/version"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("labrun", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		canary    = fs.String("canary", "127.0.0.1:8080", "canary host:port (real Log4j 2.14.1)")
		proxyAddr = fs.String("proxy", "", "LogShield host:port in ENFORCE mode; empty skips the proxy phase")
		blockCode = fs.Int("block-status", 403, "status LogShield uses for blocked requests")
		corpusDir = fs.String("corpus", "corpus", "corpus directory containing bypass/ and benign/")
		generated = fs.Int("generated", 0, "also run N generated benign requests (seed 20211209)")
		outDir    = fs.String("out", "lab-out", "directory for results.json and report.md")
		timeout   = fs.Duration("timeout", 10*time.Second, "per-request timeout")
		label     = fs.String("label", "", "free-text label stored in the report (for example the VM name)")
		showVer   = fs.Bool("version", false, "print version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVer {
		say(stdout, "labrun %s\n", version.Version)
		return 0
	}

	var entries []corpus.Entry
	for _, d := range []string{"bypass", "benign"} {
		es, err := corpus.Load(os.DirFS(*corpusDir), d)
		if err != nil {
			say(stderr, "labrun: load %s: %v\n", d, err)
			return 2
		}
		entries = append(entries, es...)
	}
	// Only the hand-written corpora must be inert: generated benign traffic is
	// plain requests, some of which name real sites, and is never validated.
	if probs := corpus.Validate(entries); len(probs) > 0 {
		say(stderr, "labrun: corpus invalid: %v\n", probs[0])
		return 2
	}
	if *generated > 0 {
		entries = append(entries, corpus.Generate(*generated, 20211209)...)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	results, err := lab.Run(ctx, entries, lab.Options{
		CanaryAddr: *canary, ProxyAddr: *proxyAddr, BlockCode: *blockCode,
		Timeout: *timeout, ReadyProbe: true,
	}, func(done, total int) {
		if done%250 == 0 || done == total {
			say(stderr, "labrun: %d/%d\n", done, total)
		}
	})
	if err != nil {
		say(stderr, "labrun: %v\n", err)
		return 2
	}
	sum := lab.Summarize(results)
	meta := map[string]string{
		"Label":    *label,
		"Version":  version.Version,
		"Canary":   *canary,
		"Proxy":    orNone(*proxyAddr),
		"Entries":  fmt.Sprint(len(entries)),
		"Duration": time.Since(start).Round(time.Millisecond).String(),
		"Engine":   fmt.Sprintf("%d rules", len(engine.Rules())),
	}
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		say(stderr, "labrun: %v\n", err)
		return 2
	}
	data, _ := json.MarshalIndent(struct {
		Meta    map[string]string `json:"meta"`
		Summary lab.Summary       `json:"summary"`
		Results []lab.Result      `json:"results"`
	}{meta, sum, results}, "", " ")
	md := lab.Markdown(results, sum, meta)
	for name, content := range map[string][]byte{"results.json": data, "report.md": []byte(md)} {
		if err := os.WriteFile(filepath.Join(*outDir, name), content, 0o600); err != nil {
			say(stderr, "labrun: %v\n", err)
			return 2
		}
	}
	say(stdout, "entries=%d triggered=%d caught=%d overblocked=%d problems=%v\n",
		sum.Total, sum.Triggered, sum.Caught, sum.OverBlocked, sum.ByProblem)
	if sum.Failed() {
		say(stdout, "FAIL\n")
		return 1
	}
	say(stdout, "PASS\n")
	return 0
}

// say writes a message; a failed write to a console has nowhere to be reported.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
