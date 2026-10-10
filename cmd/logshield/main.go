// Command logshield is a virtual-patch reverse proxy for Log4Shell-class
// attacks. It sits in front of a server that cannot be patched, inspects each
// request, and blocks (or, in monitor mode, records) exploit attempts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TurlaFSB/logshield/internal/proxy"
	"github.com/TurlaFSB/logshield/internal/telemetry"
	"github.com/TurlaFSB/logshield/internal/version"
)

func main() {
	os.Exit(realMain())
}

// realMain exists so deferred cleanup runs before the process exits.
func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil)
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

const shutdownTimeout = 15 * time.Second

// run is separated from main so it can be tested without exiting the process.
// ready, if not nil, is called with the listening address once the proxy is
// accepting connections.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, ready func(addr string)) int {
	fs := flag.NewFlagSet("logshield", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		showVersion = fs.Bool("version", false, "print version information and exit")
		listen      = fs.String("listen", "127.0.0.1:8080", "address to listen on")
		upstream    = fs.String("upstream", "", "protected server as scheme://host[:port] (required)")
		mode        = fs.String("mode", "monitor", "monitor (record only) or block")
		strict      = fs.Bool("block-suspicious", false, "in block mode, also block suspicious requests")
		onError     = fs.String("on-error", "closed", "when inspection itself fails in block mode: closed or open")
		maxBody     = fs.Int64("max-body", 1<<20, "largest request body inspected, in bytes")
		forwarded   = fs.String("forwarded-for", "replace", "X-Forwarded-For handling: replace, append or off")
		rewriteHost = fs.Bool("rewrite-host", false, "send the upstream's host in the Host header")
		adminListen = fs.String("admin-listen", "", "address for /metrics, /healthz and /readyz (disabled when empty; keep it off public interfaces)")
		maxInFlight = fs.Int("max-in-flight", 0, "most requests handled at once, then 503 (0 = 1024, -1 = no limit)")
		logLevel    = fs.String("log-level", "info", "debug, info, warn or error")
		skip        listFlag
	)
	fs.Var(&skip, "skip-body-type", "media type or prefix such as image/ whose body is streamed uninspected (repeatable)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.String())
		return 0
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: invalid -log-level %q\n", *logLevel)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))

	if *upstream == "" {
		_, _ = fmt.Fprintln(stderr, "logshield: -upstream is required")
		return 2
	}
	target, err := url.Parse(*upstream)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: invalid -upstream: %v\n", err)
		return 2
	}
	cfg := proxy.Config{
		Upstream:        target,
		Mode:            proxy.Mode(*mode),
		BlockSuspicious: *strict,
		OnError:         proxy.FailPolicy(*onError),
		MaxBodyBytes:    *maxBody,
		SkipBodyTypes:   skip,
		ForwardedFor:    proxy.ForwardedFor(*forwarded),
		RewriteHost:     *rewriteHost,
		MaxInFlight:     *maxInFlight,
		Logger:          logger,
	}
	var (
		metrics *telemetry.Metrics
		admin   *telemetry.Admin
	)
	if *adminListen != "" {
		metrics = telemetry.New(version.String())
		cfg.Observer = metrics
	}
	p, err := proxy.New(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: invalid configuration:\n%v\n", err)
		return 2
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: %v\n", err)
		return 1
	}
	var adminLn net.Listener
	if metrics != nil {
		metrics.SetInFlight(p.InFlight)
		admin = telemetry.NewAdmin(telemetry.AdminConfig{Metrics: metrics, Upstream: upstreamAddr(target)})
		if adminLn, err = lc.Listen(ctx, "tcp", *adminListen); err != nil {
			_ = ln.Close()
			_, _ = fmt.Fprintf(stderr, "logshield: admin listener: %v\n", err)
			return 1
		}
	}
	ln = p.WrapListener(ln) // also observe requests the HTTP server refuses before the proxy sees them
	srv := proxy.NewServer(*listen, p, proxy.ServerConfig{}, logger)

	// Credentials in the upstream URL are rejected by validation, so the address
	// is safe to log.
	logger.Info("listening", "addr", ln.Addr().String(), "upstream", target.Redacted(),
		"mode", *mode, "version", version.String())
	if *mode == string(proxy.ModeMonitor) {
		logger.Info("monitor mode: requests are recorded but never blocked; use -mode block to enforce")
	}
	if ready != nil {
		ready(ln.Addr().String())
	}

	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(ln) }()
	var adminSrv *http.Server
	if adminLn != nil {
		adminSrv = telemetry.NewAdminServer(*adminListen, admin.Handler())
		logger.Info("admin endpoints", "addr", adminLn.Addr().String(), "paths", "/metrics /healthz /readyz")
		go func() { errc <- adminSrv.Serve(adminLn) }()
	}
	select {
	case err := <-errc:
		_, _ = fmt.Fprintf(stderr, "logshield: %v\n", err)
		return 1
	case <-ctx.Done():
	}
	if admin != nil {
		admin.Drain() // readiness fails first, so load balancers stop sending traffic
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if adminSrv != nil {
		defer func() { _ = adminSrv.Shutdown(sctx) }()
	}
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_, _ = fmt.Fprintf(stderr, "logshield: shutdown: %v\n", err)
		return 1
	}
	logger.Info("stopped")
	return 0
}

// upstreamAddr returns host:port for a TCP readiness probe of the upstream.
func upstreamAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
