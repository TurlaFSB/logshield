// Command logshield is a virtual-patch reverse proxy for Log4Shell-class
// attacks. It sits in front of a server that cannot be patched, inspects each
// request, and blocks (or, in monitor mode, records) exploit attempts.
package main

import (
	"context"
	"crypto/tls"
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

	"github.com/TurlaFSB/logshield/internal/config"
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
	d := config.Defaults()
	var (
		showVersion = fs.Bool("version", false, "print version information and exit")
		configPath  = fs.String("config", "", "JSON configuration file (also $"+config.EnvConfigFile+"); flags and $LOGSHIELD_* override it")
		checkConfig = fs.Bool("check-config", false, "validate the configuration, print it, and exit")
		listen      = fs.String("listen", d.Listen, "address to listen on")
		upstream    = fs.String("upstream", "", "protected server as scheme://host[:port] (required)")
		mode        = fs.String("mode", d.Mode, "monitor (record only) or block")
		strict      = fs.Bool("block-suspicious", d.BlockSuspicious, "in block mode, also block suspicious requests")
		onError     = fs.String("on-error", d.OnError, "when inspection itself fails in block mode: closed or open")
		maxBody     = fs.Int64("max-body", d.MaxBodyBytes, "largest request body inspected, in bytes")
		forwarded   = fs.String("forwarded-for", d.ForwardedFor, "X-Forwarded-For handling: replace, append or off")
		rewriteHost = fs.Bool("rewrite-host", d.RewriteHost, "send the upstream's host in the Host header")
		adminListen = fs.String("admin-listen", d.AdminListen, "address for /metrics, /healthz and /readyz (disabled when empty; keep it off public interfaces)")
		maxInFlight = fs.Int("max-in-flight", d.MaxInFlight, "most requests handled at once, then 503 (-1 = no limit)")
		logLevel    = fs.String("log-level", d.LogLevel, "debug, info, warn or error")
		tlsCert     = fs.String("tls-cert", d.TLSCertFile, "PEM certificate chain: serve HTTPS (and HTTP/2) to clients; reloaded when the file changes")
		tlsKey      = fs.String("tls-key", d.TLSKeyFile, "PEM private key for -tls-cert")
		tlsMin      = fs.String("tls-min-version", d.TLSMinVersion, "lowest TLS version accepted from clients: 1.2 or 1.3")
		upstreamCA  = fs.String("upstream-ca", d.UpstreamCAFile, "PEM CA bundle to verify an https upstream (instead of the system roots)")
		upstreamSNI = fs.String("upstream-server-name", d.UpstreamServerName, "name to verify in the https upstream's certificate, for upstreams addressed by IP")
		readTimeout = fs.String("read-timeout", d.ReadTimeout, "longest a client may take to send a whole request (raise for large streamed uploads)")
		writeStall  = fs.String("client-write-timeout", d.ClientWriteTimeout, "longest a single write to a client may stall; 0s disables")
		drainDelay  = fs.String("drain-delay", d.DrainDelay, "keep serving this long after /readyz starts failing on shutdown")
		disable     listFlag
		skip        listFlag
	)
	fs.Var(&skip, "skip-body-type", "media type or prefix such as image/ whose body is streamed uninspected (repeatable)")
	fs.Var(&disable, "disable-rule", "rule ID to switch off, for tuning false positives (repeatable)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.String())
		return 0
	}

	// Precedence, lowest to highest: built-in defaults, file, environment, flags.
	settings := config.Defaults()
	path := *configPath
	if path == "" {
		path = os.Getenv(config.EnvConfigFile)
	}
	if path != "" {
		if err := settings.LoadFile(path); err != nil {
			_, _ = fmt.Fprintf(stderr, "logshield: configuration file: %v\n", err)
			return 2
		}
	}
	unknown, err := settings.ApplyEnv(os.Environ())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: environment: %v\n", err)
		return 2
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			settings.Listen = *listen
		case "upstream":
			settings.Upstream = *upstream
		case "mode":
			settings.Mode = *mode
		case "block-suspicious":
			settings.BlockSuspicious = *strict
		case "on-error":
			settings.OnError = *onError
		case "max-body":
			settings.MaxBodyBytes = *maxBody
		case "forwarded-for":
			settings.ForwardedFor = *forwarded
		case "rewrite-host":
			settings.RewriteHost = *rewriteHost
		case "admin-listen":
			settings.AdminListen = *adminListen
		case "max-in-flight":
			settings.MaxInFlight = *maxInFlight
		case "log-level":
			settings.LogLevel = *logLevel
		case "read-timeout":
			settings.ReadTimeout = *readTimeout
		case "client-write-timeout":
			settings.ClientWriteTimeout = *writeStall
		case "drain-delay":
			settings.DrainDelay = *drainDelay
		case "tls-cert":
			settings.TLSCertFile = *tlsCert
		case "tls-key":
			settings.TLSKeyFile = *tlsKey
		case "tls-min-version":
			settings.TLSMinVersion = *tlsMin
		case "upstream-ca":
			settings.UpstreamCAFile = *upstreamCA
		case "upstream-server-name":
			settings.UpstreamServerName = *upstreamSNI
		case "skip-body-type":
			settings.SkipBodyTypes = skip
		case "disable-rule":
			settings.DisabledRules = disable
		}
	})

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: settings.Level()}))
	for _, name := range unknown {
		logger.Warn("ignoring unrecognized environment variable (typo?)", "name", name)
	}
	cfg, err := settings.ProxyConfig(logger)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: invalid configuration:\n%v\n", err)
		return 2
	}
	var tlsCfg *tls.Config
	if settings.TLSCertFile != "" {
		tc, _ := settings.TLSConfig() // validated by ProxyConfig
		if tlsCfg, err = proxy.NewServerTLS(tc, logger); err != nil {
			_, _ = fmt.Fprintf(stderr, "logshield: invalid configuration:\n%v\n", err)
			return 2
		}
	}
	if *checkConfig {
		_, _ = fmt.Fprintf(stdout, "configuration OK\n%s\n", settings.Redacted())
		return 0
	}
	target := cfg.Upstream
	var (
		metrics *telemetry.Metrics
		admin   *telemetry.Admin
	)
	if settings.AdminListen != "" {
		metrics = telemetry.New(version.String())
		cfg.Observer = metrics
	}
	p, err := proxy.New(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: invalid configuration:\n%v\n", err)
		return 2
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", settings.Listen)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "logshield: %v\n", err)
		return 1
	}
	var adminLn net.Listener
	if metrics != nil {
		metrics.SetInFlight(p.InFlight)
		admin = telemetry.NewAdmin(telemetry.AdminConfig{Metrics: metrics, Upstream: upstreamAddr(target)})
		if adminLn, err = lc.Listen(ctx, "tcp", settings.AdminListen); err != nil {
			_ = ln.Close()
			_, _ = fmt.Fprintf(stderr, "logshield: admin listener: %v\n", err)
			return 1
		}
	}
	timeouts, _ := settings.Timeouts() // validated by ProxyConfig
	srv := proxy.NewServer(settings.Listen, p, proxy.ServerConfig{ReadTimeout: timeouts.Read}, logger)
	if tlsCfg != nil {
		// HTTP/2 needs the *tls.Conn the server sees, so the listener cannot also
		// be wrapped to observe protocol errors (documented limitation).
		srv.TLSConfig = tlsCfg
		ln = tls.NewListener(ln, tlsCfg)
	} else {
		ln = p.WrapListener(ln) // also observe requests the HTTP server refuses before the proxy sees them
	}

	// Credentials in the upstream URL are rejected by validation, so the address
	// is safe to log.
	logger.Info("listening", "addr", ln.Addr().String(), "upstream", target.Redacted(),
		"mode", settings.Mode, "tls", tlsCfg != nil, "version", version.String())
	if settings.Mode == string(proxy.ModeMonitor) {
		logger.Info("monitor mode: requests are recorded but never blocked; use -mode block to enforce")
	}
	if ready != nil {
		ready(ln.Addr().String())
	}

	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(ln) }()
	var adminSrv *http.Server
	if adminLn != nil {
		adminSrv = telemetry.NewAdminServer(settings.AdminListen, admin.Handler())
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
		if timeouts.Drain > 0 {
			logger.Info("draining", "delay", timeouts.Drain.String())
			time.Sleep(timeouts.Drain)
		}
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
