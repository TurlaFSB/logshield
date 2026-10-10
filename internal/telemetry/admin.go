package telemetry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// AdminConfig configures the admin handler.
type AdminConfig struct {
	// Metrics is served at /metrics. Required.
	Metrics *Metrics
	// Upstream is the address (host:port) readiness probes with a TCP dial.
	// Empty disables the upstream check.
	Upstream string
	// DialTimeout bounds the readiness dial. Default 1s.
	DialTimeout time.Duration
	// CacheFor is how long a readiness result is reused, so probes cannot be
	// turned into a dial flood. Default 2s.
	CacheFor time.Duration
}

// Admin serves /metrics, /healthz and /readyz. It is meant for a separate,
// non-public listener: it exposes nothing a client could reach through the
// proxy port.
type Admin struct {
	cfg      AdminConfig
	draining chan struct{}
	once     sync.Once

	mu      sync.Mutex
	checked time.Time
	lastErr error
}

// NewAdmin returns an Admin.
func NewAdmin(cfg AdminConfig) *Admin {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = time.Second
	}
	if cfg.CacheFor == 0 {
		cfg.CacheFor = 2 * time.Second
	}
	return &Admin{cfg: cfg, draining: make(chan struct{})}
}

// Drain marks the process as shutting down: /readyz starts failing so a load
// balancer stops sending traffic while in-flight requests finish.
func (a *Admin) Drain() { a.once.Do(func() { close(a.draining) }) }

var errDraining = errors.New("shutting down")

func (a *Admin) ready(ctx context.Context) error {
	select {
	case <-a.draining:
		return errDraining
	default:
	}
	if a.cfg.Upstream == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.checked.IsZero() && time.Since(a.checked) < a.cfg.CacheFor {
		return a.lastErr
	}
	d := net.Dialer{Timeout: a.cfg.DialTimeout}
	c, err := d.DialContext(ctx, "tcp", a.cfg.Upstream)
	if err == nil {
		_ = c.Close()
	}
	a.checked, a.lastErr = time.Now(), err
	return err
}

// Handler returns the admin routes. Only GET and HEAD are allowed.
func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		text(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// The error text is not returned: it could name internal addresses.
		if err := a.ready(r.Context()); err != nil {
			text(w, http.StatusServiceUnavailable, "not ready\n")
			return
		}
		text(w, http.StatusOK, "ready\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = a.cfg.Metrics.WriteTo(w)
	})
	return methodGuard(mux)
}

func methodGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			text(w, http.StatusMethodNotAllowed, "method not allowed\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func text(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// NewAdminServer returns a hardened http.Server for the admin handler.
func NewAdminServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}
