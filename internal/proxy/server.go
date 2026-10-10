package proxy

import (
	"log/slog"
	"net/http"
	"time"
)

// ServerConfig bounds how long and how large a client request may be. The
// zero value selects defaults that suit a proxy in front of a web application.
type ServerConfig struct {
	// ReadHeaderTimeout limits the time to receive request headers. Default 10s.
	ReadHeaderTimeout time.Duration
	// ReadTimeout limits the time to receive the whole request. Default 30s.
	ReadTimeout time.Duration
	// WriteTimeout limits the time to send the response. Default 0 (none), so
	// long downloads work; set it if the upstream is not trusted to finish.
	WriteTimeout time.Duration
	// IdleTimeout limits keep-alive idleness. Default 90s.
	IdleTimeout time.Duration
	// MaxHeaderBytes limits request header size. Default 64 KiB.
	MaxHeaderBytes int
}

// NewServer returns an http.Server for handler with explicit limits. Go's
// defaults leave several of these unbounded, which makes slow-client attacks
// trivial.
func NewServer(addr string, handler http.Handler, c ServerConfig, logger *slog.Logger) *http.Server {
	if c.ReadHeaderTimeout == 0 {
		c.ReadHeaderTimeout = 10 * time.Second
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 30 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 90 * time.Second
	}
	if c.MaxHeaderBytes == 0 {
		c.MaxHeaderBytes = 64 << 10
	}
	if logger == nil {
		logger = slog.Default()
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: c.ReadHeaderTimeout,
		ReadTimeout:       c.ReadTimeout,
		WriteTimeout:      c.WriteTimeout,
		IdleTimeout:       c.IdleTimeout,
		MaxHeaderBytes:    c.MaxHeaderBytes,
		// The server's own error lines can quote request data, so they go through
		// the same neutralizing handler as everything else.
		ErrorLog: slog.NewLogLogger(newSafeLogger(logger).Handler(), slog.LevelWarn),
		// HTTP/2 (used when TLS is on): bound concurrent streams per connection.
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 100},
	}
	return srv
}
