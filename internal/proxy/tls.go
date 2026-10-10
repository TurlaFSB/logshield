package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// TLSConfig configures TLS termination for clients.
type TLSConfig struct {
	// CertFile and KeyFile are PEM files. The certificate chain goes in CertFile.
	// Both are re-read when their modification time changes (checked at most
	// every ReloadEvery), so certificate rotation needs no restart.
	CertFile, KeyFile string
	// MinVersion is tls.VersionTLS12 (default) or tls.VersionTLS13.
	MinVersion uint16
	// ReloadEvery bounds how often the files are stat'ed. Default 10s.
	ReloadEvery time.Duration
}

// Validate reports configuration mistakes.
func (c TLSConfig) Validate() error {
	var errs []error
	if (c.CertFile == "") != (c.KeyFile == "") {
		errs = append(errs, errors.New("tls certificate and key must be set together"))
	}
	switch c.MinVersion {
	case 0, tls.VersionTLS12, tls.VersionTLS13:
	default:
		errs = append(errs, fmt.Errorf("unsupported minimum TLS version %#x (want 1.2 or 1.3)", c.MinVersion))
	}
	return errors.Join(errs...)
}

// ParseTLSVersion maps "1.2" and "1.3" (or "") to a tls version constant.
func ParseTLSVersion(s string) (uint16, error) {
	switch s {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unsupported TLS version %q (want 1.2 or 1.3)", s)
}

// NewServerTLS returns a *tls.Config that serves HTTP/2 and HTTP/1.1 with a
// certificate that is reloaded from disk when it changes. The initial load must
// succeed, so a bad path fails at startup instead of on the first connection.
func NewServerTLS(c TLSConfig, logger *slog.Logger) (*tls.Config, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.CertFile == "" {
		return nil, errors.New("tls certificate and key are required")
	}
	if c.MinVersion == 0 {
		c.MinVersion = tls.VersionTLS12
	}
	if c.ReloadEvery == 0 {
		c.ReloadEvery = 10 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	r := &certReloader{cfg: c, log: logger}
	if err := r.load(); err != nil {
		return nil, err
	}
	return &tls.Config{ //nolint:gosec // MinVersion was validated above: only TLS 1.2 or 1.3 gets here
		MinVersion:     c.MinVersion,
		GetCertificate: r.get,
		NextProtos:     []string{"h2", "http/1.1"},
	}, nil
}

type certReloader struct {
	cfg TLSConfig
	log *slog.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	lastStat time.Time
}

func (r *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("loading tls certificate: %w", err)
	}
	r.cert = &cert
	r.certMod, r.keyMod = modTime(r.cfg.CertFile), modTime(r.cfg.KeyFile)
	r.lastStat = time.Now()
	return nil
}

func modTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastStat) >= r.cfg.ReloadEvery {
		r.lastStat = time.Now()
		if cm, km := modTime(r.cfg.CertFile), modTime(r.cfg.KeyFile); !cm.Equal(r.certMod) || !km.Equal(r.keyMod) {
			if cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile); err != nil {
				// A half-written rotation must not take TLS down: keep serving the
				// previous certificate and say so. It is retried when the files change again.
				r.log.Error("tls certificate reload failed; keeping the previous certificate", "error", err.Error())
				r.certMod, r.keyMod = cm, km
			} else {
				r.cert, r.certMod, r.keyMod = &cert, cm, km
				r.log.Info("tls certificate reloaded")
			}
		}
	}
	return r.cert, nil
}

// UpstreamTLS configures how the proxy verifies an https upstream.
type UpstreamTLS struct {
	// CAFile is a PEM bundle of CA certificates to trust instead of the system
	// roots (private CAs). Verification is never disabled.
	CAFile string
	// ServerName overrides the name verified in the upstream certificate and sent
	// as SNI, for upstreams addressed by IP.
	ServerName string
}

// NewTransport returns DefaultTransport with the upstream TLS settings applied.
func NewTransport(u UpstreamTLS) (*http.Transport, error) {
	t := DefaultTransport()
	if u.CAFile == "" && u.ServerName == "" {
		return t, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.ServerName}
	if u.CAFile != "" {
		pem, err := os.ReadFile(u.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("upstream CA file contains no PEM certificates")
		}
		cfg.RootCAs = pool
	}
	t.TLSClientConfig = cfg
	return t, nil
}
