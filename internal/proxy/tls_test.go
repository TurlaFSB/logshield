package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned writes a certificate and key for 127.0.0.1/localhost and returns
// the paths and the certificate (as a CA pool for clients).
func selfSigned(t *testing.T, dir, name string, notAfter time.Time) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

func TestTLSConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		c  TLSConfig
		ok bool
	}{
		"empty is valid (no TLS)": {TLSConfig{}, true},
		"cert and key":            {TLSConfig{CertFile: "a", KeyFile: "b"}, true},
		"cert only":               {TLSConfig{CertFile: "a"}, false},
		"key only":                {TLSConfig{KeyFile: "b"}, false},
		"tls 1.3":                 {TLSConfig{CertFile: "a", KeyFile: "b", MinVersion: tls.VersionTLS13}, true},
		"tls 1.1":                 {TLSConfig{CertFile: "a", KeyFile: "b", MinVersion: tls.VersionTLS11}, false},
	} {
		if err := tc.c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for in, want := range map[string]uint16{"": tls.VersionTLS12, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13} {
		if got, err := ParseTLSVersion(in); err != nil || got != want {
			t.Errorf("ParseTLSVersion(%q) = %#x, %v", in, got, err)
		}
	}
	for _, bad := range []string{"1.0", "1.1", "TLS1.2", "2"} {
		if _, err := ParseTLSVersion(bad); err == nil {
			t.Errorf("ParseTLSVersion(%q) accepted", bad)
		}
	}
}

func TestNewServerTLSFailsAtStartup(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewServerTLS(TLSConfig{}, nil); err == nil {
		t.Error("empty config accepted")
	}
	if _, err := NewServerTLS(TLSConfig{CertFile: "a"}, nil); err == nil {
		t.Error("invalid config accepted")
	}
	if _, err := NewServerTLS(TLSConfig{CertFile: filepath.Join(dir, "no.crt"), KeyFile: filepath.Join(dir, "no.key")}, nil); err == nil {
		t.Error("missing files accepted")
	}
	c, k, _ := selfSigned(t, dir, "a", time.Now().Add(time.Hour))
	cfg, err := NewServerTLS(TLSConfig{CertFile: c, KeyFile: k}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" {
		t.Errorf("config: %+v", cfg)
	}
}

func TestCertificateIsReloadedWhenFilesChange(t *testing.T) {
	dir := t.TempDir()
	c, k, _ := selfSigned(t, dir, "live", time.Now().Add(time.Hour))
	sink := &logSink{}
	cfg, err := NewServerTLS(TLSConfig{CertFile: c, KeyFile: k, ReloadEvery: time.Millisecond}, newTestLogger(sink))
	if err != nil {
		t.Fatal(err)
	}
	serial := func() string {
		cert, err := cfg.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		x, _ := x509.ParseCertificate(cert.Certificate[0])
		return x.SerialNumber.String()
	}
	first := serial()

	// Rotate: write a different certificate over the same paths, with a later mtime.
	c2, k2, _ := selfSigned(t, dir, "next", time.Now().Add(2*time.Hour))
	later := time.Now().Add(time.Minute)
	for from, to := range map[string]string{c2: c, k2: k} {
		b, _ := os.ReadFile(from)
		if err := os.WriteFile(to, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(to, later, later)
	}
	time.Sleep(5 * time.Millisecond)
	if second := serial(); second == first {
		t.Fatal("the new certificate was not picked up")
	}
	if !strings.Contains(sink.String(), "tls certificate reloaded") {
		t.Errorf("no reload log: %s", sink.String())
	}

	// A broken rotation keeps the previous certificate and logs an error.
	good := serial()
	if err := os.WriteFile(c, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := later.Add(time.Minute)
	_ = os.Chtimes(c, broken, broken)
	time.Sleep(5 * time.Millisecond)
	if got := serial(); got != good {
		t.Error("a broken rotation replaced the working certificate")
	}
	if !strings.Contains(sink.String(), "reload failed") {
		t.Errorf("no failure log: %s", sink.String())
	}
}

func TestNewTransportVerifiesUpstreamCertificates(t *testing.T) {
	dir := t.TempDir()
	plain, perr := NewTransport(UpstreamTLS{})
	if perr != nil || plain.TLSClientConfig != nil {
		t.Errorf("no options: %v %+v", perr, plain.TLSClientConfig)
	}
	if _, err := NewTransport(UpstreamTLS{CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Error("missing CA file accepted")
	}
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o600)
	if _, err := NewTransport(UpstreamTLS{CAFile: empty}); err == nil {
		t.Error("CA file without certificates accepted")
	}

	// A real https upstream with a private CA: trusted only when the CA is given.
	certFile, keyFile, _ := selfSigned(t, dir, "up", time.Now().Add(time.Hour))
	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secure")) }))
	up.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	up.StartTLS()
	defer up.Close()

	get := func(tr *http.Transport) error {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, up.URL, nil)
		resp, doErr := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
		if doErr == nil {
			_ = resp.Body.Close()
		}
		return doErr
	}
	if get(plain) == nil {
		t.Error("an unknown CA was trusted")
	}
	trusted, err := NewTransport(UpstreamTLS{CAFile: certFile})
	if err != nil {
		t.Fatal(err)
	}
	if e := get(trusted); e != nil {
		t.Errorf("private CA not honored: %v", e)
	}
	wrongName, _ := NewTransport(UpstreamTLS{CAFile: certFile, ServerName: "not-the-name.example"})
	if get(wrongName) == nil {
		t.Error("a certificate for the wrong name was accepted")
	}
	rightName, _ := NewTransport(UpstreamTLS{CAFile: certFile, ServerName: "localhost"})
	if e := get(rightName); e != nil {
		t.Errorf("ServerName override: %v", e)
	}
}
