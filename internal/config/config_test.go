package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TurlaFSB/logshield/internal/proxy"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "logshield.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreSafe(t *testing.T) {
	d := Defaults()
	if d.Listen != "127.0.0.1:8080" || d.Mode != "monitor" || d.OnError != "closed" || d.MaxInFlight != 1024 || d.AdminListen != "" {
		t.Errorf("unsafe defaults: %+v", d)
	}
	d.Upstream = "http://127.0.0.1:9000"
	if _, err := d.ProxyConfig(nil); err != nil {
		t.Errorf("defaults plus an upstream must be valid: %v", err)
	}
}

func TestLoadFileMergesOntoDefaults(t *testing.T) {
	s := Defaults()
	err := s.LoadFile(write(t, `{"upstream":"http://10.0.0.5:8080","mode":"block","skip_body_types":["image/"],"disabled_rules":["LSH-2001"],"max_in_flight":10}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != "block" || s.Upstream != "http://10.0.0.5:8080" || s.MaxInFlight != 10 || s.Listen != "127.0.0.1:8080" || len(s.SkipBodyTypes) != 1 {
		t.Errorf("merge wrong: %+v", s)
	}
	cfg, err := s.ProxyConfig(nil)
	if err != nil || len(cfg.Engine.Disabled) != 1 || cfg.Mode != proxy.ModeBlock {
		t.Errorf("ProxyConfig: %+v %v", cfg, err)
	}
}

func TestLoadFileRejectsMistakes(t *testing.T) {
	for name, content := range map[string]string{
		"unknown key":    `{"upstrem":"http://x"}`,
		"wrong type":     `{"max_in_flight":"ten"}`,
		"trailing data":  `{} {}`,
		"not json":       `mode: block`,
		"empty":          ``,
		"comment":        `{"mode":"block"} // hi`,
		"oversize value": `{"upstream":"` + strings.Repeat("a", maxFileBytes) + `"}`,
	} {
		s := Defaults()
		if err := s.LoadFile(write(t, content)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := Defaults()
	if err := s.LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing file was accepted")
	}
	dir := t.TempDir()
	if err := s.LoadFile(dir); err == nil {
		t.Error("a directory was accepted")
	}
}

func TestApplyEnv(t *testing.T) {
	s := Defaults()
	unknown, err := s.ApplyEnv([]string{
		"PATH=/usr/bin",
		"LOGSHIELD_LISTEN=0.0.0.0:80",
		"LOGSHIELD_UPSTREAM=http://backend:8080",
		"LOGSHIELD_MODE=block",
		"LOGSHIELD_BLOCK_SUSPICIOUS=true",
		"LOGSHIELD_ON_ERROR=open",
		"LOGSHIELD_MAX_BODY_BYTES=2048",
		"LOGSHIELD_SKIP_BODY_TYPES=image/, video/ ,",
		"LOGSHIELD_FORWARDED_FOR=append",
		"LOGSHIELD_REWRITE_HOST=1",
		"LOGSHIELD_ADMIN_LISTEN=127.0.0.1:9090",
		"LOGSHIELD_MAX_IN_FLIGHT=-1",
		"LOGSHIELD_LOG_LEVEL=debug",
		"LOGSHIELD_DISABLED_RULES=LSH-2001,LSH-2002",
		"LOGSHIELD_CONFIG=/etc/logshield.json",
		"LOGSHIELD_TYPO=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{
		Listen: "0.0.0.0:80", Upstream: "http://backend:8080", Mode: "block", BlockSuspicious: true, OnError: "open",
		MaxBodyBytes: 2048, SkipBodyTypes: []string{"image/", "video/"}, ForwardedFor: "append", RewriteHost: true,
		AdminListen: "127.0.0.1:9090", MaxInFlight: -1, LogLevel: "debug", DisabledRules: []string{"LSH-2001", "LSH-2002"}, TLSMinVersion: "1.2", ReadTimeout: "30s", ClientWriteTimeout: "60s", DrainDelay: "0s",
	}
	if strings.Join(s.SkipBodyTypes, "|") != "image/|video/" || strings.Join(s.DisabledRules, "|") != "LSH-2001|LSH-2002" {
		t.Errorf("lists: %+v", s)
	}
	s.SkipBodyTypes, s.DisabledRules, want.SkipBodyTypes, want.DisabledRules = nil, nil, nil, nil
	if s.Redacted() != want.Redacted() {
		t.Errorf("settings:\n%s\nwant:\n%s", s.Redacted(), want.Redacted())
	}
	if len(unknown) != 1 || unknown[0] != "LOGSHIELD_TYPO" {
		t.Errorf("unknown = %v (LOGSHIELD_CONFIG must be recognized)", unknown)
	}
}

func TestApplyEnvReportsBadValues(t *testing.T) {
	s := Defaults()
	_, err := s.ApplyEnv([]string{"LOGSHIELD_BLOCK_SUSPICIOUS=maybe", "LOGSHIELD_MAX_BODY_BYTES=big", "LOGSHIELD_MAX_IN_FLIGHT=many", "LOGSHIELD_MODE=block"})
	if err == nil {
		t.Fatal("bad values accepted")
	}
	for _, name := range []string{"LOGSHIELD_BLOCK_SUSPICIOUS", "LOGSHIELD_MAX_BODY_BYTES", "LOGSHIELD_MAX_IN_FLIGHT"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name %s: %v", name, err)
		}
	}
	if s.Mode != "block" {
		t.Error("valid variables must still apply")
	}
}

func TestProxyConfigReportsEveryProblem(t *testing.T) {
	s := Defaults()
	s.Mode, s.LogLevel, s.Listen = "enforce", "loud", ""
	s.DisabledRules = []string{"LSH-9999", "LSH-3001"}
	_, err := s.ProxyConfig(nil)
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"upstream is required", "unknown mode", "unknown log level", "listen is required", "LSH-9999", "mandatory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestCredentialsNeverAppearInErrorsOrOutput(t *testing.T) {
	s := Defaults()
	s.Upstream = "http://admin:hunter2@backend:8080"
	_, err := s.ProxyConfig(slog.Default())
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("credentials must be rejected without echoing them: %v", err)
	}
	if out := s.Redacted(); strings.Contains(out, "hunter2") {
		t.Errorf("Redacted leaks the password:\n%s", out)
	}
	s.Upstream = "http://[::bad"
	if _, err := s.ProxyConfig(nil); err == nil || strings.Contains(err.Error(), "[::bad") {
		t.Errorf("invalid URL error: %v", err)
	}
}

func TestLevel(t *testing.T) {
	s := Defaults()
	s.LogLevel = "warn"
	if s.Level() != slog.LevelWarn {
		t.Errorf("level = %v", s.Level())
	}
}

func TestTLSSettings(t *testing.T) {
	s := Defaults()
	s.Upstream = "http://x:1"
	s.TLSCertFile = "only-cert.pem"
	if _, err := s.ProxyConfig(nil); err == nil || !strings.Contains(err.Error(), "together") {
		t.Errorf("cert without key: %v", err)
	}
	s.TLSKeyFile, s.TLSMinVersion = "k.pem", "1.0"
	if _, err := s.ProxyConfig(nil); err == nil || !strings.Contains(err.Error(), "unsupported TLS version") {
		t.Errorf("TLS 1.0: %v", err)
	}
	s.TLSMinVersion = "1.3"
	if _, err := s.ProxyConfig(nil); err != nil {
		t.Errorf("valid TLS settings: %v", err)
	}
	c, err := s.TLSConfig()
	if err != nil || c.CertFile != "only-cert.pem" || c.MinVersion == 0 {
		t.Errorf("TLSConfig: %+v %v", c, err)
	}
}

func TestUpstreamTLSSettings(t *testing.T) {
	s := Defaults()
	s.Upstream = "https://x:1"
	s.UpstreamCAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := s.ProxyConfig(nil); err == nil || !strings.Contains(err.Error(), "upstream CA") {
		t.Errorf("missing CA file: %v", err)
	}
	s.UpstreamCAFile, s.UpstreamServerName = "", "backend.internal"
	cfg, err := s.ProxyConfig(nil)
	if err != nil || cfg.Transport == nil {
		t.Errorf("server name only: %v %v", cfg.Transport, err)
	}
}

func TestTLSEnvironment(t *testing.T) {
	s := Defaults()
	if _, err := s.ApplyEnv([]string{"LOGSHIELD_TLS_CERT_FILE=c", "LOGSHIELD_TLS_KEY_FILE=k", "LOGSHIELD_TLS_MIN_VERSION=1.3", "LOGSHIELD_UPSTREAM_CA_FILE=ca", "LOGSHIELD_UPSTREAM_SERVER_NAME=n"}); err != nil {
		t.Fatal(err)
	}
	if s.TLSCertFile != "c" || s.TLSKeyFile != "k" || s.TLSMinVersion != "1.3" || s.UpstreamCAFile != "ca" || s.UpstreamServerName != "n" {
		t.Errorf("%+v", s)
	}
}

func TestTimeouts(t *testing.T) {
	s := Defaults()
	got, err := s.Timeouts()
	if err != nil || got.Read != 30*time.Second || got.ClientWrite != 60*time.Second || got.Drain != 0 {
		t.Errorf("defaults: %+v %v", got, err)
	}
	s.ClientWriteTimeout, s.DrainDelay, s.ReadTimeout = "0s", "5s", "2m"
	got, err = s.Timeouts()
	if err != nil || got.ClientWrite >= 0 || got.Drain != 5*time.Second || got.Read != 2*time.Minute {
		t.Errorf("custom: %+v %v", got, err)
	}
	for name, mut := range map[string]func(*Settings){
		"not a duration": func(s *Settings) { s.ReadTimeout = "soon" },
		"read too small": func(s *Settings) { s.ReadTimeout = "0s" },
		"negative drain": func(s *Settings) { s.DrainDelay = "-1s" },
		"negative write": func(s *Settings) { s.ClientWriteTimeout = "-5s" },
		"missing unit":   func(s *Settings) { s.DrainDelay = "10" },
	} {
		bad := Defaults()
		bad.Upstream = "http://x:1"
		mut(&bad)
		if _, err := bad.ProxyConfig(nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s = Defaults()
	s.Upstream = "http://x:1"
	s.ClientWriteTimeout = "0s"
	if cfg, err := s.ProxyConfig(nil); err != nil || cfg.ClientWriteTimeout >= 0 {
		t.Errorf("0s must disable the write timeout: %v %v", cfg.ClientWriteTimeout, err)
	}
}
