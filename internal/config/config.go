// Package config loads LogShield's settings from a JSON file, environment
// variables and command-line flags, in that order of increasing precedence, and
// turns them into a proxy.Config.
//
// Unknown keys in the file and unknown LOGSHIELD_* environment variables are
// reported, because a misspelled setting in a security control that silently
// does nothing is worse than a refusal to start.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
	"github.com/TurlaFSB/logshield/internal/proxy"
)

// maxFileBytes bounds the configuration file. Real files are tiny.
const maxFileBytes = 1 << 20

// Settings is everything the operator can configure. JSON keys are the
// documented names; omitted keys keep their defaults.
type Settings struct {
	Listen          string   `json:"listen"`
	Upstream        string   `json:"upstream"`
	Mode            string   `json:"mode"`
	BlockSuspicious bool     `json:"block_suspicious"`
	OnError         string   `json:"on_error"`
	MaxBodyBytes    int64    `json:"max_body_bytes"`
	SkipBodyTypes   []string `json:"skip_body_types"`
	ForwardedFor    string   `json:"forwarded_for"`
	RewriteHost     bool     `json:"rewrite_host"`
	AdminListen     string   `json:"admin_listen"`
	MaxInFlight     int      `json:"max_in_flight"`
	LogLevel        string   `json:"log_level"`
	// DisabledRules switches off non-mandatory rules (for tuning false positives).
	DisabledRules []string `json:"disabled_rules"`

	// Timeouts, as Go duration strings such as "30s". ReadTimeout bounds receiving a
	// whole request (raise it for large streamed uploads). ClientWriteTimeout is the
	// longest a single write to a client may stall ("0s" disables). DrainDelay is how
	// long the proxy keeps serving after /readyz starts failing on shutdown, so load
	// balancers can notice.
	ReadTimeout        string `json:"read_timeout"`
	ClientWriteTimeout string `json:"client_write_timeout"`
	DrainDelay         string `json:"drain_delay"`

	// TLS termination for clients. Empty cert and key mean plain HTTP.
	TLSCertFile   string `json:"tls_cert_file"`
	TLSKeyFile    string `json:"tls_key_file"`
	TLSMinVersion string `json:"tls_min_version"` // "1.2" (default) or "1.3"

	// Verification of an https upstream. Verification is never disabled.
	UpstreamCAFile     string `json:"upstream_ca_file"`
	UpstreamServerName string `json:"upstream_server_name"`
}

// Defaults returns the built-in settings: loopback listener and monitor mode.
func Defaults() Settings {
	return Settings{
		Listen:             "127.0.0.1:8080",
		Mode:               string(proxy.ModeMonitor),
		OnError:            string(proxy.FailClosed),
		MaxBodyBytes:       1 << 20,
		ForwardedFor:       string(proxy.ForwardedForReplace),
		MaxInFlight:        1024,
		LogLevel:           "info",
		TLSMinVersion:      "1.2",
		ReadTimeout:        "30s",
		ClientWriteTimeout: "60s",
		DrainDelay:         "0s",
	}
}

// LoadFile merges the JSON file at path into s. Unknown keys, trailing data and
// oversize files are errors.
func (s *Settings) LoadFile(path string) error {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's own configuration file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxFileBytes {
		return fmt.Errorf("%s: larger than %d bytes", path, maxFileBytes)
	}
	return s.LoadJSON(data, path)
}

// LoadJSON merges JSON data into s; name is used in error messages.
func (s *Settings) LoadJSON(data []byte, name string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if dec.More() {
		return fmt.Errorf("%s: unexpected data after the JSON object", name)
	}
	return nil
}

// EnvPrefix is the prefix of every recognized environment variable.
const EnvPrefix = "LOGSHIELD_"

type envVar struct {
	name  string
	apply func(*Settings, string) error
}

func str(f func(*Settings) *string) func(*Settings, string) error {
	return func(s *Settings, v string) error { *f(s) = v; return nil }
}

func boolean(f func(*Settings) *bool) func(*Settings, string) error {
	return func(s *Settings, v string) error {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%q is not a boolean", v)
		}
		*f(s) = b
		return nil
	}
}

func list(f func(*Settings) *[]string) func(*Settings, string) error {
	return func(s *Settings, v string) error {
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		*f(s) = out
		return nil
	}
}

var envVars = []envVar{
	{"LISTEN", str(func(s *Settings) *string { return &s.Listen })},
	{"UPSTREAM", str(func(s *Settings) *string { return &s.Upstream })},
	{"MODE", str(func(s *Settings) *string { return &s.Mode })},
	{"BLOCK_SUSPICIOUS", boolean(func(s *Settings) *bool { return &s.BlockSuspicious })},
	{"ON_ERROR", str(func(s *Settings) *string { return &s.OnError })},
	{"MAX_BODY_BYTES", func(s *Settings, v string) error {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not an integer", v)
		}
		s.MaxBodyBytes = n
		return nil
	}},
	{"SKIP_BODY_TYPES", list(func(s *Settings) *[]string { return &s.SkipBodyTypes })},
	{"FORWARDED_FOR", str(func(s *Settings) *string { return &s.ForwardedFor })},
	{"REWRITE_HOST", boolean(func(s *Settings) *bool { return &s.RewriteHost })},
	{"ADMIN_LISTEN", str(func(s *Settings) *string { return &s.AdminListen })},
	{"MAX_IN_FLIGHT", func(s *Settings, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%q is not an integer", v)
		}
		s.MaxInFlight = n
		return nil
	}},
	{"LOG_LEVEL", str(func(s *Settings) *string { return &s.LogLevel })},
	{"DISABLED_RULES", list(func(s *Settings) *[]string { return &s.DisabledRules })},
	{"READ_TIMEOUT", str(func(s *Settings) *string { return &s.ReadTimeout })},
	{"CLIENT_WRITE_TIMEOUT", str(func(s *Settings) *string { return &s.ClientWriteTimeout })},
	{"DRAIN_DELAY", str(func(s *Settings) *string { return &s.DrainDelay })},
	{"TLS_CERT_FILE", str(func(s *Settings) *string { return &s.TLSCertFile })},
	{"TLS_KEY_FILE", str(func(s *Settings) *string { return &s.TLSKeyFile })},
	{"TLS_MIN_VERSION", str(func(s *Settings) *string { return &s.TLSMinVersion })},
	{"UPSTREAM_CA_FILE", str(func(s *Settings) *string { return &s.UpstreamCAFile })},
	{"UPSTREAM_SERVER_NAME", str(func(s *Settings) *string { return &s.UpstreamServerName })},
}

// EnvConfigFile is the variable naming the configuration file. It is read by the
// caller before the file is loaded, so it is not part of Settings.
const EnvConfigFile = EnvPrefix + "CONFIG"

// ApplyEnv overrides s from environment variables. environ is in os.Environ
// format. Unrecognized LOGSHIELD_* names are returned so the caller can warn.
func (s *Settings) ApplyEnv(environ []string) (unknown []string, err error) {
	known := map[string]envVar{}
	for _, e := range envVars {
		known[EnvPrefix+e.name] = e
	}
	values := map[string]string{}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, EnvPrefix) || name == EnvConfigFile {
			continue
		}
		if _, ok := known[name]; !ok {
			unknown = append(unknown, name)
			continue
		}
		values[name] = value
	}
	sort.Strings(unknown)
	var errs []error
	for _, e := range envVars { // fixed order: deterministic errors
		if v, ok := values[EnvPrefix+e.name]; ok {
			if err := e.apply(s, v); err != nil {
				errs = append(errs, fmt.Errorf("%s%s: %w", EnvPrefix, e.name, err))
			}
		}
	}
	return unknown, errors.Join(errs...)
}

// ProxyConfig validates s and converts it. The upstream URL is parsed here so
// that credentials never travel further than this function's error path.
func (s Settings) ProxyConfig(logger *slog.Logger) (proxy.Config, error) {
	var errs []error
	if s.Upstream == "" {
		errs = append(errs, errors.New("upstream is required"))
	}
	target, err := url.Parse(s.Upstream)
	if err != nil {
		errs = append(errs, errors.New("upstream is not a valid URL"))
		target = nil
	}
	if s.Listen == "" {
		errs = append(errs, errors.New("listen is required"))
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(s.LogLevel)); err != nil {
		errs = append(errs, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s.LogLevel))
	}
	disabled := make([]engine.RuleID, len(s.DisabledRules))
	for i, id := range s.DisabledRules {
		disabled[i] = engine.RuleID(id)
	}
	cfg := proxy.Config{
		Upstream:        target,
		Mode:            proxy.Mode(s.Mode),
		BlockSuspicious: s.BlockSuspicious,
		OnError:         proxy.FailPolicy(s.OnError),
		Engine:          engine.Config{Disabled: disabled},
		MaxBodyBytes:    s.MaxBodyBytes,
		SkipBodyTypes:   s.SkipBodyTypes,
		ForwardedFor:    proxy.ForwardedFor(s.ForwardedFor),
		RewriteHost:     s.RewriteHost,
		MaxInFlight:     s.MaxInFlight,
		Logger:          logger,
	}
	// Validate everything else even when the upstream is missing or unusable,
	// so the operator sees all problems at once without a duplicate upstream complaint.
	checked := cfg
	if target == nil || s.Upstream == "" {
		checked.Upstream = &url.URL{Scheme: "http", Host: "placeholder.invalid"}
	}
	if err := checked.Validate(); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.Timeouts(); err != nil {
		errs = append(errs, err)
	}
	if t, err := s.Timeouts(); err == nil {
		cfg.ClientWriteTimeout = t.ClientWrite
	}
	if _, err := s.TLSConfig(); err != nil {
		errs = append(errs, err)
	}
	if s.UpstreamCAFile != "" || s.UpstreamServerName != "" {
		if tr, err := proxy.NewTransport(proxy.UpstreamTLS{CAFile: s.UpstreamCAFile, ServerName: s.UpstreamServerName}); err != nil {
			errs = append(errs, err)
		} else {
			cfg.Transport = tr
		}
	}
	if err := cfg.Engine.Validate(); err != nil {
		errs = append(errs, err)
	}
	return cfg, errors.Join(errs...)
}

// Timeouts are the parsed duration settings. ClientWrite is negative when disabled.
type Timeouts struct {
	Read, ClientWrite, Drain time.Duration
}

// Timeouts parses and validates the duration settings.
func (s Settings) Timeouts() (Timeouts, error) {
	var errs []error
	parse := func(name, v string, min time.Duration) time.Duration {
		d, err := time.ParseDuration(v)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %q is not a duration such as 30s or 2m", name, v))
		case d < min:
			errs = append(errs, fmt.Errorf("%s: %q is too small", name, v))
		}
		return d
	}
	t := Timeouts{
		Read:        parse("read_timeout", s.ReadTimeout, time.Second),
		ClientWrite: parse("client_write_timeout", s.ClientWriteTimeout, 0),
		Drain:       parse("drain_delay", s.DrainDelay, 0),
	}
	if t.ClientWrite == 0 {
		t.ClientWrite = -1
	}
	return t, errors.Join(errs...)
}

// TLSConfig returns the client-facing TLS settings, validated. Its CertFile is
// empty when TLS is not configured.
func (s Settings) TLSConfig() (proxy.TLSConfig, error) {
	v, err := proxy.ParseTLSVersion(s.TLSMinVersion)
	c := proxy.TLSConfig{CertFile: s.TLSCertFile, KeyFile: s.TLSKeyFile, MinVersion: v}
	return c, errors.Join(err, c.Validate())
}

// Level returns the configured log level (valid once ProxyConfig succeeded).
func (s Settings) Level() slog.Level {
	var l slog.Level
	_ = l.UnmarshalText([]byte(s.LogLevel))
	return l
}

// Redacted returns s as indented JSON with the upstream's userinfo removed, for
// "show me the effective configuration".
func (s Settings) Redacted() string {
	if u, err := url.Parse(s.Upstream); err == nil && u.User != nil {
		s.Upstream = u.Redacted()
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return string(b)
}
