package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version flag", args: []string{"-version"}, wantCode: 0, wantStdout: "logshield "},
		{name: "no args reports not implemented", args: nil, wantCode: 1, wantStderr: "not implemented"},
		{name: "unknown flag is a usage error", args: []string{"-nope"}, wantCode: 2, wantStderr: "flag provided but not defined"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(tc.args, &out, &errb)
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if !strings.Contains(out.String(), tc.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", out.String(), tc.wantStdout)
			}
			if !strings.Contains(errb.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", errb.String(), tc.wantStderr)
			}
		})
	}
}
