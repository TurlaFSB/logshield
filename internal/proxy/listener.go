package proxy

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
)

// reasonProtocolError marks requests that Go's HTTP server refused before the
// handler ran (bad request line, invalid header bytes, conflicting framing,
// oversize headers).
const reasonProtocolError = "protocol-error"

// goErrorHead is what follows the status line in the responses net/http writes
// by itself when it rejects a request. Handler responses always carry other
// headers first (ours start with Cache-Control), so the shape is unambiguous.
// Tests pin it for every Go version CI covers.
var goErrorHead = []byte("\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n")

// WrapListener returns ln wrapped so that requests refused by Go's HTTP server
// before they reach the proxy are still logged and delivered to the Observer
// (Action rejected, Reason "protocol-error"). They are safe, since they never
// reach the upstream, but without this they would be invisible: for a security
// control, "someone is sending malformed requests" is worth knowing.
//
// It only works on plain-text connections; with TLS, wrap the listener that is
// handed to the TLS layer's output (the decrypted connection), not its input.
func (p *Proxy) WrapListener(ln net.Listener) net.Listener {
	return &observedListener{Listener: ln, p: p}
}

type observedListener struct {
	net.Listener
	p *Proxy
}

func (l *observedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &observedConn{Conn: c, p: l.p}, nil
}

type observedConn struct {
	net.Conn
	p        *Proxy
	reported atomic.Bool
}

func (c *observedConn) Write(b []byte) (int, error) {
	if status, ok := goErrorStatus(b); ok && c.reported.CompareAndSwap(false, true) {
		c.p.protocolError(c.RemoteAddr(), status)
	}
	return c.Conn.Write(b)
}

// goErrorStatus recognizes a response written by net/http for a rejected request.
func goErrorStatus(b []byte) (int, bool) {
	const prefix = "HTTP/1.1 "
	if len(b) < len(prefix)+3 || !bytes.HasPrefix(b, []byte(prefix)) {
		return 0, false
	}
	status, err := strconv.Atoi(string(b[len(prefix) : len(prefix)+3]))
	if err != nil || status < 400 {
		return 0, false
	}
	end := bytes.Index(b, []byte("\r\n"))
	if end < 0 || !bytes.HasPrefix(b[end:], goErrorHead) {
		return 0, false
	}
	return status, true
}

func (p *Proxy) protocolError(addr net.Addr, status int) {
	remote := ""
	if addr != nil {
		remote = addr.String()
		if host, _, err := net.SplitHostPort(remote); err == nil {
			remote = host
		}
	}
	ev := Event{ID: newID(), Mode: p.cfg.Mode, Action: ActionRejected, Status: status, Reason: reasonProtocolError, Remote: remote}
	if p.cfg.Observer != nil {
		func() {
			defer func() { _ = recover() }()
			p.cfg.Observer.Observe(ev)
		}()
	}
	p.log.LogAttrs(context.Background(), slog.LevelWarn, "request refused by the HTTP server",
		slog.String("id", ev.ID), slog.String("action", string(ev.Action)), slog.Int("status", status),
		slog.String("reason", ev.Reason), slog.String("remote", remote), slog.String("status_text", http.StatusText(status)))
}
