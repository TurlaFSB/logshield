package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// neutralize makes s safe for a downstream Java logging pipeline by breaking the
// two-character sequence "${". It is the last line of defence: attacker-controlled
// fields are also defanged individually, but nothing a request influences may
// reach a log line with an active lookup, even through an error message.
func neutralize(s string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return strings.ReplaceAll(s, "${", "$%7B")
}

// safeHandler wraps a slog.Handler and neutralizes every string it is given.
type safeHandler struct{ inner slog.Handler }

// newSafeLogger returns a logger whose output can never carry "${".
func newSafeLogger(l *slog.Logger) *slog.Logger {
	if _, ok := l.Handler().(safeHandler); ok {
		return l
	}
	return slog.New(safeHandler{inner: l.Handler()})
}

func (h safeHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

func (h safeHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, neutralize(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(safeAttr(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

func (h safeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = safeAttr(a)
	}
	return safeHandler{inner: h.inner.WithAttrs(out)}
}

func (h safeHandler) WithGroup(name string) slog.Handler {
	return safeHandler{inner: h.inner.WithGroup(neutralize(name))}
}

func safeAttr(a slog.Attr) slog.Attr {
	a.Key = neutralize(a.Key)
	a.Value = safeValue(a.Value)
	return a
}

func safeValue(v slog.Value) slog.Value {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(neutralize(v.String()))
	case slog.KindGroup:
		g := v.Group()
		out := make([]slog.Attr, len(g))
		for i, a := range g {
			out[i] = safeAttr(a)
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		// Errors, slices, maps and structs: render and neutralize only if needed,
		// so well-behaved values keep their type.
		if s := fmt.Sprintf("%v", v.Any()); strings.Contains(s, "${") {
			return slog.StringValue(neutralize(s))
		}
		return v
	default:
		return v
	}
}
