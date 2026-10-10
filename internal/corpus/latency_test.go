package corpus

import (
	"slices"
	"testing"
	"time"

	"github.com/TurlaFSB/logshield/internal/engine"
)

// TestLatencyBudget guards the project's performance target: the engine's share
// of added latency must stay far below the 5 ms p99 end-to-end budget. The bound
// here is the full budget, deliberately loose so that slow CI machines and the
// race detector do not cause flakes; the benchmark baseline in docs/performance.md
// records the real numbers.
func TestLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("latency guard skipped in short mode")
	}
	entries := Generate(5000, 99)
	reqs := make([]engine.Request, len(entries))
	for i, e := range entries {
		r, err := e.EngineRequest()
		if err != nil {
			t.Fatal(err)
		}
		reqs[i] = r
	}
	durations := make([]time.Duration, len(reqs))
	for i, r := range reqs {
		start := time.Now()
		engine.Inspect(r, engine.Config{})
		durations[i] = time.Since(start)
	}
	slices.Sort(durations)
	p50, p99, max := durations[len(durations)/2], durations[len(durations)*99/100], durations[len(durations)-1]
	t.Logf("Inspect latency over %d requests: p50 %v, p99 %v, max %v", len(reqs), p50, p99, max)
	if p99 > 5*time.Millisecond {
		t.Errorf("p99 %v exceeds the 5 ms budget", p99)
	}
}
